import binascii
import re
import logging
from typing import Tuple
from pathlib import Path
from backend.validation.validators import FileValidator

logger = logging.getLogger("lab_suite.md5_service")

def _rotl32(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


class MD5Service:
    _IV = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476)
    _S = (
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    )
    _T = tuple(int(abs(__import__("math").sin(i + 1)) * (1 << 32)) & 0xFFFFFFFF for i in range(64))

    def __init__(self, data: bytes | bytearray | None = None):
        self._a, self._b, self._c, self._d = self._IV
        self._count = 0
        self._buffer = bytearray()
        if data:
            self.update(data)

    def copy(self) -> "MD5Service":
        other = MD5Service()
        other._a, other._b, other._c, other._d = self._a, self._b, self._c, self._d
        other._count = self._count
        other._buffer = bytearray(self._buffer)
        return other

    def _transform(self, block64: bytes) -> None:
        X = [int.from_bytes(block64[i*4:(i+1)*4], "little") for i in range(16)]
        a, b, c, d = self._a, self._b, self._c, self._d
        for i in range(64):
            if 0 <= i < 16:
                f = (b & c) | (~b & d)
                g = i
            elif 16 <= i < 32:
                f = (d & b) | (~d & c)
                g = (5*i + 1) & 15
            elif 32 <= i < 48:
                f = b ^ c ^ d
                g = (3*i + 5) & 15
            else:
                f = c ^ (b | ~d)
                g = (7*i) & 15
            f = (f + a + self._T[i] + X[g]) & 0xFFFFFFFF
            a, d, c, b = d, c, b, (b + _rotl32(f, self._S[i])) & 0xFFFFFFFF
        self._a = (self._a + a) & 0xFFFFFFFF
        self._b = (self._b + b) & 0xFFFFFFFF
        self._c = (self._c + c) & 0xFFFFFFFF
        self._d = (self._d + d) & 0xFFFFFFFF

    def update(self, data: bytes | bytearray | memoryview) -> None:
        if not data:
            return
        mv = memoryview(data)
        self._count += len(mv)
        self._buffer += mv.tobytes()
        i = 0
        while len(self._buffer) - i >= 64:
            self._transform(self._buffer[i:i+64])
            i += 64
        if i:
            self._buffer = bytearray(self._buffer[i:])

    def _finalize_bytes(self) -> bytes:
        a, b, c, d = self._a, self._b, self._c, self._d
        buffer = bytearray(self._buffer)
        count = self._count
        buffer += b"\x80"
        while (len(buffer) % 64) != 56:
            buffer += b"\x00"
        bit_len = (count * 8) & 0xFFFFFFFFFFFFFFFF
        buffer += bit_len.to_bytes(8, "little")
        i = 0
        A, B, C, D = a, b, c, d
        while i < len(buffer):
            self._a, self._b, self._c, self._d = A, B, C, D
            self._transform(buffer[i:i+64])
            A, B, C, D = self._a, self._b, self._c, self._d
            i += 64
        self._a, self._b, self._c, self._d = a, b, c, d
        return (A.to_bytes(4, "little") + B.to_bytes(4, "little") + C.to_bytes(4, "little") + D.to_bytes(4, "little"))

    def digest(self) -> bytes:
        return self._finalize_bytes()

    def hexdigest(self) -> str:
        return binascii.hexlify(self.digest()).decode("ascii")


def md5_string(text: str, encoding: str = "utf-8") -> str:
    return MD5Service(text.encode(encoding)).hexdigest()


def md5_file(file_path: str) -> str:
    h = MD5Service()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def save_md5_to_file(hex_hash: str, file_path: str) -> None:
    FileValidator.validate_write_permissions(Path(file_path))
    with open(file_path, "wt", encoding="utf-8") as f:
        f.write(hex_hash + "\n")


_MD5_HEX_RE = re.compile(r"^[0-9a-fA-F]{32}$")


def verify_string_with_hash(input_string: str, expected_hash: str) -> Tuple[bool, str]:
    try:
        calculated_hash = md5_string(input_string)
        is_valid = calculated_hash.lower() == expected_hash.lower()
        return is_valid, calculated_hash
    except Exception as e:
        return False, str(e)


def verify_file_with_hash_file(text_file_path: str, hash_file_path: str) -> Tuple[bool, str, str]:
    try:
        FileValidator.validate_file_path(text_file_path)
        FileValidator.validate_file_path(hash_file_path)
        
        with open(hash_file_path, "rt", encoding="utf-8", errors="replace") as f:
            expected_hash = f.read().strip()
        if not _MD5_HEX_RE.match(expected_hash):
            return False, "", "Invalid hash format in file"
        calculated_hash = md5_file(text_file_path)
        is_valid = calculated_hash.lower() == expected_hash.lower()
        return is_valid, calculated_hash, expected_hash
    except Exception as e:
        return False, "", str(e)