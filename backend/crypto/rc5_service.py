import logging
from typing import Tuple, Optional
from pathlib import Path
from backend.crypto.symmetric import SymmetricCrypto
from backend.crypto.md5_service import MD5Service as MD5
from backend.validation.validators import FileValidator
from backend.rng.lcg_generator import LCG

logger = logging.getLogger("lab_suite.rc5_service")

SECRET_PATH = Path("secret.bin")

class RC5(SymmetricCrypto):
    def __init__(self, w: int, r: int, key: bytes):
        assert w in (16, 32, 64)
        assert 0 < r <= 32
        self.w = w
        self.r = r
        self.mod = 1 << w
        self.mask = self.mod - 1
        self.word_bytes = w // 8
        if w == 16:
            self.Pw = 0xB7E1
            self.Qw = 0x9E37
        elif w == 32:
            self.Pw = 0xB7E15163
            self.Qw = 0x9E3779B9
        else:
            self.Pw = 0xB7E151628AED2A6B
            self.Qw = 0x9E3779B97F4A7C15
        self.S = self._key_schedule(key)

    def _rotl(self, x: int, s: int) -> int:
        s &= self.w - 1
        return ((x << s) & self.mask) | (x >> (self.w - s))

    def _rotr(self, x: int, s: int) -> int:
        s &= self.w - 1
        return ((x >> s) | ((x << (self.w - s)) & self.mask)) & self.mask

    def _key_schedule(self, K: bytes):
        u = self.word_bytes
        c = max(1, (len(K) + u - 1) // u)
        L = [0] * c
        for i in range(len(K)-1, -1, -1):
            L[i // u] = ((L[i // u] << 8) + K[i]) & self.mask
        t = 2 * (self.r + 1)
        S = [0] * t
        S[0] = self.Pw
        for i in range(1, t):
            S[i] = (S[i-1] + self.Qw) & self.mask
        A = B = i = j = 0
        n = 3 * max(t, c)
        for _ in range(n):
            A = S[i] = self._rotl((S[i] + A + B) & self.mask, 3)
            B = L[j] = self._rotl((L[j] + A + B) & self.mask, (A + B) & (self.w - 1))
            i = (i + 1) % t
            j = (j + 1) % c
        return S

    def encrypt_block(self, block: bytes) -> bytes:
        A = int.from_bytes(block[:self.word_bytes], 'little')
        B = int.from_bytes(block[self.word_bytes:], 'little')
        A = (A + self.S[0]) & self.mask
        B = (B + self.S[1]) & self.mask
        for _i in range(1, self.r + 1):
            A = (self._rotl((A ^ B), B) + self.S[2 * _i]) & self.mask
            B = (self._rotl((B ^ A), A) + self.S[2 * _i + 1]) & self.mask
        return A.to_bytes(self.word_bytes, 'little') + B.to_bytes(self.word_bytes, 'little')

    def decrypt_block(self, block: bytes) -> bytes:
        A = int.from_bytes(block[:self.word_bytes], 'little')
        B = int.from_bytes(block[self.word_bytes:], 'little')
        for _i in range(self.r, 0, -1):
            B = self._rotr((B - self.S[2 * _i + 1]) & self.mask, A) ^ A
            A = self._rotr((A - self.S[2 * _i]) & self.mask, B) ^ B
        B = (B - self.S[1]) & self.mask
        A = (A - self.S[0]) & self.mask
        return A.to_bytes(self.word_bytes, 'little') + B.to_bytes(self.word_bytes, 'little')


def derive_key(passphrase: str, key_bytes: int) -> bytes:
    p = passphrase.encode('utf-8')
    h = MD5(p).digest()
    if key_bytes == 8:
        return h[-8:]
    if key_bytes == 16:
        return h
    if key_bytes == 32:
        return MD5(h).digest() + h
    raise ValueError("key_bytes must be one of {8,16,32}")


def pad(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len]) * pad_len


def unpad(data: bytes, block_size: int) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("Invalid padded data length")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Invalid padding")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid padding bytes")
    return data[:-pad_len]


def _prng_bytes(n: int) -> bytes:
    lcg = LCG(m=2147483647, a=16807, c=0, seed=12345)
    out = bytearray()
    while len(out) < n:
        out.extend(lcg.next().to_bytes(4, 'little'))
    return bytes(out[:n])


def encrypt_file(in_path: str, out_path: str, passphrase: str, w: int, r: int, key_bytes: int) -> Tuple[bool, str]:
    try:
        key = derive_key(passphrase, key_bytes)
        cipher = RC5(w=w, r=r, key=key)
        block_size = 2 * (w // 8)
        with open(in_path, 'rb') as f:
            plaintext = f.read()
        padded = pad(plaintext, block_size)
        iv = _prng_bytes(block_size)
        with open(out_path, 'wb') as out:
            out.write(cipher.encrypt_block(iv))
            prev = iv
            for i in range(0, len(padded), block_size):
                block = padded[i:i+block_size]
                x = bytes(a ^ b for a, b in zip(block, prev))
                c = cipher.encrypt_block(x)
                out.write(c)
                prev = c
        return True, f"File encrypted successfully. Output saved to: {out_path}"
    except Exception as e:
        return False, f"Encryption failed: {str(e)}"


def decrypt_with_pass(in_path: str, out_path: str, passphrase: str, w: int, r: int, key_bytes: int) -> Tuple[bool, str]:
    try:
        key = derive_key(passphrase, key_bytes)
        cipher = RC5(w=w, r=r, key=key)
        block_size = 2 * (w // 8)
        with open(in_path, 'rb') as f:
            data = f.read()
        if len(data) < block_size or len(data) % block_size != 0:
            raise ValueError("Ciphertext length is invalid")
        enc_iv = data[:block_size]
        ct = data[block_size:]
        iv = cipher.decrypt_block(enc_iv)
        prev = iv
        out = bytearray()
        for i in range(0, len(ct), block_size):
            c = ct[i:i+block_size]
            x = cipher.decrypt_block(c)
            p = bytes(a ^ b for a, b in zip(x, prev))
            out.extend(p)
            prev = c
        plaintext = unpad(bytes(out), block_size)
        with open(out_path, 'wb') as f:
            f.write(plaintext)
        return True, f"File decrypted successfully. Output saved to: {out_path}"
    except Exception as e:
        return False, f"Decryption failed: Invalid passphrase"


def validate_parameters(w: int, r: int, key_bytes: int) -> Tuple[bool, str]:
    if w not in [16, 32, 64]:
        return False, "Word size (w) must be 16, 32, or 64"
    if not (1 <= r <= 32):
        return False, "Rounds (r) must be between 1 and 32"
    if key_bytes not in [8, 16, 32]:
        return False, "Key length (b) must be 8, 16, or 32 bytes"
    return True, "Parameters are valid"