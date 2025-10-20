import logging
import os
import binascii
from typing import Tuple, Optional
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import dsa, utils
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

from backend.crypto.base import CryptoService
from backend.validation.validators import FileValidator
from backend.storage.key_manager import (
    load_private_key, 
    load_public_key,
    save_private_key,
    save_public_key
)
from backend.storage.file_manager import save_signature

logger = logging.getLogger("lab_suite.dss_service")

DEFAULT_PRIVATE_KEY = Path("dss_private.pem")
DEFAULT_PUBLIC_KEY = Path("dss_public.pem")
DEFAULT_SIGNATURE_FILE = Path("dss_signature.txt")

CHUNK_SIZE = 1024 * 1024

class DSSService(CryptoService):
    
    def __init__(self):
        pass

    @staticmethod
    def hash_bytes(data: bytes, algo_name: str = "sha256") -> bytes:
        algo = DSSService.get_hash_algo(algo_name)
        h = hashes.Hash(algo)
        h.update(data)
        return h.finalize()

    @staticmethod
    def hash_file(path: str, algo_name: str = "sha256") -> bytes:
        algo = DSSService.get_hash_algo(algo_name)
        h = hashes.Hash(algo)
        with open(path, "rb") as f:
            while True:
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                h.update(chunk)
        return h.finalize()

    @staticmethod
    def get_hash_algo(name: str):
        n = name.lower()
        if n in ("sha1", "sha-1"):
            return hashes.SHA1()
        if n in ("sha224", "sha-224"):
            return hashes.SHA224()
        if n in ("sha256", "sha-256"):
            return hashes.SHA256()
        if n in ("sha384", "sha-384"):
            return hashes.SHA384()
        if n in ("sha512", "sha-512"):
            return hashes.SHA512()
        raise ValueError(f"Unsupported hash algorithm: {name}")

    def generate_keys(self, key_size: int, priv_path: str, pub_path: str, password: Optional[str] = None) -> Tuple[bool, str]:
        try:
            logger.info(f"Generating DSA keys: {key_size} bits, private={priv_path}, public={pub_path}")
            
            if key_size not in (1024, 2048, 3072, 4096):
                return False, "DSA key_size must be one of 1024, 2048, 3072, 4096"
            
            FileValidator.validate_write_permissions(Path(priv_path))
            FileValidator.validate_write_permissions(Path(pub_path))
            
            private_key = dsa.generate_private_key(key_size=key_size)
            public_key = private_key.public_key()
            
            pwd = password.encode("utf-8") if password else None
            save_private_key(priv_path, private_key, pwd)
            save_public_key(pub_path, public_key)
            
            logger.info(f"DSA keys generated successfully: {priv_path} and {pub_path}")
            return True, f"DSA keys generated successfully:\nPrivate key: {priv_path}\nPublic key: {pub_path}"
            
        except Exception as e:
            logger.error(f"DSA key generation failed: {e}")
            return False, f"Key generation failed: {str(e)}"

    def sign_string(self, message: str, priv_path: str, password: Optional[str] = None, hash_algo: str = "sha256") -> Tuple[bool, str]:
        try:
            logger.info(f"Signing string with private key: {priv_path}")
            
            pwd = password.encode("utf-8") if password else None
            private_key = load_private_key(priv_path, password=pwd)
            
            data = message.encode("utf-8")
            algo = self.get_hash_algo(hash_algo)
            signature = private_key.sign(data, algo)
            
            sig_hex = binascii.hexlify(signature).decode("ascii")
            message_hash = self.hash_bytes(data, hash_algo).hex()
            
            logger.info("String signing successful")
            return True, f"String signed successfully:\nMessage: {message}\nHash: {message_hash} ({hash_algo})\nSignature (hex): {sig_hex}"
            
        except Exception as e:
            logger.error(f"String signing failed: {e}")
            return False, f"String signing failed: {str(e)}"

    def verify_string(self, message: str, signature_hex: str, pub_path: str, hash_algo: str = "sha256") -> Tuple[bool, str]:
        try:
            logger.info(f"Verifying string with public key: {pub_path}")
            
            public_key = load_public_key(pub_path)
            
            data = message.encode("utf-8")
            algo = self.get_hash_algo(hash_algo)
            
            try:
                signature = binascii.unhexlify(signature_hex)
            except binascii.Error:
                return False, "Invalid hex signature format"
            
            try:
                public_key.verify(signature, data, algo)
                message_hash = self.hash_bytes(data, hash_algo).hex()
                logger.info("String verification successful")
                return True, f"✓ VERIFIED – signature is valid for message.\nHash used: {hash_algo} ; digest = {message_hash}"
            except InvalidSignature:
                message_hash = self.hash_bytes(data, hash_algo).hex()
                logger.info("String verification failed")
                return False, f"✗ NOT VERIFIED – signature is INVALID for message.\nHash used: {hash_algo} ; digest = {message_hash}"
            
        except Exception as e:
            logger.error(f"String verification failed: {e}")
            return False, f"String verification failed: {str(e)}"

    def sign_file(self, file_path: str, priv_path: str, password: Optional[str] = None, hash_algo: str = "sha256") -> Tuple[bool, str]:
        try:
            logger.info(f"Signing file: {file_path}")
            
            FileValidator.validate_file_path(file_path)
            
            pwd = password.encode("utf-8") if password else None
            private_key = load_private_key(priv_path, password=pwd)
            
            digest = self.hash_file(file_path, hash_algo)
            algo = self.get_hash_algo(hash_algo)
            
            signature = private_key.sign(digest, utils.Prehashed(algo))
            sig_hex = binascii.hexlify(signature).decode("ascii")
            
            logger.info(f"File signing successful: {file_path}")
            return True, f"File signed successfully:\nFile: {os.path.basename(file_path)}\nHash: {digest.hex()} ({hash_algo})\nSignature (hex): {sig_hex}"
            
        except Exception as e:
            logger.error(f"File signing failed: {e}")
            return False, f"File signing failed: {str(e)}"

    def verify_file(self, file_path: str, signature_hex: str, pub_path: str, hash_algo: str = "sha256") -> Tuple[bool, str]:
        try:
            logger.info(f"Verifying file: {file_path}")
            
            FileValidator.validate_file_path(file_path)
            public_key = load_public_key(pub_path)
            
            try:
                signature = binascii.unhexlify(signature_hex)
            except binascii.Error:
                return False, "Invalid hex signature format"
            
            digest = self.hash_file(file_path, hash_algo)
            algo = self.get_hash_algo(hash_algo)
            
            try:
                public_key.verify(signature, digest, utils.Prehashed(algo))
                logger.info(f"File verification successful: {file_path}")
                return True, f"✓ VERIFIED – signature is valid for file '{os.path.basename(file_path)}'.\nHash used: {hash_algo} ; digest = {digest.hex()}"
            except InvalidSignature:
                logger.info(f"File verification failed: {file_path}")
                return False, f"✗ NOT VERIFIED – signature is INVALID for file '{os.path.basename(file_path)}'.\nHash used: {hash_algo} ; digest = {digest.hex()}"
            
        except Exception as e:
            logger.error(f"File verification failed: {e}")
            return False, f"File verification failed: {str(e)}"

    def save_signature_to_file(self, signature_hex: str, output_path: str) -> Tuple[bool, str]:
        return save_signature(signature_hex, output_path)


def generate_keys_no_password(key_size: int = 2048) -> Tuple[bool, str]:
    service = DSSService()
    return service.generate_keys(key_size, str(DEFAULT_PRIVATE_KEY), str(DEFAULT_PUBLIC_KEY), None)


def generate_keys_with_password(key_size: int = 2048, password: str = "") -> Tuple[bool, str]:
    service = DSSService()
    return service.generate_keys(key_size, str(DEFAULT_PRIVATE_KEY), str(DEFAULT_PUBLIC_KEY), password)


def sign_string_to_file(message: str, priv_path: str, password: str = None, hash_algo: str = "sha256", out_path: str = None) -> Tuple[bool, str]:
    service = DSSService()
    success, result = service.sign_string(message, priv_path, password, hash_algo)
    if success and out_path:
        try:
            signature_hex = result.split("Signature (hex): ")[1]
            save_success, save_result = service.save_signature_to_file(signature_hex, out_path)
            if save_success:
                result += f"\n{save_result}"
            else:
                return False, save_result
        except Exception as e:
            return False, f"Failed to extract signature: {e}"
    return success, result


def verify_string_from_hex(message: str, signature_hex: str, pub_path: str, hash_algo: str = "sha256") -> Tuple[bool, str]:
    service = DSSService()
    return service.verify_string(message, signature_hex, pub_path, hash_algo)


def sign_file_to_file(file_path: str, priv_path: str, password: str = None, hash_algo: str = "sha256", out_path: str = None) -> Tuple[bool, str]:
    service = DSSService()
    success, result = service.sign_file(file_path, priv_path, password, hash_algo)
    if success and out_path:
        try:
            signature_hex = result.split("Signature (hex): ")[1]
            save_success, save_result = service.save_signature_to_file(signature_hex, out_path)
            if save_success:
                result += f"\n{save_result}"
            else:
                return False, save_result
        except Exception as e:
            return False, f"Failed to extract signature: {e}"
    return success, result


def verify_file_from_hex(file_path: str, signature_hex: str, pub_path: str, hash_algo: str = "sha256") -> Tuple[bool, str]:
    service = DSSService()
    return service.verify_file(file_path, signature_hex, pub_path, hash_algo)