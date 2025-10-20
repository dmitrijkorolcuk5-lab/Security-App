import logging
import os
import base64
from typing import Tuple, Optional
from pathlib import Path
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

from backend.crypto.base import CryptoService
from backend.validation.validators import FileValidator
from backend.storage.key_manager import (
    load_private_key, 
    load_public_key,
    save_private_key,
    save_public_key
)

logger = logging.getLogger("lab_suite.rsa_service")

DEFAULT_PRIVATE_KEY = Path("rsa_private.pem")
DEFAULT_PUBLIC_KEY = Path("rsa_public.pem")
DEFAULT_ENCRYPTED_FILE = Path("rsa_encrypted.bin")
DEFAULT_DECRYPTED_FILE = Path("rsa_decrypted.txt")


class RSAService(CryptoService):
    
    def __init__(self):
        self.format = b"RSA"
        self.header_len = 5

    @staticmethod
    def oaep():
        return padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )

    @staticmethod
    def key_bytes_from_public(pub) -> int:
        return (pub.key_size + 7) // 8

    @staticmethod
    def max_plainblock_oaep(key_bytes: int, hash_len: int = 32) -> int:
        return key_bytes - 2 * hash_len - 2

    def generate_keys(self, bits: int, priv_path: str, pub_path: str, password: Optional[str] = None) -> Tuple[bool, str]:
        try:
            logger.info(f"Generating RSA keys: {bits} bits, private={priv_path}, public={pub_path}")
            
            FileValidator.validate_write_permissions(Path(priv_path))
            FileValidator.validate_write_permissions(Path(pub_path))
            
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
            
            enc_alg = (serialization.BestAvailableEncryption(password.encode("utf-8"))
                      if password else serialization.NoEncryption())
            
            pwd = password.encode("utf-8") if password else None
            save_private_key(priv_path, private_key, pwd)
            
            pub_key = private_key.public_key()
            save_public_key(pub_path, pub_key)
            
            logger.info(f"RSA keys generated successfully: {priv_path} and {pub_path}")
            return True, f"RSA keys generated successfully:\nPrivate key: {priv_path}\nPublic key: {pub_path}"
            
        except Exception as e:
            logger.error(f"RSA key generation failed: {e}")
            return False, f"Key generation failed: {str(e)}"

    def sign_string(self, text: str, priv_path: str, password: Optional[str] = None, hash_algo: str = "sha256") -> Tuple[bool, str]:
        try:
            logger.info(f"Encrypting string with private key: {priv_path}")
            
            pwd = password.encode("utf-8") if password else None
            priv = load_private_key(priv_path, password=pwd)
            plain = text.encode("utf-8")
            signature = priv.sign(
                plain,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            sig_hex = base64.b64encode(signature).decode("ascii")
            return True, f"String signed successfully:\nSignature (base64): {sig_hex}"
            
        except Exception as e:
            logger.error(f"String signing failed: {e}")
            return False, f"String signing failed: {str(e)}"

    def verify_string(self, text: str, signature_b64: str, pub_path: str, hash_algo: str = "sha256") -> Tuple[bool, str]:
        try:
            logger.info(f"Verifying string with public key: {pub_path}")
            
            pub = load_public_key(pub_path)
            try:
                signature = base64.b64decode(signature_b64)
            except Exception:
                return False, "Invalid base64 signature format"

            try:
                pub.verify(
                    signature,
                    text.encode("utf-8"),
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                return True, "✓ VERIFIED – signature is valid for text"
            except Exception:
                return False, "✗ NOT VERIFIED – signature is invalid for text"
            
        except Exception as e:
            logger.error(f"String verification failed: {e}")
            return False, f"String verification failed: {str(e)}"

    def sign_file(self, file_path: str, priv_path: str, password: Optional[str] = None, hash_algo: str = "sha256") -> Tuple[bool, str]:
        try:
            logger.info(f"Signing file: {file_path}")
            
            FileValidator.validate_file_path(file_path)
            
            pwd = password.encode("utf-8") if password else None
            priv = load_private_key(priv_path, password=pwd)
            
            with open(file_path, "rb") as f:
                content = f.read()

            signature = priv.sign(
                content,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            sig_hex = base64.b64encode(signature).decode("ascii")
            
            logger.info(f"File signing successful: {file_path}")
            return True, f"File signed successfully:\nFile: {os.path.basename(file_path)}\nSignature (base64): {sig_hex}"
            
        except Exception as e:
            logger.error(f"File signing failed: {e}")
            return False, f"File signing failed: {str(e)}"

    def verify_file(self, file_path: str, signature_b64: str, pub_path: str, hash_algo: str = "sha256") -> Tuple[bool, str]:
        try:
            logger.info(f"Verifying file: {file_path}")
            
            FileValidator.validate_file_path(file_path)
            pub = load_public_key(pub_path)
            
            try:
                signature = base64.b64decode(signature_b64)
            except Exception:
                return False, "Invalid base64 signature format"
            
            with open(file_path, "rb") as f:
                content = f.read()

            try:
                pub.verify(
                    signature,
                    content,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                logger.info(f"File verification successful: {file_path}")
                return True, f"✓ VERIFIED – signature is valid for file '{os.path.basename(file_path)}'"
            except Exception:
                logger.info(f"File verification failed: {file_path}")
                return False, f"✗ NOT VERIFIED – signature is invalid for file '{os.path.basename(file_path)}'"
            
        except Exception as e:
            logger.error(f"File verification failed: {e}")
            return False, f"File verification failed: {str(e)}"

    def encrypt_string(self, text: str, pub_path: str) -> Tuple[bool, str]:
        try:
            logger.info(f"Encrypting string with public key: {pub_path}")
            
            pub = load_public_key(pub_path)
            key_bytes = (pub.key_size + 7) // 8  # Convert bits to bytes
            max_plain = key_bytes - 2 * 32 - 2  # Overhead for OAEP with SHA-256
            
            data = text.encode("utf-8")
            if len(data) > max_plain:
                return False, f"String too large for RSA-OAEP encryption ({len(data)} > {max_plain} bytes)"
            
            encrypted = pub.encrypt(data, self.oaep())
            encrypted_b64 = base64.b64encode(encrypted).decode("ascii")
            
            with open(DEFAULT_ENCRYPTED_FILE, "wb") as f:
                f.write(b"RSA")  # Format identifier
                f.write(key_bytes.to_bytes(2, "big"))  # Key size
                f.write(encrypted)
            
            logger.info(f"String encryption successful")
            return True, (f"String encrypted successfully.\n\n"
                         f"Encrypted text (base64):\n{encrypted_b64}")
            
        except Exception as e:
            logger.error(f"String encryption failed: {e}")
            return False, f"String encryption failed: {str(e)}"

    def encrypt_file(self, file_path: str, pub_path: str) -> Tuple[bool, str]:
        try:
            logger.info(f"Encrypting file: {file_path}")
            
            FileValidator.validate_file_path(file_path)
            FileValidator.validate_write_permissions(DEFAULT_ENCRYPTED_FILE)
            
            pub = load_public_key(pub_path)
            key_bytes = (pub.key_size + 7) // 8  # Convert bits to bytes
            max_plain = key_bytes - 2 * 32 - 2  # Overhead for OAEP with SHA-256
            
            with open(file_path, "rb") as fin, open(DEFAULT_ENCRYPTED_FILE, "wb") as fout:
                # Write header
                fout.write(b"RSA")  # Format identifier
                fout.write(key_bytes.to_bytes(2, "big"))  # Key size
                
                # Process file in blocks
                blocks_processed = 0
                while True:
                    chunk = fin.read(max_plain)
                    if not chunk:
                        break
                        
                    encrypted = pub.encrypt(chunk, self.oaep())
                    if len(encrypted) != key_bytes:
                        raise RuntimeError("Unexpected RSA cipher block length")
                        
                    fout.write(encrypted)
                    blocks_processed += 1
            
            logger.info(f"File encryption successful: {file_path}")
            return True, (f"File encrypted successfully.\n\n"
                         f"Input file: {os.path.basename(file_path)}\n"
                         f"Output file: {DEFAULT_ENCRYPTED_FILE}\n"
                         f"Blocks processed: {blocks_processed}")
            
        except Exception as e:
            logger.error(f"File encryption failed: {e}")
            return False, f"File encryption failed: {str(e)}"

    def decrypt_string(self, encrypted_b64: str, priv_path: str, password: Optional[str] = None) -> Tuple[bool, str]:
        try:
            logger.info(f"Decrypting string with private key: {priv_path}")
            
            pwd = password.encode("utf-8") if password else None
            priv = load_private_key(priv_path, password=pwd)
            
            try:
                encrypted = base64.b64decode(encrypted_b64)
            except Exception:
                return False, "Invalid base64 encrypted format"
                
            try:
                decrypted = priv.decrypt(encrypted, self.oaep())
                text = decrypted.decode("utf-8")
                logger.info("String decryption successful")
                return True, f"Decrypted text:\n{text}"
            except Exception:
                return False, "Decryption failed - invalid private key or corrupted data"
            
        except Exception as e:
            logger.error(f"String decryption failed: {e}")
            return False, f"String decryption failed: {str(e)}"
    
    def decrypt_file(self, encrypted_path: str, priv_path: str, password: Optional[str] = None) -> Tuple[bool, str]:
        try:
            logger.info(f"Decrypting file: {encrypted_path}")
            
            FileValidator.validate_file_path(encrypted_path)
            FileValidator.validate_write_permissions(DEFAULT_DECRYPTED_FILE)
            
            pwd = password.encode("utf-8") if password else None
            priv = load_private_key(priv_path, password=pwd)
            
            with open(encrypted_path, "rb") as fin, open(DEFAULT_DECRYPTED_FILE, "wb") as fout:
                # Read and verify header
                header = fin.read(5)  # RSA + 2 bytes key size
                if len(header) != 5 or header[:3] != b"RSA":
                    raise ValueError("Invalid or corrupted file header")
                    
                key_bytes = int.from_bytes(header[3:5], "big")
                if key_bytes < 64:  # Minimum reasonable RSA key size
                    raise ValueError("Invalid key size in header")
                
                # Process file in blocks
                blocks_processed = 0
                while True:
                    block = fin.read(key_bytes)
                    if not block:
                        break
                    if len(block) != key_bytes:
                        raise ValueError("Incomplete block at end of file")
                        
                    decrypted = priv.decrypt(block, self.oaep())
                    fout.write(decrypted)
                    blocks_processed += 1
            
            logger.info(f"File decryption successful: {encrypted_path}")
            return True, (f"File decrypted successfully.\n\n"
                         f"Input file: {os.path.basename(encrypted_path)}\n"
                         f"Output file: {DEFAULT_DECRYPTED_FILE}\n"
                         f"Blocks processed: {blocks_processed}")
            
        except Exception as e:
            logger.error(f"File decryption failed: {e}")
            return False, f"File decryption failed: {str(e)}"


def generate_keys_no_password(bits: int = 2048) -> Tuple[bool, str]:
    service = RSAService()
    return service.generate_keys(bits, str(DEFAULT_PRIVATE_KEY), str(DEFAULT_PUBLIC_KEY), None)


def generate_keys_with_password(bits: int = 2048, password: str = "") -> Tuple[bool, str]:
    service = RSAService()
    return service.generate_keys(bits, str(DEFAULT_PRIVATE_KEY), str(DEFAULT_PUBLIC_KEY), password)


def encrypt_string_to_file(text: str, pub_path: str = str(DEFAULT_PUBLIC_KEY)) -> Tuple[bool, str]:
    service = RSAService()
    return service.encrypt_string(text, pub_path)


def encrypt_file_to_file(file_path: str, pub_path: str = str(DEFAULT_PUBLIC_KEY)) -> Tuple[bool, str]:
    service = RSAService()
    return service.encrypt_file(file_path, pub_path)


def decrypt_string_from_base64(encrypted_b64: str, priv_path: str = str(DEFAULT_PRIVATE_KEY), 
                             password: Optional[str] = None) -> Tuple[bool, str]:
    service = RSAService()
    return service.decrypt_string(encrypted_b64, priv_path, password)


def decrypt_file_no_password(encrypted_path: str, priv_path: str = str(DEFAULT_PRIVATE_KEY)) -> Tuple[bool, str]:
    service = RSAService()
    return service.decrypt_file(encrypted_path, priv_path, None)


def decrypt_file_with_password(encrypted_path: str, priv_path: str = str(DEFAULT_PRIVATE_KEY), 
                             password: str = "") -> Tuple[bool, str]:
    service = RSAService()
    return service.decrypt_file(encrypted_path, priv_path, password)