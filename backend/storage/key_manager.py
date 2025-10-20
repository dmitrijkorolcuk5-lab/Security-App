import logging
from typing import Optional, Tuple
from pathlib import Path
from cryptography.hazmat.primitives import serialization

logger = logging.getLogger("lab_suite.storage.key_manager")

def load_private_key(path: str, password: Optional[bytes] = None):
    try:
        with open(path, "rb") as f:
            data = f.read()
        return serialization.load_pem_private_key(data, password=password)
    except Exception as e:
        raise ValueError(f"Failed to load private key from {path}: {e}")

def load_public_key(path: str):
    try:
        with open(path, "rb") as f:
            data = f.read()
        return serialization.load_pem_public_key(data)
    except Exception as e:
        raise ValueError(f"Failed to load public key from {path}: {e}")

def save_private_key(path: str, private_key, password: Optional[bytes] = None):
    enc = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=enc,
    )
    with open(path, "wb") as f:
        f.write(pem)

def save_public_key(path: str, public_key):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(path, "wb") as f:
        f.write(pem)