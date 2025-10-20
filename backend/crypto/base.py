from abc import ABC, abstractmethod
from typing import Tuple, Optional

class CryptoService(ABC):
    @abstractmethod
    def generate_keys(self, key_size: int, priv_path: str, pub_path: str, password: Optional[str] = None) -> Tuple[bool, str]:
        pass
    
    @abstractmethod
    def sign_string(self, message: str, priv_path: str, password: Optional[str] = None, hash_algo: str = "sha256") -> Tuple[bool, str]:
        pass
        
    @abstractmethod
    def verify_string(self, message: str, signature: str, pub_path: str, hash_algo: str = "sha256") -> Tuple[bool, str]:
        pass
    
    @abstractmethod
    def sign_file(self, file_path: str, priv_path: str, password: Optional[str] = None, hash_algo: str = "sha256") -> Tuple[bool, str]:
        pass
        
    @abstractmethod
    def verify_file(self, file_path: str, signature: str, pub_path: str, hash_algo: str = "sha256") -> Tuple[bool, str]:
        pass