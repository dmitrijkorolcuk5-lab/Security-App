from abc import ABC, abstractmethod


class SymmetricCrypto(ABC):
    @abstractmethod
    def encrypt_block(self, block: bytes) -> bytes:
        pass
    
    @abstractmethod
    def decrypt_block(self, block: bytes) -> bytes:
        pass