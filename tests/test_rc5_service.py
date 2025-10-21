import pytest
import tempfile
from pathlib import Path
from backend.crypto.rc5_service import (
    RC5,
    derive_key,
    pad,
    unpad,
    encrypt_file,
    decrypt_with_pass,
    validate_parameters
)


class TestRC5:
    def test_rc5_encrypt_decrypt_block(self):
        key = b"test_key_16bytes"
        cipher = RC5(w=32, r=12, key=key)
        
        plaintext = b"hello123"
        ciphertext = cipher.encrypt_block(plaintext)
        decrypted = cipher.decrypt_block(ciphertext)
        
        assert decrypted == plaintext
    
    def test_rc5_different_word_sizes(self):
        key = b"testkey1"
        
        for w in [16, 32, 64]:
            cipher = RC5(w=w, r=12, key=key)
            block_size = 2 * (w // 8)
            plaintext = b"x" * block_size
            
            ciphertext = cipher.encrypt_block(plaintext)
            decrypted = cipher.decrypt_block(ciphertext)
            
            assert decrypted == plaintext
    
    def test_derive_key_8_bytes(self):
        key = derive_key("password", 8)
        assert len(key) == 8
    
    def test_derive_key_16_bytes(self):
        key = derive_key("password", 16)
        assert len(key) == 16
    
    def test_derive_key_32_bytes(self):
        key = derive_key("password", 32)
        assert len(key) == 32
    
    def test_derive_key_invalid_size(self):
        with pytest.raises(ValueError):
            derive_key("password", 24)
    
    def test_pad_full_block(self):
        data = b"12345678"
        padded = pad(data, 8)
        assert len(padded) % 8 == 0
        assert len(padded) == 16
    
    def test_pad_partial_block(self):
        data = b"12345"
        padded = pad(data, 8)
        assert len(padded) % 8 == 0
        assert len(padded) == 8
    
    def test_unpad_valid(self):
        data = b"12345678"
        padded = pad(data, 8)
        unpadded = unpad(padded, 8)
        assert unpadded == data
    
    def test_unpad_invalid_length(self):
        with pytest.raises(ValueError, match="Invalid padded data length"):
            unpad(b"123", 8)
    
    def test_unpad_invalid_padding(self):
        with pytest.raises(ValueError, match="Invalid padding"):
            unpad(b"12345678", 8)
    
    def test_encrypt_decrypt_file(self):
        test_content = "Hello, World! This is a test."
        passphrase = "test_password"
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write(test_content)
            plaintext_file = f.name
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
            encrypted_file = f.name
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            decrypted_file = f.name
        
        try:
            success, msg = encrypt_file(plaintext_file, encrypted_file, passphrase, w=32, r=12, key_bytes=16)
            assert success is True
            assert Path(encrypted_file).exists()
            
            success, msg = decrypt_with_pass(encrypted_file, decrypted_file, passphrase, w=32, r=12, key_bytes=16)
            assert success is True
            
            with open(decrypted_file, 'r') as f:
                decrypted_content = f.read()
            assert decrypted_content == test_content
        finally:
            Path(plaintext_file).unlink(missing_ok=True)
            Path(encrypted_file).unlink(missing_ok=True)
            Path(decrypted_file).unlink(missing_ok=True)
    
    def test_decrypt_with_wrong_password(self):
        test_content = "Secret message"
        correct_pass = "correct"
        wrong_pass = "wrong"
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write(test_content)
            plaintext_file = f.name
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.bin') as f:
            encrypted_file = f.name
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            decrypted_file = f.name
        
        try:
            success, _ = encrypt_file(plaintext_file, encrypted_file, correct_pass, w=32, r=12, key_bytes=16)
            assert success is True
            
            success, msg = decrypt_with_pass(encrypted_file, decrypted_file, wrong_pass, w=32, r=12, key_bytes=16)
            assert success is False
            assert "Invalid passphrase" in msg
        finally:
            Path(plaintext_file).unlink(missing_ok=True)
            Path(encrypted_file).unlink(missing_ok=True)
            Path(decrypted_file).unlink(missing_ok=True)
    
    def test_validate_parameters_valid(self):
        success, msg = validate_parameters(w=32, r=12, key_bytes=16)
        assert success is True
        assert "valid" in msg
    
    def test_validate_parameters_invalid_w(self):
        success, msg = validate_parameters(w=24, r=12, key_bytes=16)
        assert success is False
        assert "Word size" in msg
    
    def test_validate_parameters_invalid_r(self):
        success, msg = validate_parameters(w=32, r=0, key_bytes=16)
        assert success is False
        assert "Rounds" in msg
    
    def test_validate_parameters_invalid_key_bytes(self):
        success, msg = validate_parameters(w=32, r=12, key_bytes=24)
        assert success is False
        assert "Key length" in msg
