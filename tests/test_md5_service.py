import pytest
import tempfile
from pathlib import Path
from backend.crypto.md5_service import (
    MD5Service,
    md5_string,
    md5_file,
    save_md5_to_file,
    verify_string_with_hash,
    verify_file_with_hash_file
)


class TestMD5Service:
    def test_empty_string(self):
        result = md5_string("")
        assert result == "d41d8cd98f00b204e9800998ecf8427e"
    
    def test_known_string(self):
        result = md5_string("hello")
        assert result == "5d41402abc4b2a76b9719d911017c592"
    
    def test_unicode_string(self):
        result = md5_string("Привіт")
        assert len(result) == 32
        assert result.isalnum()
    
    def test_long_string(self):
        long_text = "a" * 10000
        result = md5_string(long_text)
        assert len(result) == 32
    
    def test_md5_service_update(self):
        h1 = MD5Service()
        h1.update(b"hello")
        h1.update(b"world")
        
        h2 = MD5Service()
        h2.update(b"helloworld")
        
        assert h1.hexdigest() == h2.hexdigest()
    
    def test_md5_service_copy(self):
        h1 = MD5Service(b"hello")
        h2 = h1.copy()
        h2.update(b"world")
        
        assert h1.hexdigest() != h2.hexdigest()
    
    def test_md5_file(self):
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("test content")
            temp_path = f.name
        
        try:
            result = md5_file(temp_path)
            assert len(result) == 32
            assert result.isalnum()
        finally:
            Path(temp_path).unlink()
    
    def test_save_md5_to_file(self):
        test_hash = "5d41402abc4b2a76b9719d911017c592"
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            temp_path = f.name
        
        try:
            save_md5_to_file(test_hash, temp_path)
            
            with open(temp_path, 'r') as f:
                saved_hash = f.read().strip()
            
            assert saved_hash == test_hash
        finally:
            Path(temp_path).unlink()
    
    def test_verify_string_with_hash_valid(self):
        text = "hello"
        expected_hash = "5d41402abc4b2a76b9719d911017c592"
        
        is_valid, calculated = verify_string_with_hash(text, expected_hash)
        assert is_valid is True
        assert calculated.lower() == expected_hash.lower()
    
    def test_verify_string_with_hash_invalid(self):
        text = "hello"
        wrong_hash = "ffffffffffffffffffffffffffffffff"
        
        is_valid, calculated = verify_string_with_hash(text, wrong_hash)
        assert is_valid is False
    
    def test_verify_file_with_hash_file_valid(self):
        test_content = "test content"
        test_hash = md5_string(test_content)
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write(test_content)
            text_file = f.name
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write(test_hash)
            hash_file = f.name
        
        try:
            is_valid, calculated, expected = verify_file_with_hash_file(text_file, hash_file)
            assert is_valid is True
            assert calculated.lower() == expected.lower()
        finally:
            Path(text_file).unlink()
            Path(hash_file).unlink()
    
    def test_verify_file_with_hash_file_invalid(self):
        test_content = "test content"
        wrong_hash = "ffffffffffffffffffffffffffffffff"
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write(test_content)
            text_file = f.name
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write(wrong_hash)
            hash_file = f.name
        
        try:
            is_valid, _, _ = verify_file_with_hash_file(text_file, hash_file)
            assert is_valid is False
        finally:
            Path(text_file).unlink()
            Path(hash_file).unlink()
    
    def test_verify_file_with_invalid_hash_format(self):
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("test")
            text_file = f.name
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("not_a_valid_hash")
            hash_file = f.name
        
        try:
            is_valid, calculated, error = verify_file_with_hash_file(text_file, hash_file)
            assert is_valid is False
            assert error == "Invalid hash format in file"
        finally:
            Path(text_file).unlink()
            Path(hash_file).unlink()
