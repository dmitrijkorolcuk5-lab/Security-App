import pytest
import tempfile
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa, dsa
from backend.storage.key_manager import (
    load_private_key,
    load_public_key,
    save_private_key,
    save_public_key
)


class TestKeyManager:
    def test_save_and_load_rsa_private_key_no_password(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pem') as f:
            temp_path = f.name
        
        try:
            save_private_key(temp_path, private_key, None)
            
            loaded_key = load_private_key(temp_path, None)
            
            assert loaded_key.private_numbers().public_numbers.n == private_key.private_numbers().public_numbers.n
            assert loaded_key.private_numbers().public_numbers.e == private_key.private_numbers().public_numbers.e
        finally:
            Path(temp_path).unlink(missing_ok=True)
    
    def test_save_and_load_rsa_private_key_with_password(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        password = b"test_password"
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pem') as f:
            temp_path = f.name
        
        try:
            save_private_key(temp_path, private_key, password)
            
            loaded_key = load_private_key(temp_path, password)
            
            assert loaded_key.private_numbers().public_numbers.n == private_key.private_numbers().public_numbers.n
        finally:
            Path(temp_path).unlink(missing_ok=True)
    
    def test_load_rsa_private_key_wrong_password(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        correct_password = b"correct"
        wrong_password = b"wrong"
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pem') as f:
            temp_path = f.name
        
        try:
            save_private_key(temp_path, private_key, correct_password)
            
            with pytest.raises(ValueError, match="Failed to load private key"):
                load_private_key(temp_path, wrong_password)
        finally:
            Path(temp_path).unlink(missing_ok=True)
    
    def test_load_rsa_private_key_missing_password(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        password = b"password"
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pem') as f:
            temp_path = f.name
        
        try:
            save_private_key(temp_path, private_key, password)
            
            with pytest.raises(ValueError, match="Failed to load private key"):
                load_private_key(temp_path, None)
        finally:
            Path(temp_path).unlink(missing_ok=True)
    
    def test_save_and_load_rsa_public_key(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        public_key = private_key.public_key()
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pem') as f:
            temp_path = f.name
        
        try:
            save_public_key(temp_path, public_key)
            
            loaded_key = load_public_key(temp_path)
            
            assert loaded_key.public_numbers().n == public_key.public_numbers().n
            assert loaded_key.public_numbers().e == public_key.public_numbers().e
        finally:
            Path(temp_path).unlink(missing_ok=True)
    
    def test_save_and_load_dsa_private_key(self):
        private_key = dsa.generate_private_key(key_size=1024)
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pem') as f:
            temp_path = f.name
        
        try:
            save_private_key(temp_path, private_key, None)
            
            loaded_key = load_private_key(temp_path, None)
            
            assert loaded_key.private_numbers().public_numbers.y == private_key.private_numbers().public_numbers.y
        finally:
            Path(temp_path).unlink(missing_ok=True)
    
    def test_save_and_load_dsa_public_key(self):
        private_key = dsa.generate_private_key(key_size=1024)
        public_key = private_key.public_key()
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pem') as f:
            temp_path = f.name
        
        try:
            save_public_key(temp_path, public_key)
            
            loaded_key = load_public_key(temp_path)
            
            assert loaded_key.public_numbers().y == public_key.public_numbers().y
        finally:
            Path(temp_path).unlink(missing_ok=True)
    
    def test_load_private_key_file_not_found(self):
        with pytest.raises(ValueError, match="Failed to load private key"):
            load_private_key("nonexistent_file.pem", None)
    
    def test_load_public_key_file_not_found(self):
        with pytest.raises(ValueError, match="Failed to load public key"):
            load_public_key("nonexistent_file.pem")
    
    def test_load_private_key_invalid_file(self):
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.pem') as f:
            f.write("This is not a valid PEM file")
            temp_path = f.name
        
        try:
            with pytest.raises(ValueError, match="Failed to load private key"):
                load_private_key(temp_path, None)
        finally:
            Path(temp_path).unlink()
    
    def test_load_public_key_invalid_file(self):
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.pem') as f:
            f.write("This is not a valid PEM file")
            temp_path = f.name
        
        try:
            with pytest.raises(ValueError, match="Failed to load public key"):
                load_public_key(temp_path)
        finally:
            Path(temp_path).unlink()
    
    def test_save_rsa_key_pair_and_cross_verify(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        public_key = private_key.public_key()
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='_priv.pem') as f:
            priv_path = f.name
        with tempfile.NamedTemporaryFile(delete=False, suffix='_pub.pem') as f:
            pub_path = f.name
        
        try:
            save_private_key(priv_path, private_key, None)
            save_public_key(pub_path, public_key)
            
            loaded_priv = load_private_key(priv_path, None)
            loaded_pub = load_public_key(pub_path)
            
            assert loaded_priv.public_key().public_numbers().n == loaded_pub.public_numbers().n
        finally:
            Path(priv_path).unlink(missing_ok=True)
            Path(pub_path).unlink(missing_ok=True)
    
    def test_save_dsa_key_pair_and_cross_verify(self):
        private_key = dsa.generate_private_key(key_size=1024)
        public_key = private_key.public_key()
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='_priv.pem') as f:
            priv_path = f.name
        with tempfile.NamedTemporaryFile(delete=False, suffix='_pub.pem') as f:
            pub_path = f.name
        
        try:
            save_private_key(priv_path, private_key, None)
            save_public_key(pub_path, public_key)
            
            loaded_priv = load_private_key(priv_path, None)
            loaded_pub = load_public_key(pub_path)
            
            assert loaded_priv.public_key().public_numbers().y == loaded_pub.public_numbers().y
        finally:
            Path(priv_path).unlink(missing_ok=True)
            Path(pub_path).unlink(missing_ok=True)
    
    def test_multiple_password_protected_keys(self):
        key1 = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        key2 = rsa.generate_private_key(public_exponent=65537, key_size=1024)
        
        password1 = b"password1"
        password2 = b"password2"
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='_1.pem') as f:
            path1 = f.name
        with tempfile.NamedTemporaryFile(delete=False, suffix='_2.pem') as f:
            path2 = f.name
        
        try:
            save_private_key(path1, key1, password1)
            save_private_key(path2, key2, password2)
            
            loaded_key1 = load_private_key(path1, password1)
            loaded_key2 = load_private_key(path2, password2)
            
            assert loaded_key1.private_numbers().public_numbers.n != loaded_key2.private_numbers().public_numbers.n
            
            with pytest.raises(ValueError):
                load_private_key(path1, password2)
        finally:
            Path(path1).unlink(missing_ok=True)
            Path(path2).unlink(missing_ok=True)
