import pytest
import tempfile
import base64
from pathlib import Path
from backend.crypto.rsa_service import RSAService


class TestRSAService:
    @pytest.fixture
    def rsa_service(self):
        return RSAService()
    
    @pytest.fixture
    def key_files(self):
        priv_file = tempfile.NamedTemporaryFile(delete=False, suffix='_priv.pem')
        pub_file = tempfile.NamedTemporaryFile(delete=False, suffix='_pub.pem')
        priv_file.close()
        pub_file.close()
        
        yield priv_file.name, pub_file.name
        
        Path(priv_file.name).unlink(missing_ok=True)
        Path(pub_file.name).unlink(missing_ok=True)
    
    def test_generate_keys_no_password(self, rsa_service, key_files):
        priv_path, pub_path = key_files
        
        success, msg = rsa_service.generate_keys(1024, priv_path, pub_path, None)
        
        assert success is True
        assert Path(priv_path).exists()
        assert Path(pub_path).exists()
        assert "generated successfully" in msg
    
    def test_generate_keys_with_password(self, rsa_service, key_files):
        priv_path, pub_path = key_files
        password = "test_password"
        
        success, msg = rsa_service.generate_keys(1024, priv_path, pub_path, password)
        
        assert success is True
        assert Path(priv_path).exists()
        assert Path(pub_path).exists()
    
    def test_sign_and_verify_string(self, rsa_service, key_files):
        priv_path, pub_path = key_files
        
        rsa_service.generate_keys(1024, priv_path, pub_path, None)
        
        test_string = "Hello, World!"
        success, result = rsa_service.sign_string(test_string, priv_path, None)
        
        assert success is True
        assert "Signature (base64):" in result
        
        signature = result.split("Signature (base64): ")[1]
        
        success, result = rsa_service.verify_string(test_string, signature, pub_path)
        
        assert success is True
        assert "VERIFIED" in result
    
    def test_verify_string_invalid_signature(self, rsa_service, key_files):
        priv_path, pub_path = key_files
        
        rsa_service.generate_keys(1024, priv_path, pub_path, None)
        
        fake_signature = base64.b64encode(b"fake_signature" * 10).decode()
        
        success, result = rsa_service.verify_string("test", fake_signature, pub_path)
        
        assert success is False
        assert "NOT VERIFIED" in result
    
    def test_sign_and_verify_file(self, rsa_service, key_files):
        priv_path, pub_path = key_files
        
        rsa_service.generate_keys(1024, priv_path, pub_path, None)
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("Test file content")
            test_file = f.name
        
        try:
            success, result = rsa_service.sign_file(test_file, priv_path, None)
            
            assert success is True
            assert "Signature (base64):" in result
            
            signature = result.split("Signature (base64): ")[1]
            
            success, result = rsa_service.verify_file(test_file, signature, pub_path)
            
            assert success is True
            assert "VERIFIED" in result
        finally:
            Path(test_file).unlink()
    
    def test_encrypt_and_decrypt_string(self, rsa_service, key_files):
        priv_path, pub_path = key_files
        
        rsa_service.generate_keys(1024, priv_path, pub_path, None)
        
        test_string = "Secret message"
        success, result = rsa_service.encrypt_string(test_string, pub_path)
        
        assert success is True
        assert "Encrypted text (base64):" in result
        
        encrypted_b64 = result.split("Encrypted text (base64):\n")[1].strip()
        
        success, result = rsa_service.decrypt_string(encrypted_b64, priv_path, None)
        
        assert success is True
        assert test_string in result
    
    def test_encrypt_string_too_large(self, rsa_service, key_files):
        priv_path, pub_path = key_files
        
        rsa_service.generate_keys(1024, priv_path, pub_path, None)
        
        long_string = "x" * 1000
        success, msg = rsa_service.encrypt_string(long_string, pub_path)
        
        assert success is False
        assert "too large" in msg
    
    def test_encrypt_and_decrypt_file(self, rsa_service, key_files):
        priv_path, pub_path = key_files
        
        rsa_service.generate_keys(2048, priv_path, pub_path, None)
        
        test_content = "Short test content"
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write(test_content)
            test_file = f.name
        
        encrypted_file = "rsa_encrypted.bin"
        decrypted_file = "rsa_decrypted.txt"
        
        try:
            success, result = rsa_service.encrypt_file(test_file, pub_path)
            
            assert success is True
            assert Path(encrypted_file).exists()
            
            success, result = rsa_service.decrypt_file(encrypted_file, priv_path, None)
            
            assert success is True
            assert Path(decrypted_file).exists()
            
            with open(decrypted_file, 'r') as f:
                decrypted_content = f.read()
            assert decrypted_content == test_content
        finally:
            Path(test_file).unlink(missing_ok=True)
            Path(encrypted_file).unlink(missing_ok=True)
            Path(decrypted_file).unlink(missing_ok=True)
    
    def test_decrypt_with_wrong_key(self, rsa_service):
        priv1 = tempfile.NamedTemporaryFile(delete=False, suffix='_priv1.pem')
        pub1 = tempfile.NamedTemporaryFile(delete=False, suffix='_pub1.pem')
        priv2 = tempfile.NamedTemporaryFile(delete=False, suffix='_priv2.pem')
        pub2 = tempfile.NamedTemporaryFile(delete=False, suffix='_pub2.pem')
        
        priv1.close()
        pub1.close()
        priv2.close()
        pub2.close()
        
        try:
            rsa_service.generate_keys(1024, priv1.name, pub1.name, None)
            rsa_service.generate_keys(1024, priv2.name, pub2.name, None)
            
            test_string = "Secret"
            success, result = rsa_service.encrypt_string(test_string, pub1.name)
            assert success is True
            
            encrypted_b64 = result.split("Encrypted text (base64):\n")[1].strip()
            
            success, result = rsa_service.decrypt_string(encrypted_b64, priv2.name, None)
            
            assert success is False
        finally:
            Path(priv1.name).unlink(missing_ok=True)
            Path(pub1.name).unlink(missing_ok=True)
            Path(priv2.name).unlink(missing_ok=True)
            Path(pub2.name).unlink(missing_ok=True)
    
    def test_sign_with_password_protected_key(self, rsa_service, key_files):
        priv_path, pub_path = key_files
        password = "secure_password"
        
        rsa_service.generate_keys(1024, priv_path, pub_path, password)
        
        success, result = rsa_service.sign_string("test", priv_path, password)
        assert success is True
        
        success, result = rsa_service.sign_string("test", priv_path, None)
        assert success is False
