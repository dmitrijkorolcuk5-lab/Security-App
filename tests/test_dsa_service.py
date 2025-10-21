import pytest
import tempfile
import binascii
from pathlib import Path
from backend.crypto.dsa_service import DSSService


class TestDSSService:
    @pytest.fixture
    def dss_service(self):
        return DSSService()
    
    @pytest.fixture
    def key_files(self):
        priv_file = tempfile.NamedTemporaryFile(delete=False, suffix='_priv.pem')
        pub_file = tempfile.NamedTemporaryFile(delete=False, suffix='_pub.pem')
        priv_file.close()
        pub_file.close()
        
        yield priv_file.name, pub_file.name
        
        Path(priv_file.name).unlink(missing_ok=True)
        Path(pub_file.name).unlink(missing_ok=True)
    
    def test_generate_keys_1024(self, dss_service, key_files):
        priv_path, pub_path = key_files
        
        success, msg = dss_service.generate_keys(1024, priv_path, pub_path, None)
        
        assert success is True
        assert Path(priv_path).exists()
        assert Path(pub_path).exists()
        assert "generated successfully" in msg
    
    def test_generate_keys_2048(self, dss_service, key_files):
        priv_path, pub_path = key_files
        
        success, msg = dss_service.generate_keys(2048, priv_path, pub_path, None)
        
        assert success is True
        assert Path(priv_path).exists()
        assert Path(pub_path).exists()
    
    def test_generate_keys_invalid_size(self, dss_service, key_files):
        priv_path, pub_path = key_files
        
        success, msg = dss_service.generate_keys(512, priv_path, pub_path, None)
        
        assert success is False
        assert "must be one of" in msg
    
    def test_sign_and_verify_string_sha256(self, dss_service, key_files):
        priv_path, pub_path = key_files
        
        dss_service.generate_keys(1024, priv_path, pub_path, None)
        
        test_message = "Hello, World!"
        success, result = dss_service.sign_string(test_message, priv_path, None, "sha256")
        
        assert success is True
        assert "Signature (hex):" in result
        
        signature_hex = result.split("Signature (hex): ")[1].strip()
        
        success, result = dss_service.verify_string(test_message, signature_hex, pub_path, "sha256")
        
        assert success is True
        assert "VERIFIED" in result
    
    def test_sign_and_verify_string_different_hashes(self, dss_service, key_files):
        priv_path, pub_path = key_files
        
        dss_service.generate_keys(1024, priv_path, pub_path, None)
        
        test_message = "Test message"
        
        for hash_algo in ["sha1", "sha224", "sha256", "sha384", "sha512"]:
            success, result = dss_service.sign_string(test_message, priv_path, None, hash_algo)
            assert success is True
            
            signature_hex = result.split("Signature (hex): ")[1].strip()
            
            success, result = dss_service.verify_string(test_message, signature_hex, pub_path, hash_algo)
            assert success is True
    
    def test_verify_string_invalid_signature(self, dss_service, key_files):
        priv_path, pub_path = key_files
        
        dss_service.generate_keys(1024, priv_path, pub_path, None)
        
        fake_signature = "ff" * 40
        
        success, result = dss_service.verify_string("test", fake_signature, pub_path, "sha256")
        
        assert success is False
        assert "NOT VERIFIED" in result
    
    def test_verify_string_wrong_message(self, dss_service, key_files):
        priv_path, pub_path = key_files
        
        dss_service.generate_keys(1024, priv_path, pub_path, None)
        
        success, result = dss_service.sign_string("original", priv_path, None, "sha256")
        signature_hex = result.split("Signature (hex): ")[1].strip()
        
        success, result = dss_service.verify_string("modified", signature_hex, pub_path, "sha256")
        
        assert success is False
        assert "NOT VERIFIED" in result
    
    def test_sign_and_verify_file(self, dss_service, key_files):
        priv_path, pub_path = key_files
        
        dss_service.generate_keys(1024, priv_path, pub_path, None)
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("Test file content")
            test_file = f.name
        
        try:
            success, result = dss_service.sign_file(test_file, priv_path, None, "sha256")
            
            assert success is True
            assert "Signature (hex):" in result
            
            signature_hex = result.split("Signature (hex): ")[1].strip()
            
            success, result = dss_service.verify_file(test_file, signature_hex, pub_path, "sha256")
            
            assert success is True
            assert "VERIFIED" in result
        finally:
            Path(test_file).unlink()
    
    def test_verify_file_modified_content(self, dss_service, key_files):
        priv_path, pub_path = key_files
        
        dss_service.generate_keys(1024, priv_path, pub_path, None)
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("Original content")
            test_file = f.name
        
        try:
            success, result = dss_service.sign_file(test_file, priv_path, None, "sha256")
            signature_hex = result.split("Signature (hex): ")[1].strip()
            
            with open(test_file, 'w') as f:
                f.write("Modified content")
            
            success, result = dss_service.verify_file(test_file, signature_hex, pub_path, "sha256")
            
            assert success is False
            assert "NOT VERIFIED" in result
        finally:
            Path(test_file).unlink()
    
    def test_hash_bytes(self, dss_service):
        data = b"test data"
        hash_result = dss_service.hash_bytes(data, "sha256")
        
        assert isinstance(hash_result, bytes)
        assert len(hash_result) == 32
    
    def test_hash_file(self, dss_service):
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("test content")
            test_file = f.name
        
        try:
            hash_result = dss_service.hash_file(test_file, "sha256")
            
            assert isinstance(hash_result, bytes)
            assert len(hash_result) == 32
        finally:
            Path(test_file).unlink()
    
    def test_get_hash_algo_valid(self, dss_service):
        algorithms = ["sha1", "sha224", "sha256", "sha384", "sha512"]
        
        for algo in algorithms:
            hash_obj = dss_service.get_hash_algo(algo)
            assert hash_obj is not None
    
    def test_get_hash_algo_invalid(self, dss_service):
        with pytest.raises(ValueError, match="Unsupported hash algorithm"):
            dss_service.get_hash_algo("md5")
    
    def test_sign_with_password_protected_key(self, dss_service, key_files):
        priv_path, pub_path = key_files
        password = "secure_password"
        
        dss_service.generate_keys(1024, priv_path, pub_path, password)
        
        success, result = dss_service.sign_string("test", priv_path, password, "sha256")
        assert success is True
        
        success, result = dss_service.sign_string("test", priv_path, None, "sha256")
        assert success is False
    
    def test_verify_with_invalid_hex_format(self, dss_service, key_files):
        priv_path, pub_path = key_files
        
        dss_service.generate_keys(1024, priv_path, pub_path, None)
        
        success, result = dss_service.verify_string("test", "not_hex_format", pub_path, "sha256")
        
        assert success is False
        assert "Invalid hex signature format" in result
