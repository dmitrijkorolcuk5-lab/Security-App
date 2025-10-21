import pytest
import tempfile
from pathlib import Path
from backend.storage.file_manager import (
    write_int_sequence,
    read_int_sequence,
    write_text_report,
    save_signature
)


class TestFileManager:
    def test_write_and_read_int_sequence(self):
        sequence = [1, 2, 3, 4, 5, 10, 100, 1000]
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            temp_path = Path(f.name)
        
        try:
            write_int_sequence(temp_path, sequence)
            read_sequence = read_int_sequence(temp_path)
            
            assert read_sequence == sequence
        finally:
            temp_path.unlink(missing_ok=True)
    
    def test_write_int_sequence_empty(self):
        sequence = []
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            temp_path = Path(f.name)
        
        try:
            write_int_sequence(temp_path, sequence)
            read_sequence = read_int_sequence(temp_path)
            
            assert read_sequence == []
        finally:
            temp_path.unlink(missing_ok=True)
    
    def test_write_int_sequence_large_numbers(self):
        sequence = [999999999, 1234567890, 9876543210]
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            temp_path = Path(f.name)
        
        try:
            write_int_sequence(temp_path, sequence)
            read_sequence = read_int_sequence(temp_path)
            
            assert read_sequence == sequence
        finally:
            temp_path.unlink(missing_ok=True)
    
    def test_write_int_sequence_with_zeros(self):
        sequence = [0, 1, 0, 2, 0, 3]
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            temp_path = Path(f.name)
        
        try:
            write_int_sequence(temp_path, sequence)
            read_sequence = read_int_sequence(temp_path)
            
            assert read_sequence == sequence
        finally:
            temp_path.unlink(missing_ok=True)
    
    def test_read_int_sequence_with_empty_lines(self):
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("1\n\n2\n\n\n3\n")
            temp_path = Path(f.name)
        
        try:
            read_sequence = read_int_sequence(temp_path)
            
            assert read_sequence == [1, 2, 3]
        finally:
            temp_path.unlink(missing_ok=True)
    
    def test_write_text_report_single_line(self):
        lines = ["This is a test report"]
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            temp_path = Path(f.name)
        
        try:
            write_text_report(temp_path, lines)
            
            with open(temp_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            assert content == "This is a test report\n"
        finally:
            temp_path.unlink(missing_ok=True)
    
    def test_write_text_report_multiple_lines(self):
        lines = [
            "Report Header",
            "============",
            "Line 1: Some data",
            "Line 2: More data",
            "End of report"
        ]
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            temp_path = Path(f.name)
        
        try:
            write_text_report(temp_path, lines)
            
            with open(temp_path, 'r', encoding='utf-8') as f:
                read_lines = f.read().splitlines()
            
            assert read_lines == lines
        finally:
            temp_path.unlink(missing_ok=True)
    
    def test_write_text_report_empty(self):
        lines = []
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            temp_path = Path(f.name)
        
        try:
            write_text_report(temp_path, lines)
            
            with open(temp_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            assert content == ""
        finally:
            temp_path.unlink(missing_ok=True)
    
    def test_write_text_report_unicode(self):
        lines = ["Тестовий звіт", "Test report", "测试报告"]
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            temp_path = Path(f.name)
        
        try:
            write_text_report(temp_path, lines)
            
            with open(temp_path, 'r', encoding='utf-8') as f:
                read_lines = f.read().splitlines()
            
            assert read_lines == lines
        finally:
            temp_path.unlink(missing_ok=True)
    
    def test_save_signature_success(self):
        signature_hex = "aabbccdd1122334455667788"
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            temp_path = f.name
        
        try:
            success, msg = save_signature(signature_hex, temp_path)
            
            assert success is True
            assert "saved successfully" in msg
            
            with open(temp_path, 'r', encoding='utf-8') as f:
                saved_sig = f.read()
            
            assert saved_sig == signature_hex
        finally:
            Path(temp_path).unlink(missing_ok=True)
    
    def test_save_signature_empty(self):
        signature_hex = ""
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            temp_path = f.name
        
        try:
            success, msg = save_signature(signature_hex, temp_path)
            
            assert success is True
            
            with open(temp_path, 'r', encoding='utf-8') as f:
                saved_sig = f.read()
            
            assert saved_sig == ""
        finally:
            Path(temp_path).unlink(missing_ok=True)
    
    def test_save_signature_long_hex(self):
        signature_hex = "a" * 1000
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            temp_path = f.name
        
        try:
            success, msg = save_signature(signature_hex, temp_path)
            
            assert success is True
            
            with open(temp_path, 'r', encoding='utf-8') as f:
                saved_sig = f.read()
            
            assert saved_sig == signature_hex
        finally:
            Path(temp_path).unlink(missing_ok=True)
    
    def test_write_int_sequence_negative_numbers(self):
        sequence = [-1, -100, 0, 100, 1]
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.txt') as f:
            temp_path = Path(f.name)
        
        try:
            write_int_sequence(temp_path, sequence)
            read_sequence = read_int_sequence(temp_path)
            
            assert read_sequence == sequence
        finally:
            temp_path.unlink(missing_ok=True)
