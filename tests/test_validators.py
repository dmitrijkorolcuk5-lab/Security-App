import pytest
import tempfile
from pathlib import Path
from backend.validation.validators import (
    ValidationError,
    FileValidator,
    BusinessLogicValidator,
    InputValidator,
    validate_all_inputs
)


class TestFileValidator:
    def test_validate_file_path_exists(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_path = f.name
        
        try:
            FileValidator.validate_file_path(temp_path)
        finally:
            Path(temp_path).unlink()
    
    def test_validate_file_path_not_exists(self):
        with pytest.raises(ValidationError, match="File does not exist"):
            FileValidator.validate_file_path("nonexistent_file.txt")
    
    def test_validate_write_permissions_new_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            temp_path = Path(tmpdir) / "new_file.txt"
            
            FileValidator.validate_write_permissions(temp_path)
    
    def test_validate_write_permissions_existing_file(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_path = Path(f.name)
        
        try:
            FileValidator.validate_write_permissions(temp_path)
        finally:
            temp_path.unlink()


class TestBusinessLogicValidator:
    def test_validate_lcg_parameters_valid(self):
        BusinessLogicValidator.validate_lcg_parameters(m=100, a=21, c=17, seed=42)
    
    def test_validate_lcg_parameters_invalid_m(self):
        with pytest.raises(ValidationError, match="Modulus m must be positive"):
            BusinessLogicValidator.validate_lcg_parameters(m=0, a=21, c=17, seed=42)
    
    def test_validate_lcg_parameters_negative_m(self):
        with pytest.raises(ValidationError, match="Modulus m must be positive"):
            BusinessLogicValidator.validate_lcg_parameters(m=-100, a=21, c=17, seed=42)
    
    def test_validate_lcg_parameters_seed_out_of_range(self):
        with pytest.raises(ValidationError, match="Initial seed must be in range"):
            BusinessLogicValidator.validate_lcg_parameters(m=100, a=21, c=17, seed=100)
    
    def test_validate_lcg_parameters_negative_seed(self):
        with pytest.raises(ValidationError, match="Initial seed must be in range"):
            BusinessLogicValidator.validate_lcg_parameters(m=100, a=21, c=17, seed=-1)
    
    def test_validate_lcg_parameters_non_integer(self):
        with pytest.raises(ValidationError, match="All LCG parameters must be integers"):
            BusinessLogicValidator.validate_lcg_parameters(m=100.5, a=21, c=17, seed=42)
    
    def test_validate_cesaro_input_valid(self):
        values = [1, 2, 3, 4, 5, 6]
        BusinessLogicValidator.validate_cesaro_input(values, pairs=3)
    
    def test_validate_cesaro_input_insufficient(self):
        values = [1, 2, 3]
        with pytest.raises(ValidationError, match="Need at least"):
            BusinessLogicValidator.validate_cesaro_input(values, pairs=5)
    
    def test_validate_cesaro_input_exact(self):
        values = [1, 2, 3, 4]
        BusinessLogicValidator.validate_cesaro_input(values, pairs=2)


class TestInputValidator:
    def test_validate_sequence_length_valid(self):
        InputValidator.validate_sequence_length(100)
    
    def test_validate_sequence_length_zero(self):
        with pytest.raises(ValidationError, match="Sequence length must be positive"):
            InputValidator.validate_sequence_length(0)
    
    def test_validate_sequence_length_negative(self):
        with pytest.raises(ValidationError, match="Sequence length must be positive"):
            InputValidator.validate_sequence_length(-10)
    
    def test_validate_sequence_length_too_large(self):
        with pytest.raises(ValidationError, match="Sequence length too large"):
            InputValidator.validate_sequence_length(20_000_000)
    
    def test_validate_sequence_length_non_integer(self):
        with pytest.raises(ValidationError, match="Sequence length must be integer"):
            InputValidator.validate_sequence_length(100.5)
    
    def test_validate_pairs_count_valid(self):
        InputValidator.validate_pairs_count(1000)
    
    def test_validate_pairs_count_zero(self):
        with pytest.raises(ValidationError, match="Pairs count must be positive"):
            InputValidator.validate_pairs_count(0)
    
    def test_validate_pairs_count_negative(self):
        with pytest.raises(ValidationError, match="Pairs count must be positive"):
            InputValidator.validate_pairs_count(-5)
    
    def test_validate_pairs_count_too_large(self):
        with pytest.raises(ValidationError, match="Too many pairs requested"):
            InputValidator.validate_pairs_count(10_000_000)
    
    def test_validate_pairs_count_non_integer(self):
        with pytest.raises(ValidationError, match="Pairs count must be integer"):
            InputValidator.validate_pairs_count(100.5)
    
    def test_validate_period_steps_valid(self):
        InputValidator.validate_period_steps(1000)
    
    def test_validate_period_steps_zero(self):
        with pytest.raises(ValidationError, match="Period steps must be positive"):
            InputValidator.validate_period_steps(0)
    
    def test_validate_period_steps_negative(self):
        with pytest.raises(ValidationError, match="Period steps must be positive"):
            InputValidator.validate_period_steps(-10)
    
    def test_validate_period_steps_too_large(self):
        with pytest.raises(ValidationError, match="Too many period steps"):
            InputValidator.validate_period_steps(20_000_000)
    
    def test_validate_period_steps_non_integer(self):
        with pytest.raises(ValidationError, match="Period steps must be integer"):
            InputValidator.validate_period_steps(100.5)


class TestValidateAllInputs:
    def test_validate_all_inputs_valid(self):
        validate_all_inputs(variant=5, sequence_length=1000, period_steps=100)
    
    def test_validate_all_inputs_invalid_variant(self):
        with pytest.raises(ValidationError, match="Variant must be between 1 and 25"):
            validate_all_inputs(variant=0, sequence_length=1000, period_steps=100)
    
    def test_validate_all_inputs_variant_too_large(self):
        with pytest.raises(ValidationError, match="Variant must be between 1 and 25"):
            validate_all_inputs(variant=26, sequence_length=1000, period_steps=100)
    
    def test_validate_all_inputs_non_integer_variant(self):
        with pytest.raises(ValidationError, match="Variant must be integer"):
            validate_all_inputs(variant=5.5, sequence_length=1000, period_steps=100)
    
    def test_validate_all_inputs_invalid_sequence_length(self):
        with pytest.raises(ValidationError, match="Sequence length must be positive"):
            validate_all_inputs(variant=5, sequence_length=0, period_steps=100)
    
    def test_validate_all_inputs_invalid_period_steps(self):
        with pytest.raises(ValidationError, match="Period steps cannot be negative"):
            validate_all_inputs(variant=5, sequence_length=1000, period_steps=-1)
    
    def test_validate_all_inputs_zero_period_steps(self):
        validate_all_inputs(variant=5, sequence_length=1000, period_steps=0)
    
    def test_validate_all_inputs_negative_period_steps(self):
        with pytest.raises(ValidationError, match="Period steps cannot be negative"):
            validate_all_inputs(variant=5, sequence_length=1000, period_steps=-10)
