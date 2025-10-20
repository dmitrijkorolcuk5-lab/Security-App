from pathlib import Path
from typing import List
import os
class ValidationError(Exception):
    pass

def validate_all_inputs(variant: int, sequence_length: int, period_steps: int):
    if not isinstance(variant, int):
        raise ValidationError("Variant must be integer")
    if variant <= 0 or variant > 25:
        raise ValidationError("Variant must be between 1 and 25")
    
    InputValidator.validate_sequence_length(sequence_length)
    
    if period_steps < 0:
        raise ValidationError("Period steps cannot be negative")
    if period_steps > 0:
        InputValidator.validate_period_steps(period_steps)

class FileValidator:
    @staticmethod
    def validate_file_path(path: str):
        if not Path(path).is_file():
            raise ValidationError(f"File does not exist: {path}")
    
    @staticmethod
    def validate_write_permissions(path: Path):
        try:
            if path.exists() and not path.is_file():
                raise ValidationError(f"Path exists but is not a file: {path}")
            if path.exists() and not os.access(path, os.W_OK):
                raise ValidationError(f"No write permission for file: {path}")
            if not path.exists():
                try:
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.touch()
                    path.unlink()
                except Exception as e:
                    raise ValidationError(f"Cannot create file at path {path}: {e}")
        except Exception as e:
            raise ValidationError(f"File permission check failed: {e}")

class BusinessLogicValidator:
    @staticmethod
    def validate_lcg_parameters(m: int, a: int, c: int, seed: int):
        if not all(isinstance(x, int) for x in (m, a, c, seed)):
            raise ValidationError("All LCG parameters must be integers")
        if m <= 0:
            raise ValidationError("Modulus m must be positive")
        if not (0 <= seed < m):
            raise ValidationError(f"Initial seed must be in range [0, {m})")
        
    @staticmethod
    def validate_cesaro_input(values: List[int], pairs: int):
        if len(values) < 2 * pairs:
            raise ValidationError(f"Need at least {2*pairs} numbers for {pairs} pairs")

class InputValidator:
    @staticmethod
    def validate_sequence_length(n: int):
        if not isinstance(n, int):
            raise ValidationError("Sequence length must be integer")
        if n <= 0:
            raise ValidationError("Sequence length must be positive")
        if n > 10_000_000:
            raise ValidationError("Sequence length too large")
            
    @staticmethod
    def validate_pairs_count(pairs: int):
        if not isinstance(pairs, int):
            raise ValidationError("Pairs count must be integer")
        if pairs <= 0:
            raise ValidationError("Pairs count must be positive")
        if pairs > 5_000_000:
            raise ValidationError("Too many pairs requested")
    
    @staticmethod
    def validate_period_steps(steps: int):
        if not isinstance(steps, int):
            raise ValidationError("Period steps must be integer")
        if steps <= 0:
            raise ValidationError("Period steps must be positive")
        if steps > 10_000_000:
            raise ValidationError("Too many period steps")