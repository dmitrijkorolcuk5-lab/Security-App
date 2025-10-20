import logging
from typing import List, Tuple
from pathlib import Path
from backend.validation.validators import FileValidator

logger = logging.getLogger("lab_suite.storage.file_manager")

def write_int_sequence(path: Path, sequence: List[int]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for num in sequence:
            f.write(f"{num}\n")

def read_int_sequence(path: Path) -> List[int]:
    with open(path, "r", encoding="utf-8") as f:
        return [int(line.strip()) for line in f if line.strip()]

def write_text_report(path: Path, lines: List[str]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for line in lines:
            f.write(line + "\n")

def save_signature(signature_hex: str, output_path: str) -> Tuple[bool, str]:
    try:
        FileValidator.validate_write_permissions(Path(output_path))
        
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(signature_hex)
        
        logger.info(f"Signature saved to: {output_path}")
        return True, f"Signature saved successfully to: {output_path}"
        
    except Exception as e:
        logger.error(f"Failed to save signature: {e}")
        return False, f"Failed to save signature: {str(e)}"