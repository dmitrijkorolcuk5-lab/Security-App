from typing import Iterator
import logging
from backend.validation.validators import BusinessLogicValidator, InputValidator, ValidationError

logger = logging.getLogger("lab_suite.rng.lcg_generator")

class LCG:
    def __init__(self, m: int, a: int, c: int, seed: int):
        try:
            BusinessLogicValidator.validate_lcg_parameters(m, a, c, seed)
        except ValidationError as e:
            raise ValueError(f"Invalid LCG parameters: {e}")
        
        self.m, self.a, self.c, self.state = m, a, c, seed
        logger.info("LCG initialized: m=%d, a=%d, c=%d, seed=%d", m, a, c, seed)

    def next(self) -> int:
        self.state = (self.a * self.state + self.c) % self.m
        return self.state

    def stream(self, n: int) -> Iterator[int]:
        try:
            InputValidator.validate_sequence_length(n)
        except ValidationError as e:
            raise ValueError(f"Invalid stream length: {e}")
        
        logger.info("Generating stream: n=%d", n)
        for _ in range(n):
            yield self.next()