from typing import Iterable, Tuple
import math
import logging
from backend.validation.validators import BusinessLogicValidator, ValidationError

logger = logging.getLogger("lab_suite.rng.cesaro_test")

def cesaro_pi_from_iterable(values: Iterable[int], pairs: int) -> Tuple[float, float, int, int]:
    values_list = list(values)
    
    try:
        BusinessLogicValidator.validate_cesaro_input(values_list, pairs)
    except ValidationError as e:
        raise ValueError(f"Invalid Cesàro input: {e}")
    
    it = iter(values_list); cop = 0; total = 0
    for _ in range(pairs):
        try:
            x = next(it); y = next(it)
        except StopIteration:
            break
        if x == 0: x = 1
        if y == 0: y = 1
        if math.gcd(x, y) == 1: cop += 1
        total += 1
    
    if total == 0:
        logger.info("Cesàro received 0 pairs")
        return float("nan"), float("nan"), 0, 0
    
    p = cop / total
    pi_hat = math.sqrt(6.0 / p) if p > 0 else float("nan")
    
    logger.info("Cesàro: pairs=%d, coprime=%d, p=%f, pi_hat=%f", total, cop, p, pi_hat)
    return pi_hat, p, cop, total