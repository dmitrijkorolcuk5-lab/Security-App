from typing import Optional
import logging
from backend.validation.validators import BusinessLogicValidator, InputValidator, ValidationError

logger = logging.getLogger("lab_suite.rng.period_analyzer")

def estimate_period_from_state(a: int, c: int, m: int, x0: int, max_steps: int) -> Optional[int]:
    try:
        BusinessLogicValidator.validate_lcg_parameters(m, a, c, x0)
        InputValidator.validate_period_steps(max_steps)
    except ValidationError as e:
        raise ValueError(f"Invalid period estimation parameters: {e}")
    
    def step(x): return (a * x + c) % m
    
    logger.info("Estimating period: max_steps=%d", max_steps)
    
    tort = step(x0)
    hare = step(step(x0))
    steps = 0
    
    while tort != hare and steps < max_steps:
        tort = step(tort)
        hare = step(step(hare))
        steps += 1
    
    if tort != hare:
        logger.info("No meeting point within bounds")
        return None
    
    mu = 0
    tort = x0
    while tort != hare and mu < max_steps:
        tort = step(tort)
        hare = step(hare)
        mu += 1
    
    if mu >= max_steps:
        logger.info("Failed to locate cycle start")
        return None
    
    lam = 1
    hare = step(tort)
    while tort != hare and lam < max_steps:
        hare = step(hare)
        lam += 1
    
    if lam >= max_steps:
        logger.info("Failed to measure cycle length")
        return None
    
    logger.info("Estimated period (lambda)=%d", lam)
    return lam