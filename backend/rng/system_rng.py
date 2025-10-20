import random
from typing import Iterator

def system_range(max_value: int, count: int) -> Iterator[int]:
    for _ in range(count):
        yield random.randrange(max_value)