import pytest
import math
from backend.rng.cesaro_test import cesaro_pi_from_iterable


class TestCesaroTest:
    def test_cesaro_basic(self):
        values = [2, 3, 4, 6, 5, 7, 8, 9]
        pi_hat, p, cop, total = cesaro_pi_from_iterable(values, pairs=4)
        
        assert total == 4
        assert cop >= 0
        assert cop <= total
        assert 0 <= p <= 1
        assert not math.isnan(pi_hat)
    
    def test_cesaro_coprime_pairs(self):
        values = [2, 3, 5, 7, 11, 13]
        pi_hat, p, cop, total = cesaro_pi_from_iterable(values, pairs=3)
        
        assert total == 3
        assert cop == 3
        assert p == 1.0
    
    def test_cesaro_non_coprime_pairs(self):
        values = [2, 4, 6, 8, 10, 12]
        pi_hat, p, cop, total = cesaro_pi_from_iterable(values, pairs=3)
        
        assert total == 3
        assert cop == 0
    
    def test_cesaro_zero_handling(self):
        values = [0, 0, 0, 5, 3, 7]
        pi_hat, p, cop, total = cesaro_pi_from_iterable(values, pairs=3)
        
        assert total == 3
        assert cop == 3
    
    def test_cesaro_insufficient_values(self):
        values = [1, 2, 3]
        
        with pytest.raises(ValueError, match="Invalid Cesàro input"):
            cesaro_pi_from_iterable(values, pairs=2)
    
    def test_cesaro_empty_list(self):
        values = []
        
        with pytest.raises(ValueError, match="Invalid Cesàro input"):
            cesaro_pi_from_iterable(values, pairs=1)
    
    def test_cesaro_exact_pairs(self):
        values = [3, 5, 7, 11]
        pi_hat, p, cop, total = cesaro_pi_from_iterable(values, pairs=2)
        
        assert total == 2
        assert cop == 2
    
    def test_cesaro_pi_approximation(self):
        values = []
        for i in range(1, 201):
            values.append(i)
        
        pi_hat, p, cop, total = cesaro_pi_from_iterable(values, pairs=100)
        
        assert total == 100
        assert 2.0 < pi_hat < 4.5
    
    def test_cesaro_probability_bounds(self):
        values = list(range(2, 102))
        pi_hat, p, cop, total = cesaro_pi_from_iterable(values, pairs=50)
        
        assert 0 <= p <= 1
        assert cop <= total
        assert cop >= 0
    
    def test_cesaro_return_types(self):
        values = [2, 3, 5, 7]
        pi_hat, p, cop, total = cesaro_pi_from_iterable(values, pairs=2)
        
        assert isinstance(pi_hat, float)
        assert isinstance(p, float)
        assert isinstance(cop, int)
        assert isinstance(total, int)
    
    def test_cesaro_large_numbers(self):
        values = [1000000, 1000001, 2000000, 2000001, 3000000, 3000001]
        pi_hat, p, cop, total = cesaro_pi_from_iterable(values, pairs=3)
        
        assert total == 3
        assert not math.isnan(pi_hat)
    
    def test_cesaro_same_numbers(self):
        values = [5, 5, 5, 5, 5, 5]
        pi_hat, p, cop, total = cesaro_pi_from_iterable(values, pairs=3)
        
        assert total == 3
        assert cop == 0
    
    def test_cesaro_consecutive_numbers(self):
        values = [10, 11, 12, 13, 14, 15]
        pi_hat, p, cop, total = cesaro_pi_from_iterable(values, pairs=3)
        
        assert total == 3
        assert cop == 3
    
    def test_cesaro_iterator_input(self):
        values = (i for i in range(2, 12))
        pi_hat, p, cop, total = cesaro_pi_from_iterable(values, pairs=5)
        
        assert total == 5
        assert not math.isnan(pi_hat)
    
    def test_cesaro_negative_pairs(self):
        values = [2, 3, 5, 7]
        
        pi_hat, p, cop, total = cesaro_pi_from_iterable(values, pairs=-1)
        assert total == 0
        assert math.isnan(pi_hat)
