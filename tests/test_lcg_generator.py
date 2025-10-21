import pytest
from backend.rng.lcg_generator import LCG


class TestLCG:
    def test_lcg_initialization(self):
        lcg = LCG(m=100, a=21, c=17, seed=42)
        
        assert lcg.m == 100
        assert lcg.a == 21
        assert lcg.c == 17
        assert lcg.state == 42
    
    def test_lcg_next(self):
        lcg = LCG(m=100, a=21, c=17, seed=42)
        
        first = lcg.next()
        second = lcg.next()
        
        assert first != second
        assert 0 <= first < 100
        assert 0 <= second < 100
    
    def test_lcg_deterministic(self):
        lcg1 = LCG(m=100, a=21, c=17, seed=42)
        lcg2 = LCG(m=100, a=21, c=17, seed=42)
        
        for _ in range(10):
            assert lcg1.next() == lcg2.next()
    
    def test_lcg_stream(self):
        lcg = LCG(m=100, a=21, c=17, seed=42)
        
        stream = list(lcg.stream(10))
        
        assert len(stream) == 10
        for value in stream:
            assert 0 <= value < 100
    
    def test_lcg_stream_matches_next(self):
        lcg1 = LCG(m=100, a=21, c=17, seed=42)
        lcg2 = LCG(m=100, a=21, c=17, seed=42)
        
        stream = list(lcg1.stream(5))
        manual = [lcg2.next() for _ in range(5)]
        
        assert stream == manual
    
    def test_lcg_invalid_m(self):
        with pytest.raises(ValueError, match="Invalid LCG parameters"):
            LCG(m=0, a=21, c=17, seed=42)
    
    def test_lcg_invalid_seed(self):
        with pytest.raises(ValueError, match="Invalid LCG parameters"):
            LCG(m=100, a=21, c=17, seed=100)
    
    def test_lcg_negative_seed(self):
        with pytest.raises(ValueError, match="Invalid LCG parameters"):
            LCG(m=100, a=21, c=17, seed=-1)
    
    def test_lcg_large_parameters(self):
        lcg = LCG(m=2147483647, a=16807, c=0, seed=12345)
        
        value = lcg.next()
        assert 0 <= value < 2147483647
    
    def test_lcg_stream_invalid_length(self):
        lcg = LCG(m=100, a=21, c=17, seed=42)
        
        with pytest.raises(ValueError, match="Invalid stream length"):
            list(lcg.stream(0))
    
    def test_lcg_stream_negative_length(self):
        lcg = LCG(m=100, a=21, c=17, seed=42)
        
        with pytest.raises(ValueError, match="Invalid stream length"):
            list(lcg.stream(-5))
    
    def test_lcg_stream_too_large(self):
        lcg = LCG(m=100, a=21, c=17, seed=42)
        
        with pytest.raises(ValueError, match="Invalid stream length"):
            list(lcg.stream(20_000_000))
    
    def test_lcg_zero_c(self):
        lcg = LCG(m=2147483647, a=16807, c=0, seed=1)
        
        value = lcg.next()
        assert 0 <= value < 2147483647
        assert value != 1
    
    def test_lcg_period_detection(self):
        lcg = LCG(m=10, a=3, c=7, seed=0)
        
        values = []
        for _ in range(20):
            values.append(lcg.next())
        
        assert len(values) > len(set(values))
    
    def test_lcg_non_integer_parameters(self):
        with pytest.raises(ValueError, match="Invalid LCG parameters"):
            LCG(m=100.5, a=21, c=17, seed=42)
    
    def test_lcg_different_seeds_different_sequences(self):
        lcg1 = LCG(m=100, a=21, c=17, seed=1)
        lcg2 = LCG(m=100, a=21, c=17, seed=2)
        
        stream1 = list(lcg1.stream(10))
        stream2 = list(lcg2.stream(10))
        
        assert stream1 != stream2
