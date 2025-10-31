"""Unit tests for rate limiter."""
import pytest
import time
from utils import RateLimiter


def test_rate_limiter_allows_requests():
    """Test that rate limiter allows requests within limit."""
    limiter = RateLimiter(requests_per_minute=60, burst_size=10)
    
    # Should allow requests up to limit
    for i in range(10):
        allowed, meta = limiter.check_rate_limit("192.168.1.1")
        assert allowed is True
        assert meta["remaining_tokens"] >= 0


def test_rate_limiter_blocks_excessive_requests():
    """Test that rate limiter blocks excessive requests."""
    limiter = RateLimiter(requests_per_minute=10, burst_size=2)
    
    ip = "192.168.1.1"
    
    # Consume all tokens
    for i in range(12):  # 10 + 2 burst
        allowed, meta = limiter.check_rate_limit(ip)
    
    # Next request should be blocked
    allowed, meta = limiter.check_rate_limit(ip)
    assert allowed is False
    assert meta["remaining_tokens"] < 1.0


def test_rate_limiter_refills_tokens():
    """Test that tokens refill over time."""
    limiter = RateLimiter(requests_per_minute=60, burst_size=0)
    
    ip = "192.168.1.1"
    
    # Consume all tokens
    for i in range(60):
        limiter.check_rate_limit(ip)
    
    # Should be blocked
    allowed, _ = limiter.check_rate_limit(ip)
    assert allowed is False
    
    # Wait for token refill (1 second = 1 token at 60 RPM = 1 token/sec)
    time.sleep(1.1)
    
    # Should allow one more request (might have slightly less than 1.0 due to timing)
    allowed, meta = limiter.check_rate_limit(ip)
    assert allowed is True
    assert meta["remaining_tokens"] > 0  # At least some tokens available


def test_rate_limiter_separate_buckets_per_ip():
    """Test that each IP has separate bucket."""
    limiter = RateLimiter(requests_per_minute=10, burst_size=0)
    
    ip1 = "192.168.1.1"
    ip2 = "192.168.1.2"
    
    # Consume all tokens for IP1
    for i in range(10):
        limiter.check_rate_limit(ip1)
    
    # IP1 should be blocked
    allowed1, _ = limiter.check_rate_limit(ip1)
    assert allowed1 is False
    
    # IP2 should still be allowed
    allowed2, _ = limiter.check_rate_limit(ip2)
    assert allowed2 is True


def test_rate_limiter_cleanup():
    """Test cleanup of old buckets."""
    limiter = RateLimiter(requests_per_minute=60, burst_size=0)
    
    ip = "192.168.1.1"
    limiter.check_rate_limit(ip)
    
    assert len(limiter.buckets) == 1
    
    # Cleanup shouldn't remove recent buckets
    limiter.cleanup_old_buckets()
    assert len(limiter.buckets) == 1


def test_rate_limiter_stats():
    """Test rate limiter statistics."""
    limiter = RateLimiter(requests_per_minute=60, burst_size=10)
    
    stats = limiter.get_stats()
    assert stats["requests_per_minute"] == 60
    assert stats["burst_size"] == 10
    assert stats["active_buckets"] >= 0

