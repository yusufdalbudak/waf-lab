"""Token bucket rate limiter for IP-based request throttling."""
import time
from typing import Dict, Tuple
from collections import defaultdict
from dataclasses import dataclass


@dataclass
class TokenBucket:
    """Token bucket for rate limiting algorithm."""
    tokens: float
    last_refill: float
    capacity: float
    refill_rate: float  # tokens per second


class RateLimiter:
    """
    In-memory token bucket rate limiter.
    
    Uses sliding window token bucket algorithm:
    - Each IP has a bucket with tokens
    - Requests consume tokens
    - Tokens refill at a constant rate
    - Burst capacity allows short bursts above average rate
    
    Production consideration: For distributed deployments, use Redis-based
    rate limiter with distributed locks (e.g., redlock algorithm).
    """
    
    def __init__(
        self,
        requests_per_minute: int = 60,
        burst_size: int = 10,
        window_seconds: int = 60
    ):
        """
        Initialize rate limiter.
        
        Args:
            requests_per_minute: Average allowed requests per minute
            burst_size: Maximum burst capacity (extra tokens)
            window_seconds: Time window for rate calculation
        """
        self.requests_per_minute = requests_per_minute
        self.burst_size = burst_size
        self.window_seconds = window_seconds
        
        # Calculate refill rate (tokens per second)
        self.refill_rate = requests_per_minute / 60.0
        
        # Token buckets per IP
        self.buckets: Dict[str, TokenBucket] = {}
        
        # Cleanup threshold (remove old buckets after this many seconds of inactivity)
        self.cleanup_threshold = 300  # 5 minutes
    
    def _refill_bucket(self, bucket: TokenBucket, now: float):
        """
        Refill token bucket based on elapsed time.
        
        Args:
            bucket: TokenBucket to refill
            now: Current timestamp
        """
        elapsed = now - bucket.last_refill
        
        # Calculate tokens to add
        tokens_to_add = elapsed * self.refill_rate
        
        # Refill up to capacity
        bucket.tokens = min(
            bucket.capacity,
            bucket.tokens + tokens_to_add
        )
        bucket.last_refill = now
    
    def _get_or_create_bucket(self, ip: str, now: float) -> TokenBucket:
        """Get or create token bucket for IP."""
        if ip not in self.buckets:
            self.buckets[ip] = TokenBucket(
                tokens=float(self.requests_per_minute + self.burst_size),
                last_refill=now,
                capacity=float(self.requests_per_minute + self.burst_size),
                refill_rate=self.refill_rate
            )
        else:
            # Refill existing bucket
            self._refill_bucket(self.buckets[ip], now)
        
        return self.buckets[ip]
    
    def check_rate_limit(self, ip: str) -> Tuple[bool, Dict[str, float]]:
        """
        Check if request should be allowed based on rate limit.
        
        Args:
            ip: Client IP address
            
        Returns:
            Tuple of (is_allowed, metadata_dict)
            metadata contains: remaining_tokens, reset_seconds
        """
        now = time.time()
        bucket = self._get_or_create_bucket(ip, now)
        
        # Check if tokens available
        if bucket.tokens >= 1.0:
            bucket.tokens -= 1.0
            is_allowed = True
        else:
            is_allowed = False
        
        # Calculate reset time (seconds until next token available)
        reset_seconds = 0.0
        if bucket.tokens < bucket.capacity:
            reset_seconds = (1.0 - bucket.tokens) / self.refill_rate
        
        metadata = {
            "remaining_tokens": max(0.0, bucket.tokens),
            "reset_seconds": reset_seconds,
            "limit": self.requests_per_minute,
            "window": self.window_seconds
        }
        
        return is_allowed, metadata
    
    def cleanup_old_buckets(self):
        """Remove buckets that haven't been used recently (memory management)."""
        now = time.time()
        ips_to_remove = [
            ip for ip, bucket in self.buckets.items()
            if now - bucket.last_refill > self.cleanup_threshold
        ]
        for ip in ips_to_remove:
            del self.buckets[ip]
    
    def get_stats(self) -> Dict[str, int]:
        """Get rate limiter statistics."""
        return {
            "active_buckets": len(self.buckets),
            "requests_per_minute": self.requests_per_minute,
            "burst_size": self.burst_size
        }

