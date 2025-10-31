"""Pytest configuration and shared fixtures."""
import pytest
from unittest.mock import Mock, MagicMock
from aiohttp import web
from config import load_config
from inspector import RuleEngine
from logger import StructuredLogger
from utils import RateLimiter
from metrics import MetricsCollector


@pytest.fixture
def config():
    """Load test configuration."""
    return load_config("rules.json")


@pytest.fixture
def rule_engine(config):
    """Create rule engine instance."""
    return RuleEngine(config)


@pytest.fixture
def logger(config):
    """Create logger instance."""
    return StructuredLogger(
        log_file="/tmp/test_waf.log",
        log_level="DEBUG",
        enable_console=False
    )


@pytest.fixture
def rate_limiter():
    """Create rate limiter instance."""
    return RateLimiter(requests_per_minute=60, burst_size=10)


@pytest.fixture
def metrics():
    """Create metrics collector instance."""
    return MetricsCollector()


def create_mock_request(method="GET", path="/test", body="", headers=None, remote="127.0.0.1"):
    """
    Create a properly mocked aiohttp request for testing.
    
    Args:
        method: HTTP method
        path: Request path
        body: Request body string
        headers: Optional headers dict
        remote: Client IP address
        
    Returns:
        Mock request object with all required attributes
    """
    from yarl import URL
    from multidict import CIMultiDict
    
    if headers is None:
        headers = {}
    
    # Create mock request
    request = Mock(spec=web.Request)
    request.method = method
    request.rel_url = URL(path)
    request.remote = remote
    request.headers = CIMultiDict(headers)
    
    # Mock body reading
    async def read():
        return body.encode() if body else b""
    
    async def text():
        return body
    
    request.read = read
    request.text = text
    
    return request

