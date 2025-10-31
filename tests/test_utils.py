"""Unit tests for utility functions."""
import pytest
from unittest.mock import Mock
from multidict import CIMultiDict
from utils import get_client_ip, is_valid_ip, is_private_ip


def test_get_client_ip_direct():
    """Test getting client IP from direct connection."""
    request = Mock()
    request.remote = "192.168.1.1"
    request.headers = CIMultiDict()
    
    ip = get_client_ip(request)
    assert ip == "192.168.1.1"


def test_get_client_ip_from_x_forwarded_for():
    """Test getting client IP from X-Forwarded-For header."""
    request = Mock()
    request.remote = "10.0.0.1"
    request.headers = CIMultiDict({
        "X-Forwarded-For": "192.168.1.100, 10.0.0.1"
    })
    
    ip = get_client_ip(request)
    assert ip == "192.168.1.100"


def test_get_client_ip_from_x_real_ip():
    """Test getting client IP from X-Real-IP header."""
    request = Mock()
    request.remote = "10.0.0.1"
    request.headers = CIMultiDict({
        "X-Real-IP": "192.168.1.200"
    })
    
    ip = get_client_ip(request)
    assert ip == "192.168.1.200"


def test_is_valid_ip():
    """Test IP validation."""
    assert is_valid_ip("192.168.1.1") is True
    assert is_valid_ip("::1") is True  # IPv6
    assert is_valid_ip("invalid") is False
    assert is_valid_ip("999.999.999.999") is False


def test_is_private_ip():
    """Test private IP detection."""
    assert is_private_ip("192.168.1.1") is True
    assert is_private_ip("10.0.0.1") is True
    assert is_private_ip("127.0.0.1") is True
    assert is_private_ip("8.8.8.8") is False
    assert is_private_ip("invalid") is False

