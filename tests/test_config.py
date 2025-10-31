"""Unit tests for configuration management."""
import pytest
import os
import json
import tempfile
from config import load_config, Config


def test_load_config_defaults():
    """Test loading default configuration."""
    config = load_config("rules.json")
    
    assert config is not None
    assert isinstance(config, Config)
    assert config.backend.url is not None
    assert config.rate_limit.requests_per_minute > 0
    assert config.security.anomaly_threshold > 0


def test_load_config_with_rules():
    """Test loading configuration with rules."""
    config = load_config("rules.json")
    
    assert len(config.negative_rules) > 0
    assert all("id" in rule for rule in config.negative_rules)
    assert all("pattern" in rule for rule in config.negative_rules)


def test_load_config_environment_variables(monkeypatch):
    """Test environment variable overrides."""
    monkeypatch.setenv("WAF_BACKEND_URL", "http://custom-backend:8080")
    monkeypatch.setenv("WAF_RATE_LIMIT_RPM", "120")
    monkeypatch.setenv("WAF_ANOMALY_THRESHOLD", "75.0")
    
    config = load_config("rules.json")
    
    assert config.backend.url == "http://custom-backend:8080"
    assert config.rate_limit.requests_per_minute == 120
    assert config.security.anomaly_threshold == 75.0


def test_config_structure():
    """Test configuration structure completeness."""
    config = load_config("rules.json")
    
    # Check all main sections exist
    assert hasattr(config, "rate_limit")
    assert hasattr(config, "backend")
    assert hasattr(config, "logging")
    assert hasattr(config, "security")
    assert hasattr(config, "metrics")
    assert hasattr(config, "negative_rules")
    assert hasattr(config, "positive_rules")


def test_config_security_settings():
    """Test security configuration defaults."""
    config = load_config("rules.json")
    
    assert config.security.enable_csp is True
    assert config.security.enable_hsts is True
    assert config.security.anomaly_threshold > 0

