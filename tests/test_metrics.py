"""Unit tests for metrics collector."""
import pytest
from prometheus_client import CollectorRegistry
from metrics import MetricsCollector


@pytest.fixture
def registry():
    """Create a fresh registry for each test to avoid conflicts."""
    return CollectorRegistry()


def test_metrics_collector_initialization(registry):
    """Test metrics collector initialization."""
    metrics = MetricsCollector(registry=registry)
    
    assert metrics is not None
    assert metrics.requests_total is not None
    assert metrics.blocks_total is not None
    assert metrics.request_duration is not None


def test_record_request(registry):
    """Test recording a request."""
    metrics = MetricsCollector(registry=registry)
    
    metrics.record_request(
        decision="allow",
        method="GET",
        status_code=200,
        duration_seconds=0.1,
        anomaly_score=0.0
    )
    
    # Metrics should be recorded without error
    assert True


def test_record_block(registry):
    """Test recording a blocked request."""
    metrics = MetricsCollector(registry=registry)
    
    metrics.record_block(
        reason="rule:SQLi-1",
        threat_category="sql_injection",
        rule_id="SQLi-1"
    )
    
    # Metrics should be recorded without error
    assert True


def test_record_rate_limit(registry):
    """Test recording rate limit violation."""
    metrics = MetricsCollector(registry=registry)
    
    metrics.record_rate_limit("192.168.1.1")
    
    # Metrics should be recorded without error
    assert True


def test_get_metrics_output(registry):
    """Test getting Prometheus metrics output."""
    metrics = MetricsCollector(registry=registry)
    
    output = metrics.get_metrics_output()
    
    assert output is not None
    assert isinstance(output, bytes)
    assert len(output) > 0
    assert b"# HELP" in output or b"# TYPE" in output


def test_get_prtg_xml(registry):
    """Test getting PRTG XML output."""
    metrics = MetricsCollector(registry=registry)
    
    xml = metrics.get_prtg_xml()
    
    assert xml is not None
    assert isinstance(xml, str)
    assert "<prtg>" in xml
    assert "</prtg>" in xml


def test_connection_tracking(registry):
    """Test active connection tracking."""
    metrics = MetricsCollector(registry=registry)
    
    metrics.increment_connections()
    metrics.decrement_connections()
    
    # Should not raise errors
    assert True

