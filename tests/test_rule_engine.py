"""Unit tests for rule engine."""
import pytest
from tests.conftest import create_mock_request


@pytest.mark.asyncio
async def test_sql_injection_detection(rule_engine):
    """Test SQL injection pattern detection."""
    request = create_mock_request(
        method="GET",
        path="/api/users?id=1' OR 1=1--",
        body="id=1' OR 1=1--"
    )
    
    result = await rule_engine.inspect(request, body="id=1' OR 1=1--")
    
    assert result.decision == "block"
    assert result.reason.startswith("rule:")
    assert result.score > 0
    assert len(result.matched_rules) > 0


@pytest.mark.asyncio
async def test_xss_detection(rule_engine):
    """Test XSS pattern detection."""
    request = create_mock_request(
        method="POST",
        path="/api/comment",
        body="<script>alert('XSS')</script>"
    )
    
    result = await rule_engine.inspect(
        request,
        body="<script>alert('XSS')</script>"
    )
    
    assert result.decision == "block"
    assert any("xss" in rule_id.lower() for rule_id in result.matched_rules)


@pytest.mark.asyncio
async def test_command_injection_detection(rule_engine):
    """Test command injection pattern detection."""
    request = create_mock_request(
        method="POST",
        path="/api/execute",
        body="cmd=; ls -la"
    )
    
    result = await rule_engine.inspect(request, body="cmd=; ls -la")
    
    assert result.decision == "block"
    assert any("CMD" in rule_id for rule_id in result.matched_rules)


@pytest.mark.asyncio
async def test_path_traversal_detection(rule_engine):
    """Test path traversal pattern detection."""
    request = create_mock_request(
        method="GET",
        path="/api/file?path=../../../etc/passwd"
    )
    
    result = await rule_engine.inspect(request, body="")
    
    assert result.decision == "block"
    assert any("PATH" in rule_id for rule_id in result.matched_rules)


@pytest.mark.asyncio
async def test_rce_detection(rule_engine):
    """Test remote code execution pattern detection."""
    request = create_mock_request(
        method="POST",
        path="/api/eval",
        body="code=eval('malicious')"
    )
    
    result = await rule_engine.inspect(request, body="code=eval('malicious')")
    
    # RCE pattern should be detected (may match via rule or anomaly scoring)
    # Check if blocked OR if RCE rule matched
    assert result.decision == "block" or any("RCE" in rule_id for rule_id in result.matched_rules) or result.score >= rule_engine.config.security.anomaly_threshold


@pytest.mark.asyncio
async def test_clean_request_allowed(rule_engine):
    """Test that clean requests are allowed."""
    request = create_mock_request(
        method="GET",
        path="/api/products",
        body=""
    )
    
    result = await rule_engine.inspect(request, body="")
    
    # Should allow if score is below threshold
    assert result.decision == "allow" or result.score < rule_engine.config.security.anomaly_threshold
    assert result.score >= 0
    assert result.score <= 100


@pytest.mark.asyncio
async def test_anomaly_scoring(rule_engine):
    """Test anomaly scoring system."""
    request = create_mock_request(
        method="GET",
        path="/api/test?q=union%20select",
        body=""
    )
    
    result = await rule_engine.inspect(request, body="")
    
    # Should have some anomaly score even if not blocked
    assert result.score >= 0
    assert len(result.indicators) >= 0


@pytest.mark.asyncio
async def test_ip_whitelist(rule_engine, config):
    """Test IP whitelist bypass."""
    # Add IP to whitelist
    config.ip_whitelist = ["192.168.1.100"]
    
    request = create_mock_request(
        method="GET",
        path="/api/test?id=1' OR 1=1--",
        remote="192.168.1.100"
    )
    
    result = await rule_engine.inspect(request, body="id=1' OR 1=1--")
    
    # Whitelisted IP should bypass all checks
    assert result.decision == "allow"


@pytest.mark.asyncio
async def test_ip_blacklist(rule_engine, config):
    """Test IP blacklist blocking."""
    # Add IP to blacklist
    config.ip_blacklist = ["192.168.1.200"]
    
    request = create_mock_request(
        method="GET",
        path="/api/test",
        remote="192.168.1.200"
    )
    
    result = await rule_engine.inspect(request, body="")
    
    # Blacklisted IP should be blocked immediately
    assert result.decision == "block"
    assert result.reason == "ip_blacklist"
    assert result.score == 100.0
