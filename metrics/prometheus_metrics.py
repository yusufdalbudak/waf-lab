"""Prometheus metrics collection for WAF performance and security monitoring."""
from typing import Dict, Optional
from prometheus_client import Counter, Histogram, Gauge, generate_latest, CONTENT_TYPE_LATEST, CollectorRegistry, REGISTRY


class MetricsCollector:
    """
    Prometheus metrics collector for WAF observability.
    
    Metrics exposed:
    - waf_requests_total: Total requests processed (by decision: allow/block)
    - waf_blocks_total: Total blocked requests (by reason: rule/anomaly/rate_limit)
    - waf_request_duration_seconds: Request processing latency histogram
    - waf_anomaly_scores: Anomaly scores distribution histogram
    - waf_active_connections: Current active connections (gauge)
    - waf_rate_limit_hits_total: Rate limit violations counter
    
    These metrics can be scraped by Prometheus and visualized in Grafana.
    Also suitable for PRTG sensor integration via custom XML/JSON endpoint.
    """
    
    def __init__(self, registry=None):
        """
        Initialize Prometheus metrics.
        
        Args:
            registry: Optional CollectorRegistry. If None, uses default registry.
                     For testing, pass a custom registry to avoid conflicts.
        """
        if registry is None:
            registry = REGISTRY
        
        # Counter: Total requests by decision
        self.requests_total = Counter(
            'waf_requests_total',
            'Total requests processed by WAF',
            ['decision', 'method', 'status_code'],
            registry=registry
        )
        
        # Counter: Blocked requests by reason
        self.blocks_total = Counter(
            'waf_blocks_total',
            'Total blocked requests',
            ['reason', 'threat_category', 'rule_id'],
            registry=registry
        )
        
        # Histogram: Request processing duration
        self.request_duration = Histogram(
            'waf_request_duration_seconds',
            'Request processing duration in seconds',
            ['decision'],
            buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0),
            registry=registry
        )
        
        # Histogram: Anomaly scores distribution
        self.anomaly_scores = Histogram(
            'waf_anomaly_scores',
            'Anomaly score distribution',
            ['decision'],
            buckets=(0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100),
            registry=registry
        )
        
        # Gauge: Active connections
        self.active_connections = Gauge(
            'waf_active_connections',
            'Current number of active connections',
            registry=registry
        )
        
        # Counter: Rate limit violations
        self.rate_limit_hits = Counter(
            'waf_rate_limit_hits_total',
            'Total rate limit violations',
            ['client_ip'],
            registry=registry
        )
        
        # Counter: Backend errors
        self.backend_errors = Counter(
            'waf_backend_errors_total',
            'Total backend proxy errors',
            ['error_type', 'status_code'],
            registry=registry
        )
        
        self.registry = registry
    
    def record_request(
        self,
        decision: str,
        method: str,
        status_code: int,
        duration_seconds: float,
        anomaly_score: float = 0.0
    ):
        """
        Record a processed request.
        
        Args:
            decision: allow|block|challenge
            method: HTTP method
            status_code: Response status code
            duration_seconds: Processing duration
            anomaly_score: Anomaly score (0-100)
        """
        self.requests_total.labels(
            decision=decision,
            method=method,
            status_code=str(status_code)
        ).inc()
        
        self.request_duration.labels(decision=decision).observe(duration_seconds)
        
        if anomaly_score > 0:
            self.anomaly_scores.labels(decision=decision).observe(anomaly_score)
    
    def record_block(
        self,
        reason: str,
        threat_category: Optional[str] = None,
        rule_id: Optional[str] = None
    ):
        """
        Record a blocked request.
        
        Args:
            reason: Block reason (rule:SQLi-1, anomaly, rate_limit, etc.)
            threat_category: Threat category
            rule_id: Matched rule ID
        """
        self.blocks_total.labels(
            reason=reason.split(':')[0] if ':' in reason else reason,
            threat_category=threat_category or "unknown",
            rule_id=rule_id or "none"
        ).inc()
    
    def record_rate_limit(self, client_ip: str):
        """Record a rate limit violation."""
        self.rate_limit_hits.labels(client_ip=client_ip[:20]).inc()  # Truncate long IPs
    
    def record_backend_error(self, error_type: str, status_code: int):
        """Record a backend proxy error."""
        self.backend_errors.labels(
            error_type=error_type,
            status_code=str(status_code)
        ).inc()
    
    def increment_connections(self):
        """Increment active connections counter."""
        self.active_connections.inc()
    
    def decrement_connections(self):
        """Decrement active connections counter."""
        self.active_connections.dec()
    
    def get_metrics_output(self) -> bytes:
        """
        Get Prometheus metrics in text format.
        
        Returns:
            Prometheus exposition format text
        """
        try:
            # Always use default registry for production (singleton pattern)
            # Custom registries are only for testing
            return generate_latest()
        except Exception as e:
            # Return empty metrics if there's an issue
            return b"# Error generating metrics\n"
    
    def get_prtg_xml(self) -> str:
        """
        Generate PRTG-compatible XML sensor output.
        
        PRTG can monitor custom XML endpoints for sensor data.
        This provides WAF statistics in PRTG-native format.
        
        Returns:
            PRTG XML sensor data
        """
        # Note: This is a simplified example. In production, you'd query
        # the actual metric values from Prometheus registry or store them separately.
        
        xml = """<?xml version="1.0" encoding="UTF-8"?>
<prtg>
    <result>
        <channel>Total Requests</channel>
        <value>0</value>
        <unit>Count</unit>
        <mode>Absolute</mode>
    </result>
    <result>
        <channel>Blocked Requests</channel>
        <value>0</value>
        <unit>Count</unit>
        <mode>Absolute</mode>
    </result>
    <result>
        <channel>Rate Limit Hits</channel>
        <value>0</value>
        <unit>Count</unit>
        <mode>Absolute</mode>
    </result>
    <result>
        <channel>Average Response Time</channel>
        <value>0</value>
        <unit>TimeResponse</unit>
        <mode>Absolute</mode>
    </result>
    <result>
        <channel>Active Connections</channel>
        <value>0</value>
        <unit>Count</unit>
        <mode>Absolute</mode>
    </result>
</prtg>"""
        return xml


# Global metrics collector instance
_metrics_instance: Optional[MetricsCollector] = None


def get_metrics_collector() -> MetricsCollector:
    """Get or create global metrics collector."""
    global _metrics_instance
    if _metrics_instance is None:
        _metrics_instance = MetricsCollector()
    return _metrics_instance

