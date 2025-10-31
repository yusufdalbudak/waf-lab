"""Prometheus metrics module for WAF observability."""
from .prometheus_metrics import MetricsCollector, get_metrics_collector

__all__ = ["MetricsCollector", "get_metrics_collector"]

