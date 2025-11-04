"""WAF configuration settings with environment variable support."""
import os
import json
from typing import Dict, List, Optional
from dataclasses import dataclass, field


@dataclass
class RateLimitConfig:
    """Rate limiting configuration per IP."""
    requests_per_minute: int = 60
    burst_size: int = 10
    window_seconds: int = 60


@dataclass
class BackendConfig:
    """Backend proxy configuration."""
    url: str = "http://backend:3000"
    timeout: float = 30.0
    max_retries: int = 3
    health_check_path: str = "/api/status"
    health_check_interval: int = 30


@dataclass
class LoggingConfig:
    """Structured logging configuration."""
    log_dir: str = "/app/logs"
    log_file: str = "waf.log"
    log_level: str = "INFO"
    json_format: bool = True
    enable_console: bool = True
    destination: str = "/app/logs/waf.log"
    structured: bool = True


@dataclass
class SecurityConfig:
    """Security and hardening settings."""
    # Security headers
    enable_csp: bool = True
    enable_hsts: bool = True
    enable_xss_protection: bool = True
    
    # Header sanitization
    block_sensitive_headers: List[str] = field(default_factory=lambda: [
        "x-forwarded-for", "x-real-ip", "x-original-forwarded-for"
    ])
    
    # CORS
    cors_allow_origins: List[str] = field(default_factory=lambda: ["*"])
    cors_allow_methods: List[str] = field(default_factory=lambda: ["GET", "POST", "PUT", "DELETE", "OPTIONS"])
    
    # Anomaly detection
    anomaly_threshold: float = 50.0  # Score threshold for blocking
    enable_anomaly_detection: bool = True
    
    # Security headers dictionary from config
    security_headers: Dict[str, str] = field(default_factory=dict)


@dataclass
class MetricsConfig:
    """Prometheus metrics configuration."""
    enabled: bool = True
    endpoint: str = "/metrics"
    port: int = 9090


@dataclass
class Config:
    """Main WAF configuration container."""
    rate_limit: RateLimitConfig = field(default_factory=RateLimitConfig)
    backend: BackendConfig = field(default_factory=BackendConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    metrics: MetricsConfig = field(default_factory=MetricsConfig)
    
    # Rule sets
    negative_rules: List[Dict] = field(default_factory=list)
    positive_rules: List[Dict] = field(default_factory=list)
    
    # IP reputation (whitelist/blacklist)
    ip_whitelist: List[str] = field(default_factory=list)
    ip_blacklist: List[str] = field(default_factory=list)


def load_config(config_path: str = "rules.json") -> Config:
    """
    Load WAF configuration from JSON file and environment variables.
    
    Environment variables override JSON settings:
    - WAF_BACKEND_URL
    - WAF_LOG_LEVEL
    - WAF_RATE_LIMIT_RPM
    - WAF_ANOMALY_THRESHOLD
    
    Args:
        config_path: Path to rules.json configuration file
        
    Returns:
        Config instance with loaded settings
    """
    config = Config()
    
    # Load from JSON file
    if os.path.exists(config_path):
        with open(config_path, "r") as f:
            data = json.load(f)
            
            # Backend URL
            if "backend" in data:
                config.backend.url = data["backend"]
            
            # Meta thresholds (anomaly_block_threshold)
            if "meta" in data and "thresholds" in data["meta"]:
                if "anomaly_block_threshold" in data["meta"]["thresholds"]:
                    config.security.anomaly_threshold = float(data["meta"]["thresholds"]["anomaly_block_threshold"])
                
            # Rate limiting configuration
            if "rate_limit" in data:
                rate_limit = data["rate_limit"]
                if "enabled" in rate_limit and rate_limit["enabled"]:
                    if "requests_per_minute" in rate_limit:
                        config.rate_limit.requests_per_minute = int(rate_limit["requests_per_minute"])
                    if "burst" in rate_limit:
                        config.rate_limit.burst_size = int(rate_limit["burst"])
                
            # Logging configuration
            if "logging" in data:
                logging_config = data["logging"]
                if "destination" in logging_config:
                    config.logging.destination = logging_config["destination"]
                    # Parse directory and filename from destination
                    dest_path = logging_config["destination"]
                    if "/" in dest_path:
                        config.logging.log_dir = os.path.dirname(dest_path)
                        config.logging.log_file = os.path.basename(dest_path)
                if "level" in logging_config:
                    config.logging.log_level = logging_config["level"].upper()
                if "structured" in logging_config:
                    config.logging.structured = bool(logging_config["structured"])
                if "format" in logging_config:
                    config.logging.json_format = logging_config["format"].lower() == "json"
                
            # Security headers
            if "security_headers" in data:
                config.security.security_headers = data["security_headers"]
                
            # Negative security rules (block patterns)
            if "negative_rules" in data:
                config.negative_rules = data["negative_rules"]
                
            # Positive security rules (allow patterns)
            if "positive_rules" in data:
                config.positive_rules = data["positive_rules"]
                
            # IP lists
            if "ip_whitelist" in data:
                config.ip_whitelist = data["ip_whitelist"]
            if "ip_blacklist" in data:
                config.ip_blacklist = data["ip_blacklist"]
    
    # Override with environment variables (12-factor app principle)
    config.backend.url = os.getenv("WAF_BACKEND_URL", config.backend.url)
    config.logging.log_level = os.getenv("WAF_LOG_LEVEL", config.logging.log_level).upper()
    config.rate_limit.requests_per_minute = int(
        os.getenv("WAF_RATE_LIMIT_RPM", config.rate_limit.requests_per_minute)
    )
    config.security.anomaly_threshold = float(
        os.getenv("WAF_ANOMALY_THRESHOLD", config.security.anomaly_threshold)
    )
    
    return config

