#!/usr/bin/env python3
"""
Production-Grade Web Application Firewall (WAF)
Built with aiohttp for high-performance async request processing.

Author: Yusuf Dalbudak
Company: CyberDistro - PRTG Pre-Sales Specialist
Project: waf-lab

Features:
- Negative & Positive Security Models
- Anomaly Scoring System
- Rate Limiting (Token Bucket)
- Structured JSON Logging (ELK/Loki compatible)
- Prometheus Metrics
- PRTG Sensor Integration
- Security Headers (CSP, HSTS, etc.)
- Reverse Proxy with Hardening
"""

import os
import sys
from aiohttp import web

# Add project root to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core import create_app


def main():
    """Main entry point for WAF application."""
    # Get configuration path from environment or use default
    config_path = os.getenv("WAF_CONFIG_PATH", "rules.json")
    
    # Create application
    app = create_app(config_path)
    
    # Get port from environment or use default
    port = int(os.getenv("WAF_PORT", "8000"))
    host = os.getenv("WAF_HOST", "0.0.0.0")
    
    # Run application
    web.run_app(
        app,
        host=host,
        port=port,
        access_log=None  # We use structured logging instead
    )


if __name__ == "__main__":
    main()
