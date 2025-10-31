# 🔒 Production-Grade WAF Lab
<img width="1470" height="875" alt="Screenshot 2025-11-01 at 01 57 44" src="https://github.com/user-attachments/assets/0e0c0962-b90d-4df2-b003-e91589a1b2dc" />


**Advanced Web Application Firewall** built with Python `aiohttp` for high-performance asynchronous request processing.

> ⚠️ **Educational/Lab Use Only** - This project is designed for learning WAF architecture and cybersecurity concepts. Do not use in production without comprehensive security audit and hardening.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

## 🎯 Features

### Core Security
- ✅ **Negative Security Model (NSM)**: Pattern-based blocking of known attack signatures
- ✅ **Positive Security Model (PSM)**: Whitelist-based allow-only approach
- ✅ **Anomaly Scoring System**: Behavioral analysis with weighted threat indicators
- ✅ **Rate Limiting**: Token bucket algorithm with IP-based throttling
- ✅ **IP Reputation**: Whitelist/Blacklist support

### Observability & Monitoring
- ✅ **Structured JSON Logging**: ELK Stack (Elasticsearch, Logstash, Kibana) compatible
- ✅ **Loki Integration**: Grafana Loki compatible log format
- ✅ **Prometheus Metrics**: Full instrumentation for scraping and alerting
- ✅ **PRTG Sensor Integration**: XML endpoint for PRTG monitoring
- ✅ **Health Checks**: Kubernetes/Docker orchestration support

### Reverse Proxy & Hardening
- ✅ **Security Headers**: CSP, HSTS, X-Frame-Options, XSS-Protection
- ✅ **Header Sanitization**: Removes sensitive/proxy headers
- ✅ **Backend Resilience**: Timeouts, error handling, connection pooling
- ✅ **CORS Support**: Configurable cross-origin resource sharing

### Architecture
- ✅ **Modular Design**: Separation of concerns (config/logger/inspector/router/core)
- ✅ **Async/Await**: Non-blocking I/O for maximum performance
- ✅ **Production-Ready**: Error handling, logging, metrics throughout

## 📁 Project Structure

```
waf-lab/
├── config/          # Configuration management
├── core/            # Main application orchestration
├── inspector/       # Rule engine & anomaly detection
├── logger/          # Async structured logging
├── metrics/         # Prometheus metrics & PRTG integration
├── router/          # Reverse proxy with security hardening
├── utils/           # Rate limiter, IP utilities
├── tests/           # Pytest test suite
├── waf.py           # Main entry point
├── rules.json       # Security rules configuration
├── Dockerfile       # Multi-stage secure build
└── docker-compose.yml
```

## 🚀 Quick Start

### Prerequisites
- Docker & Docker Compose
- Python 3.11+ (for local development)

### Using Docker Compose

```bash
# Build and start services
docker-compose up --build

# WAF will be available at http://localhost:8000
# Juice Shop backend at http://localhost:8080
```

### Local Development

```bash
# Install dependencies
pip install -r requirements.txt

# Run WAF
python waf.py

# Run tests
pytest tests/
```

## ⚙️ Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `WAF_BACKEND_URL` | Backend application URL | `http://backend:3000` |
| `WAF_PORT` | WAF listening port | `8000` |
| `WAF_HOST` | WAF listening host | `0.0.0.0` |
| `WAF_LOG_LEVEL` | Logging level | `INFO` |
| `WAF_RATE_LIMIT_RPM` | Requests per minute limit | `60` |
| `WAF_ANOMALY_THRESHOLD` | Anomaly score threshold | `50.0` |

### Rules Configuration (`rules.json`)

```json
{
  "backend": "http://backend:3000",
  "negative_rules": [
    {
      "id": "SQLi-1",
      "pattern": "(?i)(union.*select|drop.*table)",
      "category": "sql_injection",
      "severity": "high",
      "score": 80.0
    }
  ],
  "positive_rules": [],
  "ip_whitelist": [],
  "ip_blacklist": []
}
```

## 📊 Monitoring

### Prometheus Metrics

Scrape metrics from: `http://localhost:8000/metrics`

Available metrics:
- `waf_requests_total` - Total requests by decision
- `waf_blocks_total` - Blocked requests by reason
- `waf_request_duration_seconds` - Request processing latency
- `waf_anomaly_scores` - Anomaly score distribution
- `waf_active_connections` - Current active connections
- `waf_rate_limit_hits_total` - Rate limit violations

### PRTG Sensor

Access XML endpoint: `http://localhost:8000/prtg`

Returns PRTG-compatible XML with:
- Total Requests
- Blocked Requests
- Rate Limit Hits
- Average Response Time
- Active Connections

### Structured Logs

Logs are written to `/app/logs/waf.log` in JSON format:

```json
{
  "@timestamp": "2024-01-15T10:30:00Z",
  "level": "WARNING",
  "service": "waf",
  "event_type": "request",
  "method": "POST",
  "path": "/api/login",
  "client_ip": "192.168.1.100",
  "decision": "block",
  "reason": "rule:SQLi-1",
  "score": 80.0,
  "threat_category": "sql_injection"
}
```

## 🧪 Testing

### Unit Tests

```bash
pytest tests/test_rule_engine.py -v
```

### Integration Tests

```bash
# Start services
docker-compose up -d

# Run integration tests
pytest tests/test_integration.py -v
```

### Manual Testing with Juice Shop

```bash
# Test SQL injection (should be blocked)
curl -X GET "http://localhost:8000/api/products?q=1' OR 1=1--"

# Test XSS (should be blocked)
curl -X POST "http://localhost:8000/api/comment" \
  -d "comment=<script>alert('XSS')</script>"

# Normal request (should be allowed)
curl -X GET "http://localhost:8000/api/products"
```

## 🔐 Security Best Practices

### Implemented
- ✅ Non-root Docker user
- ✅ Multi-stage Docker builds
- ✅ Security headers (CSP, HSTS)
- ✅ Header sanitization
- ✅ Rate limiting
- ✅ IP-based access control
- ✅ Input validation via rules

### Recommendations
- 🔒 Use TLS/HTTPS in production
- 🔒 Configure proper CORS policies
- 🔒 Regularly update security rules
- 🔒 Monitor anomaly scores and adjust thresholds
- 🔒 Implement Redis-based distributed rate limiting for multi-instance deployments
- 🔒 Add circuit breaker for backend resilience
- 🔒 Implement CAPTCHA challenge for suspicious requests (challenge mode)

## 📈 Performance

- **Async I/O**: Non-blocking request processing
- **Connection Pooling**: Reusable backend connections
- **Regex Compilation**: Pre-compiled patterns for fast matching
- **Token Bucket**: Efficient rate limiting algorithm

## 🛠️ Development

### Code Quality

```bash
# Format code
black .

# Lint code
flake8 .

# Security scanning
bandit -r .

# Type checking
mypy .
```

### Adding New Rules

1. Edit `rules.json`
2. Add rule with pattern, category, severity, and score
3. Restart WAF service

### Extending Anomaly Scoring

Modify `inspector/rule_engine.py` → `_calculate_anomaly_score()` to add new behavioral indicators.

## 📚 Architecture Details

### Request Flow

```
Client Request
    ↓
[Rate Limiter] → Block if exceeded
    ↓
[Rule Engine] → Inspect (NSM + PSM + Anomaly)
    ↓
Decision: Block or Allow
    ↓
[Reverse Proxy] → Forward to backend (if allowed)
    ↓
[Security Headers] → Add hardening headers
    ↓
[Logging & Metrics] → Record event
    ↓
Response to Client
```

### Rule Engine Pipeline

1. **IP Check**: Whitelist/Blacklist validation
2. **Positive Security**: Whitelist pattern matching
3. **Negative Security**: Block pattern matching
4. **Anomaly Scoring**: Behavioral analysis
5. **Threshold Decision**: Block if score exceeds threshold

## 🤝 Contributing

This is a learning/research project for WAF architecture and cybersecurity observability.

## 📝 License

MIT License - Educational/Research Use

## 👤 Author

**Yusuf Dalbudak**  
PRTG Pre-Sales Specialist @ CyberDistro

---

Built with ❤️ for cybersecurity research and WAF architecture exploration.

