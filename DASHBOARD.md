# 🛡️ WAF Traffic Dashboard

## Overview

The WAF includes a **real-time web dashboard** for monitoring all traffic details, security events, and statistics.

## Access Dashboard

### Web Interface
```
http://localhost:8000/dashboard
```

### API Endpoints

#### 1. Statistics API
```bash
curl http://localhost:8000/api/dashboard/stats
```

Returns:
```json
{
  "total_requests": 1250,
  "total_allowed": 1100,
  "total_blocked": 150,
  "total_bytes": 52428800,
  "by_threat_category": {
    "sql_injection": 45,
    "cross_site_scripting": 78,
    "command_injection": 12
  },
  "by_rule": {
    "SQLi-1": 25,
    "XSS-1": 60,
    "CMD-1": 8
  },
  "by_ip": {
    "192.168.1.100": 500,
    "10.0.0.5": 300
  },
  "uptime_seconds": 3600,
  "requests_per_minute": 20.8,
  "block_rate": 12.0,
  "current_entries": 1000
}
```

#### 2. Traffic History API
```bash
# Get last 100 entries
curl http://localhost:8000/api/dashboard/traffic?limit=100
```

Returns array of traffic entries:
```json
[
  {
    "timestamp": 1699123456.789,
    "method": "POST",
    "path": "/api/login",
    "client_ip": "192.168.1.100",
    "user_agent": "Mozilla/5.0...",
    "decision": "block",
    "reason": "rule:SQLi-1",
    "score": 80.0,
    "threat_category": "sql_injection",
    "status_code": 403,
    "response_time_ms": 12.5,
    "bytes_sent": 0
  }
]
```

## Dashboard Features

### Real-Time Monitoring
- ✅ **Live traffic feed** - See requests as they happen
- ✅ **Auto-refresh** - Updates every 5 seconds
- ✅ **Color-coded decisions** - Green (allowed), Red (blocked), Orange (rate limit)

### Statistics Cards
- **Total Requests** - Overall request count and rate
- **Allowed Requests** - Requests that passed WAF checks
- **Blocked Requests** - Security blocks with percentage
- **Uptime & Data Transfer** - System health metrics

### Traffic Table
Shows detailed information for each request:
- **Timestamp** - When request occurred
- **IP Address** - Client IP (with X-Forwarded-For support)
- **Method** - HTTP method (GET, POST, etc.)
- **Path** - Request URL path
- **Decision** - allow/block/challenge
- **Reason** - Block reason (rule ID, rate_limit, etc.)
- **Score** - Anomaly score (0-100)
- **Threat Category** - Detected threat type
- **Response Time** - Processing latency

### Threat Analytics
- Threat category breakdown
- Rule match statistics
- Top blocked IPs
- Block rate trends

## Data Storage

### In-Memory Store
- Stores up to **10,000 entries** by default (configurable)
- Circular buffer (FIFO) - oldest entries automatically purged
- Zero external dependencies

### Production Considerations
For production deployments, consider:
- **Redis backend** - Distributed storage for multi-instance deployments
- **Database persistence** - PostgreSQL/MySQL for historical analysis
- **Time-series DB** - InfluxDB/TimescaleDB for long-term metrics

## Example Queries

### Get traffic for specific IP
```python
from core.traffic_store import get_traffic_store
store = get_traffic_store()
entries = store.get_entries_by_ip("192.168.1.100", limit=50)
```

### Get all blocked requests
```python
blocked = store.get_entries_by_decision("block", limit=100)
```

### Get statistics
```python
stats = store.get_stats()
print(f"Block rate: {stats['block_rate']:.1f}%")
```

## Integration with Other Systems

### Grafana Dashboard
Export traffic data to Grafana:
```bash
# Use Prometheus metrics endpoint
curl http://localhost:8000/metrics | promtool text-to-metrics
```

### ELK Stack
Structured logs are automatically written to `/app/logs/waf.log`:
```bash
# Tail logs for real-time monitoring
tail -f /app/logs/waf.log | jq
```

### PRTG Monitoring
Use the PRTG sensor endpoint:
```
http://localhost:8000/prtg
```

## Security Notes

⚠️ **Important**: The dashboard exposes sensitive information:
- Client IP addresses
- Request paths (may contain parameters)
- User-Agent strings
- Security rule matches

**Recommendations**:
1. Restrict dashboard access via reverse proxy/nginx
2. Add authentication (Basic Auth, OAuth, etc.)
3. Use HTTPS in production
4. Limit dashboard to internal networks only

## Future Enhancements

- [ ] Search and filter functionality
- [ ] Export traffic logs (CSV, JSON)
- [ ] IP reputation visualization
- [ ] Geographic IP mapping
- [ ] Custom alerts and notifications
- [ ] Historical trend graphs
- [ ] Rule effectiveness analysis

