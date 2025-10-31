# Security Policy

## Supported Versions

This is a **laboratory/educational project** for learning WAF architecture and cybersecurity concepts.

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Security Considerations

### ⚠️ Important Notes

This WAF is designed for **educational purposes and lab environments only**. 

**DO NOT use in production without:**
- Comprehensive security audit
- Penetration testing
- Code review by security experts
- Production hardening
- Authentication/authorization for dashboard
- HTTPS/TLS configuration
- Rate limiting configuration review
- Rule set validation

### Reporting Security Vulnerabilities

If you discover a security vulnerability, please:

1. **DO NOT** create a public GitHub issue
2. Email security concerns to the repository maintainer
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### Known Limitations

- In-memory traffic store (data lost on restart)
- No authentication on dashboard endpoint
- Default configuration may need tuning
- Rate limiting uses in-memory storage (not distributed)

### Best Practices

- Always run behind a reverse proxy (nginx, Traefik) with TLS
- Implement authentication for dashboard access
- Regularly update security rules
- Monitor and review logs
- Use in isolated lab/development environments only

