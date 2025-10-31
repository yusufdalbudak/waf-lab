# 🔐 Authentication & Security Guide

## Overview

The WAF dashboard now includes **enterprise-grade authentication and security features**:

- ✅ **Secure Login System** - PBKDF2 password hashing
- ✅ **Session Management** - Encrypted, signed session cookies
- ✅ **CAPTCHA Protection** - hCaptcha/reCAPTCHA integration
- ✅ **CSRF Protection** - Token-based request validation
- ✅ **Rate Limiting** - Login attempt throttling
- ✅ **Account Lockout** - Protection against brute force
- ✅ **Secure Headers** - HTTP security headers
- ✅ **Password Policies** - Strong password requirements

---

## Default Credentials

**⚠️ IMPORTANT: Change these after first login!**

- **Username:** `admin`
- **Password:** `ChangeMe123!@#`

---

## Features

### 1. Password Security

**Requirements:**
- Minimum 12 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- At least one special character

**Hashing:**
- Uses PBKDF2 with SHA-256
- 100,000 iterations
- Unique salt per password
- Constant-time comparison (prevents timing attacks)

### 2. Session Management

**Features:**
- Encrypted session cookies
- HMAC-signed for integrity
- HttpOnly flag (prevents XSS)
- Secure flag (HTTPS only)
- SameSite=Strict (CSRF protection)
- Automatic expiry (1 hour default)

### 3. CAPTCHA Integration

Supports both **hCaptcha** and **reCAPTCHA v2/v3**.

**Setup:**

1. **Get CAPTCHA Keys:**
   - hCaptcha: https://www.hcaptcha.com/
   - reCAPTCHA: https://www.google.com/recaptcha/admin

2. **Set Environment Variables:**
   ```bash
   # For hCaptcha
   export HCAPTCHA_SITE_KEY="your_site_key"
   export HCAPTCHA_SECRET_KEY="your_secret_key"
   
   # OR for reCAPTCHA
   export RECAPTCHA_SITE_KEY="your_site_key"
   export RECAPTCHA_SECRET_KEY="your_secret_key"
   ```

3. **CAPTCHA is Optional:**
   - If not configured, login works without CAPTCHA
   - Recommended for production deployments

### 4. CSRF Protection

- All forms include CSRF tokens
- Tokens verified on POST requests
- SameSite cookies provide additional protection

### 5. Rate Limiting

**Login Protection:**
- Maximum 3 login attempts per 5 minutes per IP
- Account locked after 5 failed attempts
- Lockout duration: 15 minutes

### 6. Account Lockout

After 5 failed login attempts:
- Account automatically locked
- Lockout duration: 15 minutes
- Prevents brute force attacks

---

## Usage

### Login

1. Navigate to `/login`
2. Enter username and password
3. Complete CAPTCHA (if enabled)
4. Click "Login"

### Logout

- Click "Logout" button in dashboard
- Or navigate to `/logout`

### Accessing Dashboard

- Dashboard requires authentication
- Unauthenticated users redirected to `/login`
- Sessions expire after 1 hour

---

## Configuration

### Environment Variables

```bash
# CAPTCHA (Optional)
export HCAPTCHA_SITE_KEY="your_key"
export HCAPTCHA_SECRET_KEY="your_secret"
# OR
export RECAPTCHA_SITE_KEY="your_key"
export RECAPTCHA_SECRET_KEY="your_secret"

# Session Secret (Optional - auto-generated)
export WAF_SESSION_SECRET="your_secret_key"

# Session Timeout (seconds, default: 3600)
export WAF_SESSION_TIMEOUT=3600
```

### Programmatic User Creation

```python
from auth.authenticator import get_authenticator

authenticator = get_authenticator()

# Create new user
success, error = authenticator.create_user(
    username="newuser",
    password="SecurePass123!@#",
    is_admin=False
)

if success:
    print("User created successfully")
else:
    print(f"Error: {error}")
```

### Password Change

```python
from auth.authenticator import get_authenticator

authenticator = get_authenticator()

success, error = authenticator.change_password(
    username="admin",
    old_password="old_password",
    new_password="NewSecurePass123!@#"
)
```

---

## Security Best Practices

### ✅ Implemented

1. **Password Hashing**: PBKDF2 with high iteration count
2. **Session Security**: Encrypted, signed cookies
3. **CSRF Protection**: Token validation
4. **Rate Limiting**: Login attempt throttling
5. **Account Lockout**: Brute force protection
6. **Secure Headers**: HttpOnly, Secure, SameSite
7. **CAPTCHA**: Bot protection
8. **Password Policy**: Strong password requirements

### 🔒 Recommendations for Production

1. **Change Default Password**: Immediately after deployment
2. **Enable CAPTCHA**: Configure hCaptcha or reCAPTCHA
3. **Use HTTPS**: Set `secure=True` in cookies (already done)
4. **Session Timeout**: Adjust based on security requirements
5. **Multi-Factor Authentication**: Consider adding 2FA
6. **Password Reset**: Implement password reset flow
7. **Audit Logging**: Log all authentication events
8. **IP Whitelisting**: Restrict dashboard access to trusted IPs

---

## API Endpoints

### Public
- `GET /login` - Login page
- `POST /auth/login` - Login handler

### Protected (Require Authentication)
- `GET /dashboard` - Dashboard interface
- `GET /api/dashboard/stats` - Statistics API
- `GET /api/dashboard/traffic` - Traffic API
- `GET /logout` - Logout handler
- `POST /auth/logout` - Logout handler

---

## Troubleshooting

### Can't Login

1. **Check Default Credentials:**
   - Username: `admin`
   - Password: `ChangeMe123!@#`

2. **Account Locked:**
   - Wait 15 minutes or reset in code

3. **CAPTCHA Issues:**
   - Check keys are set correctly
   - Verify network access to CAPTCHA service
   - CAPTCHA optional - can disable for testing

4. **Session Expired:**
   - Re-login after 1 hour
   - Adjust `WAF_SESSION_TIMEOUT` if needed

### Security Concerns

- **Default Password**: Change immediately!
- **HTTPS**: Always use in production
- **CAPTCHA**: Enable for public-facing deployments
- **Session Secret**: Use strong random key in production

---

## Development vs Production

### Development
- CAPTCHA optional
- Session secret auto-generated
- Secure cookies can be disabled for HTTP testing

### Production
- **MUST** enable CAPTCHA
- **MUST** set strong session secret
- **MUST** use HTTPS
- **MUST** change default password
- **SHOULD** implement password reset
- **SHOULD** add audit logging
- **CONSIDER** 2FA implementation

---

## Next Steps

1. ✅ Change default admin password
2. ✅ Configure CAPTCHA (recommended)
3. ✅ Set production session secret
4. ✅ Enable HTTPS
5. ✅ Create additional users as needed
6. ✅ Implement password reset (future enhancement)
7. ✅ Add 2FA (future enhancement)

---

**🔒 Your WAF dashboard is now enterprise-ready with comprehensive authentication and security!**

