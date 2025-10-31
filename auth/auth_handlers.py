"""Authentication handlers for login, logout, and session management."""
from aiohttp import web
from typing import Optional
import secrets

# Add parent directory to path for imports
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils import get_client_ip
from auth.authenticator import get_authenticator
from auth.session_manager import get_session_manager
from auth.csrf import get_csrf_protection
from auth.captcha import get_captcha_validator


async def login_page_handler(request: web.Request) -> web.Response:
    """Serve login page with CAPTCHA."""
    session_manager = get_session_manager()
    csrf = get_csrf_protection()
    captcha = get_captcha_validator()
    
    # Check if already logged in
    session = session_manager.get_session(request)
    if session:
        return web.HTTPFound('/dashboard')
    
    # Generate CSRF token for login form (no session exists yet)
    csrf_token = secrets.token_urlsafe(32)
    
    captcha_site_key = captcha.get_site_key()
    captcha_enabled = captcha.is_enabled()
    
    # Build HTML with simple string formatting (no f-strings with JS template literals)
    html_parts = []
    html_parts.append("""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WAF Dashboard - Login</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #0f1419 0%, #1e2328 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .login-container {
            background: #1e2328;
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.5);
            width: 100%;
            max-width: 400px;
            border: 1px solid #2d3339;
        }
        h1 {
            color: #ffd700;
            margin-bottom: 10px;
            text-align: center;
        }
        .subtitle {
            color: #a0a0a0;
            text-align: center;
            margin-bottom: 30px;
            font-size: 0.9em;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            color: #e6e1cf;
            margin-bottom: 8px;
            font-size: 0.9em;
            font-weight: 500;
        }
        input[type="text"],
        input[type="password"] {
            width: 100%;
            padding: 12px;
            background: #0f1419;
            border: 1px solid #2d3339;
            border-radius: 6px;
            color: #e6e1cf;
            font-size: 1em;
            transition: border-color 0.3s;
        }
        input:focus {
            outline: none;
            border-color: #ffd700;
        }
        .error {
            background: #ff4444;
            color: white;
            padding: 12px;
            border-radius: 6px;
            margin-bottom: 20px;
            font-size: 0.9em;
            display: none;
        }
        .error.show {
            display: block;
        }
        .captcha-container {
            margin: 20px 0;
            display: flex;
            justify-content: center;
        }
        .btn {
            width: 100%;
            padding: 12px;
            background: #ffd700;
            color: #000;
            border: none;
            border-radius: 6px;
            font-size: 1em;
            font-weight: bold;
            cursor: pointer;
            transition: background 0.3s;
        }
        .btn:hover {
            background: #ffed4e;
        }
        .btn:disabled {
            background: #555;
            cursor: not-allowed;
        }
        .security-note {
            margin-top: 20px;
            padding: 12px;
            background: #2d3339;
            border-radius: 6px;
            font-size: 0.8em;
            color: #a0a0a0;
            text-align: center;
        }
        .footer {
            margin-top: 30px;
            text-align: center;
            color: #666;
            font-size: 0.8em;
        }
    </style>""")
    
    # Add CAPTCHA script if enabled
    if captcha_enabled:
        if captcha.provider == "hcaptcha":
            html_parts.append('<script src="https://js.hcaptcha.com/1/api.js" async defer></script>')
        else:  # reCAPTCHA
            html_parts.append('<script src="https://www.google.com/recaptcha/api.js" async defer></script>')
    
    html_parts.append("""</head>
<body>
    <div class="login-container">
        <h1>🛡️ WAF Dashboard</h1>
        <p class="subtitle">Secure Login</p>
        
        <div class="error" id="errorMsg"></div>
        
        <form id="loginForm" method="POST" action="/auth/login">
            <input type="hidden" name="csrf_token" value='""")
    html_parts.append(csrf_token)
    html_parts.append("""'>
            
            <div class="form-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required autocomplete="username" autofocus>
            </div>
            
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required autocomplete="current-password">
            </div>
            """)
    
    # Add CAPTCHA widget if enabled
    if captcha_enabled:
        html_parts.append('<div class="captcha-container">')
        if captcha.provider == "hcaptcha":
            html_parts.append(f'<div class="h-captcha" data-sitekey="{captcha_site_key}"></div>')
        else:
            html_parts.append(f'<div class="g-recaptcha" data-sitekey="{captcha_site_key}"></div>')
        html_parts.append('</div>')
    
    html_parts.append("""
            <button type="submit" class="btn" id="submitBtn">Login</button>
        </form>
        
        <div class="security-note">
            🔒 Your session is protected with secure cookies and CSRF tokens
        </div>
        
        <div class="footer">
            Default: admin / ChangeMe123!@# (change after first login)
        </div>
    </div>
    
    <script>
        document.getElementById('loginForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const form = e.target;
            const formData = new FormData(form);
            const submitBtn = document.getElementById('submitBtn');
            const errorMsg = document.getElementById('errorMsg');
            """)
    
    # Add CAPTCHA handling JavaScript
    if captcha_enabled:
        if captcha.provider == "hcaptcha":
            html_parts.append("""
            let captchaToken = '';
            if (typeof hcaptcha !== 'undefined') {
                captchaToken = hcaptcha.getResponse();
                if (!captchaToken) {
                    errorMsg.textContent = 'Please complete the CAPTCHA';
                    errorMsg.classList.add('show');
                    return;
                }
                formData.append('captcha_token', captchaToken);
            }""")
        else:  # reCAPTCHA
            html_parts.append("""
            let captchaToken = '';
            if (typeof grecaptcha !== 'undefined') {
                captchaToken = grecaptcha.getResponse();
                if (!captchaToken) {
                    errorMsg.textContent = 'Please complete the CAPTCHA';
                    errorMsg.classList.add('show');
                    return;
                }
                formData.append('captcha_token', captchaToken);
            }""")
    
    html_parts.append("""
            submitBtn.disabled = true;
            submitBtn.textContent = 'Logging in...';
            errorMsg.classList.remove('show');
            
            try {
                const response = await fetch('/auth/login', {
                    method: 'POST',
                    body: formData,
                    credentials: 'include'
                });
                
                if (response.ok) {
                    window.location.href = '/dashboard';
                } else {
                    const error = await response.text();
                    errorMsg.textContent = error || 'Login failed';
                    errorMsg.classList.add('show');
                    submitBtn.disabled = false;
                    submitBtn.textContent = 'Login';
                    """)
    
    if captcha_enabled:
        if captcha.provider == "hcaptcha":
            html_parts.append("if (typeof hcaptcha !== 'undefined') hcaptcha.reset();")
        else:
            html_parts.append("if (typeof grecaptcha !== 'undefined') grecaptcha.reset();")
    
    html_parts.append("""
                }
            } catch (error) {
                errorMsg.textContent = 'Network error. Please try again.';
                errorMsg.classList.add('show');
                submitBtn.disabled = false;
                submitBtn.textContent = 'Login';
            }
        });
    </script>
</body>
</html>""")
    
    html = ''.join(html_parts)
    
    # Set CSRF token in cookie for validation
    response = web.Response(text=html, content_type='text/html')
    response.set_cookie(
        'login_csrf_token',
        csrf_token,
        max_age=600,  # 10 minutes
        httponly=True,
        secure=False,  # Allow HTTP for development (set True for HTTPS)
        samesite='Strict',
        path='/'
    )
    
    return response


async def login_handler(request: web.Request) -> web.Response:
    """Handle login POST request."""
    session_manager = get_session_manager()
    authenticator = get_authenticator()
    csrf = get_csrf_protection()
    captcha = get_captcha_validator()
    client_ip = get_client_ip(request)
    
    # Check if already logged in
    if session_manager.is_authenticated(request):
        return web.HTTPFound('/dashboard')
    
    # Parse form data
    try:
        form_data = await request.post()
        username = form_data.get('username', '').strip()
        password = form_data.get('password', '')
        captcha_token = form_data.get('captcha_token', '')
        csrf_token = form_data.get('csrf_token', '')
    except Exception:
        return web.Response(text="Invalid request", status=400)
    
    # Validate CSRF token from cookie (for login page before session exists)
    login_csrf_token = request.cookies.get('login_csrf_token', '')
    if not csrf_token or not login_csrf_token or csrf_token != login_csrf_token:
        return web.Response(
            text="Invalid CSRF token. Please refresh the page and try again.",
            status=403
        )
    
    # Verify CAPTCHA if enabled
    if captcha.is_enabled():
        is_valid, error = await captcha.verify(captcha_token, client_ip)
        if not is_valid:
            return web.Response(text=error or "CAPTCHA verification failed", status=400)
    
    # Authenticate user
    success, error, user = authenticator.authenticate(username, password, client_ip)
    
    if not success:
        return web.Response(text=error or "Authentication failed", status=401)
    
    # Create session
    session_data = session_manager.create_session(user.username, user.is_admin)
    
    # Create response with redirect
    response = web.HTTPFound('/dashboard')
    session_manager.set_session_cookie(response, session_data)
    
    # Clear login CSRF token cookie (no longer needed)
    response.del_cookie('login_csrf_token', path='/')
    
    return response


async def logout_handler(request: web.Request) -> web.Response:
    """Handle logout request."""
    session_manager = get_session_manager()
    
    response = web.HTTPFound('/login')
    session_manager.clear_session(response)
    
    return response


def require_auth(handler):
    """Decorator to require authentication for handlers."""
    async def wrapped_handler(request: web.Request) -> web.Response:
        session_manager = get_session_manager()
        session = session_manager.require_auth(request)
        
        if not session:
            return web.HTTPFound('/login')
        
        # Add session to request for handler access
        request['session'] = session
        return await handler(request)
    
    return wrapped_handler
