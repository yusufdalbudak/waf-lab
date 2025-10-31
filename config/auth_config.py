"""Authentication configuration."""
import os
from dataclasses import dataclass


@dataclass
class AuthConfig:
    """Authentication system configuration."""
    # CAPTCHA settings
    captcha_provider: str = os.getenv("CAPTCHA_PROVIDER", "hcaptcha")  # hcaptcha or recaptcha
    captcha_site_key: str = os.getenv("HCAPTCHA_SITE_KEY", os.getenv("RECAPTCHA_SITE_KEY", ""))
    captcha_secret_key: str = os.getenv("HCAPTCHA_SECRET_KEY", os.getenv("RECAPTCHA_SECRET_KEY", ""))
    
    # Session settings
    session_secret: str = os.getenv("WAF_SESSION_SECRET", "")
    session_timeout: int = int(os.getenv("WAF_SESSION_TIMEOUT", "3600"))  # 1 hour
    
    # Security settings
    cookie_secure: bool = os.getenv("WAF_COOKIE_SECURE", "true").lower() == "true"
    cookie_samesite: str = os.getenv("WAF_COOKIE_SAMESITE", "Strict")  # Strict, Lax, None
    
    # Password policy
    min_password_length: int = 12
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_numbers: bool = True
    require_special: bool = True
    
    # Account lockout
    max_failed_attempts: int = 5
    lockout_duration_minutes: int = 15
    
    # Rate limiting
    max_login_attempts_per_window: int = 3
    login_window_minutes: int = 5

