"""CAPTCHA integration for login protection."""
import aiohttp
from typing import Optional, Dict, Tuple
import os


class CAPTCHAValidator:
    """
    CAPTCHA validation support.
    Supports hCaptcha and reCAPTCHA v2/v3.
    """
    
    def __init__(self, provider: str = "hcaptcha", site_key: Optional[str] = None, secret_key: Optional[str] = None):
        """
        Initialize CAPTCHA validator.
        
        Args:
            provider: "hcaptcha" or "recaptcha"
            site_key: CAPTCHA site key (from environment or config)
            secret_key: CAPTCHA secret key (from environment or config)
        """
        self.provider = provider.lower()
        
        if provider == "hcaptcha":
            self.site_key = site_key or os.getenv("HCAPTCHA_SITE_KEY", "")
            self.secret_key = secret_key or os.getenv("HCAPTCHA_SECRET_KEY", "")
            self.verify_url = "https://hcaptcha.com/siteverify"
        elif provider == "recaptcha":
            self.site_key = site_key or os.getenv("RECAPTCHA_SITE_KEY", "")
            self.secret_key = secret_key or os.getenv("RECAPTCHA_SECRET_KEY", "")
            self.verify_url = "https://www.google.com/recaptcha/api/siteverify"
        else:
            raise ValueError(f"Unknown CAPTCHA provider: {provider}")
    
    async def verify(self, captcha_token: str, remote_ip: Optional[str] = None) -> Tuple[bool, Optional[str]]:
        """
        Verify CAPTCHA token.
        
        Args:
            captcha_token: Token from client
            remote_ip: Client IP address (recommended)
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not self.secret_key:
            # CAPTCHA not configured - allow (for development)
            return True, None
        
        if not captcha_token:
            return False, "CAPTCHA token is required"
        
        try:
            async with aiohttp.ClientSession() as session:
                data = {
                    "secret": self.secret_key,
                    "response": captcha_token
                }
                
                if remote_ip:
                    data["remoteip"] = remote_ip
                
                async with session.post(self.verify_url, data=data) as resp:
                    result = await resp.json()
                    
                    if self.provider == "hcaptcha":
                        success = result.get("success", False)
                        error_codes = result.get("error-codes", [])
                    else:  # reCAPTCHA
                        success = result.get("success", False)
                        error_codes = result.get("error-codes", [])
                    
                    if success:
                        return True, None
                    else:
                        error_msg = ", ".join(error_codes) if error_codes else "CAPTCHA verification failed"
                        return False, error_msg
                        
        except Exception as e:
            return False, f"CAPTCHA verification error: {str(e)}"
    
    def get_site_key(self) -> str:
        """Get CAPTCHA site key for client-side integration."""
        return self.site_key
    
    def is_enabled(self) -> bool:
        """Check if CAPTCHA is configured."""
        return bool(self.site_key and self.secret_key)


# Global CAPTCHA validator instance
_captcha_validator_instance: Optional[CAPTCHAValidator] = None


def get_captcha_validator(provider: str = "hcaptcha") -> CAPTCHAValidator:
    """Get or create global CAPTCHA validator."""
    global _captcha_validator_instance
    if _captcha_validator_instance is None:
        _captcha_validator_instance = CAPTCHAValidator(provider=provider)
    return _captcha_validator_instance

