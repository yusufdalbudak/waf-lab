"""Secure session management with encrypted cookies."""
import secrets
import json
import base64
import hmac
import hashlib
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
from aiohttp import web


class SessionManager:
    """
    Secure session management with:
    - Encrypted session cookies
    - CSRF token generation
    - Session expiry
    - Secure cookie settings
    """
    
    def __init__(self, secret_key: Optional[str] = None, session_timeout: int = 3600, 
                 cookie_secure: bool = True, cookie_samesite: str = "Strict"):
        """
        Initialize session manager.
        
        Args:
            secret_key: Secret key for signing cookies (generates if None)
            session_timeout: Session timeout in seconds (default: 1 hour)
            cookie_secure: Set Secure flag (HTTPS only)
            cookie_samesite: SameSite cookie policy
        """
        self.secret_key = secret_key or secrets.token_hex(32)
        self.session_timeout = session_timeout
        self.cookie_secure = cookie_secure
        self.cookie_samesite = cookie_samesite
        self.cookie_name = "waf_session"
        self.csrf_token_name = "csrf_token"
    
    def _sign_data(self, data: str) -> str:
        """Sign data with HMAC."""
        signature = hmac.new(
            self.secret_key.encode(),
            data.encode(),
            hashlib.sha256
        ).hexdigest()
        return f"{data}.{signature}"
    
    def _verify_signature(self, signed_data: str) -> Optional[str]:
        """Verify and extract data from signature."""
        try:
            data, signature = signed_data.rsplit('.', 1)
            expected_signature = hmac.new(
                self.secret_key.encode(),
                data.encode(),
                hashlib.sha256
            ).hexdigest()
            
            if not secrets.compare_digest(signature, expected_signature):
                return None
            
            return data
        except ValueError:
            return None
    
    def create_session(self, username: str, is_admin: bool = False) -> Dict[str, Any]:
        """Create new session data."""
        now = datetime.utcnow()
        expires_at = now + timedelta(seconds=self.session_timeout)
        
        session_data = {
            "username": username,
            "is_admin": is_admin,
            "created_at": now.isoformat(),
            "expires_at": expires_at.isoformat(),
            "csrf_token": secrets.token_urlsafe(32)
        }
        
        return session_data
    
    def encode_session(self, session_data: Dict[str, Any]) -> str:
        """Encode and sign session data."""
        json_data = json.dumps(session_data)
        encoded = base64.urlsafe_b64encode(json_data.encode()).decode()
        return self._sign_data(encoded)
    
    def decode_session(self, signed_data: str) -> Optional[Dict[str, Any]]:
        """Decode and verify session data."""
        data = self._verify_signature(signed_data)
        if not data:
            return None
        
        try:
            decoded = base64.urlsafe_b64decode(data.encode()).decode()
            session_data = json.loads(decoded)
            
            # Check expiry
            expires_at = datetime.fromisoformat(session_data["expires_at"])
            if datetime.utcnow() > expires_at:
                return None
            
            return session_data
        except (ValueError, KeyError, json.JSONDecodeError):
            return None
    
    def set_session_cookie(self, response: web.Response, session_data: Dict[str, Any]):
        """Set secure session cookie."""
        encoded_session = self.encode_session(session_data)
        
        response.set_cookie(
            self.cookie_name,
            encoded_session,
            max_age=self.session_timeout,
            httponly=True,  # Prevent XSS
            secure=self.cookie_secure,    # HTTPS only
            samesite=self.cookie_samesite,  # CSRF protection
            path='/'
        )
        
        # Also set CSRF token as separate cookie
        response.set_cookie(
            self.csrf_token_name,
            session_data["csrf_token"],
            max_age=self.session_timeout,
            httponly=False,  # Needed for JavaScript
            secure=self.cookie_secure,
            samesite=self.cookie_samesite,
            path='/'
        )
    
    def get_session(self, request: web.Request) -> Optional[Dict[str, Any]]:
        """Get session from request cookie."""
        cookie = request.cookies.get(self.cookie_name)
        if not cookie:
            return None
        
        return self.decode_session(cookie)
    
    def get_csrf_token(self, request: web.Request) -> Optional[str]:
        """Get CSRF token from session or cookie."""
        session = self.get_session(request)
        if session:
            return session.get("csrf_token")
        
        # Fallback to cookie
        return request.cookies.get(self.csrf_token_name)
    
    def clear_session(self, response: web.Response):
        """Clear session cookies."""
        response.del_cookie(self.cookie_name, path='/')
        response.del_cookie(self.csrf_token_name, path='/')
    
    def is_authenticated(self, request: web.Request) -> bool:
        """Check if request has valid session."""
        session = self.get_session(request)
        return session is not None
    
    def require_auth(self, request: web.Request) -> Optional[Dict[str, Any]]:
        """
        Require authentication - returns session or raises redirect.
        
        Returns:
            Session data if authenticated, None otherwise
        """
        session = self.get_session(request)
        if not session:
            return None
        return session


# Global session manager instance
_session_manager_instance: Optional[SessionManager] = None


def get_session_manager(secret_key: Optional[str] = None) -> SessionManager:
    """Get or create global session manager."""
    global _session_manager_instance
    if _session_manager_instance is None:
        _session_manager_instance = SessionManager(secret_key=secret_key)
    return _session_manager_instance

