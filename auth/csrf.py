"""CSRF protection utilities."""
from typing import Optional
from aiohttp import web
from .session_manager import get_session_manager


class CSRFProtection:
    """CSRF token validation."""
    
    def __init__(self, session_manager=None):
        """Initialize CSRF protection."""
        self.session_manager = session_manager or get_session_manager()
    
    def validate_token(self, request: web.Request, token: Optional[str] = None) -> bool:
        """
        Validate CSRF token from request.
        
        Args:
            request: aiohttp request
            token: Token from form/header (extracts from form if None)
            
        Returns:
            True if valid, False otherwise
        """
        # Get expected token from session
        expected_token = self.session_manager.get_csrf_token(request)
        if not expected_token:
            return False
        
        # Get token from request
        if token is None:
            # Try form data first
            if request.content_type == 'application/x-www-form-urlencoded':
                # Would need to read body - handled in handlers
                token = None
            # Try header
            token = request.headers.get('X-CSRF-Token')
            # Try query parameter (less secure, for GET requests)
            if not token:
                token = request.query.get('csrf_token')
        
        if not token:
            return False
        
        # Constant-time comparison
        import secrets
        return secrets.compare_digest(token, expected_token)
    
    def get_token(self, request: web.Request) -> Optional[str]:
        """Get CSRF token for current session."""
        return self.session_manager.get_csrf_token(request)


# Global CSRF protection instance
_csrf_protection_instance: Optional[CSRFProtection] = None


def get_csrf_protection() -> CSRFProtection:
    """Get or create global CSRF protection."""
    global _csrf_protection_instance
    if _csrf_protection_instance is None:
        _csrf_protection_instance = CSRFProtection()
    return _csrf_protection_instance

