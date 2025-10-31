"""User authentication with password hashing and security policies."""
import hashlib
import secrets
import time
from typing import Optional, Dict, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass


@dataclass
class User:
    """User account model."""
    username: str
    password_hash: str
    salt: str
    created_at: datetime
    last_login: Optional[datetime] = None
    failed_login_attempts: int = 0
    locked_until: Optional[datetime] = None
    is_admin: bool = False


class Authenticator:
    """
    Secure authentication system with:
    - PBKDF2 password hashing
    - Account lockout after failed attempts
    - Login rate limiting
    - Session management
    - Security best practices
    """
    
    def __init__(self):
        """Initialize authenticator."""
        self.users: Dict[str, User] = {}
        self.login_attempts: Dict[str, list] = {}  # IP -> [timestamps]
        self.max_failed_attempts = 5
        self.lockout_duration = timedelta(minutes=15)
        self.login_window = timedelta(minutes=5)
        self.max_login_attempts_per_window = 3
        
        # Password requirements
        self.min_password_length = 12
        self.require_uppercase = True
        self.require_lowercase = True
        self.require_numbers = True
        self.require_special = True
        
        # Create default admin user (password should be changed!)
        self._create_default_admin()
    
    def _create_default_admin(self):
        """Create default admin user."""
        # Default: admin / ChangeMe123!@#
        password_hash, salt = self._hash_password("ChangeMe123!@#")
        self.users["admin"] = User(
            username="admin",
            password_hash=password_hash,
            salt=salt,
            created_at=datetime.utcnow(),
            is_admin=True
        )
    
    def _hash_password(self, password: str, salt: Optional[str] = None) -> Tuple[str, str]:
        """
        Hash password using PBKDF2 with SHA-256.
        
        Args:
            password: Plain text password
            salt: Optional salt (generates new if None)
            
        Returns:
            Tuple of (hash, salt)
        """
        if salt is None:
            salt = secrets.token_hex(32)
        
        # Use PBKDF2 for password hashing
        key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt.encode('utf-8'),
            100000  # 100k iterations (adjust based on performance needs)
        )
        password_hash = key.hex()
        
        return password_hash, salt
    
    def _verify_password(self, password: str, password_hash: str, salt: str) -> bool:
        """Verify password against hash."""
        hash_to_check, _ = self._hash_password(password, salt)
        return secrets.compare_digest(hash_to_check, password_hash)
    
    def validate_password_strength(self, password: str) -> Tuple[bool, Optional[str]]:
        """
        Validate password meets security requirements.
        
        Returns:
            Tuple of (is_valid, error_message)
        """
        if len(password) < self.min_password_length:
            return False, f"Password must be at least {self.min_password_length} characters"
        
        if self.require_uppercase and not any(c.isupper() for c in password):
            return False, "Password must contain at least one uppercase letter"
        
        if self.require_lowercase and not any(c.islower() for c in password):
            return False, "Password must contain at least one lowercase letter"
        
        if self.require_numbers and not any(c.isdigit() for c in password):
            return False, "Password must contain at least one number"
        
        if self.require_special and not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            return False, "Password must contain at least one special character"
        
        return True, None
    
    def create_user(self, username: str, password: str, is_admin: bool = False) -> Tuple[bool, Optional[str]]:
        """
        Create a new user account.
        
        Returns:
            Tuple of (success, error_message)
        """
        if username in self.users:
            return False, "Username already exists"
        
        # Validate password strength
        is_valid, error = self.validate_password_strength(password)
        if not is_valid:
            return False, error
        
        # Hash password
        password_hash, salt = self._hash_password(password)
        
        # Create user
        self.users[username] = User(
            username=username,
            password_hash=password_hash,
            salt=salt,
            created_at=datetime.utcnow(),
            is_admin=is_admin
        )
        
        return True, None
    
    def check_rate_limit(self, ip_address: str) -> Tuple[bool, Optional[str]]:
        """
        Check if IP has exceeded login rate limits.
        
        Returns:
            Tuple of (allowed, error_message)
        """
        now = datetime.utcnow()
        
        # Clean old attempts
        if ip_address in self.login_attempts:
            self.login_attempts[ip_address] = [
                attempt for attempt in self.login_attempts[ip_address]
                if now - attempt < self.login_window
            ]
        
        # Check rate limit
        if ip_address in self.login_attempts:
            attempts = self.login_attempts[ip_address]
            if len(attempts) >= self.max_login_attempts_per_window:
                return False, "Too many login attempts. Please try again later."
        
        return True, None
    
    def authenticate(self, username: str, password: str, ip_address: str) -> Tuple[bool, Optional[str], Optional[User]]:
        """
        Authenticate user credentials.
        
        Returns:
            Tuple of (success, error_message, user_object)
        """
        # Check rate limit
        allowed, error = self.check_rate_limit(ip_address)
        if not allowed:
            return False, error, None
        
        # Record login attempt
        if ip_address not in self.login_attempts:
            self.login_attempts[ip_address] = []
        self.login_attempts[ip_address].append(datetime.utcnow())
        
        # Check if user exists
        if username not in self.users:
            return False, "Invalid username or password", None
        
        user = self.users[username]
        
        # Check if account is locked
        if user.locked_until and datetime.utcnow() < user.locked_until:
            remaining = (user.locked_until - datetime.utcnow()).total_seconds() / 60
            return False, f"Account locked. Try again in {remaining:.0f} minutes.", None
        
        # Verify password
        if not self._verify_password(password, user.password_hash, user.salt):
            user.failed_login_attempts += 1
            
            # Lock account after max failed attempts
            if user.failed_login_attempts >= self.max_failed_attempts:
                user.locked_until = datetime.utcnow() + self.lockout_duration
                return False, "Account locked due to too many failed attempts.", None
            
            remaining = self.max_failed_attempts - user.failed_login_attempts
            return False, f"Invalid username or password. {remaining} attempts remaining.", None
        
        # Successful login - reset counters
        user.failed_login_attempts = 0
        user.locked_until = None
        user.last_login = datetime.utcnow()
        
        # Remove successful attempt from rate limit tracking
        if ip_address in self.login_attempts:
            self.login_attempts[ip_address] = []
        
        return True, None, user
    
    def change_password(self, username: str, old_password: str, new_password: str) -> Tuple[bool, Optional[str]]:
        """Change user password."""
        if username not in self.users:
            return False, "User not found"
        
        user = self.users[username]
        
        # Verify old password
        if not self._verify_password(old_password, user.password_hash, user.salt):
            return False, "Current password is incorrect"
        
        # Validate new password strength
        is_valid, error = self.validate_password_strength(new_password)
        if not is_valid:
            return False, error
        
        # Hash and update password
        password_hash, salt = self._hash_password(new_password)
        user.password_hash = password_hash
        user.salt = salt
        
        return True, None
    
    def get_user(self, username: str) -> Optional[User]:
        """Get user by username."""
        return self.users.get(username)


# Global authenticator instance
_authenticator_instance: Optional[Authenticator] = None


def get_authenticator() -> Authenticator:
    """Get or create global authenticator instance."""
    global _authenticator_instance
    if _authenticator_instance is None:
        _authenticator_instance = Authenticator()
    return _authenticator_instance

