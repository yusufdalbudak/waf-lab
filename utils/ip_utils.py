"""IP address utilities and helpers."""
import ipaddress
from typing import Optional


def get_client_ip(request) -> str:
    """
    Extract client IP from request, handling proxy headers securely.
    
    Security note: We sanitize X-Forwarded-For to prevent header injection
    attacks. Only trust first valid IP in chain.
    
    Args:
        request: aiohttp request object
        
    Returns:
        Client IP address as string
    """
    # Direct connection IP
    direct_ip = request.remote
    
    # Check X-Forwarded-For (from reverse proxy/load balancer)
    x_forwarded_for = request.headers.get("X-Forwarded-For", "")
    
    if x_forwarded_for:
        # X-Forwarded-For can contain multiple IPs: "client, proxy1, proxy2"
        # Only trust the first one (original client)
        first_ip = x_forwarded_for.split(",")[0].strip()
        
        # Validate IP before trusting
        if is_valid_ip(first_ip):
            return first_ip
    
    # Check X-Real-IP (nginx-style)
    x_real_ip = request.headers.get("X-Real-IP", "")
    if x_real_ip and is_valid_ip(x_real_ip):
        return x_real_ip
    
    # Fallback to direct connection IP
    return direct_ip or "unknown"


def is_valid_ip(ip_str: str) -> bool:
    """
    Validate IP address format (IPv4 or IPv6).
    
    Args:
        ip_str: IP address string to validate
        
    Returns:
        True if valid IP, False otherwise
    """
    try:
        ipaddress.ip_address(ip_str)
        return True
    except (ValueError, AttributeError):
        return False


def is_private_ip(ip_str: str) -> bool:
    """
    Check if IP is in private/reserved range.
    
    Args:
        ip_str: IP address string
        
    Returns:
        True if private/reserved IP
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except (ValueError, AttributeError):
        return False

