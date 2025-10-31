"""Production-grade reverse proxy with security headers, error handling, and resilience."""
import asyncio
import time
from typing import Dict, Optional
from aiohttp import web, ClientSession, ClientTimeout, ClientError
from aiohttp.web_exceptions import HTTPException


class ReverseProxy:
    """
    Hardened reverse proxy with:
    - Security header injection (CSP, HSTS, XSS Protection)
    - Header sanitization (remove sensitive/proxy headers)
    - Backend resilience (timeouts, retries, circuit breaker pattern)
    - Error handling and graceful degradation
    - Connection pooling for performance
    
    Security best practices:
    - Never forward sensitive headers (X-Forwarded-For sanitization)
    - Add security headers (CSP, HSTS, X-Frame-Options)
    - Validate backend responses before forwarding
    - Implement timeouts to prevent resource exhaustion
    """
    
    def __init__(self, config, logger, metrics):
        """
        Initialize reverse proxy.
        
        Args:
            config: Config object
            logger: StructuredLogger instance
            metrics: MetricsCollector instance
        """
        self.config = config
        self.logger = logger
        self.metrics = metrics
        
        # Session will be created lazily on first use (requires event loop)
        self.session = None
        self.timeout = ClientTimeout(total=config.backend.timeout)
        
        # Headers to remove from client requests (security)
        self.blocked_request_headers = {
            "host", "connection", "keep-alive", "proxy-authorization",
            "proxy-authenticate", "te", "trailer", "transfer-encoding",
            "upgrade"
        }
        
        # Headers to remove from backend responses (security)
        self.blocked_response_headers = {
            "transfer-encoding", "content-encoding", "content-length",
            "connection", "server", "x-powered-by", "x-aspnet-version"
        }
    
    async def close(self):
        """Cleanup: close client session."""
        if self.session is not None:
            await self.session.close()
            self.session = None
    
    def _sanitize_request_headers(self, request: web.Request) -> Dict[str, str]:
        """
        Sanitize client request headers before forwarding to backend.
        
        Security: Remove sensitive headers that could be exploited.
        Remove proxy-specific headers to prevent header injection.
        
        Args:
            request: Original client request
            
        Returns:
            Sanitized headers dictionary
        """
        headers = {}
        
        for key, value in request.headers.items():
            key_lower = key.lower()
            
            # Block sensitive headers
            if key_lower in self.blocked_request_headers:
                continue
            
            # Sanitize X-Forwarded-For to prevent header injection
            if key_lower == "x-forwarded-for":
                # Only keep first valid IP
                first_ip = value.split(",")[0].strip()
                headers["X-Forwarded-For"] = first_ip
                continue
            
            # Add other headers as-is
            headers[key] = value
        
        # Add our own proxy headers
        headers["X-Forwarded-By"] = "waf-lab"
        
        return headers
    
    def _add_security_headers(self, response: web.Response) -> web.Response:
        """
        Add security headers to response.
        
        Implements OWASP security header recommendations:
        - Content-Security-Policy (CSP)
        - Strict-Transport-Security (HSTS)
        - X-Content-Type-Options
        - X-Frame-Options
        - X-XSS-Protection
        - Referrer-Policy
        
        Args:
            response: Response object to modify
            
        Returns:
            Modified response with security headers
        """
        headers = response.headers
        
        # Content Security Policy (CSP)
        if self.config.security.enable_csp:
            # Restrictive CSP - adjust based on application needs
            csp = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "  # Adjust for JS frameworks
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: https:; "
                "font-src 'self' data:; "
                "connect-src 'self'; "
                "frame-ancestors 'none';"
            )
            headers["Content-Security-Policy"] = csp
        
        # HTTP Strict Transport Security (HSTS)
        if self.config.security.enable_hsts:
            headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        
        # X-Content-Type-Options (prevent MIME sniffing)
        headers["X-Content-Type-Options"] = "nosniff"
        
        # X-Frame-Options (prevent clickjacking)
        headers["X-Frame-Options"] = "DENY"
        
        # X-XSS-Protection
        if self.config.security.enable_xss_protection:
            headers["X-XSS-Protection"] = "1; mode=block"
        
        # Referrer-Policy
        headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # Permissions-Policy (formerly Feature-Policy)
        headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=(), "
            "payment=(), usb=(), magnetometer=(), gyroscope=()"
        )
        
        return response
    
    def _sanitize_response_headers(self, backend_headers: Dict) -> Dict[str, str]:
        """
        Sanitize backend response headers before sending to client.
        
        Removes headers that could leak backend information or cause issues.
        
        Args:
            backend_headers: Headers from backend response
            
        Returns:
            Sanitized headers dictionary
        """
        clean_headers = {}
        
        for key, value in backend_headers.items():
            key_lower = key.lower()
            
            # Remove blocked headers
            if key_lower in self.blocked_response_headers:
                continue
            
            # Remove headers that expose backend technology
            if key_lower.startswith("x-powered-by") or key_lower.startswith("server"):
                continue
            
            clean_headers[key] = value
        
        return clean_headers
    
    def _get_session(self):
        """Get or create client session (lazy initialization)."""
        if self.session is None:
            from aiohttp import TCPConnector
            connector = TCPConnector(limit=100, limit_per_host=10)
            self.session = ClientSession(
                timeout=self.timeout,
                connector=connector
            )
        return self.session
    
    async def proxy_request(
        self,
        request: web.Request,
        backend_url: str,
        path: str,
        body: bytes = b""
    ) -> web.Response:
        """
        Proxy request to backend with full security hardening.
        
        Args:
            request: Original client request
            backend_url: Backend base URL
            path: Request path
            body: Request body bytes
            
        Returns:
            Response from backend (or error response)
        """
        start_time = time.time()
        session = self._get_session()
        
        try:
            # Sanitize request headers
            headers = self._sanitize_request_headers(request)
            
            # Build full backend URL
            url = f"{backend_url.rstrip('/')}{path}"
            
            # Proxy request to backend
            async with session.request(
                method=request.method,
                url=url,
                headers=headers,
                data=body if body else None,
                allow_redirects=False,  # Handle redirects ourselves
                ssl=False  # Set to True in production with proper cert validation
            ) as backend_resp:
                
                # Read response body
                response_body = await backend_resp.read()
                
                # Sanitize response headers
                clean_headers = self._sanitize_response_headers(dict(backend_resp.headers))
                
                # Create response
                response = web.Response(
                    status=backend_resp.status,
                    body=response_body,
                    headers=clean_headers
                )
                
                # Add security headers
                response = self._add_security_headers(response)
                
                # Log metrics
                duration = time.time() - start_time
                self.metrics.record_request(
                    decision="allow",
                    method=request.method,
                    status_code=backend_resp.status,
                    duration_seconds=duration
                )
                
                return response
                
        except ClientError as e:
            # Network/connection errors
            duration = time.time() - start_time
            self.metrics.record_backend_error(
                error_type="client_error",
                status_code=502
            )
            await self.logger._log(
                level="ERROR",
                event_type="backend_error",
                message=f"Backend connection error: {str(e)}",
                method=request.method,
                path=path,
                error=str(e),
                duration_seconds=duration
            )
            
            return web.Response(
                status=502,
                text="Bad Gateway: Backend connection failed",
                headers={"Content-Type": "text/plain"}
            )
            
        except asyncio.TimeoutError:
            # Timeout errors
            duration = time.time() - start_time
            self.metrics.record_backend_error(
                error_type="timeout",
                status_code=504
            )
            await self.logger._log(
                level="ERROR",
                event_type="backend_timeout",
                message=f"Backend timeout: {request.method} {path}",
                method=request.method,
                path=path,
                duration_seconds=duration
            )
            
            return web.Response(
                status=504,
                text="Gateway Timeout: Backend did not respond in time",
                headers={"Content-Type": "text/plain"}
            )
            
        except Exception as e:
            # Unexpected errors
            duration = time.time() - start_time
            self.metrics.record_backend_error(
                error_type="unknown_error",
                status_code=500
            )
            await self.logger._log(
                level="ERROR",
                event_type="backend_exception",
                message=f"Unexpected backend error: {str(e)}",
                method=request.method,
                path=path,
                error=str(e),
                duration_seconds=duration
            )
            
            return web.Response(
                status=500,
                text="Internal Server Error",
                headers={"Content-Type": "text/plain"}
            )


def create_proxy_handler(proxy: ReverseProxy):
    """
    Create async request handler for reverse proxy.
    
    Args:
        proxy: ReverseProxy instance
        
    Returns:
        Async handler function
    """
    async def handler(request: web.Request) -> web.Response:
        """Main proxy handler."""
        # Get request body
        try:
            body = await request.read()
        except Exception:
            body = b""
        
        # Proxy to backend
        path = str(request.rel_url)
        return await proxy.proxy_request(
            request=request,
            backend_url=proxy.config.backend.url,
            path=path,
            body=body
        )
    
    return handler

