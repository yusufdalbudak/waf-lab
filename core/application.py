"""Main WAF application orchestrating all components."""
import time
import asyncio
from typing import Optional
from aiohttp import web

from config import load_config
from logger import get_logger
from inspector import RuleEngine
from router import ReverseProxy, create_proxy_handler
from utils import RateLimiter, get_client_ip
from metrics import get_metrics_collector
from core.traffic_store import get_traffic_store, TrafficEntry


class WAFApplication:
    """
    Main WAF application orchestrating:
    - Request inspection (rule engine)
    - Rate limiting
    - Reverse proxying
    - Metrics collection
    - Structured logging
    
    Implements full request lifecycle with async performance optimization.
    """
    
    def __init__(self, config_path: str = "rules.json"):
        """Initialize WAF application with all components."""
        # Load configuration
        self.config = load_config(config_path)
        
        # Initialize core components
        self.logger = get_logger(self.config)
        self.rule_engine = RuleEngine(self.config)
        self.rate_limiter = RateLimiter(
            requests_per_minute=self.config.rate_limit.requests_per_minute,
            burst_size=self.config.rate_limit.burst_size,
            window_seconds=self.config.rate_limit.window_seconds
        )
        self.metrics = get_metrics_collector()
        self.proxy = ReverseProxy(self.config, self.logger, self.metrics)
        self.traffic_store = get_traffic_store()
        
        # Create aiohttp application
        self.app = web.Application()
        self._setup_routes()
        
        # Background tasks
        self._background_tasks = []
    
    def _setup_routes(self):
        """Setup application routes."""
        # Main request handler (catches all paths)
        self.app.router.add_route('*', '/{tail:.*}', self.handle_request)
        
        # Health check endpoint
        self.app.router.add_get('/health', self.health_check)
        
        # Prometheus metrics endpoint
        if self.config.metrics.enabled:
            self.app.router.add_get(self.config.metrics.endpoint, self.metrics_endpoint)
        
        # PRTG sensor endpoint
        self.app.router.add_get('/prtg', self.prtg_sensor)
        
        # Dashboard endpoints
        from core.dashboard_handlers import dashboard_ui_handler, dashboard_stats_handler, dashboard_traffic_handler
        self.app.router.add_get('/dashboard', dashboard_ui_handler)
        self.app.router.add_get('/api/dashboard/stats', dashboard_stats_handler)
        self.app.router.add_get('/api/dashboard/traffic', dashboard_traffic_handler)
    
    async def handle_request(self, request: web.Request) -> web.Response:
        """
        Main request handler implementing WAF pipeline:
        1. Extract client IP
        2. Rate limiting check
        3. Request inspection (rule engine)
        4. Decision: block or proxy
        5. Logging and metrics
        
        Args:
            request: aiohttp request object
            
        Returns:
            web.Response with block page or proxied response
        """
        start_time = time.time()
        client_ip = get_client_ip(request)
        method = request.method
        path = str(request.rel_url)
        user_agent = request.headers.get("User-Agent", "")
        
        # Track active connections
        self.metrics.increment_connections()
        
        try:
            # Step 1: Rate limiting check
            rate_limit_allowed, rate_limit_meta = self.rate_limiter.check_rate_limit(client_ip)
            
            if not rate_limit_allowed:
                # Rate limit exceeded
                self.metrics.record_rate_limit(client_ip)
                self.metrics.record_block(
                    reason="rate_limit",
                    threat_category="rate_limit"
                )
                
                duration = time.time() - start_time
                await self.logger.log_rate_limit(
                    client_ip=client_ip,
                    path=path,
                    limit=rate_limit_meta["limit"],
                    window=rate_limit_meta["window"]
                )
                
                self.metrics.record_request(
                    decision="block",
                    method=method,
                    status_code=429,
                    duration_seconds=duration
                )
                
                # Store in traffic store for dashboard
                self.traffic_store.add_entry(TrafficEntry(
                    timestamp=time.time(),
                    method=method,
                    path=path,
                    client_ip=client_ip,
                    user_agent=user_agent,
                    decision="block",
                    reason="rate_limit",
                    score=0.0,
                    threat_category="rate_limit",
                    status_code=429,
                    response_time_ms=duration * 1000,
                    bytes_sent=0
                ))
                
                return web.Response(
                    status=429,
                    text="Too Many Requests: Rate limit exceeded",
                    headers={
                        "X-RateLimit-Limit": str(rate_limit_meta["limit"]),
                        "X-RateLimit-Remaining": str(int(rate_limit_meta["remaining_tokens"])),
                        "X-RateLimit-Reset": str(int(rate_limit_meta["reset_seconds"])),
                        "Retry-After": str(int(rate_limit_meta["reset_seconds"]))
                    }
                )
            
            # Step 2: Read request body (for inspection)
            try:
                body_text = await request.text()
            except Exception:
                body_text = ""
            
            # Step 3: Request inspection (rule engine)
            inspection_result = await self.rule_engine.inspect(
                request=request,
                body=body_text,
                headers=dict(request.headers)
            )
            
            # Step 4: Decision - block or allow
            if inspection_result.decision != "allow":
                # Block request
                self.metrics.record_block(
                    reason=inspection_result.reason,
                    threat_category=inspection_result.threat_category.value if inspection_result.threat_category else None,
                    rule_id=inspection_result.matched_rules[0] if inspection_result.matched_rules else None
                )
                
                duration = time.time() - start_time
                await self.logger.log_block(
                    method=method,
                    path=path,
                    client_ip=client_ip,
                    reason=inspection_result.reason,
                    score=inspection_result.score,
                    threat_category=inspection_result.threat_category.value if inspection_result.threat_category else None
                )
                
                self.metrics.record_request(
                    decision="block",
                    method=method,
                    status_code=403,
                    duration_seconds=duration,
                    anomaly_score=inspection_result.score
                )
                
                # Store in traffic store for dashboard
                self.traffic_store.add_entry(TrafficEntry(
                    timestamp=time.time(),
                    method=method,
                    path=path,
                    client_ip=client_ip,
                    user_agent=user_agent,
                    decision="block",
                    reason=inspection_result.reason,
                    score=inspection_result.score,
                    threat_category=inspection_result.threat_category.value if inspection_result.threat_category else None,
                    status_code=403,
                    response_time_ms=duration * 1000,
                    bytes_sent=0
                ))
                
                return web.Response(
                    status=403,
                    text=f"Forbidden: {inspection_result.reason}",
                    headers={
                        "X-WAF-Reason": inspection_result.reason,
                        "X-WAF-Score": str(inspection_result.score)
                    }
                )
            
            # Step 5: Proxy to backend (request allowed)
            response = await self.proxy.proxy_request(
                request=request,
                backend_url=self.config.backend.url,
                path=path,
                body=body_text.encode() if body_text else b""
            )
            
            # Log allowed request
            duration = time.time() - start_time
            bytes_sent = len(response.body) if hasattr(response, 'body') and response.body else 0
            
            await self.logger.log_request(
                method=method,
                path=path,
                client_ip=client_ip,
                user_agent=user_agent,
                decision="allow",
                reason="ok",
                score=inspection_result.score,
                response_time_ms=duration * 1000,
                bytes_sent=bytes_sent,
                threat_category=inspection_result.threat_category.value if inspection_result.threat_category else None
            )
            
            # Store in traffic store for dashboard
            self.traffic_store.add_entry(TrafficEntry(
                timestamp=time.time(),
                method=method,
                path=path,
                client_ip=client_ip,
                user_agent=user_agent,
                decision="allow",
                reason="ok",
                score=inspection_result.score,
                threat_category=inspection_result.threat_category.value if inspection_result.threat_category else None,
                status_code=response.status,
                response_time_ms=duration * 1000,
                bytes_sent=bytes_sent
            ))
            
            return response
            
        except Exception as e:
            # Unexpected error - log and return 500
            duration = time.time() - start_time
            await self.logger._log(
                level="ERROR",
                event_type="request_error",
                message=f"Unexpected error processing request: {str(e)}",
                method=method,
                path=path,
                client_ip=client_ip,
                error=str(e),
                duration_seconds=duration
            )
            
            return web.Response(
                status=500,
                text="Internal Server Error",
                headers={"Content-Type": "text/plain"}
            )
        
        finally:
            # Always decrement connection counter
            self.metrics.decrement_connections()
    
    async def health_check(self, request: web.Request) -> web.Response:
        """Health check endpoint for orchestration (Kubernetes, Docker, etc.)."""
        return web.json_response({
            "status": "healthy",
            "service": "waf",
            "version": "1.0.0"
        })
    
    async def metrics_endpoint(self, request: web.Request) -> web.Response:
        """Prometheus metrics scraping endpoint."""
        try:
            output = self.metrics.get_metrics_output()
            response = web.Response(
                body=output,
                content_type="text/plain; version=0.0.4"
            )
            response.headers['Content-Type'] = 'text/plain; version=0.0.4; charset=utf-8'
            return response
        except Exception as e:
            await self.logger._log(
                level="ERROR",
                event_type="metrics_error",
                message=f"Error generating metrics: {str(e)}"
            )
            return web.Response(
                status=500,
                text=f"Error generating metrics: {str(e)}",
                content_type="text/plain"
            )
    
    async def prtg_sensor(self, request: web.Request) -> web.Response:
        """PRTG custom sensor XML endpoint."""
        xml = self.metrics.get_prtg_xml()
        return web.Response(
            body=xml,
            content_type="application/xml"
        )
    
    async def startup(self, app: web.Application):
        """Application startup hook."""
        await self.logger._log(
            level="INFO",
            event_type="startup",
            message="WAF application starting",
            config={
                "backend": self.config.backend.url,
                "rate_limit_rpm": self.config.rate_limit.requests_per_minute,
                "anomaly_threshold": self.config.security.anomaly_threshold
            }
        )
        
        # Start background cleanup tasks
        task = asyncio.create_task(self._background_cleanup())
        self._background_tasks.append(task)
    
    async def shutdown(self, app: web.Application):
        """Application shutdown hook."""
        await self.logger._log(
            level="INFO",
            event_type="shutdown",
            message="WAF application shutting down"
        )
        
        # Cancel background tasks
        for task in self._background_tasks:
            task.cancel()
        
        # Cleanup resources
        await self.proxy.close()
        await self.logger.close()
    
    async def _background_cleanup(self):
        """Background task for periodic cleanup (rate limiter buckets)."""
        while True:
            try:
                await asyncio.sleep(300)  # Every 5 minutes
                self.rate_limiter.cleanup_old_buckets()
            except asyncio.CancelledError:
                break
            except Exception as e:
                await self.logger._log(
                    level="ERROR",
                    event_type="cleanup_error",
                    message=f"Background cleanup error: {str(e)}"
                )


def create_app(config_path: str = "rules.json") -> web.Application:
    """
    Factory function to create WAF application.
    
    Args:
        config_path: Path to configuration file
        
    Returns:
        Configured aiohttp Application instance
    """
    waf_app = WAFApplication(config_path)
    app = waf_app.app
    
    # Register startup/shutdown hooks
    app.on_startup.append(waf_app.startup)
    app.on_shutdown.append(waf_app.shutdown)
    
    # Store WAF instance in app for access in handlers
    app["waf"] = waf_app
    
    return app

