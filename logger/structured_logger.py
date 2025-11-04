"""Asynchronous structured logger with JSON output for ELK/Loki integration."""
import json
import logging
import aiofiles
import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any, Optional, List
from queue import Queue, Empty
from threading import Thread


class AsyncLogWriter:
    """
    Asynchronous log writer using background thread + queue.
    
    This prevents blocking the event loop while writing logs to disk.
    Uses aiofiles for true async I/O when possible, with fallback to thread-based queue.
    """
    
    def __init__(self, log_file: str):
        self.log_file = log_file
        self.queue: Queue = Queue()
        self.running = True
        
        # Ensure log directory exists
        try:
            Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        except (OSError, PermissionError):
            # If we can't create the directory, log to current directory instead
            self.log_file = Path(".") / Path(log_file).name
        
        # Start background writer thread
        self.writer_thread = Thread(target=self._write_loop, daemon=True)
        self.writer_thread.start()
    
    def _write_loop(self):
        """Background thread that writes log entries from queue."""
        while self.running:
            try:
                entry = self.queue.get(timeout=1.0)
                if entry is None:  # Poison pill
                    self.queue.task_done()  # Only call task_done() for poison pill
                    break
                    
                try:
                    with open(self.log_file, "a") as f:
                        f.write(json.dumps(entry, ensure_ascii=False) + "\n")
                        f.flush()  # Ensure immediate disk write
                except Exception as e:
                    # Log errors to stderr to avoid recursion
                    print(f"Log writer error: {e}", file=__import__("sys").stderr)
                finally:
                    # Only call task_done() when we successfully retrieved an item
                    self.queue.task_done()
            except Empty:
                # Queue.get() timeout - no item retrieved, don't call task_done()
                # This is expected when queue is empty, just continue
                pass
            except Exception as e:
                # Other errors - log but don't crash
                print(f"Log writer unexpected error: {e}", file=__import__("sys").stderr)
    
    async def write(self, entry: Dict[str, Any]):
        """
        Queue log entry for async write (non-blocking).
        
        Args:
            entry: Dictionary to be JSON-serialized and written
        """
        entry["@timestamp"] = datetime.now(timezone.utc).isoformat()
        self.queue.put(entry)
    
    def close(self):
        """Gracefully shutdown log writer."""
        self.running = False
        self.queue.put(None)  # Poison pill
        self.writer_thread.join(timeout=2.0)


class StructuredLogger:
    """
    Production-grade structured logger for WAF audit trails.
    
    Features:
    - JSON-formatted logs compatible with ELK Stack (Elasticsearch, Logstash, Kibana)
    - Loki-compatible format for Grafana integration
    - Non-blocking async writes
    - Structured fields for efficient querying
    - Security event classification
    
    Log entry schema:
    {
        "@timestamp": "ISO8601",
        "level": "INFO|WARNING|ERROR|CRITICAL",
        "service": "waf",
        "event_type": "request|block|anomaly|rate_limit",
        "method": "GET|POST|...",
        "path": "/api/endpoint",
        "client_ip": "1.2.3.4",
        "user_agent": "...",
        "decision": "allow|block|challenge",
        "reason": "rule:SQLi-1|rate_limit|anomaly",
        "score": 0.0-100.0,
        "response_time_ms": 123.45,
        "bytes_sent": 1024,
        "threat_category": "sql_injection|xss|rce|..."
    }
    """
    
    def __init__(
        self,
        log_file: str = "/app/logs/waf.log",
        log_level: str = "INFO",
        enable_console: bool = True,
        json_format: bool = True
    ):
        self.log_file = log_file
        self.json_format = json_format
        self.enable_console = enable_console
        
        # Map string level to logging constant
        self.log_level = getattr(logging, log_level.upper(), logging.INFO)
        
        # Initialize async writer
        self.writer = AsyncLogWriter(log_file)
        
        # Python logging for console output
        self.console_logger = logging.getLogger("waf")
        self.console_logger.setLevel(self.log_level)
        if enable_console and not self.console_logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s [%(levelname)s] %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            handler.setFormatter(formatter)
            self.console_logger.addHandler(handler)
    
    async def _log(
        self,
        level: str,
        event_type: str,
        message: str,
        **kwargs
    ):
        """
        Internal logging method that constructs structured entry.
        
        Args:
            level: Log level (INFO, WARNING, ERROR, CRITICAL)
            event_type: Type of event (request, block, anomaly, rate_limit, etc.)
            message: Human-readable message
            **kwargs: Additional structured fields
        """
        entry = {
            "level": level,
            "service": "waf",
            "event_type": event_type,
            "message": message,
            **kwargs
        }
        
        # Write to file (async, non-blocking)
        await self.writer.write(entry)
        
        # Write to console if enabled
        if self.enable_console:
            log_method = getattr(self.console_logger, level.lower(), self.console_logger.info)
            log_method(f"[{event_type}] {message}")
    
    async def log_request(
        self,
        method: str,
        path: str,
        client_ip: str,
        user_agent: str = "",
        decision: str = "allow",
        reason: str = "ok",
        score: float = 0.0,
        response_time_ms: float = 0.0,
        bytes_sent: int = 0,
        threat_category: Optional[str] = None,
        matched_rule_ids: Optional[List[str]] = None,
        status_code: Optional[int] = None,
        **extra_fields
    ):
        """
        Log a WAF request decision with full audit trail.
        
        Args:
            method: HTTP method
            path: Request path
            client_ip: Client IP address
            user_agent: User-Agent header
            decision: allow|block|challenge|rate_limit
            reason: Block reason (e.g., "rule:SQLi-1", "rate_limit")
            score: Anomaly score (0.0-100.0)
            response_time_ms: Response time in milliseconds
            bytes_sent: Response size in bytes
            threat_category: Detected threat category
            matched_rule_ids: List of matched rule IDs
            status_code: HTTP status code
            **extra_fields: Additional custom fields
        """
        level = "WARNING" if decision != "allow" else "INFO"
        
        # Extract matched rule IDs from reason if not provided
        if matched_rule_ids is None:
            matched_rule_ids = []
            if reason.startswith("rule:"):
                matched_rule_ids = [reason.split(":", 1)[1]]
        
        # Add timestamp as epoch seconds
        import time
        timestamp = time.time()
        
        await self._log(
            level=level,
            event_type="request",
            message=f"{decision.upper()}: {method} {path} from {client_ip}",
            timestamp=timestamp,
            method=method,
            path=path,
            client_ip=client_ip,
            user_agent=user_agent,
            decision=decision,
            reason=reason,
            matched_rule_ids=matched_rule_ids,
            score=score,
            response_time_ms=response_time_ms,
            bytes_sent=bytes_sent,
            threat_category=threat_category,
            status_code=status_code,
            **extra_fields
        )
    
    async def log_block(
        self,
        method: str,
        path: str,
        client_ip: str,
        reason: str,
        score: float = 0.0,
        threat_category: Optional[str] = None
    ):
        """Shorthand for logging blocked requests."""
        await self.log_request(
            method=method,
            path=path,
            client_ip=client_ip,
            decision="block",
            reason=reason,
            score=score,
            threat_category=threat_category
        )
    
    async def log_anomaly(
        self,
        method: str,
        path: str,
        client_ip: str,
        score: float,
        indicators: Dict[str, Any]
    ):
        """Log detected anomaly with scoring details."""
        await self._log(
            level="WARNING",
            event_type="anomaly",
            message=f"Anomaly detected: {method} {path} from {client_ip} (score: {score:.2f})",
            method=method,
            path=path,
            client_ip=client_ip,
            score=score,
            indicators=indicators
        )
    
    async def log_rate_limit(
        self,
        client_ip: str,
        path: str,
        limit: int,
        window: int
    ):
        """Log rate limit violation."""
        await self._log(
            level="WARNING",
            event_type="rate_limit",
            message=f"Rate limit exceeded for {client_ip} on {path}",
            client_ip=client_ip,
            path=path,
            limit=limit,
            window=window
        )
    
    async def close(self):
        """Gracefully close logger and flush pending writes."""
        self.writer.close()


# Global logger instance (singleton pattern)
_logger_instance: Optional[StructuredLogger] = None


def get_logger(config=None) -> StructuredLogger:
    """
    Get or create global logger instance.
    
    Args:
        config: Optional Config object. If None, uses defaults.
        
    Returns:
        StructuredLogger instance
    """
    global _logger_instance
    
    if _logger_instance is None:
        if config:
            # Use destination from config if available, otherwise fall back to log_dir/log_file
            log_file = getattr(config.logging, 'destination', None) or f"{config.logging.log_dir}/{config.logging.log_file}"
            _logger_instance = StructuredLogger(
                log_file=log_file,
                log_level=config.logging.log_level,
                enable_console=config.logging.enable_console,
                json_format=config.logging.json_format
            )
        else:
            _logger_instance = StructuredLogger()
    
    return _logger_instance

