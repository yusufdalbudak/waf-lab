"""Advanced rule engine with positive/negative security models and anomaly scoring."""
import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
from aiohttp import web


class ThreatCategory(Enum):
    """OWASP Top 10 threat categories for classification."""
    SQL_INJECTION = "sql_injection"
    XSS = "cross_site_scripting"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    XXE = "xml_external_entity"
    SSRF = "server_side_request_forgery"
    RCE = "remote_code_execution"
    LFI = "local_file_inclusion"
    RFI = "remote_file_inclusion"
    CSRF = "cross_site_request_forgery"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    DATA_EXPOSURE = "sensitive_data_exposure"
    UNKNOWN = "unknown"


@dataclass
class InspectionResult:
    """
    Result of request inspection with scoring and metadata.
    
    Attributes:
        decision: allow|block|challenge (CAPTCHA/2FA)
        reason: Human-readable reason (e.g., "rule:SQLi-1", "anomaly", "positive_rule_match")
        score: Anomaly score (0.0-100.0), higher = more suspicious
        threat_category: Primary threat category detected
        matched_rules: List of rule IDs that matched
        indicators: Dict of suspicious indicators and their weights
    """
    decision: str = "allow"
    reason: str = "ok"
    score: float = 0.0
    threat_category: Optional[ThreatCategory] = None
    matched_rules: List[str] = None
    indicators: Dict[str, float] = None
    
    def __post_init__(self):
        if self.matched_rules is None:
            self.matched_rules = []
        if self.indicators is None:
            self.indicators = {}


class RuleEngine:
    """
    Production-grade rule engine combining:
    - Negative Security Model (NSM): Block known bad patterns
    - Positive Security Model (PSM): Allow only known good patterns
    - Anomaly Scoring: Behavioral analysis with weighted indicators
    - Context-Aware Inspection: Path, method, headers, body analysis
    
    Design inspired by OWASP ModSecurity Core Rule Set (CRS) v3.x
    """
    
    def __init__(self, config):
        """
        Initialize rule engine with configuration.
        
        Args:
            config: Config object containing rule sets
        """
        self.config = config
        self.negative_rules = []
        self.positive_rules = []
        
        # Compile regex patterns for performance
        self._compile_rules()
        
        # Anomaly detection weights (tunable based on threat landscape)
        self.anomaly_weights = {
            "sql_pattern": 30.0,
            "xss_pattern": 25.0,
            "command_pattern": 35.0,
            "path_traversal": 40.0,
            "suspicious_headers": 15.0,
            "unusual_method": 10.0,
            "unusual_path": 20.0,
            "large_body": 5.0,
            "encoded_payload": 10.0,
            "multiple_encoding": 15.0,
        }
    
    def _compile_rules(self):
        """Pre-compile regex patterns for performance optimization."""
        # Negative rules (block patterns)
        for rule in self.config.negative_rules:
            try:
                compiled = re.compile(
                    rule["pattern"],
                    re.IGNORECASE | re.MULTILINE | re.DOTALL
                )
                self.negative_rules.append({
                    "id": rule.get("id", "unknown"),
                    "pattern": compiled,
                    "category": self._map_category(rule.get("category", "unknown")),
                    "severity": rule.get("severity", "medium"),  # low|medium|high|critical
                    "score": rule.get("score", 50.0),  # Default anomaly score contribution
                    "phase": rule.get("phase", "request")  # request or response phase
                })
            except re.error as e:
                # Log regex compilation error but don't crash
                print(f"Warning: Invalid regex in rule {rule.get('id', 'unknown')}: {e}")
        
        # Positive rules (allow patterns) - whitelist approach
        for rule in self.config.positive_rules:
            try:
                compiled = re.compile(
                    rule["pattern"],
                    re.IGNORECASE | re.MULTILINE | re.DOTALL
                )
                self.positive_rules.append({
                    "id": rule.get("id", "unknown"),
                    "pattern": compiled,
                    "path": rule.get("path", None),  # Optional path restriction
                    "method": rule.get("method", None)  # Optional method restriction
                })
            except re.error as e:
                print(f"Warning: Invalid regex in positive rule {rule.get('id', 'unknown')}: {e}")
    
    def _map_category(self, category_str: str) -> ThreatCategory:
        """Map string category to ThreatCategory enum."""
        mapping = {
            "sqli": ThreatCategory.SQL_INJECTION,
            "sql_injection": ThreatCategory.SQL_INJECTION,
            "xss": ThreatCategory.XSS,
            "cross_site_scripting": ThreatCategory.XSS,
            "rce": ThreatCategory.RCE,
            "command_injection": ThreatCategory.COMMAND_INJECTION,
            "path_traversal": ThreatCategory.PATH_TRAVERSAL,
            "lfi": ThreatCategory.LFI,
            "rfi": ThreatCategory.RFI,
        }
        return mapping.get(category_str.lower(), ThreatCategory.UNKNOWN)
    
    async def inspect(
        self,
        request: web.Request,
        body: str = "",
        headers: Optional[Dict[str, str]] = None
    ) -> InspectionResult:
        """
        Perform comprehensive request inspection.
        
        Inspection pipeline:
        1. IP whitelist/blacklist check
        2. Positive security model (if enabled)
        3. Negative security model (pattern matching) - accumulate all matches
        4. Anomaly scoring (behavioral analysis)
        5. Decision making based on thresholds
        
        Args:
            request: aiohttp request object
            body: Request body as string
            headers: Optional headers dict (defaults to request.headers)
            
        Returns:
            InspectionResult with decision, score, and metadata
        """
        if headers is None:
            headers = dict(request.headers)
        
        result = InspectionResult()
        path = str(request.rel_url.path)
        method = request.method.upper()
        client_ip = request.remote
        
        # Build normalized inspection string from request components
        from urllib.parse import unquote
        query_string = unquote(str(request.rel_url.query_string)) if request.rel_url.query_string else ""
        
        # Build inspection context: method + path + query + relevant headers + body
        inspection_parts = [
            method,
            path,
            query_string
        ]
        
        # Add relevant headers (content-type, user-agent, etc.)
        relevant_headers = ["content-type", "user-agent", "referer", "origin"]
        for header_name in relevant_headers:
            if header_name in headers:
                inspection_parts.append(f"{header_name}:{headers[header_name]}")
        
        # Add body for POST/PUT requests
        if body:
            inspection_parts.append(body)
        
        # Create normalized inspection string
        inspection_string = " ".join(inspection_parts)
        
        # Step 1: IP-based decisions (fastest path)
        if client_ip in self.config.ip_blacklist:
            result.decision = "block"
            result.reason = "ip_blacklist"
            result.score = 100.0
            result.threat_category = ThreatCategory.UNAUTHORIZED_ACCESS
            return result
        
        if client_ip in self.config.ip_whitelist:
            # Whitelisted IPs bypass all checks
            return result
        
        # Step 2: Positive Security Model (PSM) - allow only known good
        # If PSM is enabled and no positive rule matches, block by default
        if self.positive_rules:
            psm_match = False
            for rule in self.positive_rules:
                # Check path restriction
                if rule.get("path") and not re.search(rule["path"], path):
                    continue
                # Check method restriction
                if rule.get("method") and method not in rule["method"]:
                    continue
                # Check pattern match
                if rule["pattern"].search(path) or rule["pattern"].search(body):
                    psm_match = True
                    break
            
            if not psm_match:
                result.decision = "block"
                result.reason = "positive_security_model_violation"
                result.score = 80.0
                result.threat_category = ThreatCategory.UNAUTHORIZED_ACCESS
                return result
        
        # Step 3: Negative Security Model (NSM) - check all rules and accumulate scores
        # Track all matched rules and their scores
        matched_rules_with_scores = []  # List of (rule_id, score, category)
        
        for rule in self.negative_rules:
            # Only check rules with phase == "request" (skip response phase rules)
            # All our rules are request phase, but check for safety
            rule_phase = rule.get("phase", "request")
            if rule_phase != "request":
                continue
            
            # Check against normalized inspection string
            if rule["pattern"].search(inspection_string):
                matched_rules_with_scores.append((rule["id"], rule["score"], rule["category"]))
                result.matched_rules.append(rule["id"])
                result.indicators[f"negative_rule_{rule['id']}"] = rule["score"]
        
        # Accumulate total score from all matched rules
        if matched_rules_with_scores:
            # Sum all scores
            total_score = sum(score for _, score, _ in matched_rules_with_scores)
            result.score = total_score
            
            # Determine dominant threat category (highest scoring rule)
            dominant_rule = max(matched_rules_with_scores, key=lambda x: x[1])
            result.threat_category = dominant_rule[2]
            
            # First matched rule ID for response format
            first_rule_id = matched_rules_with_scores[0][0]
            
            # Decision: block if total_score >= threshold
            if total_score >= self.config.security.anomaly_threshold:
                result.decision = "block"
                result.reason = f"rule:{first_rule_id}"
            else:
                # Score below threshold, allow but log
                result.decision = "allow"
                result.reason = f"rule:{first_rule_id}"  # Still log which rules matched
        
        # Step 4: Anomaly Scoring (behavioral analysis) - only if no rules matched
        # Note: We skip anomaly scoring if rules matched to avoid double-counting
        if not matched_rules_with_scores:
            anomaly_score = await self._calculate_anomaly_score(request, body, headers, path, method)
            result.score += anomaly_score
            
            # Decision based on anomaly threshold
            if result.score >= self.config.security.anomaly_threshold:
                result.decision = "block"
                result.reason = "anomaly_score_exceeded"
                if not result.threat_category:
                    result.threat_category = ThreatCategory.UNKNOWN
        
        # Cap score at 100.0
        result.score = min(result.score, 100.0)
        
        return result
    
    async def _calculate_anomaly_score(
        self,
        request: web.Request,
        body: str,
        headers: Dict[str, str],
        path: str,
        method: str
    ) -> float:
        """
        Calculate anomaly score based on behavioral indicators.
        
        This implements a multi-factor scoring system similar to ModSecurity CRS Paranoia Levels.
        
        Args:
            request: Request object
            body: Request body
            headers: Request headers
            path: Request path
            method: HTTP method
            
        Returns:
            Anomaly score (0.0-100.0)
        """
        score = 0.0
        
        # Indicator 1: Suspicious SQL-like patterns (even if not exact match)
        sql_indicators = [
            r'\b(union|select|insert|delete|update|drop|alter|create|exec|execute)\b',
            r'(\'|"|`).*?(or|and).*?=.*?\1',
            r'--|/\*|\*/|#',
            r'\b(sql|mysql|postgres|oracle|mssql)\b'
        ]
        for pattern in sql_indicators:
            if re.search(pattern, body + path, re.I):
                score += self.anomaly_weights["sql_pattern"]
                break  # Count once
        
        # Indicator 2: XSS-like patterns
        xss_indicators = [
            r'<[^>]*(script|iframe|object|embed|onerror|onload|onclick)',
            r'javascript:|data:text/html',
            r'eval\s*\(|expression\s*\('
        ]
        for pattern in xss_indicators:
            if re.search(pattern, body + path, re.I):
                score += self.anomaly_weights["xss_pattern"]
                break
        
        # Indicator 3: Command injection patterns
        cmd_indicators = [
            r'[;&|`]\s*(ls|cat|pwd|whoami|id|uname|wget|curl)',
            r'\$\{|\$\(|`.*?`',
            r'\.\./|\.\.\\',  # Path traversal
        ]
        for pattern in cmd_indicators:
            if re.search(pattern, body + path, re.I):
                score += self.anomaly_weights["command_pattern"]
                break
        
        # Indicator 4: Unusual HTTP methods (beyond standard REST)
        unusual_methods = {"TRACE", "TRACK", "CONNECT", "DEBUG"}
        if method in unusual_methods:
            score += self.anomaly_weights["unusual_method"]
        
        # Indicator 5: Suspicious headers
        suspicious_header_names = [
            "x-forwarded-for", "x-real-ip", "x-original-url",
            "x-rewrite-url", "proxy-authorization"
        ]
        for header_name in suspicious_header_names:
            if header_name in headers:
                score += self.anomaly_weights["suspicious_headers"]
        
        # Indicator 6: Encoded payloads (possible obfuscation)
        encoding_patterns = [
            r'%[0-9a-fA-F]{2}',  # URL encoding
            r'\\x[0-9a-fA-F]{2}',  # Hex encoding
            r'&#x[0-9a-fA-F]+;|&#\d+;',  # HTML entities
        ]
        encoded_count = sum(1 for pattern in encoding_patterns if re.search(pattern, body + path))
        if encoded_count > 0:
            score += self.anomaly_weights["encoded_payload"]
        if encoded_count > 2:
            score += self.anomaly_weights["multiple_encoding"]
        
        # Indicator 7: Unusually large body
        if len(body) > 1024 * 1024:  # 1MB
            score += self.anomaly_weights["large_body"]
        
        # Indicator 8: Unusual path patterns
        unusual_path_patterns = [
            r'\.\./', r'\.\.\\',  # Path traversal
            r'\.(php|jsp|asp|aspx|sh|bat|exe)$',  # Executable extensions
            r'/etc/passwd|/proc/self|/windows/system32'
        ]
        for pattern in unusual_path_patterns:
            if re.search(pattern, path, re.I):
                score += self.anomaly_weights["unusual_path"]
                break
        
        return min(score, 100.0)  # Cap at 100

