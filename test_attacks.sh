#!/bin/bash
# WAF Attack Testing Script
# Test various attack patterns to verify blocking

WAF_IP="${1:-localhost}"
WAF_PORT="${2:-8000}"
BASE_URL="http://${WAF_IP}:${WAF_PORT}"

echo "🛡️  WAF Attack Testing Script"
echo "================================"
echo "Target: ${BASE_URL}"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

test_attack() {
    local name="$1"
    local method="$2"
    local path="$3"
    local data="$4"
    local expected_code="$5"
    
    echo -n "Testing: ${name}... "
    
    if [ "$method" = "GET" ]; then
        response=$(curl -s -w "\n%{http_code}" "${BASE_URL}${path}")
    else
        response=$(curl -s -w "\n%{http_code}" -X "$method" "${BASE_URL}${path}" -d "$data")
    fi
    
    http_code=$(echo "$response" | tail -n1)
    
    if [ "$http_code" = "$expected_code" ]; then
        echo -e "${GREEN}✓ BLOCKED (HTTP $http_code)${NC}"
        return 0
    else
        echo -e "${RED}✗ NOT BLOCKED (HTTP $http_code)${NC}"
        return 1
    fi
}

# Test 1: SQL Injection
echo "📋 SQL Injection Attacks"
echo "------------------------"
test_attack "SQL Injection - UNION SELECT" "GET" "/api/users?id=1' UNION SELECT * FROM users--" "" "403"
test_attack "SQL Injection - OR 1=1" "GET" "/api/login?user=admin' OR 1=1--" "" "403"
test_attack "SQL Injection - DROP TABLE" "POST" "/api/admin" "cmd=DROP TABLE users;" "403"

# Test 2: XSS Attacks
echo ""
echo "📋 Cross-Site Scripting (XSS) Attacks"
echo "--------------------------------------"
test_attack "XSS - Script Tag" "POST" "/api/comment" "comment=<script>alert('XSS')</script>" "403"
test_attack "XSS - Event Handler" "POST" "/api/form" "input=<img onerror=alert(1) src=x>" "403"
test_attack "XSS - JavaScript Protocol" "GET" "/api/redirect?url=javascript:alert(1)" "" "403"

# Test 3: Command Injection
echo ""
echo "📋 Command Injection Attacks"
echo "----------------------------"
test_attack "Command Injection - Semicolon" "POST" "/api/execute" "cmd=; ls -la" "403"
test_attack "Command Injection - Pipe" "POST" "/api/run" "command=cat /etc/passwd | grep root" "403"
test_attack "Command Injection - Backtick" "GET" "/api/test?cmd=\`whoami\`" "" "403"

# Test 4: Path Traversal
echo ""
echo "📋 Path Traversal Attacks"
echo "-------------------------"
test_attack "Path Traversal - Unix" "GET" "/api/file?path=../../../etc/passwd" "" "403"
test_attack "Path Traversal - Windows" "GET" "/api/download?file=..\\..\\windows\\system32\\config\\sam" "" "403"

# Test 5: Remote Code Execution
echo ""
echo "📋 Remote Code Execution Attacks"
echo "--------------------------------"
test_attack "RCE - PHP eval" "POST" "/api/eval" "code=eval('system(\"id\")')" "403"
test_attack "RCE - Python exec" "POST" "/api/execute" "script=exec('import os; os.system(\"id\")')" "403"

# Test 6: Clean Request (should be allowed if backend is running, or 502 if not)
echo ""
echo "📋 Clean Request (Should Allow)"
echo "-------------------------------"
echo -n "Testing: Clean GET request... "
response=$(curl -s -w "\n%{http_code}" "${BASE_URL}/api/products")
http_code=$(echo "$response" | tail -n1)
if [ "$http_code" = "200" ] || [ "$http_code" = "502" ]; then
    echo -e "${GREEN}✓ ALLOWED/Backend Issue (HTTP $http_code)${NC}"
else
    echo -e "${YELLOW}⚠ Unexpected (HTTP $http_code)${NC}"
fi

echo ""
echo "================================"
echo "✅ Attack testing complete!"
echo ""
echo "📊 View dashboard: ${BASE_URL}/dashboard"
echo "📈 View stats: ${BASE_URL}/api/dashboard/stats"

