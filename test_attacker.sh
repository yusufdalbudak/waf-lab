#!/bin/bash
# Quick test script for attacker tool

echo "🔥 WAF Attacker Tool Test"
echo "========================"
echo ""

# Check if WAF is running
if ! curl -s http://localhost:8000/health > /dev/null 2>&1; then
    echo "❌ WAF is not running on http://localhost:8000"
    echo "   Please start the WAF first: python3 waf.py"
    exit 1
fi

echo "✅ WAF is running"
echo ""

# Test 1: SQL Injection
echo "🧪 Test 1: SQL Injection Attack"
python3 attacker_tool.py -t http://localhost:8000 -a sql
echo ""

# Test 2: XSS
echo "🧪 Test 2: XSS Attack"
python3 attacker_tool.py -t http://localhost:8000 -a xss
echo ""

# Test 3: DDoS (light)
echo "🧪 Test 3: Light DDoS Attack (10 req/s for 5s)"
python3 attacker_tool.py -t http://localhost:8000 -a ddos --ddos-duration 5 --ddos-rps 10
echo ""

# Test 4: Full suite
echo "🧪 Test 4: Full Attack Suite"
python3 attacker_tool.py -t http://localhost:8000 -a all --ddos-duration 5 --ddos-rps 20 -o attack_results.json
echo ""

echo "✅ Testing complete!"
echo ""
echo "📊 Check attack_results.json for detailed results"
echo "📊 View WAF dashboard at: http://localhost:8000/dashboard"

