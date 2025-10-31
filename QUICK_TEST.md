# 🚀 Quick Remote Testing Guide

## Your WAF Details

**IP Address:** `192.168.1.104`  
**Port:** `8000`  
**Dashboard:** `http://192.168.1.104:8000/dashboard`

---

## ✅ Step-by-Step Testing

### 1️⃣ From Another Device - Open Dashboard

Open in browser:
```
http://192.168.1.104:8000/dashboard
```

You should see the real-time WAF traffic dashboard!

### 2️⃣ Test Attack Blocking

From another device on the same network, run:

#### SQL Injection Test:
```bash
curl "http://192.168.1.104:8000/api/test?id=1' OR 1=1--"
```
**Expected:** HTTP 403 Forbidden

#### XSS Test:
```bash
curl -X POST "http://192.168.1.104:8000/api/test" \
  -d "data=<script>alert('XSS')</script>"
```
**Expected:** HTTP 403 Forbidden

#### Command Injection Test:
```bash
curl -X POST "http://192.168.1.104:8000/api/execute" \
  -d "cmd=; ls -la"
```
**Expected:** HTTP 403 Forbidden

### 3️⃣ Watch Dashboard Update

Refresh the dashboard page and you'll see:
- ✅ Attack attempts appear in real-time
- ✅ Blocked requests show in red
- ✅ IP address of attacker visible
- ✅ Threat category and rule ID displayed
- ✅ Statistics update automatically

---

## 📱 Quick Test Script

On another device, save this as `test_waf.sh`:

```bash
#!/bin/bash
WAF="192.168.1.104:8000"

echo "🛡️  Testing WAF at $WAF"
echo ""

echo "1. Health Check:"
curl -s "http://$WAF/health" | python3 -m json.tool
echo ""

echo "2. SQL Injection (should block):"
curl -s -w " → HTTP %{http_code}\n" "http://$WAF/api/test?id=1' OR 1=1--"
echo ""

echo "3. XSS Attack (should block):"
curl -s -w " → HTTP %{http_code}\n" -X POST "http://$WAF/api/test" \
  -d "data=<script>alert(1)</script>"
echo ""

echo "4. Command Injection (should block):"
curl -s -w " → HTTP %{http_code}\n" -X POST "http://$WAF/api/test" \
  -d "cmd=; cat /etc/passwd"
echo ""

echo "5. Dashboard Stats:"
curl -s "http://$WAF/api/dashboard/stats" | python3 -c \
  "import sys,json; d=json.load(sys.stdin); \
   print(f\"   Total: {d['total_requests']}\"); \
   print(f\"   Blocked: {d['total_blocked']}\"); \
   print(f\"   Block Rate: {d['block_rate']:.1f}%\")"
```

Run with:
```bash
chmod +x test_waf.sh
./test_waf.sh
```

---

## 🎯 What to Watch For

### In Dashboard:
1. **Traffic Table** - See each attack attempt
2. **Block Rate** - Should increase with attacks
3. **Threat Categories** - SQL injection, XSS, etc.
4. **IP Addresses** - Your test device IP appears
5. **Rule IDs** - Shows which rule blocked (e.g., "SQLi-1", "XSS-1")

### Expected Results:
- ✅ All attacks return HTTP 403
- ✅ Dashboard shows blocked requests
- ✅ Threat categories populate
- ✅ Block rate increases

---

## 🔧 Troubleshooting

**Can't connect?**
- Check both devices on same WiFi/network
- Verify WAF is running: Check dashboard on server
- Try ping: `ping 192.168.1.104`

**Attacks not being blocked?**
- Check rules.json has security rules
- Verify WAF is actually processing requests (check dashboard)

**Dashboard not loading?**
- Ensure port 8000 is accessible
- Check firewall settings on WAF server

---

## 📊 Example Attack Scenario

Run multiple attacks in sequence:

```bash
# Launch 10 SQL injection attacks
for i in {1..10}; do
  curl -s "http://192.168.1.104:8000/api/test?id=$i' OR 1=1--" &
done

# Launch 10 XSS attacks  
for i in {1..10}; do
  curl -s -X POST "http://192.168.1.104:8000/api/test" \
    -d "data=<script>alert($i)</script>" &
done

wait

# Check results
curl -s "http://192.168.1.104:8000/api/dashboard/stats"
```

All 20 attacks should be blocked and visible in dashboard!

---

**🎉 Ready to test! Open `http://192.168.1.104:8000/dashboard` from another device!**

