# 🌐 Remote Testing Guide

## Testing WAF from Another Device

### Step 1: Find Your WAF Server IP Address

**On macOS/Linux:**
```bash
ifconfig | grep "inet " | grep -v 127.0.0.1
# Or
ip addr show | grep "inet "
```

**On Windows:**
```cmd
ipconfig
# Look for IPv4 Address (not 127.0.0.1)
```

### Step 2: Verify WAF is Listening on All Interfaces

The WAF should be configured to listen on `0.0.0.0` (all interfaces), not just `127.0.0.1`.

Check `waf.py`:
```python
host = os.getenv("WAF_HOST", "0.0.0.0")  # ✓ Correct - listens on all interfaces
port = int(os.getenv("WAF_PORT", "8000"))
```

### Step 3: Ensure Firewall Allows Port 8000

**macOS:**
```bash
# Check firewall status
/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate

# If firewall is on, you may need to allow Python
# Or temporarily disable for testing
```

**Linux:**
```bash
# Ubuntu/Debian
sudo ufw allow 8000/tcp
# Or
sudo iptables -A INPUT -p tcp --dport 8000 -j ACCEPT
```

### Step 4: Test from Another Device

#### Option 1: Web Browser
From another device on the same network, open:
```
http://YOUR_IP_ADDRESS:8000/dashboard
```

Replace `YOUR_IP_ADDRESS` with the IP from Step 1.

#### Option 2: Command Line (from another device)
```bash
# Test health endpoint
curl http://YOUR_IP_ADDRESS:8000/health

# Run attack tests
./test_attacks.sh YOUR_IP_ADDRESS
```

### Step 5: Attack Test Examples

#### From Another Device - SQL Injection
```bash
curl "http://YOUR_IP_ADDRESS:8000/api/users?id=1' OR 1=1--"
# Expected: HTTP 403 Forbidden
```

#### From Another Device - XSS
```bash
curl -X POST "http://YOUR_IP_ADDRESS:8000/api/comment" \
  -d "comment=<script>alert('XSS')</script>"
# Expected: HTTP 403 Forbidden
```

#### From Another Device - Command Injection
```bash
curl -X POST "http://YOUR_IP_ADDRESS:8000/api/execute" \
  -d "cmd=; ls -la"
# Expected: HTTP 403 Forbidden
```

### Step 6: View Attacks in Dashboard

1. Open dashboard on the WAF server:
   ```
   http://localhost:8000/dashboard
   ```
   Or from another device:
   ```
   http://YOUR_IP_ADDRESS:8000/dashboard
   ```

2. Watch real-time attacks appear in the traffic table

3. See statistics update:
   - Blocked requests count increases
   - Threat categories populate
   - IP addresses of attackers visible

### Quick Test Script

Save as `test_remote.sh` on another device:
```bash
#!/bin/bash
WAF_IP="192.168.1.XXX"  # Replace with your WAF IP

echo "Testing WAF at $WAF_IP:8000"
echo ""

# Test 1: Health check
echo "1. Health Check:"
curl -s "http://$WAF_IP:8000/health" | python3 -m json.tool

# Test 2: SQL Injection (should be blocked)
echo -e "\n2. SQL Injection Test:"
curl -s -w "\nHTTP Status: %{http_code}\n" \
  "http://$WAF_IP:8000/api/test?id=1' OR 1=1--"

# Test 3: XSS (should be blocked)
echo -e "\n3. XSS Test:"
curl -s -w "\nHTTP Status: %{http_code}\n" \
  -X POST "http://$WAF_IP:8000/api/test" \
  -d "data=<script>alert(1)</script>"

# Test 4: View dashboard stats
echo -e "\n4. Dashboard Stats:"
curl -s "http://$WAF_IP:8000/api/dashboard/stats" | \
  python3 -c "import sys,json; d=json.load(sys.stdin); \
  print(f\"Total: {d['total_requests']}, Blocked: {d['total_blocked']}, \
  Block Rate: {d['block_rate']:.1f}%\")"
```

### Troubleshooting

#### "Connection Refused"
- ✅ Check WAF is running: `ps aux | grep waf.py`
- ✅ Check WAF listens on 0.0.0.0: `netstat -an | grep 8000`
- ✅ Check firewall allows port 8000
- ✅ Verify both devices on same network

#### "Connection Timeout"
- ✅ Check firewall/router settings
- ✅ Verify IP address is correct
- ✅ Try pinging the WAF server: `ping YOUR_IP_ADDRESS`

#### "Can't Access Dashboard"
- ✅ WAF must be running
- ✅ Use correct IP address (not localhost from remote device)
- ✅ Include port :8000 in URL

### Security Note

⚠️ **Warning**: Exposing WAF to your local network is fine for testing, but:
- Don't expose to public internet without authentication
- Consider adding basic auth for dashboard
- Use HTTPS in production
- Monitor access logs

### Example: Full Attack Simulation

From another device, run multiple attacks:

```bash
WAF_IP="192.168.1.100"  # Your WAF IP

# Launch multiple attacks
for i in {1..10}; do
  curl -s "http://$WAF_IP:8000/api/test?id=1' OR 1=1--" > /dev/null &
  curl -s -X POST "http://$WAF_IP:8000/api/test" \
    -d "data=<script>alert($i)</script>" > /dev/null &
done

wait

# Check dashboard
curl -s "http://$WAF_IP:8000/api/dashboard/stats"
```

All attacks should be blocked (HTTP 403) and visible in the dashboard!

