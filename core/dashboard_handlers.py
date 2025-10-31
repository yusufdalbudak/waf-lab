"""Dashboard API handlers for WAF traffic monitoring."""
import json
from aiohttp import web
from typing import Optional


async def dashboard_ui_handler(request: web.Request) -> web.Response:
    """Serve the dashboard HTML interface (requires authentication)."""
    from auth.session_manager import get_session_manager
    session_manager = get_session_manager()
    session = session_manager.get_session(request)
    
    username = session.get("username", "User") if session else "User"
    is_admin = session.get("is_admin", False) if session else False
    admin_badge = " (Admin)" if is_admin else ""
    
    # Build HTML - use triple quotes and replace placeholders
    html_template = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WAF Traffic Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: #0f1419;
            color: #e6e1cf;
            padding: 20px;
        }
        .header {
            background: #1e2328;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.3);
        }
        h1 { color: #ffd700; margin-bottom: 10px; }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        .stat-card {
            background: #1e2328;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #ffd700;
            box-shadow: 0 2px 10px rgba(0,0,0,0.3);
        }
        .stat-card.blocked { border-color: #ff4444; }
        .stat-card.allowed { border-color: #44ff44; }
        .stat-value {
            font-size: 2em;
            font-weight: bold;
            color: #ffd700;
            margin: 10px 0;
        }
        .stat-label { color: #a0a0a0; font-size: 0.9em; }
        .traffic-table {
            background: #1e2328;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 10px rgba(0,0,0,0.3);
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th {
            background: #2d3339;
            padding: 12px;
            text-align: left;
            color: #ffd700;
            font-weight: 600;
        }
        td {
            padding: 10px 12px;
            border-bottom: 1px solid #2d3339;
        }
        tr:hover { background: #2d3339; }
        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8em;
            font-weight: bold;
        }
        .badge.allow { background: #44ff44; color: #000; }
        .badge.block { background: #ff4444; color: #fff; }
        .badge.rate_limit { background: #ff8800; color: #000; }
        .refresh-btn {
            background: #ffd700;
            color: #000;
            border: none;
            padding: 10px 20px;
            border-radius: 5px;
            cursor: pointer;
            font-weight: bold;
            margin: 10px 0;
        }
        .refresh-btn:hover { background: #ffed4e; }
        .auto-refresh { margin-left: 10px; }
        .timestamp { color: #888; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="header">
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <div>
                <h1>🛡️ WAF Traffic Dashboard</h1>
                <p>Real-time monitoring of Web Application Firewall traffic | Logged in as: <strong>""" + username + """</strong>""" + admin_badge + """</p>
            </div>
            <div>
                <button class="refresh-btn" onclick="loadDashboard()">🔄 Refresh</button>
                <button class="refresh-btn" onclick="window.location.href='/logout'" style="margin-left: 10px; background: #ff4444;">🚪 Logout</button>
            </div>
        </div>
        <label class="auto-refresh">
            <input type="checkbox" id="autoRefresh" onchange="toggleAutoRefresh()"> Auto-refresh (5s)
        </label>
    </div>
    
    <div class="stats-grid" id="statsGrid"></div>
    
    <div class="traffic-table">
        <table>
            <thead>
                <tr>
                    <th>Time</th>
                    <th>IP Address</th>
                    <th>Method</th>
                    <th>Path</th>
                    <th>Decision</th>
                    <th>Reason</th>
                    <th>Score</th>
                    <th>Threat</th>
                    <th>Response Time</th>
                </tr>
            </thead>
            <tbody id="trafficBody"></tbody>
        </table>
    </div>
    
    <script>
        let autoRefreshInterval = null;
        
        async function loadDashboard() {
            try {
                // Load stats
                const statsRes = await fetch('/api/dashboard/stats');
                const stats = await statsRes.json();
                renderStats(stats);
                
                // Load traffic
                const trafficRes = await fetch('/api/dashboard/traffic?limit=100');
                const traffic = await trafficRes.json();
                renderTraffic(traffic);
            } catch (error) {
                console.error('Error loading dashboard:', error);
            }
        }
        
        function renderStats(stats) {
            const grid = document.getElementById('statsGrid');
            grid.innerHTML = `
                <div class="stat-card">
                    <div class="stat-label">Total Requests</div>
                    <div class="stat-value">${stats.total_requests.toLocaleString()}</div>
                    <div class="stat-label">${stats.requests_per_minute.toFixed(1)} req/min</div>
                </div>
                <div class="stat-card allowed">
                    <div class="stat-label">Allowed</div>
                    <div class="stat-value" style="color: #44ff44">${stats.total_allowed.toLocaleString()}</div>
                    <div class="stat-label">${(100 - stats.block_rate).toFixed(1)}%</div>
                </div>
                <div class="stat-card blocked">
                    <div class="stat-label">Blocked</div>
                    <div class="stat-value" style="color: #ff4444">${stats.total_blocked.toLocaleString()}</div>
                    <div class="stat-label">${stats.block_rate.toFixed(1)}%</div>
                </div>
                <div class="stat-card">
                    <div class="stat-label">Uptime</div>
                    <div class="stat-value">${formatUptime(stats.uptime_seconds)}</div>
                    <div class="stat-label">Data Transfer: ${formatBytes(stats.total_bytes)}</div>
                </div>
            `;
        }
        
        function renderTraffic(traffic) {
            const tbody = document.getElementById('trafficBody');
            tbody.innerHTML = traffic.map(entry => `
                <tr>
                    <td class="timestamp">${formatTime(entry.timestamp)}</td>
                    <td>${entry.client_ip}</td>
                    <td><strong>${entry.method}</strong></td>
                    <td>${truncate(entry.path, 50)}</td>
                    <td><span class="badge ${entry.decision}">${entry.decision.toUpperCase()}</span></td>
                    <td>${entry.reason}</td>
                    <td>${entry.score.toFixed(1)}</td>
                    <td>${entry.threat_category || '-'}</td>
                    <td>${entry.response_time_ms.toFixed(1)}ms</td>
                </tr>
            `).join('');
        }
        
        function formatTime(timestamp) {
            const date = new Date(timestamp * 1000);
            return date.toLocaleTimeString();
        }
        
        function formatUptime(seconds) {
            const hours = Math.floor(seconds / 3600);
            const minutes = Math.floor((seconds % 3600) / 60);
            const secs = Math.floor(seconds % 60);
            return `${hours}h ${minutes}m ${secs}s`;
        }
        
        function formatBytes(bytes) {
            if (bytes < 1024) return bytes + ' B';
            if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
            return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
        }
        
        function truncate(str, len) {
            return str.length > len ? str.substring(0, len) + '...' : str;
        }
        
        function toggleAutoRefresh() {
            const checkbox = document.getElementById('autoRefresh');
            if (checkbox.checked) {
                autoRefreshInterval = setInterval(loadDashboard, 5000);
            } else {
                if (autoRefreshInterval) {
                    clearInterval(autoRefreshInterval);
                    autoRefreshInterval = null;
                }
            }
        }
        
        // Initial load
        loadDashboard();
    </script>
</body>
</html>"""
    
    # Format with username and admin badge (escape for HTML)
    import html as html_module
    safe_username = html_module.escape(username)
    html = html_template.replace("{username}", safe_username).replace("{admin_badge}", admin_badge)
    return web.Response(text=html, content_type='text/html')


async def dashboard_stats_handler(request: web.Request) -> web.Response:
    """API endpoint for dashboard statistics."""
    waf_app = request.app["waf"]
    stats = waf_app.traffic_store.get_stats()
    return web.json_response(stats)


async def dashboard_traffic_handler(request: web.Request) -> web.Response:
    """API endpoint for recent traffic entries."""
    waf_app = request.app["waf"]
    limit = int(request.query.get('limit', 100))
    entries = waf_app.traffic_store.get_recent_entries(limit=limit)
    return web.json_response(entries)

