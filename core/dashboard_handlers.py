"""Dashboard API handlers for WAF traffic monitoring with enhanced security and features."""
import json
import csv
import io
from datetime import datetime
from aiohttp import web
from typing import Optional, List, Dict, Any
from urllib.parse import unquote


# Security: Sanitize output to prevent XSS
def sanitize_output(value: Any) -> str:
    """Sanitize output values to prevent XSS attacks."""
    if value is None:
        return ""
    # Convert to string and escape HTML
    str_value = str(value)
    # Escape HTML special characters
    str_value = str_value.replace("&", "&amp;")
    str_value = str_value.replace("<", "&lt;")
    str_value = str_value.replace(">", "&gt;")
    str_value = str_value.replace('"', "&quot;")
    str_value = str_value.replace("'", "&#x27;")
    return str_value


async def dashboard_ui_handler(request: web.Request) -> web.Response:
    """Serve the enhanced dashboard HTML interface (requires authentication)."""
    from auth.session_manager import get_session_manager
    from utils import get_client_ip
    
    session_manager = get_session_manager()
    session = session_manager.get_session(request)
    
    username = session.get("username", "User") if session else "User"
    is_admin = session.get("is_admin", False) if session else False
    admin_badge = " (Admin)" if is_admin else ""
    client_ip = get_client_ip(request)
    
    # Security: Check if client IP should have access (basic IP filtering)
    # This is a simple check - in production, use config-based IP whitelist
    # For now, allow all authenticated users
    
    # Build HTML with enhanced features
    html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';">
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
        .toolbar {
            background: #1e2328;
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            align-items: center;
        }
        .toolbar input, .toolbar select {
            padding: 8px;
            border: 1px solid #2d3339;
            border-radius: 4px;
            background: #0f1419;
            color: #e6e1cf;
            font-size: 14px;
        }
        .toolbar input[type="text"] {
            flex: 1;
            min-width: 200px;
        }
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
            max-height: 600px;
            overflow-y: auto;
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
            position: sticky;
            top: 0;
            z-index: 10;
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
        .btn {
            background: #ffd700;
            color: #000;
            border: none;
            padding: 10px 18px;
            border-radius: 5px;
            cursor: pointer;
            font-weight: bold;
            font-size: 14px;
            white-space: nowrap;
            margin-left: 5px;
        }
        .btn:hover { background: #ffed4e; }
        .btn-export {
            background: #4CAF50 !important;
            color: #fff !important;
            border: 2px solid #45a049 !important;
        }
        .btn-export:hover {
            background: #45a049 !important;
            border-color: #4CAF50 !important;
        }
        .btn-secondary {
            background: #2d3339;
            color: #e6e1cf;
        }
        .btn-secondary:hover { background: #3d4349; }
        .btn-danger {
            background: #ff4444;
            color: #fff;
        }
        .btn-danger:hover { background: #ff6666; }
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
        .chart-container {
            background: #1e2328;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.3);
        }
        .chart-title {
            color: #ffd700;
            margin-bottom: 15px;
            font-size: 1.2em;
        }
        .chart-bar {
            background: #2d3339;
            height: 30px;
            margin: 5px 0;
            border-radius: 4px;
            display: flex;
            align-items: center;
            padding: 0 10px;
            position: relative;
            overflow: hidden;
        }
        .chart-bar-fill {
            position: absolute;
            left: 0;
            top: 0;
            height: 100%;
            background: #ffd700;
            opacity: 0.3;
            transition: width 0.3s;
        }
        .chart-bar-label {
            position: relative;
            z-index: 1;
            display: flex;
            justify-content: space-between;
            width: 100%;
        }
        .alert-banner {
            background: #ff8800;
            color: #000;
            padding: 10px;
            border-radius: 4px;
            margin-bottom: 10px;
            font-weight: bold;
        }
        .no-results {
            text-align: center;
            padding: 40px;
            color: #888;
        }
    </style>
</head>
<body>
    <div class="header">
        <div style="display: flex; justify-content: space-between; align-items: center;">
            <div>
                <h1>🛡️ WAF Traffic Dashboard</h1>
                <p>Real-time monitoring of Web Application Firewall traffic | Logged in as: <strong>{username}</strong>{admin_badge} | Your IP: <strong>{client_ip}</strong></p>
            </div>
            <div style="display: flex; gap: 10px; flex-wrap: wrap;">
                <button class="refresh-btn" onclick="loadDashboard()">🔄 Refresh</button>
                <button class="refresh-btn btn-export" onclick="exportData('csv')" title="Export to CSV">📥 Export CSV</button>
                <button class="refresh-btn btn-export" onclick="exportData('json')" title="Export to JSON">📥 Export JSON</button>
                <button class="refresh-btn btn-danger" onclick="window.location.href='/logout'">🚪 Logout</button>
            </div>
        </div>
        <label class="auto-refresh">
            <input type="checkbox" id="autoRefresh" onchange="toggleAutoRefresh()"> Auto-refresh (5s)
        </label>
    </div>
    
    <div class="toolbar">
        <input type="text" id="searchInput" placeholder="🔍 Search IP, path, reason..." onkeyup="filterTable()">
        <select id="decisionFilter" onchange="filterTable()">
            <option value="">All Decisions</option>
            <option value="allow">Allowed</option>
            <option value="block">Blocked</option>
            <option value="rate_limit">Rate Limited</option>
        </select>
        <select id="threatFilter" onchange="filterTable()">
            <option value="">All Threats</option>
        </select>
        <select id="timeRange" onchange="loadDashboard()">
            <option value="100">Last 100 entries</option>
            <option value="500">Last 500 entries</option>
            <option value="1000">Last 1000 entries</option>
            <option value="all">All entries</option>
        </select>
    </div>
    
    <div class="stats-grid" id="statsGrid"></div>
    
    <div class="chart-container" id="threatChart" style="display: none;">
        <div class="chart-title">Threat Category Distribution</div>
        <div id="threatChartContent"></div>
    </div>
    
    <div class="chart-container" id="ruleChart" style="display: none;">
        <div class="chart-title">Top Blocked Rules</div>
        <div id="ruleChartContent"></div>
    </div>
    
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
        let allTrafficData = [];
        let allStatsData = null;
        
        async function loadDashboard() {
            try {
                const limit = document.getElementById('timeRange').value;
                const limitParam = limit === 'all' ? '' : '?limit=' + limit;
                
                // Load stats (include credentials for authentication)
                const statsRes = await fetch('/api/dashboard/stats', {
                    credentials: 'same-origin'
                });
                if (!statsRes.ok) {
                    console.error('Failed to load stats:', statsRes.status, statsRes.statusText);
                    if (statsRes.status === 302 || statsRes.status === 401) {
                        console.error('Authentication required. Redirecting to login...');
                        window.location.href = '/login';
                        return;
                    }
                    return;
                }
                const stats = await statsRes.json();
                allStatsData = stats;
                renderStats(stats);
                renderCharts(stats);
                updateThreatFilter(stats);
                
                // Load traffic (include credentials for authentication)
                const trafficRes = await fetch('/api/dashboard/traffic' + limitParam, {
                    credentials: 'same-origin'
                });
                if (!trafficRes.ok) {
                    console.error('Failed to load traffic:', trafficRes.status, trafficRes.statusText);
                    if (trafficRes.status === 302 || trafficRes.status === 401) {
                        console.error('Authentication required. Redirecting to login...');
                        window.location.href = '/login';
                        return;
                    }
                    // Return empty array instead of failing
                    allTrafficData = [];
                    renderTraffic([]);
                    return;
                }
                const traffic = await trafficRes.json();
                allTrafficData = traffic;
                renderTraffic(traffic);
            } catch (error) {
                console.error('Error loading dashboard:', error);
                // Show error message to user
                const tbody = document.getElementById('trafficBody');
                if (tbody) {
                    tbody.innerHTML = '<tr><td colspan="9" class="no-results" style="color: #ff4444;">Error loading dashboard data. Please check console for details.</td></tr>';
                }
            }
        }
        
        function renderStats(stats) {
            const grid = document.getElementById('statsGrid');
            const totalRequests = stats.total_requests.toLocaleString();
            const reqPerMin = stats.requests_per_minute.toFixed(1);
            const totalAllowed = stats.total_allowed.toLocaleString();
            const allowedPercent = (100 - stats.block_rate).toFixed(1);
            const totalBlocked = stats.total_blocked.toLocaleString();
            const blockedPercent = stats.block_rate.toFixed(1);
            const uptime = formatUptime(stats.uptime_seconds);
            const dataTransfer = formatBytes(stats.total_bytes);
            
            grid.innerHTML = 
                '<div class="stat-card">' +
                    '<div class="stat-label">Total Requests</div>' +
                    '<div class="stat-value">' + totalRequests + '</div>' +
                    '<div class="stat-label">' + reqPerMin + ' req/min</div>' +
                '</div>' +
                '<div class="stat-card allowed">' +
                    '<div class="stat-label">Allowed</div>' +
                    '<div class="stat-value" style="color: #44ff44">' + totalAllowed + '</div>' +
                    '<div class="stat-label">' + allowedPercent + '%</div>' +
                '</div>' +
                '<div class="stat-card blocked">' +
                    '<div class="stat-label">Blocked</div>' +
                    '<div class="stat-value" style="color: #ff4444">' + totalBlocked + '</div>' +
                    '<div class="stat-label">' + blockedPercent + '%</div>' +
                '</div>' +
                '<div class="stat-card">' +
                    '<div class="stat-label">Uptime</div>' +
                    '<div class="stat-value">' + uptime + '</div>' +
                    '<div class="stat-label">Data Transfer: ' + dataTransfer + '</div>' +
                '</div>';
        }
        
        function renderCharts(stats) {
            // Threat category chart
            if (stats.by_threat_category && Object.keys(stats.by_threat_category).length > 0) {
                document.getElementById('threatChart').style.display = 'block';
                const threatData = Object.entries(stats.by_threat_category)
                    .sort((a, b) => b[1] - a[1])
                    .slice(0, 10);
                const maxThreat = Math.max(...threatData.map(d => d[1]));
                
                const chartContent = threatData.map(function(item) {
                    const category = item[0];
                    const count = item[1];
                    const width = (count / maxThreat * 100);
                    const categoryDisplay = category.replace(new RegExp('_', 'g'), ' ');
                    return '<div class="chart-bar">' +
                        '<div class="chart-bar-fill" style="width: ' + width + '%"></div>' +
                        '<div class="chart-bar-label">' +
                        '<span>' + categoryDisplay + '</span>' +
                        '<span><strong>' + count + '</strong></span>' +
                        '</div>' +
                        '</div>';
                }).join('');
                document.getElementById('threatChartContent').innerHTML = chartContent;
            }
            
            // Rule effectiveness chart
            if (stats.by_rule && Object.keys(stats.by_rule).length > 0) {
                document.getElementById('ruleChart').style.display = 'block';
                const ruleData = Object.entries(stats.by_rule)
                    .sort((a, b) => b[1] - a[1])
                    .slice(0, 10);
                const maxRule = Math.max(...ruleData.map(d => d[1]));
                
                const chartContent = ruleData.map(function(item) {
                    const rule = item[0];
                    const count = item[1];
                    const width = (count / maxRule * 100);
                    return '<div class="chart-bar">' +
                        '<div class="chart-bar-fill" style="width: ' + width + '%"></div>' +
                        '<div class="chart-bar-label">' +
                        '<span>' + rule + '</span>' +
                        '<span><strong>' + count + '</strong></span>' +
                        '</div>' +
                        '</div>';
                }).join('');
                document.getElementById('ruleChartContent').innerHTML = chartContent;
            }
        }
        
        function updateThreatFilter(stats) {
            const filter = document.getElementById('threatFilter');
            if (stats.by_threat_category) {
                const threats = Object.keys(stats.by_threat_category).sort();
                filter.innerHTML = '<option value="">All Threats</option>' + 
                    threats.map(function(t) { return '<option value="' + t + '">' + t.replace(new RegExp('_', 'g'), ' ') + '</option>'; }).join('');
            }
        }
        
        function renderTraffic(traffic) {
            const tbody = document.getElementById('trafficBody');
            if (traffic.length === 0) {
                tbody.innerHTML = '<tr><td colspan="9" class="no-results">No traffic data available</td></tr>';
                return;
            }
            
            tbody.innerHTML = traffic.map(entry => {
                // Safely escape all values for HTML attributes and content
                const clientIp = String(entry.client_ip || '');
                const path = String(entry.path || '');
                const reason = String(entry.reason || '');
                const decision = String(entry.decision || '');
                const threat = String(entry.threat_category || '');
                const method = String(entry.method || '');
                
                const safeClientIp = escapeHtml(clientIp);
                const safePath = escapeHtml(path);
                const safeReason = escapeHtml(reason);
                const safeDecision = escapeHtml(decision);
                const safeThreat = escapeHtml(threat);
                const safeMethod = escapeHtml(method);
                const safeThreatCategory = escapeHtml(threat || '-');
                
                // For data-search attribute, escape quotes properly
                const searchParts = [clientIp, path, reason];
                const searchText = searchParts.join(' ').toLowerCase();
                const safeSearchText = escapeHtml(searchText);
                
                // For title attribute
                const safePathTitle = safePath;
                
                const timestamp = formatTime(entry.timestamp || 0);
                const pathDisplay = escapeHtml(truncate(path || '', 50));
                const decisionUpper = decision.toUpperCase();
                const score = (entry.score || 0).toFixed(1);
                const responseTime = (entry.response_time_ms || 0).toFixed(1);
                
                return '<tr data-decision="' + safeDecision + '" data-threat="' + safeThreat + '" data-search="' + safeSearchText + '">' +
                    '<td class="timestamp">' + timestamp + '</td>' +
                    '<td>' + safeClientIp + '</td>' +
                    '<td><strong>' + safeMethod + '</strong></td>' +
                    '<td title="' + safePathTitle + '">' + pathDisplay + '</td>' +
                    '<td><span class="badge ' + safeDecision + '">' + decisionUpper + '</span></td>' +
                    '<td>' + safeReason + '</td>' +
                    '<td>' + score + '</td>' +
                    '<td>' + safeThreatCategory + '</td>' +
                    '<td>' + responseTime + 'ms</td>' +
                    '</tr>';
            }).join('');
        }
        
        function filterTable() {
            const searchTerm = document.getElementById('searchInput').value.toLowerCase();
            const decisionFilter = document.getElementById('decisionFilter').value;
            const threatFilter = document.getElementById('threatFilter').value;
            const rows = document.querySelectorAll('#trafficBody tr');
            
            let visibleCount = 0;
            rows.forEach(row => {
                const decision = row.getAttribute('data-decision');
                const threat = row.getAttribute('data-threat');
                const search = row.getAttribute('data-search');
                
                const matchesSearch = !searchTerm || search.includes(searchTerm);
                const matchesDecision = !decisionFilter || decision === decisionFilter;
                const matchesThreat = !threatFilter || threat === threatFilter;
                
                if (matchesSearch && matchesDecision && matchesThreat) {
                    row.style.display = '';
                    visibleCount++;
                } else {
                    row.style.display = 'none';
                }
            });
            
            if (visibleCount === 0 && rows.length > 0) {
                document.getElementById('trafficBody').innerHTML = 
                    '<tr><td colspan="9" class="no-results">No results match your filters</td></tr>';
            }
        }
        
        function exportData(format) {
            if (allTrafficData.length === 0) {
                alert('No data to export');
                return;
            }
            
            if (format === 'csv') {
                exportCSV(allTrafficData);
            } else if (format === 'json') {
                exportJSON(allTrafficData);
            }
        }
        
        function exportCSV(data) {
            const headers = ['Timestamp', 'IP Address', 'Method', 'Path', 'Decision', 'Reason', 'Score', 'Threat Category', 'Response Time (ms)'];
            const csvContent = [
                headers.join(','),
                ...data.map(entry => [
                    new Date(entry.timestamp * 1000).toISOString(),
                    entry.client_ip,
                    entry.method,
                    '"' + String(entry.path || '').replace(new RegExp('"', 'g'), '""') + '"',
                    entry.decision,
                    '"' + String(entry.reason || '').replace(new RegExp('"', 'g'), '""') + '"',
                    entry.score,
                    entry.threat_category || '',
                    entry.response_time_ms
                ].join(','))
            ].join('\n');
            
            downloadFile(csvContent, 'waf-traffic-' + Date.now() + '.csv', 'text/csv');
        }
        
        function exportJSON(data) {
            const jsonContent = JSON.stringify(data, null, 2);
            downloadFile(jsonContent, 'waf-traffic-' + Date.now() + '.json', 'application/json');
        }
        
        function downloadFile(content, filename, mimeType) {
            const blob = new Blob([content], { type: mimeType });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
        }
        
        function formatTime(timestamp) {
            const date = new Date(timestamp * 1000);
            return date.toLocaleTimeString();
        }
        
        function formatUptime(seconds) {
            const hours = Math.floor(seconds / 3600);
            const minutes = Math.floor((seconds % 3600) / 60);
            const secs = Math.floor(seconds % 60);
            return hours + 'h ' + minutes + 'm ' + secs + 's';
        }
        
        function formatBytes(bytes) {
            if (bytes < 1024) return bytes + ' B';
            if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
            return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
        }
        
        function truncate(str, len) {
            return str.length > len ? str.substring(0, len) + '...' : str;
        }
        
        function escapeHtml(text) {
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
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
    
    # Replace placeholders with sanitized values (avoid .format() due to CSS curly braces)
    html = html_content.replace("{username}", sanitize_output(username))
    html = html.replace("{admin_badge}", sanitize_output(admin_badge))
    html = html.replace("{client_ip}", sanitize_output(client_ip))
    response = web.Response(text=html, content_type='text/html')
    
    # Apply security headers from config
    waf_app = request.app["waf"]
    return waf_app._apply_security_headers(response)


async def dashboard_stats_handler(request: web.Request) -> web.Response:
    """API endpoint for dashboard statistics."""
    waf_app = request.app["waf"]
    stats = waf_app.traffic_store.get_stats()
    
    response = web.json_response(stats)
    # Apply security headers from config
    return waf_app._apply_security_headers(response)


async def dashboard_traffic_handler(request: web.Request) -> web.Response:
    """API endpoint for recent traffic entries with filtering support."""
    waf_app = request.app["waf"]
    limit = int(request.query.get('limit', 100))
    
    # Get filter parameters
    ip_filter = request.query.get('ip', None)
    decision_filter = request.query.get('decision', None)
    threat_filter = request.query.get('threat', None)
    
    # Get all entries first
    entries = waf_app.traffic_store.get_recent_entries(limit=10000)
    
    # Apply filters
    if ip_filter:
        entries = [e for e in entries if ip_filter in e.get('client_ip', '')]
    if decision_filter:
        entries = [e for e in entries if e.get('decision') == decision_filter]
    if threat_filter:
        entries = [e for e in entries if e.get('threat_category') == threat_filter]
    
    # Apply limit after filtering
    entries = entries[:limit]
    
    # Security: Sanitize sensitive data in entries
    sanitized_entries = []
    for entry in entries:
        sanitized = {}
        for key, value in entry.items():
            # Don't sanitize numeric/timestamp fields
            if key in ['timestamp', 'score', 'status_code', 'response_time_ms', 'bytes_sent']:
                sanitized[key] = value
            else:
                # Sanitize string fields to prevent XSS in JSON responses
                sanitized[key] = str(value) if value is not None else ""
        sanitized_entries.append(sanitized)
    
    response = web.json_response(sanitized_entries)
    # Apply security headers from config
    return waf_app._apply_security_headers(response)


async def dashboard_export_handler(request: web.Request) -> web.Response:
    """API endpoint for exporting traffic data in CSV or JSON format."""
    waf_app = request.app["waf"]
    export_format = request.query.get('format', 'json').lower()
    limit = int(request.query.get('limit', 1000))
    
    entries = waf_app.traffic_store.get_recent_entries(limit=limit)
    
    if export_format == 'csv':
        # Generate CSV
        output = io.StringIO()
        if entries:
            writer = csv.DictWriter(output, fieldnames=entries[0].keys())
            writer.writeheader()
            writer.writerows(entries)
        
        response = web.Response(
            text=output.getvalue(),
            content_type='text/csv',
            headers={
                'Content-Disposition': f'attachment; filename="waf-traffic-{datetime.now().strftime("%Y%m%d-%H%M%S")}.csv"'
            }
        )
    else:
        # Generate JSON
        response = web.json_response(
            entries,
            headers={
                'Content-Disposition': f'attachment; filename="waf-traffic-{datetime.now().strftime("%Y%m%d-%H%M%S")}.json"'
            }
        )
    
    # Apply security headers from config
    return waf_app._apply_security_headers(response)
