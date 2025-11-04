'use strict';

(function () {
  let autoRefreshInterval = null;
  let allTrafficData = [];
  let allStatsData = null;

  async function loadDashboard() {
    try {
      const limit = document.getElementById('timeRange').value;
      const limitParam = limit === 'all' ? '' : `?limit=${limit}`;

      const statsRes = await fetch('/api/dashboard/stats', {
        credentials: 'same-origin'
      });
      if (!statsRes.ok) {
        if (statsRes.status === 302 || statsRes.status === 401) {
          window.location.href = '/login';
          return;
        }
        console.error('Failed to load stats:', statsRes.status, statsRes.statusText);
        return;
      }

      const stats = await statsRes.json();
      allStatsData = stats;
      renderStats(stats);
      renderCharts(stats);
      updateThreatFilter(stats);

      const trafficRes = await fetch(`/api/dashboard/traffic${limitParam}`, {
        credentials: 'same-origin'
      });
      if (!trafficRes.ok) {
        if (trafficRes.status === 302 || trafficRes.status === 401) {
          window.location.href = '/login';
          return;
        }
        console.error('Failed to load traffic:', trafficRes.status, trafficRes.statusText);
        clearTrafficTable('Failed to load traffic data');
        return;
      }

      const traffic = await trafficRes.json();
      allTrafficData = traffic;
      renderTraffic(traffic);
    } catch (error) {
      console.error('Error loading dashboard:', error);
      clearTrafficTable('Error loading dashboard data. Check console for details.');
    }
  }

  function clearTrafficTable(message) {
    const tbody = document.getElementById('trafficBody');
    if (tbody) {
      tbody.innerHTML = `<tr><td colspan="9" class="no-results">${escapeHtml(message)}</td></tr>`;
    }
  }

  function renderStats(stats) {
    const grid = document.getElementById('statsGrid');
    if (!grid) {
      return;
    }

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

  function renderCharts(stats) {
    renderThreatChart(stats.by_threat_category || {});
    renderRuleChart(stats.by_rule || {});
  }

  function renderThreatChart(threats) {
    const threatChart = document.getElementById('threatChart');
    const contentEl = document.getElementById('threatChartContent');
    if (!threatChart || !contentEl) {
      return;
    }

    const entries = Object.entries(threats).sort((a, b) => b[1] - a[1]).slice(0, 10);
    if (entries.length === 0) {
      threatChart.style.display = 'none';
      return;
    }

    threatChart.style.display = 'block';
    const maxValue = Math.max(...entries.map(([, value]) => value));

    contentEl.innerHTML = entries.map(([category, count]) => {
      const width = maxValue > 0 ? (count / maxValue) * 100 : 0;
      return `
        <div class="chart-bar">
          <div class="chart-bar-fill" style="width: ${width}%"></div>
          <div class="chart-bar-label">
            <span>${category.replace(/_/g, ' ')}</span>
            <span><strong>${count}</strong></span>
          </div>
        </div>
      `;
    }).join('');
  }

  function renderRuleChart(rules) {
    const ruleChart = document.getElementById('ruleChart');
    const contentEl = document.getElementById('ruleChartContent');
    if (!ruleChart || !contentEl) {
      return;
    }

    const entries = Object.entries(rules).sort((a, b) => b[1] - a[1]).slice(0, 10);
    if (entries.length === 0) {
      ruleChart.style.display = 'none';
      return;
    }

    ruleChart.style.display = 'block';
    const maxValue = Math.max(...entries.map(([, value]) => value));

    contentEl.innerHTML = entries.map(([rule, count]) => {
      const width = maxValue > 0 ? (count / maxValue) * 100 : 0;
      return `
        <div class="chart-bar">
          <div class="chart-bar-fill" style="width: ${width}%"></div>
          <div class="chart-bar-label">
            <span>${escapeHtml(rule)}</span>
            <span><strong>${count}</strong></span>
          </div>
        </div>
      `;
    }).join('');
  }

  function updateThreatFilter(stats) {
    const filter = document.getElementById('threatFilter');
    if (!filter || !stats.by_threat_category) {
      return;
    }

    const options = Object.keys(stats.by_threat_category)
      .sort()
      .map((threat) => `<option value="${threat}">${threat.replace(/_/g, ' ')}</option>`) 
      .join('');

    filter.innerHTML = '<option value="">All Threats</option>' + options;
  }

  function renderTraffic(traffic) {
    const tbody = document.getElementById('trafficBody');
    if (!tbody) {
      return;
    }

    if (!traffic || traffic.length === 0) {
      tbody.innerHTML = '<tr><td colspan="9" class="no-results">No traffic data available</td></tr>';
      return;
    }

    tbody.innerHTML = traffic.map((entry) => {
      const clientIp = escapeHtml(String(entry.client_ip || ''));
      const path = escapeHtml(String(entry.path || ''));
      const reason = escapeHtml(String(entry.reason || ''));
      const decision = escapeHtml(String(entry.decision || ''));
      const threat = escapeHtml(String(entry.threat_category || '-'));
      const method = escapeHtml(String(entry.method || ''));
      const searchText = escapeHtml([entry.client_ip || '', entry.path || '', entry.reason || ''].join(' ').toLowerCase());
      const responseTime = (entry.response_time_ms || 0).toFixed(1);
      const score = (entry.score || 0).toFixed(1);
      const timestamp = formatTime(entry.timestamp || 0);

      return `
        <tr data-decision="${decision}" data-threat="${threat}" data-search="${searchText}">
          <td class="timestamp">${timestamp}</td>
          <td>${clientIp}</td>
          <td><strong>${method}</strong></td>
          <td title="${path}">${escapeHtml(truncate(entry.path || '', 50))}</td>
          <td><span class="badge ${decision}">${decision.toUpperCase()}</span></td>
          <td>${reason}</td>
          <td>${score}</td>
          <td>${threat}</td>
          <td>${responseTime}ms</td>
        </tr>
      `;
    }).join('');
  }

  function filterTable() {
    const searchTerm = document.getElementById('searchInput').value.toLowerCase();
    const decisionFilter = document.getElementById('decisionFilter').value;
    const threatFilter = document.getElementById('threatFilter').value;
    const rows = document.querySelectorAll('#trafficBody tr');

    let visibleCount = 0;
    rows.forEach((row) => {
      const decision = row.getAttribute('data-decision');
      const threat = row.getAttribute('data-threat');
      const search = row.getAttribute('data-search');

      const matchesSearch = !searchTerm || (search && search.includes(searchTerm));
      const matchesDecision = !decisionFilter || decision === decisionFilter;
      const matchesThreat = !threatFilter || threat === threatFilter;

      if (matchesSearch && matchesDecision && matchesThreat) {
        row.style.display = '';
        visibleCount += 1;
      } else {
        row.style.display = 'none';
      }
    });

    const tbody = document.getElementById('trafficBody');
    if (tbody && visibleCount === 0 && rows.length > 0) {
      tbody.innerHTML = '<tr><td colspan="9" class="no-results">No results match your filters</td></tr>';
    }
  }

  function exportData(format) {
    if (!allTrafficData || allTrafficData.length === 0) {
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
      ...data.map((entry) => [
        new Date(entry.timestamp * 1000).toISOString(),
        entry.client_ip,
        entry.method,
        `"${String(entry.path || '').replace(/"/g, '""')}"`,
        entry.decision,
        `"${String(entry.reason || '').replace(/"/g, '""')}"`,
        entry.score,
        entry.threat_category || '',
        entry.response_time_ms
      ].join(','))
    ].join('\n');

    downloadFile(csvContent, `waf-traffic-${Date.now()}.csv`, 'text/csv');
  }

  function exportJSON(data) {
    const jsonContent = JSON.stringify(data, null, 2);
    downloadFile(jsonContent, `waf-traffic-${Date.now()}.json`, 'application/json');
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

  function toggleAutoRefresh() {
    const checkbox = document.getElementById('autoRefresh');
    if (!checkbox) {
      return;
    }

    if (checkbox.checked) {
      loadDashboard();
      autoRefreshInterval = window.setInterval(loadDashboard, 5000);
    } else if (autoRefreshInterval) {
      window.clearInterval(autoRefreshInterval);
      autoRefreshInterval = null;
    }
  }

  function truncate(str, len) {
    if (!str) {
      return '';
    }
    return str.length > len ? `${str.substring(0, len)}...` : str;
  }

  function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  function formatTime(timestamp) {
    const date = new Date(timestamp * 1000);
    return date.toLocaleString();
  }

  function formatUptime(seconds) {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = Math.floor(seconds % 60);
    return `${hours}h ${minutes}m ${secs}s`;
  }

  function formatBytes(bytes) {
    if (bytes < 1024) {
      return `${bytes} B`;
    }
    if (bytes < 1024 * 1024) {
      return `${(bytes / 1024).toFixed(1)} KB`;
    }
    if (bytes < 1024 * 1024 * 1024) {
      return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    }
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)} GB`;
  }

  function toggleAutoRefreshHandler() {
    toggleAutoRefresh();
  }

  document.addEventListener('DOMContentLoaded', () => {
    window.loadDashboard = loadDashboard;
    window.exportData = exportData;
    window.toggleAutoRefresh = toggleAutoRefreshHandler;
    window.filterTable = filterTable;
    loadDashboard();
  });
})();

