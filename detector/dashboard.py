# dashboard.py — Live metrics web dashboard
# Served at port 8080, auto-refreshes every 3 seconds.
# Shows banned IPs, global rate, top IPs, CPU/memory, baseline stats.
# Built with Flask — single file, no frontend framework needed.

import psutil
import logging
import threading
from datetime import datetime, timezone
from flask import Flask, jsonify, render_template_string

from config import get

logger = logging.getLogger("dashboard")

# ── HTML Template ─────────────────────────────────────────────
# Single-file dashboard — HTML + CSS + JS all inline.
# Auto-refreshes via JavaScript setInterval every 3 seconds.

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HNG Anomaly Detection — Live Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: 'Courier New', monospace;
            background: #0a0a0f;
            color: #e0e0e0;
            min-height: 100vh;
        }

        header {
            background: #12121a;
            border-bottom: 2px solid #ff3333;
            padding: 16px 32px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        header h1 {
            color: #ff3333;
            font-size: 1.3rem;
            letter-spacing: 2px;
            text-transform: uppercase;
        }

        #status-bar {
            font-size: 0.75rem;
            color: #888;
        }

        #status-bar span { color: #00ff88; }

        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 16px;
            padding: 24px 32px;
        }

        .card {
            background: #12121a;
            border: 1px solid #1e1e2e;
            border-radius: 8px;
            padding: 20px;
        }

        .card h2 {
            font-size: 0.7rem;
            color: #666;
            text-transform: uppercase;
            letter-spacing: 2px;
            margin-bottom: 12px;
            border-bottom: 1px solid #1e1e2e;
            padding-bottom: 8px;
        }

        .metric-big {
            font-size: 2.8rem;
            font-weight: bold;
            color: #00ff88;
            line-height: 1;
        }

        .metric-label {
            font-size: 0.7rem;
            color: #555;
            margin-top: 4px;
        }

        .metric-row {
            display: flex;
            justify-content: space-between;
            padding: 6px 0;
            border-bottom: 1px solid #1a1a2a;
            font-size: 0.8rem;
        }

        .metric-row:last-child { border-bottom: none; }
        .metric-row .label { color: #888; }
        .metric-row .value { color: #e0e0e0; }
        .metric-row .value.danger { color: #ff3333; }
        .metric-row .value.warn   { color: #ffa500; }
        .metric-row .value.good   { color: #00ff88; }

        /* Banned IPs table */
        .ban-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.75rem;
        }

        .ban-table th {
            text-align: left;
            color: #555;
            font-size: 0.65rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            padding: 4px 8px;
            border-bottom: 1px solid #1e1e2e;
        }

        .ban-table td {
            padding: 6px 8px;
            border-bottom: 1px solid #141420;
            color: #ccc;
        }

        .ban-table td.ip   { color: #ff6666; font-weight: bold; }
        .ban-table td.cond { color: #ffa500; font-size: 0.65rem; }
        .ban-table td.dur  { color: #888; }

        /* Top IPs table */
        .ip-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.75rem;
        }

        .ip-table td {
            padding: 5px 8px;
            border-bottom: 1px solid #141420;
        }

        .ip-table td.rank  { color: #444; width: 24px; }
        .ip-table td.ip    { color: #88aaff; }
        .ip-table td.count { color: #00ff88; text-align: right; }
        .ip-table td.rate  { color: #888; text-align: right; font-size: 0.65rem; }

        /* Baseline graph area */
        .graph-area {
            background: #0d0d15;
            border: 1px solid #1e1e2e;
            border-radius: 4px;
            padding: 12px;
            margin-top: 8px;
            height: 80px;
            display: flex;
            align-items: flex-end;
            gap: 2px;
            overflow: hidden;
        }

        .bar {
            flex: 1;
            background: #1e4d3a;
            border-radius: 2px 2px 0 0;
            min-height: 2px;
            transition: height 0.3s ease;
        }

        .no-data {
            color: #333;
            font-size: 0.75rem;
            text-align: center;
            width: 100%;
            align-self: center;
        }

        #last-updated {
            text-align: center;
            color: #333;
            font-size: 0.65rem;
            padding: 8px;
        }

        .pulse {
            display: inline-block;
            width: 8px; height: 8px;
            background: #00ff88;
            border-radius: 50%;
            animation: pulse 1.5s infinite;
            margin-right: 6px;
        }

        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50%       { opacity: 0.2; }
        }

        .card.wide {
            grid-column: 1 / -1;
        }
    </style>
</head>
<body>

<header>
    <h1>🛡 HNG Anomaly Detection Engine</h1>
    <div id="status-bar">
        <span class="pulse"></span>
        LIVE &nbsp;|&nbsp; Refreshing every 3s &nbsp;|&nbsp;
        Uptime: <span id="uptime-display">—</span>
    </div>
</header>

<div class="grid" id="main-grid">

    <!-- Global Rate -->
    <div class="card">
        <h2>Global Request Rate</h2>
        <div class="metric-big" id="global-rate">—</div>
        <div class="metric-label">requests / second</div>
    </div>

    <!-- Active Bans -->
    <div class="card">
        <h2>Active Bans</h2>
        <div class="metric-big" id="ban-count" style="color:#ff3333">—</div>
        <div class="metric-label">IPs currently blocked</div>
    </div>

    <!-- Baseline -->
    <div class="card">
        <h2>Effective Baseline</h2>
        <div class="metric-row">
            <span class="label">Mean</span>
            <span class="value" id="bl-mean">—</span>
        </div>
        <div class="metric-row">
            <span class="label">Std Dev</span>
            <span class="value" id="bl-stddev">—</span>
        </div>
        <div class="metric-row">
            <span class="label">Samples</span>
            <span class="value" id="bl-samples">—</span>
        </div>
        <div class="metric-row">
            <span class="label">Ready</span>
            <span class="value" id="bl-ready">—</span>
        </div>
        <div class="metric-row">
            <span class="label">Recalcs</span>
            <span class="value" id="bl-recalcs">—</span>
        </div>
    </div>

    <!-- System Resources -->
    <div class="card">
        <h2>System Resources</h2>
        <div class="metric-row">
            <span class="label">CPU Usage</span>
            <span class="value" id="cpu">—</span>
        </div>
        <div class="metric-row">
            <span class="label">Memory Usage</span>
            <span class="value" id="mem">—</span>
        </div>
        <div class="metric-row">
            <span class="label">Memory Used</span>
            <span class="value" id="mem-used">—</span>
        </div>
        <div class="metric-row">
            <span class="label">Entries Processed</span>
            <span class="value" id="entries">—</span>
        </div>
        <div class="metric-row">
            <span class="label">Active IPs Tracked</span>
            <span class="value" id="active-ips">—</span>
        </div>
    </div>

    <!-- Banned IPs Table -->
    <div class="card wide">
        <h2>Currently Banned IPs</h2>
        <table class="ban-table">
            <thead>
                <tr>
                    <th>IP Address</th>
                    <th>Condition</th>
                    <th>Rate (req/s)</th>
                    <th>Z-Score</th>
                    <th>Offense #</th>
                    <th>Duration</th>
                    <th>Expires At</th>
                </tr>
            </thead>
            <tbody id="ban-tbody">
                <tr><td colspan="7" style="color:#333;text-align:center;padding:16px">
                    No active bans
                </td></tr>
            </tbody>
        </table>
    </div>

    <!-- Top 10 Source IPs -->
    <div class="card wide">
        <h2>Top 10 Source IPs (by total requests)</h2>
        <table class="ip-table">
            <tbody id="top-ips-tbody">
                <tr><td colspan="4" class="no-data">Waiting for traffic...</td></tr>
            </tbody>
        </table>
    </div>

    <!-- Baseline History Graph -->
    <div class="card wide">
        <h2>Baseline Mean — History</h2>
        <div class="graph-area" id="baseline-graph">
            <div class="no-data">Collecting data...</div>
        </div>
    </div>

</div>

<div id="last-updated">Last updated: —</div>

<script>
    const API = '/api/metrics';
    const REFRESH_MS = 3000;

    async function fetchMetrics() {
        try {
            const res  = await fetch(API);
            const data = await res.json();
            render(data);
        } catch (e) {
            console.error('Fetch error:', e);
        }
    }

    function render(d) {
        // Global rate
        const rate = d.global_rate ?? 0;
        document.getElementById('global-rate').textContent = rate.toFixed(3);

        // Active bans
        const bans = d.active_bans ?? [];
        document.getElementById('ban-count').textContent = bans.length;

        // Baseline
        const bl = d.baseline ?? {};
        document.getElementById('bl-mean').textContent    = (bl.mean    ?? 0).toFixed(4) + ' req/s';
        document.getElementById('bl-stddev').textContent  = (bl.stddev  ?? 0).toFixed(4);
        document.getElementById('bl-samples').textContent = bl.samples  ?? '—';
        document.getElementById('bl-ready').textContent   = bl.ready ? '✅ Yes' : '⏳ Building...';
        document.getElementById('bl-recalcs').textContent = bl.recalc_count ?? 0;

        // System
        const sys = d.system ?? {};
        const cpuEl = document.getElementById('cpu');
        cpuEl.textContent = (sys.cpu_percent ?? 0).toFixed(1) + '%';
        cpuEl.className   = 'value ' + colorClass(sys.cpu_percent, 60, 85);

        const memEl = document.getElementById('mem');
        memEl.textContent = (sys.mem_percent ?? 0).toFixed(1) + '%';
        memEl.className   = 'value ' + colorClass(sys.mem_percent, 70, 90);

        document.getElementById('mem-used').textContent =
            formatBytes(sys.mem_used_bytes ?? 0);
        document.getElementById('entries').textContent =
            (d.entries_processed ?? 0).toLocaleString();
        document.getElementById('active-ips').textContent =
            d.active_ips ?? 0;

        // Uptime
        document.getElementById('uptime-display').textContent =
            formatUptime(d.uptime_secs ?? 0);

        // Banned IPs table
        const tbody = document.getElementById('ban-tbody');
        if (bans.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" style="color:#333;text-align:center;padding:16px">No active bans</td></tr>';
        } else {
            tbody.innerHTML = bans.map(b => `
                <tr>
                    <td class="ip">${b.ip}</td>
                    <td class="cond">${b.condition}</td>
                    <td>${b.rate.toFixed(3)}</td>
                    <td>${b.z_score.toFixed(2)}</td>
                    <td>${b.offense}</td>
                    <td class="dur">${b.duration_min === -1 ? 'PERMANENT' : b.duration_min + ' min'}</td>
                    <td class="dur">${b.expires_at}</td>
                </tr>
            `).join('');
        }

        // Top IPs table
        const topIps   = d.top_ips ?? [];
        const ipTbody  = document.getElementById('top-ips-tbody');
        if (topIps.length === 0) {
            ipTbody.innerHTML = '<tr><td colspan="4" class="no-data">Waiting for traffic...</td></tr>';
        } else {
            ipTbody.innerHTML = topIps.map((ip, i) => `
                <tr>
                    <td class="rank">${i + 1}</td>
                    <td class="ip">${ip.ip}</td>
                    <td class="count">${ip.total.toLocaleString()} reqs</td>
                    <td class="rate">${ip.rate.toFixed(3)} req/s</td>
                </tr>
            `).join('');
        }

        // Baseline history graph
        const history = d.baseline_history ?? [];
        const graph   = document.getElementById('baseline-graph');
        if (history.length < 2) {
            graph.innerHTML = '<div class="no-data">Collecting baseline history...</div>';
        } else {
            const maxMean = Math.max(...history.map(h => h.mean), 1);
            graph.innerHTML = history.slice(-60).map(h => {
                const pct = Math.max(4, (h.mean / maxMean) * 100);
                return `<div class="bar" style="height:${pct}%" title="${h.timestamp}: mean=${h.mean}"></div>`;
            }).join('');
        }

        // Last updated
        document.getElementById('last-updated').textContent =
            'Last updated: ' + new Date().toUTCString();
    }

    function colorClass(val, warnAt, dangerAt) {
        if (val >= dangerAt) return 'danger';
        if (val >= warnAt)   return 'warn';
        return 'good';
    }

    function formatBytes(bytes) {
        if (bytes > 1073741824) return (bytes / 1073741824).toFixed(1) + ' GB';
        if (bytes > 1048576)    return (bytes / 1048576).toFixed(1) + ' MB';
        return (bytes / 1024).toFixed(1) + ' KB';
    }

    function formatUptime(secs) {
        const h = Math.floor(secs / 3600);
        const m = Math.floor((secs % 3600) / 60);
        const s = Math.floor(secs % 60);
        return `${h}h ${m}m ${s}s`;
    }

    // Start refresh loop
    fetchMetrics();
    setInterval(fetchMetrics, REFRESH_MS);
</script>
</body>
</html>
"""


# ══════════════════════════════════════════════════════════════
# Dashboard Server
# ══════════════════════════════════════════════════════════════

class Dashboard:
    """
    Flask-based live metrics dashboard.
    Serves HTML at / and JSON metrics at /api/metrics.
    Runs in a background daemon thread.
    """

    def __init__(self, detector, blocker, baseline, monitor):
        self.detector  = detector
        self.blocker   = blocker
        self.baseline  = baseline
        self.monitor   = monitor

        self.host      = get("dashboard.host", "0.0.0.0")
        self.port      = get("dashboard.port", 8080)
        self.started_at = datetime.now(tz=timezone.utc)

        self.app = Flask(__name__)
        self._register_routes()

        logger.info(
            f"Dashboard initialized — "
            f"http://{self.host}:{self.port}"
        )

    def start(self):
        """Start Flask in a background daemon thread."""
        t = threading.Thread(
            target=self._run_flask,
            name="dashboard",
            daemon=True
        )
        t.start()
        logger.info(f"Dashboard live at http://0.0.0.0:{self.port}")

    # ══════════════════════════════════════════════════════════
    # Routes
    # ══════════════════════════════════════════════════════════

    def _register_routes(self):

        @self.app.route("/")
        def index():
            return render_template_string(DASHBOARD_HTML)

        @self.app.route("/api/metrics")
        def metrics():
            return jsonify(self._collect_metrics())

        @self.app.route("/health")
        def health():
            return jsonify({"status": "ok", "ts": datetime.utcnow().isoformat()})

    # ══════════════════════════════════════════════════════════
    # Metrics Collection
    # ══════════════════════════════════════════════════════════

    def _collect_metrics(self) -> dict:
        """
        Gather all metrics from detector, blocker, baseline, monitor.
        Called on every /api/metrics request (every 3 seconds).
        """
        uptime_secs = (
            datetime.now(tz=timezone.utc) - self.started_at
        ).total_seconds()

        # System resources via psutil
        mem = psutil.virtual_memory()
        sys_metrics = {
            "cpu_percent"  : psutil.cpu_percent(interval=None),
            "mem_percent"  : mem.percent,
            "mem_used_bytes": mem.used,
            "mem_total_bytes": mem.total,
        }

        # Detector stats
        det_stats = self.detector.get_stats()

        # Baseline
        bl = self.baseline.get_effective()

        return {
            "timestamp"        : datetime.utcnow().isoformat(),
            "uptime_secs"      : round(uptime_secs, 1),
            "global_rate"      : self.detector.get_global_rate(),
            "active_bans"      : self.blocker.get_active_bans(),
            "top_ips"          : self.detector.get_top_ips(
                                    get("dashboard.top_ips_count", 10)
                                 ),
            "baseline"         : bl,
            "baseline_history" : self.baseline.get_history(),
            "system"           : sys_metrics,
            "entries_processed": det_stats["entries_processed"],
            "active_ips"       : det_stats["active_ips"],
            "ip_anomalies"     : det_stats["ip_anomalies"],
            "global_anomalies" : det_stats["global_anomalies"],
            "monitor"          : self.monitor.get_stats(),
        }

    def _run_flask(self):
        """Run Flask — disable reloader and debugger for daemon use."""
        import os
        # Suppress Flask startup banner
        os.environ["WERKZEUG_RUN_MAIN"] = "true"
        log = logging.getLogger("werkzeug")
        log.setLevel(logging.ERROR)

        self.app.run(
            host=self.host,
            port=self.port,
            debug=False,
            use_reloader=False,
            threaded=True,
        )
