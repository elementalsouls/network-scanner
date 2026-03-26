"""HTML report generator with embedded CSS/JS."""
from datetime import datetime
from typing import Optional

from scanner.models.scan_result import ScanResult
from scanner.models.port import PortState


class HTMLReport:
    """Generate a standalone HTML report for scan results."""

    def format(self, result: ScanResult) -> str:
        """Generate full HTML report as string."""
        scan_date = result.start_time.strftime("%Y-%m-%d %H:%M:%S") if result.start_time else "N/A"
        duration = f"{result.duration:.2f}s" if result.duration else "N/A"
        alive_count = len(result.alive_hosts)
        total_count = len(result.hosts)
        open_ports = result.total_open_ports

        # Build port distribution for chart
        port_counts: dict = {}
        for host in result.hosts:
            for port in host.open_ports:
                svc = port.service or str(port.number)
                port_counts[svc] = port_counts.get(svc, 0) + 1
        top_services = sorted(port_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        chart_labels = [s[0] for s in top_services]
        chart_data = [s[1] for s in top_services]

        # Build host rows
        host_rows = []
        for host in result.hosts:
            alive_badge = (
                '<span class="badge bg-success">Alive</span>'
                if host.is_alive
                else '<span class="badge bg-secondary">Down</span>'
            )
            open_port_list = ", ".join(
                f'<span class="badge bg-primary">{p.number}/{p.protocol.value}</span>'
                for p in host.open_ports[:10]
            )
            if len(host.open_ports) > 10:
                open_port_list += f" +{len(host.open_ports) - 10} more"
            row = f"""
            <tr>
                <td>{host.ip}</td>
                <td>{host.hostname or ''}</td>
                <td>{alive_badge}</td>
                <td>{host.os or 'Unknown'}</td>
                <td>{host.mac or ''}</td>
                <td>{host.vendor or ''}</td>
                <td>{f"{host.response_time:.1f}ms" if host.response_time else ''}</td>
                <td>{len(host.open_ports)}</td>
                <td>{open_port_list}</td>
            </tr>"""
            host_rows.append(row)

        hosts_html = "\n".join(host_rows)

        # Build detailed port tables per host
        details_html_parts = []
        for host in result.alive_hosts:
            if not host.open_ports:
                continue
            port_rows = []
            for port in host.open_ports:
                port_rows.append(f"""
                <tr>
                    <td>{port.number}</td>
                    <td>{port.protocol.value.upper()}</td>
                    <td><span class="badge bg-success">{port.state.value}</span></td>
                    <td>{port.service or ''}</td>
                    <td>{port.version or ''}</td>
                    <td><code>{(port.banner or '')[:80]}</code></td>
                </tr>""")
            details_html_parts.append(f"""
            <div class="card mb-3">
                <div class="card-header">
                    <strong>{host.display_name}</strong>
                    {f'<span class="text-muted ms-2">({host.os})</span>' if host.os else ''}
                    {f'<span class="text-muted ms-2">{host.vendor}</span>' if host.vendor else ''}
                </div>
                <div class="card-body p-0">
                    <table class="table table-sm table-striped mb-0">
                        <thead><tr>
                            <th>Port</th><th>Protocol</th><th>State</th>
                            <th>Service</th><th>Version</th><th>Banner</th>
                        </tr></thead>
                        <tbody>{"".join(port_rows)}</tbody>
                    </table>
                </div>
            </div>""")

        details_html = "\n".join(details_html_parts)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Network Scan Report - {result.target}</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.3.0/dist/chart.umd.min.js"></script>
<style>
:root {{
    --bg-dark: #1a1a2e;
    --bg-card: #16213e;
    --accent: #0f3460;
    --highlight: #e94560;
}}
body {{ background: #f8f9fa; font-family: 'Segoe UI', sans-serif; }}
.hero {{ background: linear-gradient(135deg, var(--bg-dark), var(--accent)); color: white; padding: 2rem 0; }}
.stat-card {{ border: none; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); transition: transform .2s; }}
.stat-card:hover {{ transform: translateY(-4px); }}
.stat-number {{ font-size: 2.5rem; font-weight: 700; }}
.table {{ font-size: 0.875rem; }}
.badge {{ font-size: 0.75rem; }}
code {{ font-size: 0.8rem; background: #f0f0f0; padding: 1px 4px; border-radius: 3px; }}
#searchInput {{ max-width: 300px; }}
@media (prefers-color-scheme: dark) {{
    body {{ background: #121212; color: #e0e0e0; }}
    .card {{ background: #1e1e1e; border-color: #333; }}
    .table {{ color: #e0e0e0; }}
    .table-striped > tbody > tr:nth-of-type(odd) {{ background: #252525; }}
}}
</style>
</head>
<body>
<div class="hero mb-4">
    <div class="container">
        <h1 class="mb-1">&#128268; Network Scan Report</h1>
        <p class="mb-0 opacity-75">Target: <strong>{result.target}</strong> &nbsp;|&nbsp; Scan Date: {scan_date} &nbsp;|&nbsp; Duration: {duration}</p>
        {f'<span class="badge bg-secondary">{result.profile}</span>' if result.profile else ''}
    </div>
</div>

<div class="container">
    <!-- Stats Row -->
    <div class="row g-3 mb-4">
        <div class="col-md-3">
            <div class="card stat-card text-center p-3 border-start border-success border-4">
                <div class="stat-number text-success">{alive_count}</div>
                <div class="text-muted">Alive Hosts</div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card stat-card text-center p-3 border-start border-primary border-4">
                <div class="stat-number text-primary">{total_count}</div>
                <div class="text-muted">Total Hosts</div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card stat-card text-center p-3 border-start border-warning border-4">
                <div class="stat-number text-warning">{open_ports}</div>
                <div class="text-muted">Open Ports</div>
            </div>
        </div>
        <div class="col-md-3">
            <div class="card stat-card text-center p-3 border-start border-info border-4">
                <div class="stat-number text-info">{result.ports_scanned}</div>
                <div class="text-muted">Ports Scanned</div>
            </div>
        </div>
    </div>

    {'<!-- Service Chart -->' if chart_labels else ''}
    {f'''<div class="card mb-4">
        <div class="card-header"><strong>Top Services</strong></div>
        <div class="card-body">
            <canvas id="serviceChart" height="80"></canvas>
        </div>
    </div>''' if chart_labels else ''}

    <!-- Host Table -->
    <div class="card mb-4">
        <div class="card-header d-flex justify-content-between align-items-center">
            <strong>Host Overview</strong>
            <input type="text" id="searchInput" class="form-control form-control-sm" placeholder="Filter hosts...">
        </div>
        <div class="card-body p-0">
            <div class="table-responsive">
                <table class="table table-striped table-hover mb-0" id="hostsTable">
                    <thead class="table-dark">
                        <tr>
                            <th>IP</th><th>Hostname</th><th>Status</th><th>OS</th>
                            <th>MAC</th><th>Vendor</th><th>RTT</th><th>Open Ports</th><th>Ports</th>
                        </tr>
                    </thead>
                    <tbody>{hosts_html}</tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- Port Details -->
    {f'<h4 class="mb-3">Port Details</h4>{details_html}' if details_html else ''}
</div>

<footer class="text-center text-muted py-3 mt-4">
    <small>Generated by Network Scanner &mdash; {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</small>
</footer>

<script>
// Search filter
document.getElementById('searchInput').addEventListener('input', function() {{
    const val = this.value.toLowerCase();
    document.querySelectorAll('#hostsTable tbody tr').forEach(row => {{
        row.style.display = row.textContent.toLowerCase().includes(val) ? '' : 'none';
    }});
}});

// Service chart
{f"""
const ctx = document.getElementById('serviceChart').getContext('2d');
new Chart(ctx, {{
    type: 'bar',
    data: {{
        labels: {chart_labels},
        datasets: [{{
            label: 'Open Ports',
            data: {chart_data},
            backgroundColor: 'rgba(14, 52, 96, 0.8)',
            borderColor: 'rgba(14, 52, 96, 1)',
            borderWidth: 1
        }}]
    }},
    options: {{
        responsive: true,
        plugins: {{ legend: {{ display: false }} }},
        scales: {{ y: {{ beginAtZero: true, ticks: {{ stepSize: 1 }} }} }}
    }}
}});
""" if chart_labels else ""}
</script>
</body>
</html>"""

    def write(self, result: ScanResult, filepath: str) -> None:
        """Write HTML report to a file."""
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(self.format(result))
