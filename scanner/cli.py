"""CLI entry point using Click."""
import asyncio
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console

console = Console()


@click.group()
@click.version_option(version="1.0.0", prog_name="network-scanner")
def cli():
    """Network Scanner - A powerful cross-platform network scanning tool."""
    pass


@cli.command()
@click.argument("target")
@click.option("-p", "--ports", default="top100", show_default=True,
              help="Port specification: top100, top1000, all, or e.g. 22-443,8080")
@click.option("--profile", default=None, help="Scan profile: quick, full, stealth, service")
@click.option("--scan-type", default="connect", show_default=True,
              type=click.Choice(["connect", "syn", "udp"]), help="Scan technique")
@click.option("-t", "--timeout", default=3.0, show_default=True, type=float, help="Connection timeout (seconds)")
@click.option("--threads", default=100, show_default=True, type=int, help="Maximum concurrent threads")
@click.option("--rate-limit", default=0.0, show_default=True, type=float, help="Delay between probes (seconds)")
@click.option("--ping-only", is_flag=True, help="Ping sweep only, no port scanning")
@click.option("--service-detection", is_flag=True, help="Enable service/version detection")
@click.option("--os-detection", is_flag=True, help="Enable OS detection")
@click.option("-o", "--output", default=None, help="Output file path")
@click.option("-f", "--format", "output_format",
              type=click.Choice(["console", "json", "csv", "xml", "html"]),
              default="console", show_default=True, help="Output format")
@click.option("-v", "--verbose", is_flag=True, help="Verbose output")
def scan(
    target: str,
    ports: str,
    profile: Optional[str],
    scan_type: str,
    timeout: float,
    threads: int,
    rate_limit: float,
    ping_only: bool,
    service_detection: bool,
    os_detection: bool,
    output: Optional[str],
    output_format: str,
    verbose: bool,
):
    """Scan TARGET for open ports and services.

    TARGET can be: IP, CIDR (192.168.1.0/24), range (192.168.1.1-254), or hostname.
    """
    from scanner.core.async_engine import ScanEngine
    from scanner.config.profiles import get_profile, PROFILES

    # Apply profile if given
    if profile:
        try:
            p = get_profile(profile)
            ports = p.ports or ports
            scan_type = p.scan_type
            timeout = p.timeout
            threads = p.max_threads
            rate_limit = p.rate_limit
            service_detection = service_detection or p.service_detection
            os_detection = os_detection or p.os_detection
            ping_only = ping_only or p.ping_only
        except ValueError as e:
            console.print(f"[red]Error:[/] {e}")
            sys.exit(1)

    def progress(msg: str):
        if verbose:
            console.print(f"[dim]{msg}[/]")

    engine = ScanEngine(
        timeout=timeout,
        max_threads=threads,
        rate_limit=rate_limit,
        service_detection=service_detection,
        os_detection=os_detection,
        progress_callback=progress,
    )

    console.print(f"[bold blue]Scanning:[/] {target}")
    if verbose:
        console.print(f"  Ports: {ports} | Type: {scan_type} | Timeout: {timeout}s | Threads: {threads}")

    try:
        result = asyncio.run(engine.scan(
            target=target,
            ports=ports,
            scan_type=scan_type,
            ping_only=ping_only,
            profile_name=profile,
        ))
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user.[/]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[red]Scan failed:[/] {e}")
        sys.exit(1)

    if result.error:
        console.print(f"[red]Error:[/] {result.error}")

    # Output
    if output_format == "console" or (output_format == "console" and not output):
        from scanner.output.console_output import print_full_results
        print_full_results(result)
    elif output_format == "json":
        from scanner.output.json_output import JSONOutput
        content = JSONOutput().format(result)
        if output:
            Path(output).write_text(content, encoding="utf-8")
            console.print(f"[green]JSON saved to:[/] {output}")
        else:
            print(content)
    elif output_format == "csv":
        from scanner.output.csv_output import CSVOutput
        content = CSVOutput().format(result)
        if output:
            Path(output).write_text(content, encoding="utf-8")
            console.print(f"[green]CSV saved to:[/] {output}")
        else:
            print(content)
    elif output_format == "xml":
        from scanner.output.xml_output import XMLOutput
        content = XMLOutput().format(result)
        if output:
            Path(output).write_text(content, encoding="utf-8")
            console.print(f"[green]XML saved to:[/] {output}")
        else:
            print(content)
    elif output_format == "html":
        from scanner.output.html_report import HTMLReport
        out_path = output or "scan_report.html"
        HTMLReport().write(result, out_path)
        console.print(f"[green]HTML report saved to:[/] {out_path}")

    # Also output to console if we wrote to file
    if output and output_format != "console":
        from scanner.output.console_output import print_scan_summary
        print_scan_summary(result)


@cli.command()
@click.argument("target")
@click.option("-i", "--interval", default=300, show_default=True, type=int, help="Scan interval (seconds)")
@click.option("-p", "--ports", default="top100", show_default=True, help="Port specification")
@click.option("--db", default="scanner.db", show_default=True, help="Database path")
def monitor(target: str, interval: int, ports: str, db: str):
    """Continuously monitor TARGET for network changes."""
    from scanner.monitoring.watcher import NetworkWatcher
    from scanner.monitoring.alerts import AlertLevel

    def on_change(change: dict):
        level = change.get("level", AlertLevel.INFO)
        msg = change.get("message", "")
        color = {"info": "blue", "warning": "yellow", "critical": "red"}.get(level.value if hasattr(level, 'value') else str(level), "white")
        console.print(f"[{color}][{str(level).upper()}][/] {msg}")

    watcher = NetworkWatcher(
        target=target,
        interval=interval,
        ports=ports,
        db_path=db,
        on_change=on_change,
    )

    console.print(f"[bold blue]Monitoring:[/] {target} every {interval}s")
    console.print("[dim]Press Ctrl+C to stop.[/]")
    watcher.start()

    try:
        while True:
            import time
            time.sleep(1)
    except KeyboardInterrupt:
        console.print("\n[yellow]Monitoring stopped.[/]")
        watcher.stop()


@cli.command()
@click.option("--host", default="127.0.0.1", show_default=True, help="Bind host")
@click.option("--port", default=8080, show_default=True, type=int, help="Bind port")
@click.option("--db", default="scanner.db", show_default=True, help="Database path")
@click.option("--debug", is_flag=True, help="Enable Flask debug mode")
def web(host: str, port: int, db: str, debug: bool):
    """Start the web interface."""
    from scanner.web.app import create_app

    app = create_app(db_path=db)
    console.print(f"[bold green]Web interface started:[/] http://{host}:{port}")
    app.run(host=host, port=port, debug=debug)


@cli.command()
@click.option("--db", default="scanner.db", show_default=True, help="Database path")
@click.option("-n", "--limit", default=20, show_default=True, type=int, help="Number of scans to show")
@click.option("--target", default=None, help="Filter by target")
def history(db: str, limit: int, target: Optional[str]):
    """Show scan history."""
    from scanner.monitoring.history import ScanHistory
    from rich.table import Table
    from rich import box

    hist = ScanHistory(db_path=db)
    scans = hist.list_scans(limit=limit, target=target)

    if not scans:
        console.print("[yellow]No scan history found.[/]")
        return

    table = Table(title="Scan History", box=box.ROUNDED, header_style="bold white on blue")
    table.add_column("Scan ID", style="dim", max_width=36)
    table.add_column("Target", style="cyan")
    table.add_column("Profile")
    table.add_column("Started")
    table.add_column("Duration", justify="right")
    table.add_column("Alive", justify="right", style="green")
    table.add_column("Open Ports", justify="right", style="yellow")

    for s in scans:
        duration = f"{s['duration']:.1f}s" if s.get("duration") else "-"
        table.add_row(
            str(s["scan_id"])[:8] + "...",
            str(s["target"]),
            str(s.get("profile") or "-"),
            str(s.get("start_time") or "-"),
            duration,
            str(s.get("alive_hosts", 0)),
            str(s.get("total_open_ports", 0)),
        )
    console.print(table)


@cli.command()
@click.argument("scan_id")
@click.option("-f", "--format", "output_format",
              type=click.Choice(["json", "csv", "xml", "html"]),
              default="json", show_default=True, help="Export format")
@click.option("-o", "--output", required=True, help="Output file path")
@click.option("--db", default="scanner.db", show_default=True, help="Database path")
def export(scan_id: str, output_format: str, output: str, db: str):
    """Export a scan result to file."""
    from scanner.monitoring.history import ScanHistory

    hist = ScanHistory(db_path=db)
    result = hist.get(scan_id)
    if result is None:
        console.print(f"[red]Scan not found:[/] {scan_id}")
        sys.exit(1)

    if output_format == "json":
        from scanner.output.json_output import JSONOutput
        JSONOutput().write(result, output)
    elif output_format == "csv":
        from scanner.output.csv_output import CSVOutput
        CSVOutput().write(result, output)
    elif output_format == "xml":
        from scanner.output.xml_output import XMLOutput
        XMLOutput().write(result, output)
    elif output_format == "html":
        from scanner.output.html_report import HTMLReport
        HTMLReport().write(result, output)

    console.print(f"[green]Exported to:[/] {output}")


if __name__ == "__main__":
    cli()
