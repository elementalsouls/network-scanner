"""Console output using rich library."""
from datetime import datetime
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

from scanner.models.scan_result import ScanResult
from scanner.models.host import Host
from scanner.models.port import PortState


_console = Console()


def get_console() -> Console:
    return _console


def print_scan_summary(result: ScanResult, console: Optional[Console] = None) -> None:
    """Print a summary of scan results to the console."""
    c = console or _console

    duration = f"{result.duration:.2f}s" if result.duration else "N/A"
    title = f"Scan Results: [bold cyan]{result.target}[/]"
    if result.profile:
        title += f" [dim](profile: {result.profile})[/]"

    summary = (
        f"[green]Alive hosts:[/] {len(result.alive_hosts)}/{len(result.hosts)}  "
        f"[yellow]Open ports:[/] {result.total_open_ports}  "
        f"[blue]Ports scanned:[/] {result.ports_scanned}  "
        f"[dim]Duration:[/] {duration}"
    )
    c.print(Panel(summary, title=title, border_style="blue"))


def print_host_table(result: ScanResult, console: Optional[Console] = None) -> None:
    """Print host overview table."""
    c = console or _console

    table = Table(
        title="Discovered Hosts",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold white on blue",
    )
    table.add_column("IP Address", style="cyan", no_wrap=True)
    table.add_column("Hostname", style="white")
    table.add_column("Status", justify="center")
    table.add_column("OS", style="yellow")
    table.add_column("MAC", style="dim")
    table.add_column("Vendor", style="magenta")
    table.add_column("RTT", justify="right", style="green")
    table.add_column("Open Ports", justify="right", style="bold green")

    for host in result.hosts:
        status = "[green]● Alive[/]" if host.is_alive else "[dim]○ Down[/]"
        rtt = f"{host.response_time:.1f}ms" if host.response_time else ""
        table.add_row(
            host.ip,
            host.hostname or "",
            status,
            host.os or "",
            host.mac or "",
            host.vendor or "",
            rtt,
            str(len(host.open_ports)),
        )

    c.print(table)


def print_port_table(host: Host, console: Optional[Console] = None) -> None:
    """Print open ports for a single host."""
    c = console or _console

    if not host.open_ports:
        return

    table = Table(
        title=f"Open Ports: {host.display_name}",
        box=box.SIMPLE_HEAD,
        show_header=True,
        header_style="bold",
    )
    table.add_column("Port", justify="right", style="cyan")
    table.add_column("Protocol", style="blue")
    table.add_column("State", style="green")
    table.add_column("Service", style="yellow")
    table.add_column("Version", style="white")

    for port in sorted(host.open_ports, key=lambda p: p.number):
        table.add_row(
            str(port.number),
            port.protocol.value.upper(),
            port.state.value,
            port.service or "",
            port.version or "",
        )

    c.print(table)


def print_full_results(result: ScanResult, console: Optional[Console] = None) -> None:
    """Print complete scan results including host and port tables."""
    c = console or _console
    print_scan_summary(result, c)
    if result.hosts:
        print_host_table(result, c)
        for host in result.alive_hosts:
            if host.open_ports:
                print_port_table(host, c)


def create_progress() -> Progress:
    """Create a rich Progress bar for scan progress display."""
    return Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=_console,
    )
