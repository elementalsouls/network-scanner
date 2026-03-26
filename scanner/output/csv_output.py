"""CSV output formatter."""
import csv
import io
from typing import List

from scanner.models.scan_result import ScanResult
from scanner.models.host import Host
from scanner.models.port import PortState


class CSVOutput:
    """Output scan results as CSV."""

    HOST_FIELDS = ["ip", "hostname", "mac", "vendor", "os", "ttl", "is_alive", "response_time", "open_ports"]
    PORT_FIELDS = ["ip", "port", "protocol", "state", "service", "version", "banner"]

    def format_hosts(self, result: ScanResult) -> str:
        """Format hosts as CSV (one row per host)."""
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=self.HOST_FIELDS)
        writer.writeheader()
        for host in result.hosts:
            writer.writerow({
                "ip": host.ip,
                "hostname": host.hostname or "",
                "mac": host.mac or "",
                "vendor": host.vendor or "",
                "os": host.os or "",
                "ttl": host.ttl or "",
                "is_alive": host.is_alive,
                "response_time": f"{host.response_time:.2f}" if host.response_time else "",
                "open_ports": len(host.open_ports),
            })
        return output.getvalue()

    def format_ports(self, result: ScanResult) -> str:
        """Format ports as CSV (one row per port)."""
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=self.PORT_FIELDS)
        writer.writeheader()
        for host in result.hosts:
            for port in host.ports:
                if port.state == PortState.OPEN:
                    writer.writerow({
                        "ip": host.ip,
                        "port": port.number,
                        "protocol": port.protocol.value,
                        "state": port.state.value,
                        "service": port.service or "",
                        "version": port.version or "",
                        "banner": (port.banner or "").replace("\n", " ").replace("\r", ""),
                    })
        return output.getvalue()

    def format(self, result: ScanResult) -> str:
        """Format hosts + ports as combined CSV."""
        return self.format_ports(result)

    def write(self, result: ScanResult, filepath: str, mode: str = "ports") -> None:
        """Write CSV output to a file."""
        content = self.format_hosts(result) if mode == "hosts" else self.format_ports(result)
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            f.write(content)
