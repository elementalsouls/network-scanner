"""Service detection module."""
import asyncio
import re
import socket
from typing import Optional, Tuple

from scanner.models.port import Port, PortState, Protocol
from scanner.models.host import Host
from scanner.config.constants import SERVICE_SIGNATURES, WELL_KNOWN_PORTS


class ServiceDetector:
    """Detects services and version information on open ports."""

    BANNER_TIMEOUT = 3.0
    MAX_BANNER_BYTES = 1024

    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout

    async def grab_banner(self, ip: str, port: int, protocol: Protocol = Protocol.TCP) -> Optional[str]:
        """Attempt to grab a service banner from an open port."""
        if protocol == Protocol.UDP:
            return None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=self.timeout,
            )
            banner = b""
            try:
                banner = await asyncio.wait_for(
                    reader.read(self.MAX_BANNER_BYTES),
                    timeout=self.timeout,
                )
            except asyncio.TimeoutError:
                # Some services only respond after a probe
                probe = b"\r\n"
                writer.write(probe)
                await writer.drain()
                try:
                    banner = await asyncio.wait_for(
                        reader.read(self.MAX_BANNER_BYTES),
                        timeout=self.timeout,
                    )
                except asyncio.TimeoutError:
                    pass
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return banner.decode("utf-8", errors="replace").strip() if banner else None
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None

    def identify_service(self, banner: Optional[str], port: int) -> Tuple[Optional[str], Optional[str]]:
        """Identify service and version from banner. Returns (service, version)."""
        service = WELL_KNOWN_PORTS.get(port)

        if not banner:
            return service, None

        # Try signature matching
        for svc_name, pattern in SERVICE_SIGNATURES.items():
            try:
                if re.search(pattern, banner, re.IGNORECASE | re.DOTALL):
                    # Try to extract version
                    version = self._extract_version(svc_name, banner)
                    return svc_name, version
            except re.error:
                continue

        # Extract version from banner generically
        version = self._extract_generic_version(banner)
        return service, version

    def _extract_version(self, service: str, banner: str) -> Optional[str]:
        """Extract version string for known services."""
        patterns = {
            "ssh": r"SSH-([\d.]+)-(\S+)",
            "http": r"Server:\s*(.+?)[\r\n]",
            "ftp": r"220[- ](.+?)[\r\n]",
            "smtp": r"220[- ](.+?)[\r\n]",
            "pop3": r"\+OK (.+?)[\r\n]",
            "imap": r"\* OK (.+?)[\r\n]",
        }
        pattern = patterns.get(service)
        if pattern:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                return match.group(1).strip()[:100]
        return None

    def _extract_generic_version(self, banner: str) -> Optional[str]:
        """Try to extract a version from a banner generically."""
        version_match = re.search(r"([\w\-]+)[/ ]([\d]+\.[\d]+(?:\.[\d]+)?)", banner)
        if version_match:
            return f"{version_match.group(1)} {version_match.group(2)}"
        return None

    async def detect_port_service(self, ip: str, port: Port) -> Port:
        """Detect service on a single open port."""
        if port.state != PortState.OPEN:
            return port

        banner = await self.grab_banner(ip, port.number, port.protocol)
        service, version = self.identify_service(banner, port.number)

        if service:
            port.service = service
        if version:
            port.version = version
        if banner:
            port.banner = banner[:256]

        return port

    async def detect_services(self, host: Host) -> Host:
        """Detect services for all open ports on a host."""
        tasks = [
            self.detect_port_service(host.ip, port)
            for port in host.ports
            if port.state == PortState.OPEN
        ]
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        return host
