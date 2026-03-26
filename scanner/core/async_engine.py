"""Async scan engine orchestrating discovery, port scanning, and detection."""
import asyncio
from datetime import datetime
from typing import List, Optional, Callable

from scanner.core.network_utils import parse_targets
from scanner.core.host_discovery import HostDiscovery
from scanner.core.port_scanner import PortScanner
from scanner.core.service_detector import ServiceDetector
from scanner.core.os_detector import OSDetector
from scanner.core.mac_vendor import MacVendorLookup, get_mac_from_arp
from scanner.models.host import Host
from scanner.models.scan_result import ScanResult
from scanner.config.profiles import ScanProfile


class ScanEngine:
    """Orchestrates the full scan pipeline."""

    def __init__(
        self,
        timeout: float = 3.0,
        max_threads: int = 100,
        rate_limit: float = 0.0,
        service_detection: bool = False,
        os_detection: bool = False,
        progress_callback: Optional[Callable[[str], None]] = None,
    ):
        self.timeout = timeout
        self.max_threads = max_threads
        self.rate_limit = rate_limit
        self.service_detection = service_detection
        self.os_detection = os_detection
        self.progress_callback = progress_callback

        self.discovery = HostDiscovery(timeout=timeout, max_threads=max_threads)
        self.port_scanner = PortScanner(timeout=timeout, max_threads=max_threads, rate_limit=rate_limit)
        self.service_detector = ServiceDetector(timeout=timeout)
        self.os_detector = OSDetector(timeout=timeout)
        self.mac_vendor = MacVendorLookup()

    def _emit(self, message: str) -> None:
        if self.progress_callback:
            self.progress_callback(message)

    async def scan(
        self,
        target: str,
        ports: str = "top100",
        scan_type: str = "connect",
        ping_only: bool = False,
        profile_name: Optional[str] = None,
    ) -> ScanResult:
        """Execute a full scan against a target."""
        result = ScanResult(
            target=target,
            start_time=datetime.now(),
            profile=profile_name,
        )

        self._emit(f"Parsing targets for {target}...")
        targets = parse_targets(target)
        if not targets:
            result.error = f"Could not resolve target: {target}"
            result.end_time = datetime.now()
            return result

        self._emit(f"Discovering hosts ({len(targets)} targets)...")
        hosts = await self.discovery.discover_hosts(targets)
        result.hosts = hosts

        if ping_only:
            result.end_time = datetime.now()
            return result

        port_list = self.port_scanner.parse_port_spec(ports)
        result.ports_scanned = len(port_list)
        self._emit(f"Scanning {len(port_list)} ports on {len(hosts)} hosts...")

        # Enrich with MAC vendor
        for host in hosts:
            mac = get_mac_from_arp(host.ip)
            if mac:
                host.mac = mac
                vendor = self.mac_vendor.lookup(mac)
                if vendor:
                    host.vendor = vendor

        # Port scan all alive hosts
        scan_tasks = [
            self.port_scanner.scan_host_ports(host, port_list, scan_type)
            for host in hosts
        ]
        scanned_hosts = await asyncio.gather(*scan_tasks, return_exceptions=True)
        result.hosts = [h for h in scanned_hosts if isinstance(h, Host)]

        if self.service_detection:
            self._emit("Detecting services...")
            service_tasks = [self.service_detector.detect_services(h) for h in result.hosts]
            await asyncio.gather(*service_tasks, return_exceptions=True)

        if self.os_detection:
            self._emit("Detecting OS...")
            os_tasks = [self.os_detector.detect_os(h) for h in result.hosts]
            await asyncio.gather(*os_tasks, return_exceptions=True)

        result.end_time = datetime.now()
        self._emit(
            f"Scan complete: {len(result.alive_hosts)} alive, "
            f"{result.total_open_ports} open ports, "
            f"duration {result.duration:.2f}s"
        )
        return result

    @classmethod
    async def run_from_profile(
        cls,
        target: str,
        profile: ScanProfile,
        progress_callback: Optional[Callable[[str], None]] = None,
    ) -> ScanResult:
        """Run a scan using a profile configuration."""
        engine = cls(
            timeout=profile.timeout,
            max_threads=profile.max_threads,
            rate_limit=profile.rate_limit,
            service_detection=profile.service_detection,
            os_detection=profile.os_detection,
            progress_callback=progress_callback,
        )
        ports = profile.ports or "top100"
        return await engine.scan(
            target=target,
            ports=ports,
            scan_type=profile.scan_type,
            ping_only=profile.ping_only,
            profile_name=profile.name,
        )
