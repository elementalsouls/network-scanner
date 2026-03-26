"""Port scanner module."""
import asyncio
import socket
import time
from typing import List, Optional, Tuple

try:
    from scapy.all import IP, TCP, sr1  # type: ignore
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

from scanner.models.port import Port, PortState, Protocol
from scanner.models.host import Host
from scanner.config.constants import WELL_KNOWN_PORTS, TOP_100_PORTS, TOP_1000_PORTS


class PortScanner:
    """Scans ports on target hosts."""

    def __init__(self, timeout: float = 3.0, max_threads: int = 100, rate_limit: float = 0.0):
        self.timeout = timeout
        self.max_threads = max_threads
        self.rate_limit = rate_limit

    def parse_port_spec(self, port_spec: str) -> List[int]:
        """Parse port specification string into a list of port numbers.

        Supports: 'top100', 'top1000', 'all', single ports, ranges (80-443),
        and comma-separated lists (22,80,443).
        """
        if port_spec == "top100":
            return list(TOP_100_PORTS)
        if port_spec == "top1000":
            return list(TOP_1000_PORTS)
        if port_spec == "all":
            return list(range(1, 65536))

        ports: List[int] = []
        for part in port_spec.split(","):
            part = part.strip()
            if "-" in part:
                start_s, end_s = part.split("-", 1)
                start = int(start_s.strip())
                end = int(end_s.strip())
                ports.extend(range(start, end + 1))
            elif part.isdigit():
                ports.append(int(part))
        return sorted(set(p for p in ports if 1 <= p <= 65535))

    async def tcp_connect_scan(self, ip: str, port: int) -> Port:
        """Attempt a full TCP connect to determine port state."""
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=self.timeout,
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            service = WELL_KNOWN_PORTS.get(port)
            return Port(number=port, protocol=Protocol.TCP, state=PortState.OPEN, service=service)
        except asyncio.TimeoutError:
            return Port(number=port, protocol=Protocol.TCP, state=PortState.FILTERED)
        except ConnectionRefusedError:
            return Port(number=port, protocol=Protocol.TCP, state=PortState.CLOSED)
        except OSError:
            return Port(number=port, protocol=Protocol.TCP, state=PortState.FILTERED)

    async def tcp_syn_scan(self, ip: str, port: int) -> Port:
        """SYN scan using scapy (requires root). Falls back to connect scan."""
        if not HAS_SCAPY:
            return await self.tcp_connect_scan(ip, port)

        loop = asyncio.get_event_loop()

        def _syn_probe() -> Port:
            try:
                pkt = IP(dst=ip) / TCP(dport=port, flags="S")
                resp = sr1(pkt, timeout=self.timeout, verbose=False)
                if resp is None:
                    return Port(number=port, protocol=Protocol.TCP, state=PortState.FILTERED)
                if resp.haslayer(TCP):
                    flags = resp[TCP].flags
                    if flags == 0x12:  # SYN-ACK
                        service = WELL_KNOWN_PORTS.get(port)
                        return Port(number=port, protocol=Protocol.TCP, state=PortState.OPEN, service=service)
                    elif flags == 0x14:  # RST-ACK
                        return Port(number=port, protocol=Protocol.TCP, state=PortState.CLOSED)
                return Port(number=port, protocol=Protocol.TCP, state=PortState.FILTERED)
            except Exception:
                return Port(number=port, protocol=Protocol.TCP, state=PortState.UNKNOWN)

        return await loop.run_in_executor(None, _syn_probe)

    async def udp_scan(self, ip: str, port: int) -> Port:
        """UDP port scan."""
        if not HAS_SCAPY:
            return Port(number=port, protocol=Protocol.UDP, state=PortState.OPEN_FILTERED)

        from scapy.all import UDP, ICMP  # type: ignore

        loop = asyncio.get_event_loop()

        def _udp_probe() -> Port:
            try:
                pkt = IP(dst=ip) / UDP(dport=port)
                resp = sr1(pkt, timeout=self.timeout, verbose=False)
                if resp is None:
                    return Port(number=port, protocol=Protocol.UDP, state=PortState.OPEN_FILTERED)
                if resp.haslayer(UDP):
                    service = WELL_KNOWN_PORTS.get(port)
                    return Port(number=port, protocol=Protocol.UDP, state=PortState.OPEN, service=service)
                if resp.haslayer(ICMP):
                    icmp_type = resp[ICMP].type
                    if icmp_type == 3:  # Destination unreachable
                        return Port(number=port, protocol=Protocol.UDP, state=PortState.CLOSED)
                return Port(number=port, protocol=Protocol.UDP, state=PortState.OPEN_FILTERED)
            except Exception:
                return Port(number=port, protocol=Protocol.UDP, state=PortState.UNKNOWN)

        return await loop.run_in_executor(None, _udp_probe)

    async def scan_host_ports(
        self,
        host: Host,
        ports: List[int],
        scan_type: str = "connect",
    ) -> Host:
        """Scan all specified ports on a host and return updated host."""
        semaphore = asyncio.Semaphore(self.max_threads)
        scanned_ports: List[Port] = []

        async def scan_port(port: int) -> Port:
            async with semaphore:
                if self.rate_limit > 0:
                    await asyncio.sleep(self.rate_limit)
                if scan_type == "syn":
                    return await self.tcp_syn_scan(host.ip, port)
                elif scan_type == "udp":
                    return await self.udp_scan(host.ip, port)
                else:
                    return await self.tcp_connect_scan(host.ip, port)

        tasks = [scan_port(p) for p in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, Port):
                scanned_ports.append(result)

        host.ports = scanned_ports
        return host
