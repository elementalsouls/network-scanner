"""Host discovery module."""
import asyncio
import socket
import subprocess
import platform
from typing import List, Optional, Dict

try:
    from scapy.all import ARP, Ether, srp  # type: ignore
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

from scanner.models.host import Host


class HostDiscovery:
    """Discovers live hosts on the network."""

    def __init__(self, timeout: float = 1.0, max_threads: int = 100):
        self.timeout = timeout
        self.max_threads = max_threads

    async def ping_host(self, ip: str) -> Optional[float]:
        """ICMP ping a host. Returns response time in ms or None if unreachable."""
        system = platform.system().lower()
        if system == "windows":
            cmd = ["ping", "-n", "1", "-w", str(int(self.timeout * 1000)), ip]
        else:
            cmd = ["ping", "-c", "1", "-W", str(int(self.timeout)), ip]

        try:
            start = asyncio.get_event_loop().time()
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(proc.wait(), timeout=self.timeout + 1)
            elapsed = (asyncio.get_event_loop().time() - start) * 1000
            if proc.returncode == 0:
                return elapsed
        except (asyncio.TimeoutError, FileNotFoundError):
            pass
        return None

    async def tcp_ping(self, ip: str, port: int = 80) -> Optional[float]:
        """TCP ping - attempt connection to check if host is alive."""
        try:
            start = asyncio.get_event_loop().time()
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=self.timeout,
            )
            elapsed = (asyncio.get_event_loop().time() - start) * 1000
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return elapsed
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None

    def arp_scan(self, network: str) -> List[Dict[str, str]]:
        """ARP scan to discover hosts and MAC addresses on the local network."""
        results: List[Dict[str, str]] = []
        if not HAS_SCAPY:
            return results
        try:
            arp_request = ARP(pdst=network)
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = broadcast / arp_request
            answered, _ = srp(packet, timeout=int(self.timeout), verbose=False)
            for sent, received in answered:
                results.append({"ip": received.psrc, "mac": received.hwsrc})
        except Exception:
            pass
        return results

    async def discover_hosts(self, targets: List[str]) -> List[Host]:
        """Discover alive hosts from a list of target IPs."""
        semaphore = asyncio.Semaphore(self.max_threads)
        hosts: List[Host] = []

        async def check_host(ip: str) -> Optional[Host]:
            async with semaphore:
                response_time = await self.ping_host(ip)
                if response_time is None:
                    # Try TCP fallback on common ports
                    for port in [80, 443, 22, 445]:
                        response_time = await self.tcp_ping(ip, port)
                        if response_time is not None:
                            break

                is_alive = response_time is not None
                if is_alive:
                    hostname = await self._resolve_hostname(ip)
                    return Host(
                        ip=ip,
                        hostname=hostname,
                        is_alive=True,
                        response_time=response_time,
                    )
                return None

        tasks = [check_host(ip) for ip in targets]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, Host):
                hosts.append(result)

        return hosts

    async def _resolve_hostname(self, ip: str) -> Optional[str]:
        """Resolve hostname from IP via reverse DNS."""
        loop = asyncio.get_event_loop()
        try:
            result = await loop.run_in_executor(None, lambda: socket.gethostbyaddr(ip)[0])
            return result
        except (socket.herror, socket.gaierror):
            return None
