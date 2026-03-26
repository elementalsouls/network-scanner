"""OS detection module."""
import asyncio
import re
import socket
import struct
from typing import Optional, Dict, Tuple

try:
    from scapy.all import IP, TCP, ICMP, sr1  # type: ignore
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

from scanner.models.host import Host
from scanner.config.constants import OS_TTL_SIGNATURES


class OSDetector:
    """Detects operating system information using TTL and fingerprinting techniques."""

    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout

    def detect_os_from_ttl(self, ttl: int) -> Optional[str]:
        """Guess OS from TTL value."""
        for (low, high), os_name in OS_TTL_SIGNATURES.items():
            if low <= ttl <= high:
                return os_name
        return None

    async def get_ttl(self, ip: str) -> Optional[int]:
        """Get TTL from ICMP ping response using scapy."""
        if not HAS_SCAPY:
            return await self._get_ttl_socket(ip)

        loop = asyncio.get_event_loop()

        def _probe() -> Optional[int]:
            try:
                pkt = IP(dst=ip) / ICMP()
                resp = sr1(pkt, timeout=self.timeout, verbose=False)
                if resp and resp.haslayer(IP):
                    return resp[IP].ttl
            except Exception:
                pass
            return None

        return await loop.run_in_executor(None, _probe)

    async def _get_ttl_socket(self, ip: str) -> Optional[int]:
        """Attempt to get TTL using a raw ping subprocess."""
        import subprocess
        import platform
        import re

        system = platform.system().lower()
        cmd = ["ping", "-c", "1", ip] if system != "windows" else ["ping", "-n", "1", ip]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=self.timeout + 2)
            output = stdout.decode("utf-8", errors="replace")
            match = re.search(r"ttl[= ](\d+)", output, re.IGNORECASE)
            if match:
                return int(match.group(1))
        except (asyncio.TimeoutError, FileNotFoundError):
            pass
        return None

    async def tcp_fingerprint(self, ip: str, port: int = 80) -> Dict[str, Optional[str]]:
        """Basic TCP fingerprinting - analyze TCP window size and options."""
        if not HAS_SCAPY:
            return {}

        loop = asyncio.get_event_loop()

        def _fingerprint() -> Dict[str, Optional[str]]:
            try:
                pkt = IP(dst=ip) / TCP(dport=port, flags="S", options=[("MSS", 1460), ("SAck", b"")])
                resp = sr1(pkt, timeout=self.timeout, verbose=False)
                if resp and resp.haslayer(TCP):
                    tcp = resp[TCP]
                    return {
                        "window_size": str(tcp.window),
                        "flags": str(tcp.flags),
                        "ttl": str(resp[IP].ttl) if resp.haslayer(IP) else None,
                    }
            except Exception:
                pass
            return {}

        return await loop.run_in_executor(None, _fingerprint)

    async def detect_os(self, host: Host) -> Host:
        """Detect OS for a host and update the host object."""
        # Try TTL-based detection
        ttl = await self.get_ttl(host.ip)
        if ttl:
            host.ttl = ttl
            os_guess = self.detect_os_from_ttl(ttl)
            if os_guess:
                host.os = os_guess

        # Try TCP fingerprinting if we have open ports
        if not host.os and host.open_ports:
            first_port = host.open_ports[0].number
            fingerprint = await self.tcp_fingerprint(host.ip, first_port)
            if fingerprint.get("ttl"):
                try:
                    ttl = int(fingerprint["ttl"])
                    host.ttl = ttl
                    os_guess = self.detect_os_from_ttl(ttl)
                    if os_guess:
                        host.os = os_guess
                except (ValueError, TypeError):
                    pass

        return host
