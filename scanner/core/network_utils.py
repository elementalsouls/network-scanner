"""Network utility functions."""
import ipaddress
import socket
import subprocess
import re
from typing import List, Optional, Dict, Any

try:
    import netifaces
    HAS_NETIFACES = True
except ImportError:
    HAS_NETIFACES = False


def parse_targets(target: str) -> List[str]:
    """Parse target string into list of IP addresses.

    Supports CIDR notation, IP ranges (192.168.1.1-254), single IPs, and hostnames.
    """
    targets: List[str] = []
    target = target.strip()

    # CIDR notation
    try:
        network = ipaddress.ip_network(target, strict=False)
        return [str(ip) for ip in network.hosts()]
    except ValueError:
        pass

    # IP range like 192.168.1.1-254
    range_match = re.match(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})$", target)
    if range_match:
        base = range_match.group(1)
        start = int(range_match.group(2))
        end = int(range_match.group(3))
        for i in range(start, end + 1):
            ip = f"{base}{i}"
            if is_valid_ip(ip):
                targets.append(ip)
        return targets

    # Full range like 192.168.1.1-192.168.1.254
    full_range_match = re.match(
        r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})-(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$",
        target,
    )
    if full_range_match:
        start_ip = ip_to_int(full_range_match.group(1))
        end_ip = ip_to_int(full_range_match.group(2))
        for i in range(start_ip, end_ip + 1):
            targets.append(int_to_ip(i))
        return targets

    # Single IP
    if is_valid_ip(target):
        return [target]

    # Hostname - resolve it
    resolved = resolve_hostname(target)
    if resolved:
        return [resolved]

    return []


def resolve_hostname(hostname: str) -> Optional[str]:
    """Resolve hostname to IP address."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def get_local_interfaces() -> List[Dict[str, Any]]:
    """Get local network interfaces with addresses."""
    interfaces = []

    if HAS_NETIFACES:
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            ipv4 = addrs.get(netifaces.AF_INET, [])
            mac_info = addrs.get(netifaces.AF_LINK, [])
            mac = mac_info[0].get("addr", "") if mac_info else ""
            for addr in ipv4:
                ip = addr.get("addr", "")
                netmask = addr.get("netmask", "")
                if ip and not ip.startswith("127."):
                    interfaces.append({
                        "name": iface,
                        "ip": ip,
                        "netmask": netmask,
                        "mac": mac,
                    })
    else:
        # Fallback using socket
        try:
            hostname = socket.gethostname()
            ip = socket.gethostbyname(hostname)
            interfaces.append({"name": "default", "ip": ip, "netmask": "", "mac": ""})
        except Exception:
            pass

    return interfaces


def get_local_network() -> Optional[str]:
    """Get primary local network CIDR."""
    interfaces = get_local_interfaces()
    for iface in interfaces:
        ip = iface.get("ip", "")
        netmask = iface.get("netmask", "")
        if ip and netmask:
            try:
                network = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                return str(network)
            except ValueError:
                continue
        elif ip:
            # Default to /24
            parts = ip.rsplit(".", 1)
            if len(parts) == 2:
                return f"{parts[0]}.0/24"
    return None


def is_valid_ip(ip: str) -> bool:
    """Check if string is a valid IPv4 address."""
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ValueError:
        return False


def ip_to_int(ip: str) -> int:
    """Convert IPv4 address string to integer."""
    parts = ip.split(".")
    result = 0
    for part in parts:
        result = result * 256 + int(part)
    return result


def int_to_ip(n: int) -> str:
    """Convert integer to IPv4 address string."""
    parts = []
    for _ in range(4):
        parts.append(str(n & 0xFF))
        n >>= 8
    return ".".join(reversed(parts))


def calculate_subnet_info(cidr: str) -> Dict[str, Any]:
    """Calculate subnet information from CIDR notation."""
    try:
        network = ipaddress.IPv4Network(cidr, strict=False)
        return {
            "network": str(network.network_address),
            "broadcast": str(network.broadcast_address),
            "netmask": str(network.netmask),
            "prefix_length": network.prefixlen,
            "num_hosts": network.num_addresses - 2 if network.num_addresses > 2 else 0,
            "first_host": str(list(network.hosts())[0]) if list(network.hosts()) else None,
            "last_host": str(list(network.hosts())[-1]) if list(network.hosts()) else None,
            "cidr": cidr,
        }
    except ValueError as e:
        raise ValueError(f"Invalid CIDR notation: {cidr}") from e


def get_reverse_dns(ip: str) -> Optional[str]:
    """Get reverse DNS entry for an IP address."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return None
