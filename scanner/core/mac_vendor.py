"""MAC address vendor lookup."""
import re
import subprocess
from typing import Optional, Dict

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from scanner.config.constants import OUI_API_URL

_OUI_DATABASE: Dict[str, str] = {
    "00:00:0C": "Cisco Systems",
    "00:50:56": "VMware",
    "00:0C:29": "VMware",
    "00:1A:11": "Google",
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Foundation",
    "E4:5F:01": "Raspberry Pi Foundation",
    "00:1B:63": "Apple",
    "00:25:00": "Apple",
    "AC:DE:48": "Apple",
    "3C:22:FB": "Apple",
    "00:50:F2": "Microsoft",
    "00:15:5D": "Microsoft (Hyper-V)",
    "00:03:FF": "Microsoft",
    "00:1C:14": "VMware",
    "00:0D:56": "Dell",
    "00:14:22": "Dell",
    "18:03:73": "Dell",
    "B0:83:FE": "Dell",
    "3C:4A:92": "HP",
    "00:1F:29": "HP",
    "00:23:7D": "HP",
    "00:08:55": "Intel",
    "00:02:B3": "Intel",
    "00:AA:00": "Intel",
    "48:45:20": "Intel",
    "00:07:E9": "Intel",
    "FC:AA:14": "ASUSTek",
    "00:1D:60": "ASUSTek",
    "00:26:18": "ASUSTek",
    "00:10:DB": "Juniper Networks",
    "28:8A:1C": "Juniper Networks",
    "00:16:3E": "Xen Virtual",
    "52:54:00": "QEMU/KVM",
    "00:E0:4C": "Realtek",
    "00:0B:82": "Grandstream",
    "00:04:F2": "Polycom",
    "00:1E:8C": "TP-Link",
    "50:C7:BF": "TP-Link",
    "C0:4A:00": "TP-Link",
    "00:23:CD": "Netgear",
    "20:E5:2A": "Netgear",
    "28:C6:8E": "Netgear",
    "00:18:4D": "Netgear",
    "00:0F:B5": "Netgear",
    "00:17:F2": "Apple",
    "00:19:E3": "Apple",
    "00:1C:B3": "Apple",
    "00:1E:52": "Apple",
    "70:56:81": "Apple",
}


def _normalize_mac(mac: str) -> str:
    """Normalize MAC address to uppercase colon-separated format."""
    mac = mac.upper().replace("-", ":").replace(".", ":")
    # Handle formats without separators (AABBCCDDEEFF)
    if len(mac) == 12 and ":" not in mac:
        mac = ":".join(mac[i:i+2] for i in range(0, 12, 2))
    return mac


def _get_oui(mac: str) -> str:
    """Extract OUI (first 3 octets) from MAC address."""
    normalized = _normalize_mac(mac)
    parts = normalized.split(":")
    if len(parts) >= 3:
        return ":".join(parts[:3])
    return ""


class MacVendorLookup:
    """Lookup MAC address vendor information."""

    def __init__(self, use_api: bool = False, api_timeout: float = 3.0):
        self.use_api = use_api
        self.api_timeout = api_timeout
        self._cache: Dict[str, Optional[str]] = {}

    def lookup(self, mac: str) -> Optional[str]:
        """Look up vendor from embedded OUI database."""
        oui = _get_oui(mac)
        if not oui:
            return None

        # Check cache
        if oui in self._cache:
            return self._cache[oui]

        # Check embedded database
        vendor = _OUI_DATABASE.get(oui)
        if vendor:
            self._cache[oui] = vendor
            return vendor

        # Try API if enabled
        if self.use_api and HAS_REQUESTS:
            vendor = self._lookup_api(mac)
            self._cache[oui] = vendor
            return vendor

        self._cache[oui] = None
        return None

    def _lookup_api(self, mac: str) -> Optional[str]:
        """Look up vendor via macvendors.com API."""
        try:
            url = OUI_API_URL.format(mac=mac)
            response = requests.get(url, timeout=self.api_timeout)
            if response.status_code == 200:
                return response.text.strip()
        except Exception:
            pass
        return None

    def get_all_vendors(self) -> Dict[str, str]:
        """Return a copy of the embedded OUI database."""
        return dict(_OUI_DATABASE)


def get_mac_from_arp(ip: str) -> Optional[str]:
    """Get MAC address for an IP from the system ARP table."""
    try:
        result = subprocess.run(
            ["arp", "-n", ip],
            capture_output=True,
            text=True,
            timeout=5,
        )
        output = result.stdout
        # Match MAC address pattern
        mac_match = re.search(r"([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}", output)
        if mac_match:
            return _normalize_mac(mac_match.group(0))
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        pass
    return None
