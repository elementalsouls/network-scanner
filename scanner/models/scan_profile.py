"""ScanProfile model (standalone)."""
from dataclasses import dataclass
from typing import Optional, Dict, Any


@dataclass
class ScanProfile:
    name: str
    description: str
    ping_only: bool = False
    ports: Optional[str] = None
    scan_type: str = "connect"
    service_detection: bool = False
    os_detection: bool = False
    timeout: float = 3.0
    max_threads: int = 100
    rate_limit: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "ping_only": self.ping_only,
            "ports": self.ports,
            "scan_type": self.scan_type,
            "service_detection": self.service_detection,
            "os_detection": self.os_detection,
            "timeout": self.timeout,
            "max_threads": self.max_threads,
            "rate_limit": self.rate_limit,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScanProfile":
        return cls(
            name=data["name"],
            description=data.get("description", ""),
            ping_only=data.get("ping_only", False),
            ports=data.get("ports"),
            scan_type=data.get("scan_type", "connect"),
            service_detection=data.get("service_detection", False),
            os_detection=data.get("os_detection", False),
            timeout=data.get("timeout", 3.0),
            max_threads=data.get("max_threads", 100),
            rate_limit=data.get("rate_limit", 0.0),
        )
