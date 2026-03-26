"""Host model."""
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any

from scanner.models.port import Port, PortState


@dataclass
class Host:
    ip: str
    hostname: Optional[str] = None
    mac: Optional[str] = None
    vendor: Optional[str] = None
    os: Optional[str] = None
    ttl: Optional[int] = None
    ports: List[Port] = field(default_factory=list)
    is_alive: bool = True
    response_time: Optional[float] = None

    @property
    def open_ports(self) -> List[Port]:
        """Return only open ports."""
        return [p for p in self.ports if p.state == PortState.OPEN]

    @property
    def display_name(self) -> str:
        if self.hostname:
            return f"{self.hostname} ({self.ip})"
        return self.ip

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "mac": self.mac,
            "vendor": self.vendor,
            "os": self.os,
            "ttl": self.ttl,
            "ports": [p.to_dict() for p in self.ports],
            "is_alive": self.is_alive,
            "response_time": self.response_time,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Host":
        ports = [Port.from_dict(p) for p in data.get("ports", [])]
        return cls(
            ip=data["ip"],
            hostname=data.get("hostname"),
            mac=data.get("mac"),
            vendor=data.get("vendor"),
            os=data.get("os"),
            ttl=data.get("ttl"),
            ports=ports,
            is_alive=data.get("is_alive", True),
            response_time=data.get("response_time"),
        )

    def __str__(self) -> str:
        return f"Host({self.display_name}, alive={self.is_alive}, open_ports={len(self.open_ports)})"
