"""Port model."""
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Dict, Any


class PortState(str, Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    OPEN_FILTERED = "open|filtered"
    UNKNOWN = "unknown"


class Protocol(str, Enum):
    TCP = "tcp"
    UDP = "udp"


@dataclass
class Port:
    number: int
    protocol: Protocol = Protocol.TCP
    state: PortState = PortState.UNKNOWN
    service: Optional[str] = None
    version: Optional[str] = None
    banner: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "number": self.number,
            "protocol": self.protocol.value,
            "state": self.state.value,
            "service": self.service,
            "version": self.version,
            "banner": self.banner,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Port":
        return cls(
            number=data["number"],
            protocol=Protocol(data.get("protocol", "tcp")),
            state=PortState(data.get("state", "unknown")),
            service=data.get("service"),
            version=data.get("version"),
            banner=data.get("banner"),
        )

    def __str__(self) -> str:
        svc = f" ({self.service})" if self.service else ""
        return f"{self.number}/{self.protocol.value}{svc} [{self.state.value}]"
