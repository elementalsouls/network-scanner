"""ScanResult model."""
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict, Any

from scanner.models.host import Host


@dataclass
class ScanResult:
    target: str
    hosts: List[Host] = field(default_factory=list)
    scan_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    profile: Optional[str] = None
    ports_scanned: int = 0
    error: Optional[str] = None

    @property
    def alive_hosts(self) -> List[Host]:
        """Return only alive hosts."""
        return [h for h in self.hosts if h.is_alive]

    @property
    def duration(self) -> Optional[float]:
        """Return scan duration in seconds."""
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return None

    @property
    def total_open_ports(self) -> int:
        return sum(len(h.open_ports) for h in self.hosts)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "profile": self.profile,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration": self.duration,
            "ports_scanned": self.ports_scanned,
            "hosts_found": len(self.hosts),
            "alive_hosts": len(self.alive_hosts),
            "total_open_ports": self.total_open_ports,
            "error": self.error,
            "hosts": [h.to_dict() for h in self.hosts],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScanResult":
        hosts = [Host.from_dict(h) for h in data.get("hosts", [])]
        start_time = None
        end_time = None
        if data.get("start_time"):
            start_time = datetime.fromisoformat(data["start_time"])
        if data.get("end_time"):
            end_time = datetime.fromisoformat(data["end_time"])
        return cls(
            scan_id=data.get("scan_id", str(uuid.uuid4())),
            target=data["target"],
            hosts=hosts,
            start_time=start_time,
            end_time=end_time,
            profile=data.get("profile"),
            ports_scanned=data.get("ports_scanned", 0),
            error=data.get("error"),
        )

    def __str__(self) -> str:
        return (
            f"ScanResult(target={self.target}, alive={len(self.alive_hosts)}/{len(self.hosts)}, "
            f"open_ports={self.total_open_ports}, duration={self.duration:.2f}s)"
            if self.duration
            else f"ScanResult(target={self.target})"
        )
