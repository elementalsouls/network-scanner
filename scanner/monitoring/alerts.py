"""Alert management for network monitoring."""
import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Optional, Callable, Dict, Any


class AlertLevel(str, Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass
class Alert:
    level: AlertLevel
    message: str
    source_ip: Optional[str] = None
    port: Optional[int] = None
    timestamp: datetime = field(default_factory=datetime.now)
    acknowledged: bool = False
    details: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "level": self.level.value,
            "message": self.message,
            "source_ip": self.source_ip,
            "port": self.port,
            "timestamp": self.timestamp.isoformat(),
            "acknowledged": self.acknowledged,
            "details": self.details,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Alert":
        return cls(
            level=AlertLevel(data["level"]),
            message=data["message"],
            source_ip=data.get("source_ip"),
            port=data.get("port"),
            timestamp=datetime.fromisoformat(data["timestamp"]) if data.get("timestamp") else datetime.now(),
            acknowledged=data.get("acknowledged", False),
            details=data.get("details"),
        )


class AlertManager:
    """Manages alerts generated during network monitoring."""

    def __init__(self, max_alerts: int = 1000):
        self.max_alerts = max_alerts
        self._alerts: List[Alert] = []
        self._handlers: List[Callable[[Alert], None]] = []

    def add_handler(self, handler: Callable[[Alert], None]) -> None:
        """Register a callback that will be called for each new alert."""
        self._handlers.append(handler)

    def create_alert(
        self,
        level: AlertLevel,
        message: str,
        source_ip: Optional[str] = None,
        port: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> Alert:
        """Create and store a new alert, calling all registered handlers."""
        alert = Alert(
            level=level,
            message=message,
            source_ip=source_ip,
            port=port,
            details=details,
        )
        self._alerts.append(alert)
        # Trim if exceeding max
        if len(self._alerts) > self.max_alerts:
            self._alerts = self._alerts[-self.max_alerts:]
        # Notify handlers
        for handler in self._handlers:
            try:
                handler(alert)
            except Exception:
                pass
        return alert

    def get_alerts(
        self,
        level: Optional[AlertLevel] = None,
        unacknowledged_only: bool = False,
        limit: int = 100,
    ) -> List[Alert]:
        """Retrieve alerts with optional filtering."""
        alerts = self._alerts
        if level:
            alerts = [a for a in alerts if a.level == level]
        if unacknowledged_only:
            alerts = [a for a in alerts if not a.acknowledged]
        return sorted(alerts, key=lambda a: a.timestamp, reverse=True)[:limit]

    def acknowledge(self, index: int) -> bool:
        """Acknowledge an alert by index. Returns True if found."""
        alerts = self.get_alerts()
        if 0 <= index < len(alerts):
            alerts[index].acknowledged = True
            return True
        return False

    def acknowledge_all(self) -> int:
        """Acknowledge all unacknowledged alerts. Returns count."""
        count = 0
        for alert in self._alerts:
            if not alert.acknowledged:
                alert.acknowledged = True
                count += 1
        return count

    def clear(self) -> None:
        """Clear all alerts."""
        self._alerts.clear()

    @property
    def unacknowledged_count(self) -> int:
        return sum(1 for a in self._alerts if not a.acknowledged)

    @property
    def critical_count(self) -> int:
        return sum(1 for a in self._alerts if a.level == AlertLevel.CRITICAL)
