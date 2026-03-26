"""Network watcher for continuous monitoring."""
import asyncio
import threading
import time
from datetime import datetime
from typing import Optional, Callable, List, Dict, Any

from scanner.core.async_engine import ScanEngine
from scanner.monitoring.history import ScanHistory
from scanner.monitoring.alerts import AlertManager, AlertLevel
from scanner.models.scan_result import ScanResult
from scanner.models.host import Host
from scanner.models.port import PortState


class NetworkWatcher:
    """Continuously monitors a target network and raises alerts on changes."""

    def __init__(
        self,
        target: str,
        interval: int = 300,
        ports: str = "top100",
        db_path: str = "scanner.db",
        alert_manager: Optional[AlertManager] = None,
        on_change: Optional[Callable[[Dict[str, Any]], None]] = None,
    ):
        self.target = target
        self.interval = interval
        self.ports = ports
        self.history = ScanHistory(db_path=db_path)
        self.alert_manager = alert_manager or AlertManager()
        self.on_change = on_change

        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._last_result: Optional[ScanResult] = None
        self._scan_count = 0

    def start(self) -> None:
        """Start the monitoring loop in a background thread."""
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop the monitoring loop."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=10)

    def _run_loop(self) -> None:
        """Main monitoring loop running in a thread."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            while self._running:
                try:
                    result = loop.run_until_complete(self._do_scan())
                    self._process_result(result)
                except Exception as e:
                    self.alert_manager.create_alert(
                        AlertLevel.WARNING,
                        f"Scan error for {self.target}: {e}",
                    )
                # Sleep in chunks so we can respond to stop()
                for _ in range(self.interval):
                    if not self._running:
                        break
                    time.sleep(1)
        finally:
            loop.close()

    async def _do_scan(self) -> ScanResult:
        """Execute a single monitoring scan."""
        engine = ScanEngine(timeout=3.0, max_threads=50)
        return await engine.scan(target=self.target, ports=self.ports)

    def _process_result(self, result: ScanResult) -> None:
        """Compare result against previous scan and raise alerts on changes."""
        self._scan_count += 1
        self.history.save(result)

        if self._last_result is None:
            self._last_result = result
            self.alert_manager.create_alert(
                AlertLevel.INFO,
                f"Initial scan of {self.target}: {len(result.alive_hosts)} hosts alive",
            )
            return

        changes = self._diff_results(self._last_result, result)
        for change in changes:
            level = change.get("level", AlertLevel.INFO)
            self.alert_manager.create_alert(
                level=level,
                message=change["message"],
                source_ip=change.get("ip"),
                port=change.get("port"),
                details=change,
            )
            if self.on_change:
                try:
                    self.on_change(change)
                except Exception:
                    pass

        self._last_result = result

    def _diff_results(
        self,
        previous: ScanResult,
        current: ScanResult,
    ) -> List[Dict[str, Any]]:
        """Generate list of changes between two scan results."""
        changes: List[Dict[str, Any]] = []
        prev_hosts = {h.ip: h for h in previous.alive_hosts}
        curr_hosts = {h.ip: h for h in current.alive_hosts}

        # New hosts
        for ip in set(curr_hosts) - set(prev_hosts):
            changes.append({
                "type": "new_host",
                "ip": ip,
                "message": f"New host detected: {ip}",
                "level": AlertLevel.WARNING,
            })

        # Hosts that went down
        for ip in set(prev_hosts) - set(curr_hosts):
            changes.append({
                "type": "host_down",
                "ip": ip,
                "message": f"Host went offline: {ip}",
                "level": AlertLevel.INFO,
            })

        # Port changes on existing hosts
        for ip in set(prev_hosts) & set(curr_hosts):
            prev_open = {p.number for p in prev_hosts[ip].open_ports}
            curr_open = {p.number for p in curr_hosts[ip].open_ports}

            for port_num in curr_open - prev_open:
                changes.append({
                    "type": "port_opened",
                    "ip": ip,
                    "port": port_num,
                    "message": f"New open port on {ip}: {port_num}",
                    "level": AlertLevel.CRITICAL,
                })

            for port_num in prev_open - curr_open:
                changes.append({
                    "type": "port_closed",
                    "ip": ip,
                    "port": port_num,
                    "message": f"Port closed on {ip}: {port_num}",
                    "level": AlertLevel.INFO,
                })

        return changes

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def scan_count(self) -> int:
        return self._scan_count
