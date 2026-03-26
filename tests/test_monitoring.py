"""Tests for monitoring modules."""
import pytest
import time
from datetime import datetime
from unittest.mock import MagicMock, patch

from scanner.monitoring.history import ScanHistory
from scanner.monitoring.alerts import AlertManager, AlertLevel, Alert
from scanner.models.scan_result import ScanResult
from scanner.models.host import Host
from scanner.models.port import Port, PortState


class TestScanHistory:
    def test_save_and_retrieve(self, temp_db, sample_scan_result):
        temp_db.save(sample_scan_result)
        retrieved = temp_db.get(sample_scan_result.scan_id)
        assert retrieved is not None
        assert retrieved.scan_id == sample_scan_result.scan_id
        assert retrieved.target == sample_scan_result.target

    def test_list_scans_empty(self, temp_db):
        scans = temp_db.list_scans()
        assert scans == []

    def test_list_scans_returns_metadata(self, temp_db, sample_scan_result):
        temp_db.save(sample_scan_result)
        scans = temp_db.list_scans()
        assert len(scans) == 1
        assert scans[0]["target"] == "192.168.1.0/24"
        assert "start_time" in scans[0]

    def test_list_scans_limit(self, temp_db):
        for i in range(5):
            result = ScanResult(target=f"10.0.0.{i}", scan_id=f"scan-{i}")
            temp_db.save(result)
        scans = temp_db.list_scans(limit=3)
        assert len(scans) == 3

    def test_list_scans_filter_by_target(self, temp_db):
        temp_db.save(ScanResult(target="192.168.1.0/24", scan_id="scan-a"))
        temp_db.save(ScanResult(target="10.0.0.1", scan_id="scan-b"))
        scans = temp_db.list_scans(target="192.168")
        assert len(scans) == 1
        assert scans[0]["target"] == "192.168.1.0/24"

    def test_delete_scan(self, temp_db, sample_scan_result):
        temp_db.save(sample_scan_result)
        deleted = temp_db.delete(sample_scan_result.scan_id)
        assert deleted is True
        assert temp_db.get(sample_scan_result.scan_id) is None

    def test_delete_nonexistent(self, temp_db):
        deleted = temp_db.delete("nonexistent-id")
        assert deleted is False

    def test_get_stats(self, temp_db, sample_scan_result):
        temp_db.save(sample_scan_result)
        stats = temp_db.get_stats()
        assert stats["total_scans"] == 1

    def test_upsert_on_same_scan_id(self, temp_db, sample_scan_result):
        temp_db.save(sample_scan_result)
        temp_db.save(sample_scan_result)
        scans = temp_db.list_scans()
        assert len(scans) == 1


class TestAlertManager:
    @pytest.fixture
    def manager(self):
        return AlertManager()

    def test_create_alert(self, manager):
        alert = manager.create_alert(AlertLevel.INFO, "Test alert")
        assert alert.level == AlertLevel.INFO
        assert alert.message == "Test alert"
        assert not alert.acknowledged

    def test_get_alerts(self, manager):
        manager.create_alert(AlertLevel.INFO, "info alert")
        manager.create_alert(AlertLevel.WARNING, "warning alert")
        manager.create_alert(AlertLevel.CRITICAL, "critical alert")

        all_alerts = manager.get_alerts()
        assert len(all_alerts) == 3

    def test_filter_by_level(self, manager):
        manager.create_alert(AlertLevel.INFO, "info")
        manager.create_alert(AlertLevel.WARNING, "warn")
        manager.create_alert(AlertLevel.CRITICAL, "critical")

        critical_alerts = manager.get_alerts(level=AlertLevel.CRITICAL)
        assert len(critical_alerts) == 1
        assert critical_alerts[0].level == AlertLevel.CRITICAL

    def test_acknowledge_all(self, manager):
        manager.create_alert(AlertLevel.INFO, "a")
        manager.create_alert(AlertLevel.WARNING, "b")
        count = manager.acknowledge_all()
        assert count == 2
        assert manager.unacknowledged_count == 0

    def test_unacknowledged_count(self, manager):
        manager.create_alert(AlertLevel.INFO, "a")
        manager.create_alert(AlertLevel.INFO, "b")
        assert manager.unacknowledged_count == 2

    def test_critical_count(self, manager):
        manager.create_alert(AlertLevel.INFO, "a")
        manager.create_alert(AlertLevel.CRITICAL, "b")
        manager.create_alert(AlertLevel.CRITICAL, "c")
        assert manager.critical_count == 2

    def test_handler_called(self, manager):
        received = []
        manager.add_handler(lambda alert: received.append(alert))
        manager.create_alert(AlertLevel.WARNING, "test")
        assert len(received) == 1
        assert received[0].message == "test"

    def test_max_alerts_trimmed(self):
        manager = AlertManager(max_alerts=5)
        for i in range(10):
            manager.create_alert(AlertLevel.INFO, f"alert {i}")
        assert len(manager.get_alerts(limit=100)) == 5

    def test_alert_with_source_ip(self, manager):
        alert = manager.create_alert(AlertLevel.CRITICAL, "port open", source_ip="10.0.0.1", port=22)
        assert alert.source_ip == "10.0.0.1"
        assert alert.port == 22

    def test_alert_to_dict(self, manager):
        alert = manager.create_alert(AlertLevel.WARNING, "test", source_ip="1.2.3.4")
        d = alert.to_dict()
        assert d["level"] == "warning"
        assert d["source_ip"] == "1.2.3.4"

    def test_clear_alerts(self, manager):
        manager.create_alert(AlertLevel.INFO, "a")
        manager.create_alert(AlertLevel.INFO, "b")
        manager.clear()
        assert manager.get_alerts() == []
