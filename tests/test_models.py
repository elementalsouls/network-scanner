"""Tests for data models."""
import pytest
from datetime import datetime
from scanner.models.port import Port, PortState, Protocol
from scanner.models.host import Host
from scanner.models.scan_result import ScanResult
from scanner.models.scan_profile import ScanProfile


class TestPort:
    def test_default_values(self):
        port = Port(number=80)
        assert port.number == 80
        assert port.protocol == Protocol.TCP
        assert port.state == PortState.UNKNOWN
        assert port.service is None

    def test_to_dict(self):
        port = Port(number=443, protocol=Protocol.TCP, state=PortState.OPEN, service="https")
        d = port.to_dict()
        assert d["number"] == 443
        assert d["protocol"] == "tcp"
        assert d["state"] == "open"
        assert d["service"] == "https"

    def test_from_dict(self):
        data = {"number": 22, "protocol": "tcp", "state": "open", "service": "ssh", "version": "8.0"}
        port = Port.from_dict(data)
        assert port.number == 22
        assert port.state == PortState.OPEN
        assert port.service == "ssh"

    def test_roundtrip(self):
        port = Port(number=8080, protocol=Protocol.TCP, state=PortState.FILTERED, service="http-alt")
        port2 = Port.from_dict(port.to_dict())
        assert port2.number == port.number
        assert port2.state == port.state
        assert port2.service == port.service

    def test_str(self):
        port = Port(number=80, protocol=Protocol.TCP, state=PortState.OPEN, service="http")
        s = str(port)
        assert "80" in s
        assert "tcp" in s
        assert "open" in s


class TestHost:
    def test_default_values(self):
        host = Host(ip="10.0.0.1")
        assert host.ip == "10.0.0.1"
        assert host.ports == []
        assert host.is_alive is True

    def test_open_ports_property(self):
        ports = [
            Port(number=80, state=PortState.OPEN),
            Port(number=443, state=PortState.OPEN),
            Port(number=8080, state=PortState.CLOSED),
            Port(number=22, state=PortState.FILTERED),
        ]
        host = Host(ip="10.0.0.1", ports=ports)
        assert len(host.open_ports) == 2
        assert all(p.state == PortState.OPEN for p in host.open_ports)

    def test_display_name_with_hostname(self):
        host = Host(ip="10.0.0.1", hostname="server.local")
        assert "server.local" in host.display_name
        assert "10.0.0.1" in host.display_name

    def test_display_name_without_hostname(self):
        host = Host(ip="10.0.0.1")
        assert host.display_name == "10.0.0.1"

    def test_to_dict(self):
        host = Host(ip="192.168.1.1", hostname="test.local", is_alive=True)
        d = host.to_dict()
        assert d["ip"] == "192.168.1.1"
        assert d["hostname"] == "test.local"
        assert d["is_alive"] is True
        assert isinstance(d["ports"], list)

    def test_from_dict(self):
        data = {
            "ip": "192.168.1.2",
            "hostname": "host2.local",
            "mac": "AA:BB:CC:DD:EE:FF",
            "is_alive": True,
            "ports": [{"number": 80, "protocol": "tcp", "state": "open"}],
        }
        host = Host.from_dict(data)
        assert host.ip == "192.168.1.2"
        assert len(host.ports) == 1

    def test_roundtrip(self):
        host = Host(
            ip="10.0.0.1",
            hostname="test",
            mac="00:11:22:33:44:55",
            os="Linux/Unix",
            ttl=64,
            ports=[Port(number=22, state=PortState.OPEN, service="ssh")],
        )
        host2 = Host.from_dict(host.to_dict())
        assert host2.ip == host.ip
        assert host2.os == host.os
        assert len(host2.ports) == 1


class TestScanResult:
    def test_alive_hosts(self, sample_scan_result):
        assert len(sample_scan_result.alive_hosts) == 1
        assert sample_scan_result.alive_hosts[0].ip == "192.168.1.1"

    def test_duration(self, sample_scan_result):
        assert sample_scan_result.duration == 30.0

    def test_total_open_ports(self, sample_scan_result):
        assert sample_scan_result.total_open_ports == 2

    def test_to_dict(self, sample_scan_result):
        d = sample_scan_result.to_dict()
        assert d["target"] == "192.168.1.0/24"
        assert d["alive_hosts"] == 1
        assert d["duration"] == 30.0
        assert len(d["hosts"]) == 2

    def test_from_dict_roundtrip(self, sample_scan_result):
        d = sample_scan_result.to_dict()
        result2 = ScanResult.from_dict(d)
        assert result2.target == sample_scan_result.target
        assert result2.scan_id == sample_scan_result.scan_id
        assert len(result2.hosts) == 2

    def test_scan_id_auto_generated(self):
        result = ScanResult(target="10.0.0.1")
        assert result.scan_id
        assert len(result.scan_id) == 36  # UUID4 format

    def test_duration_none_when_times_missing(self):
        result = ScanResult(target="10.0.0.1")
        assert result.duration is None


class TestScanProfile:
    def test_to_dict(self):
        profile = ScanProfile(name="test", description="A test profile", ports="top100")
        d = profile.to_dict()
        assert d["name"] == "test"
        assert d["ports"] == "top100"

    def test_from_dict(self):
        data = {"name": "quick", "description": "Quick scan", "ports": "top100", "timeout": 2.0}
        profile = ScanProfile.from_dict(data)
        assert profile.name == "quick"
        assert profile.timeout == 2.0

    def test_defaults(self):
        profile = ScanProfile(name="default", description="")
        assert profile.scan_type == "connect"
        assert profile.service_detection is False
        assert profile.os_detection is False
        assert profile.max_threads == 100
