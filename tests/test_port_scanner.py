"""Tests for port scanner module."""
import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from scanner.core.port_scanner import PortScanner
from scanner.models.port import Port, PortState, Protocol
from scanner.models.host import Host


@pytest.fixture
def scanner():
    return PortScanner(timeout=1.0, max_threads=10)


class TestParsePortSpec:
    def test_top100(self, scanner):
        ports = scanner.parse_port_spec("top100")
        assert len(ports) == 100
        assert 80 in ports
        assert 443 in ports

    def test_top1000(self, scanner):
        ports = scanner.parse_port_spec("top1000")
        assert len(ports) == 1000

    def test_all(self, scanner):
        ports = scanner.parse_port_spec("all")
        assert len(ports) == 65535
        assert 1 in ports
        assert 65535 in ports

    def test_single_port(self, scanner):
        ports = scanner.parse_port_spec("80")
        assert ports == [80]

    def test_range(self, scanner):
        ports = scanner.parse_port_spec("80-85")
        assert ports == [80, 81, 82, 83, 84, 85]

    def test_comma_separated(self, scanner):
        ports = scanner.parse_port_spec("22,80,443")
        assert ports == [22, 80, 443]

    def test_mixed(self, scanner):
        ports = scanner.parse_port_spec("22,80-82,443")
        assert 22 in ports
        assert 80 in ports
        assert 81 in ports
        assert 82 in ports
        assert 443 in ports

    def test_deduplication(self, scanner):
        ports = scanner.parse_port_spec("80,80,80")
        assert ports.count(80) == 1


class TestTcpConnectScan:
    async def test_open_port(self, scanner):
        with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_conn:
            writer = MagicMock()
            writer.wait_closed = AsyncMock()
            mock_conn.return_value = (MagicMock(), writer)
            port = await scanner.tcp_connect_scan("127.0.0.1", 80)
            assert port.state == PortState.OPEN
            assert port.number == 80

    async def test_closed_port(self, scanner):
        with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_conn:
            mock_conn.side_effect = ConnectionRefusedError
            port = await scanner.tcp_connect_scan("127.0.0.1", 9999)
            assert port.state == PortState.CLOSED

    async def test_filtered_port(self, scanner):
        with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_conn:
            mock_conn.side_effect = asyncio.TimeoutError
            port = await scanner.tcp_connect_scan("10.0.0.1", 80)
            assert port.state == PortState.FILTERED

    async def test_service_assigned(self, scanner):
        with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_conn:
            writer = MagicMock()
            writer.wait_closed = AsyncMock()
            mock_conn.return_value = (MagicMock(), writer)
            port = await scanner.tcp_connect_scan("127.0.0.1", 22)
            assert port.service == "ssh"


class TestScanHostPorts:
    async def test_scan_host(self, scanner):
        host = Host(ip="192.168.1.1", is_alive=True)

        async def fake_scan(ip, port):
            if port == 80:
                return Port(number=80, state=PortState.OPEN, service="http")
            return Port(number=port, state=PortState.CLOSED)

        with patch.object(scanner, "tcp_connect_scan", side_effect=fake_scan):
            result = await scanner.scan_host_ports(host, [80, 443, 8080])
            open_ports = [p for p in result.ports if p.state == PortState.OPEN]
            assert len(open_ports) == 1
            assert open_ports[0].number == 80

    async def test_scan_empty_ports(self, scanner):
        host = Host(ip="10.0.0.1")
        result = await scanner.scan_host_ports(host, [])
        assert result.ports == []
