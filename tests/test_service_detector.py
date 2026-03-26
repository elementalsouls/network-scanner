"""Tests for service detector module."""
import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from scanner.core.service_detector import ServiceDetector
from scanner.models.port import Port, PortState, Protocol
from scanner.models.host import Host


@pytest.fixture
def detector():
    return ServiceDetector(timeout=1.0)


class TestGrabBanner:
    async def test_grab_banner_success(self, detector):
        reader = MagicMock()
        reader.read = AsyncMock(return_value=b"SSH-2.0-OpenSSH_8.0\r\n")
        writer = MagicMock()
        writer.wait_closed = AsyncMock()
        with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_conn:
            mock_conn.return_value = (reader, writer)
            banner = await detector.grab_banner("127.0.0.1", 22)
            assert banner is not None
            assert "SSH" in banner

    async def test_grab_banner_connection_refused(self, detector):
        with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_conn:
            mock_conn.side_effect = ConnectionRefusedError
            banner = await detector.grab_banner("127.0.0.1", 9999)
            assert banner is None

    async def test_grab_banner_timeout(self, detector):
        with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_conn:
            mock_conn.side_effect = asyncio.TimeoutError
            banner = await detector.grab_banner("10.0.0.1", 80)
            assert banner is None

    async def test_grab_banner_udp_returns_none(self, detector):
        banner = await detector.grab_banner("127.0.0.1", 53, Protocol.UDP)
        assert banner is None


class TestIdentifyService:
    def test_identify_ssh(self, detector):
        banner = "SSH-2.0-OpenSSH_8.0"
        service, version = detector.identify_service(banner, 22)
        assert service == "ssh"

    def test_identify_http(self, detector):
        banner = "HTTP/1.1 200 OK\r\nServer: Apache/2.4\r\n"
        service, version = detector.identify_service(banner, 80)
        assert service == "http"

    def test_identify_ftp(self, detector):
        banner = "220 Welcome to FTP server\r\n"
        service, version = detector.identify_service(banner, 21)
        assert service == "ftp"

    def test_unknown_service_uses_well_known_port(self, detector):
        service, version = detector.identify_service(None, 443)
        assert service == "https"

    def test_no_banner_no_service_for_unknown_port(self, detector):
        service, version = detector.identify_service(None, 54321)
        assert service is None


class TestDetectServices:
    async def test_detect_services_for_host(self, detector):
        host = Host(
            ip="127.0.0.1",
            ports=[
                Port(number=22, state=PortState.OPEN),
                Port(number=80, state=PortState.OPEN),
                Port(number=9999, state=PortState.CLOSED),
            ],
        )

        async def fake_grab(ip, port, protocol=Protocol.TCP):
            if port == 22:
                return "SSH-2.0-OpenSSH_8.0"
            if port == 80:
                return "HTTP/1.1 200 OK\r\nServer: nginx/1.18\r\n"
            return None

        with patch.object(detector, "grab_banner", side_effect=fake_grab):
            result = await detector.detect_services(host)
            open_ports = result.open_ports
            assert len(open_ports) == 2

    async def test_skip_non_open_ports(self, detector):
        host = Host(
            ip="127.0.0.1",
            ports=[Port(number=80, state=PortState.CLOSED)],
        )
        with patch.object(detector, "grab_banner", new_callable=AsyncMock) as mock_grab:
            await detector.detect_services(host)
            mock_grab.assert_not_called()
