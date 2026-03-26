"""Tests for host discovery module."""
import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from scanner.core.host_discovery import HostDiscovery
from scanner.models.host import Host


@pytest.fixture
def discovery():
    return HostDiscovery(timeout=1.0, max_threads=10)


class TestPingHost:
    async def test_ping_success(self, discovery):
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            proc = MagicMock()
            proc.returncode = 0
            proc.wait = AsyncMock(return_value=0)
            mock_exec.return_value = proc
            result = await discovery.ping_host("192.168.1.1")
            assert result is not None
            assert result >= 0

    async def test_ping_failure(self, discovery):
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            proc = MagicMock()
            proc.returncode = 1
            proc.wait = AsyncMock(return_value=1)
            mock_exec.return_value = proc
            result = await discovery.ping_host("192.168.1.255")
            assert result is None

    async def test_ping_timeout(self, discovery):
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            proc = MagicMock()
            proc.wait = AsyncMock(side_effect=asyncio.TimeoutError)
            mock_exec.return_value = proc
            result = await discovery.ping_host("10.0.0.1")
            assert result is None


class TestTcpPing:
    async def test_tcp_ping_open(self, discovery):
        with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_conn:
            writer = MagicMock()
            writer.wait_closed = AsyncMock()
            mock_conn.return_value = (MagicMock(), writer)
            result = await discovery.tcp_ping("127.0.0.1", 80)
            assert result is not None
            assert result >= 0

    async def test_tcp_ping_refused(self, discovery):
        with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_conn:
            mock_conn.side_effect = ConnectionRefusedError
            result = await discovery.tcp_ping("127.0.0.1", 9999)
            assert result is None

    async def test_tcp_ping_timeout(self, discovery):
        with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_conn:
            mock_conn.side_effect = asyncio.TimeoutError
            result = await discovery.tcp_ping("10.255.255.1", 80)
            assert result is None


class TestDiscoverHosts:
    async def test_discover_alive_hosts(self, discovery):
        with patch.object(discovery, "ping_host", new_callable=AsyncMock) as mock_ping:
            mock_ping.return_value = 5.0  # 5ms response time
            with patch.object(discovery, "_resolve_hostname", new_callable=AsyncMock) as mock_dns:
                mock_dns.return_value = "host.local"
                hosts = await discovery.discover_hosts(["192.168.1.1", "192.168.1.2"])
                assert len(hosts) == 2
                assert all(h.is_alive for h in hosts)
                assert all(h.hostname == "host.local" for h in hosts)

    async def test_discover_no_alive_hosts(self, discovery):
        with patch.object(discovery, "ping_host", new_callable=AsyncMock) as mock_ping:
            mock_ping.return_value = None
            with patch.object(discovery, "tcp_ping", new_callable=AsyncMock) as mock_tcp:
                mock_tcp.return_value = None
                hosts = await discovery.discover_hosts(["10.0.0.1"])
                assert len(hosts) == 0

    async def test_discover_empty_list(self, discovery):
        hosts = await discovery.discover_hosts([])
        assert hosts == []

    async def test_tcp_fallback_when_ping_fails(self, discovery):
        with patch.object(discovery, "ping_host", new_callable=AsyncMock) as mock_ping:
            mock_ping.return_value = None
            with patch.object(discovery, "tcp_ping", new_callable=AsyncMock) as mock_tcp:
                # First TCP ping attempt succeeds
                mock_tcp.return_value = 10.0
                with patch.object(discovery, "_resolve_hostname", new_callable=AsyncMock) as mock_dns:
                    mock_dns.return_value = None
                    hosts = await discovery.discover_hosts(["10.0.0.1"])
                    assert len(hosts) == 1
                    assert hosts[0].is_alive is True
