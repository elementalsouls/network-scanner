"""Pytest fixtures for network scanner tests."""
import pytest
import tempfile
import os
from datetime import datetime
from unittest.mock import MagicMock

from scanner.models.port import Port, PortState, Protocol
from scanner.models.host import Host
from scanner.models.scan_result import ScanResult
from scanner.config.settings import ScannerSettings
from scanner.monitoring.history import ScanHistory


@pytest.fixture
def sample_port_open():
    return Port(number=80, protocol=Protocol.TCP, state=PortState.OPEN, service="http", version="Apache 2.4")


@pytest.fixture
def sample_port_ssh():
    return Port(number=22, protocol=Protocol.TCP, state=PortState.OPEN, service="ssh", version="OpenSSH 8.0")


@pytest.fixture
def sample_host(sample_port_open, sample_port_ssh):
    return Host(
        ip="192.168.1.1",
        hostname="gateway.local",
        mac="00:1A:11:AA:BB:CC",
        vendor="Google",
        os="Linux/Unix",
        ttl=64,
        ports=[sample_port_open, sample_port_ssh],
        is_alive=True,
        response_time=1.5,
    )


@pytest.fixture
def sample_host_down():
    return Host(ip="192.168.1.254", is_alive=False)


@pytest.fixture
def sample_scan_result(sample_host, sample_host_down):
    return ScanResult(
        scan_id="test-scan-001",
        target="192.168.1.0/24",
        hosts=[sample_host, sample_host_down],
        start_time=datetime(2024, 1, 1, 12, 0, 0),
        end_time=datetime(2024, 1, 1, 12, 0, 30),
        profile="quick",
        ports_scanned=100,
    )


@pytest.fixture
def mock_settings():
    return ScannerSettings(
        timeout=1.0,
        max_threads=10,
        max_retries=1,
        rate_limit=0.0,
        verbose=False,
    )


@pytest.fixture
def temp_db(tmp_path):
    """Provide a temporary SQLite database for testing."""
    db_path = str(tmp_path / "test_scanner.db")
    history = ScanHistory(db_path=db_path)
    yield history
    # Cleanup is handled by tmp_path fixture


@pytest.fixture
def flask_app(tmp_path):
    """Create a Flask test application."""
    from scanner.web.app import create_app
    db_path = str(tmp_path / "test.db")
    app = create_app(db_path=db_path, testing=True)
    return app


@pytest.fixture
def flask_client(flask_app):
    """Flask test client."""
    return flask_app.test_client()
