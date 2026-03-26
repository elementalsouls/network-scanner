"""Tests for the CLI."""
import json
import pytest
from click.testing import CliRunner
from unittest.mock import patch, MagicMock, AsyncMock

from scanner.cli import cli


@pytest.fixture
def runner():
    return CliRunner()


class TestScanCommand:
    def test_scan_invokes_engine(self, runner):
        mock_result = MagicMock()
        mock_result.error = None
        mock_result.alive_hosts = []
        mock_result.hosts = []
        mock_result.total_open_ports = 0
        mock_result.ports_scanned = 100
        mock_result.duration = 1.0
        mock_result.target = "127.0.0.1"
        mock_result.profile = None

        with patch("scanner.core.async_engine.ScanEngine") as mock_engine_cls:
            mock_engine = MagicMock()
            mock_engine_cls.return_value = mock_engine
            with patch("scanner.cli.asyncio.run", return_value=mock_result):
                result = runner.invoke(cli, ["scan", "127.0.0.1", "--ports", "80"])
                assert result.exit_code == 0

    def test_scan_with_json_output(self, runner, tmp_path):
        from scanner.models.scan_result import ScanResult
        from datetime import datetime
        scan_result = ScanResult(
            target="127.0.0.1",
            start_time=datetime.now(),
            end_time=datetime.now(),
        )

        with patch("scanner.cli.asyncio.run", return_value=scan_result):
            output_file = str(tmp_path / "out.json")
            result = runner.invoke(cli, [
                "scan", "127.0.0.1",
                "--format", "json",
                "--output", output_file,
            ])
            assert result.exit_code == 0
            with open(output_file) as f:
                data = json.load(f)
            assert data["target"] == "127.0.0.1"

    def test_scan_invalid_profile(self, runner):
        result = runner.invoke(cli, ["scan", "127.0.0.1", "--profile", "nonexistent_profile"])
        assert result.exit_code != 0 or "Unknown profile" in result.output

    def test_scan_help(self, runner):
        result = runner.invoke(cli, ["scan", "--help"])
        assert result.exit_code == 0
        assert "TARGET" in result.output


class TestHistoryCommand:
    def test_history_no_scans(self, runner, tmp_path):
        db_path = str(tmp_path / "empty.db")
        result = runner.invoke(cli, ["history", "--db", db_path])
        assert result.exit_code == 0
        assert "No scan history" in result.output

    def test_history_with_scans(self, runner, tmp_path, sample_scan_result):
        from scanner.monitoring.history import ScanHistory
        db_path = str(tmp_path / "test.db")
        hist = ScanHistory(db_path=db_path)
        hist.save(sample_scan_result)

        result = runner.invoke(cli, ["history", "--db", db_path])
        assert result.exit_code == 0
        # Check for duration and alive hosts which are in narrower columns
        assert "30.0s" in result.output
        assert "Scan History" in result.output


class TestExportCommand:
    def test_export_json(self, runner, tmp_path, sample_scan_result):
        from scanner.monitoring.history import ScanHistory
        db_path = str(tmp_path / "test.db")
        hist = ScanHistory(db_path=db_path)
        hist.save(sample_scan_result)

        output_file = str(tmp_path / "export.json")
        result = runner.invoke(cli, [
            "export", sample_scan_result.scan_id,
            "--format", "json",
            "--output", output_file,
            "--db", db_path,
        ])
        assert result.exit_code == 0
        assert "Exported to" in result.output

    def test_export_csv(self, runner, tmp_path, sample_scan_result):
        from scanner.monitoring.history import ScanHistory
        db_path = str(tmp_path / "test.db")
        hist = ScanHistory(db_path=db_path)
        hist.save(sample_scan_result)

        output_file = str(tmp_path / "export.csv")
        result = runner.invoke(cli, [
            "export", sample_scan_result.scan_id,
            "--format", "csv",
            "--output", output_file,
            "--db", db_path,
        ])
        assert result.exit_code == 0

    def test_export_nonexistent_scan(self, runner, tmp_path):
        db_path = str(tmp_path / "empty.db")
        result = runner.invoke(cli, [
            "export", "nonexistent-id",
            "--format", "json",
            "--output", str(tmp_path / "out.json"),
            "--db", db_path,
        ])
        assert result.exit_code != 0


class TestWebCommand:
    def test_web_help(self, runner):
        result = runner.invoke(cli, ["web", "--help"])
        assert result.exit_code == 0
        assert "--port" in result.output


class TestCliGeneral:
    def test_version(self, runner):
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "1.0.0" in result.output

    def test_help(self, runner):
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "scan" in result.output
        assert "monitor" in result.output
        assert "web" in result.output
        assert "history" in result.output
