"""Tests for the Flask REST API."""
import json
import pytest
from unittest.mock import patch, MagicMock


class TestHealthEndpoint:
    def test_health_ok(self, flask_client):
        resp = flask_client.get("/api/health")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "ok"
        assert "timestamp" in data


class TestScansEndpoint:
    def test_list_scans_empty(self, flask_client):
        resp = flask_client.get("/api/scans")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["scans"] == []
        assert data["count"] == 0

    def test_list_scans_with_data(self, flask_client, flask_app, sample_scan_result):
        with flask_app.app_context():
            hist = flask_app.config["SCAN_HISTORY"]
            hist.save(sample_scan_result)

        resp = flask_client.get("/api/scans")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["count"] == 1
        assert data["scans"][0]["target"] == "192.168.1.0/24"

    def test_get_scan_by_id(self, flask_client, flask_app, sample_scan_result):
        with flask_app.app_context():
            hist = flask_app.config["SCAN_HISTORY"]
            hist.save(sample_scan_result)

        resp = flask_client.get(f"/api/scans/{sample_scan_result.scan_id}")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["scan_id"] == sample_scan_result.scan_id

    def test_get_scan_not_found(self, flask_client):
        resp = flask_client.get("/api/scans/nonexistent-id")
        assert resp.status_code == 404

    def test_delete_scan(self, flask_client, flask_app, sample_scan_result):
        with flask_app.app_context():
            hist = flask_app.config["SCAN_HISTORY"]
            hist.save(sample_scan_result)

        resp = flask_client.delete(f"/api/scans/{sample_scan_result.scan_id}")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "deleted" in data["message"]

    def test_delete_nonexistent_scan(self, flask_client):
        resp = flask_client.delete("/api/scans/nonexistent-id")
        assert resp.status_code == 404


class TestStartScanEndpoint:
    def test_start_scan_requires_target(self, flask_client):
        resp = flask_client.post("/api/scan", json={})
        assert resp.status_code == 400
        data = resp.get_json()
        assert "error" in data

    def test_start_scan_returns_scan_id(self, flask_client):
        with patch("scanner.web.api.threading.Thread") as mock_thread:
            mock_thread.return_value.start = MagicMock()
            resp = flask_client.post("/api/scan", json={"target": "127.0.0.1"})
            assert resp.status_code == 202
            data = resp.get_json()
            assert "scan_id" in data
            assert data["status"] == "running"

    def test_scan_status_running(self, flask_client):
        with patch("scanner.web.api.threading.Thread") as mock_thread:
            mock_thread.return_value.start = MagicMock()
            resp = flask_client.post("/api/scan", json={"target": "127.0.0.1"})
            scan_id = resp.get_json()["scan_id"]

        resp = flask_client.get(f"/api/scan/{scan_id}/status")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] in ("running", "completed", "error")


class TestStatsEndpoint:
    def test_stats_empty(self, flask_client):
        resp = flask_client.get("/api/stats")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "total_scans" in data

    def test_stats_with_data(self, flask_client, flask_app, sample_scan_result):
        with flask_app.app_context():
            hist = flask_app.config["SCAN_HISTORY"]
            hist.save(sample_scan_result)

        resp = flask_client.get("/api/stats")
        assert resp.status_code == 200
        data = resp.get_json()
        assert int(data.get("total_scans", 0)) >= 1


class TestProfilesEndpoint:
    def test_list_profiles(self, flask_client):
        resp = flask_client.get("/api/profiles")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "quick" in data
        assert "full" in data
        assert "stealth" in data
        assert "service" in data
