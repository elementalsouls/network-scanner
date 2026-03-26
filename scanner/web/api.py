"""REST API blueprint."""
import asyncio
import threading
from datetime import datetime
from typing import Any, Dict

from flask import Blueprint, jsonify, request, current_app

from scanner.core.async_engine import ScanEngine
from scanner.monitoring.history import ScanHistory
from scanner.models.scan_result import ScanResult

api_bp = Blueprint("api", __name__)

# In-memory store for running scans
_running_scans: Dict[str, Dict[str, Any]] = {}


def _get_history() -> ScanHistory:
    return current_app.config["SCAN_HISTORY"]


@api_bp.route("/health", methods=["GET"])
def health():
    """Health check endpoint."""
    return jsonify({"status": "ok", "timestamp": datetime.now().isoformat()})


@api_bp.route("/scans", methods=["GET"])
def list_scans():
    """List all saved scans."""
    limit = int(request.args.get("limit", 50))
    target = request.args.get("target")
    history = _get_history()
    scans = history.list_scans(limit=limit, target=target)
    return jsonify({"scans": scans, "count": len(scans)})


@api_bp.route("/scans/<scan_id>", methods=["GET"])
def get_scan(scan_id: str):
    """Get a specific scan result."""
    history = _get_history()
    result = history.get(scan_id)
    if result is None:
        return jsonify({"error": f"Scan {scan_id} not found"}), 404
    return jsonify(result.to_dict())


@api_bp.route("/scans/<scan_id>", methods=["DELETE"])
def delete_scan(scan_id: str):
    """Delete a scan result."""
    history = _get_history()
    deleted = history.delete(scan_id)
    if not deleted:
        return jsonify({"error": f"Scan {scan_id} not found"}), 404
    return jsonify({"message": f"Scan {scan_id} deleted"})


@api_bp.route("/scan", methods=["POST"])
def start_scan():
    """Start an async scan. Returns scan_id immediately."""
    data = request.get_json(force=True, silent=True) or {}
    target = data.get("target")
    if not target:
        return jsonify({"error": "target is required"}), 400

    ports = data.get("ports", "top100")
    scan_type = data.get("scan_type", "connect")
    timeout = float(data.get("timeout", 3.0))
    max_threads = int(data.get("max_threads", 100))
    service_detection = bool(data.get("service_detection", False))
    os_detection = bool(data.get("os_detection", False))
    profile = data.get("profile")

    # Create a placeholder in running scans
    import uuid
    scan_id = str(uuid.uuid4())
    _running_scans[scan_id] = {"status": "running", "target": target, "started": datetime.now().isoformat()}

    db_path = current_app.config["DB_PATH"]

    def _run_scan():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            engine = ScanEngine(
                timeout=timeout,
                max_threads=max_threads,
                service_detection=service_detection,
                os_detection=os_detection,
            )
            result = loop.run_until_complete(engine.scan(
                target=target,
                ports=ports,
                scan_type=scan_type,
                profile_name=profile,
            ))
            # Override scan_id to match what we advertised
            result.scan_id = scan_id
            history = ScanHistory(db_path=db_path)
            history.save(result)
            _running_scans[scan_id] = {"status": "completed", "scan_id": scan_id}
        except Exception as e:
            _running_scans[scan_id] = {"status": "error", "error": str(e)}
        finally:
            loop.close()

    thread = threading.Thread(target=_run_scan, daemon=True)
    thread.start()

    return jsonify({"scan_id": scan_id, "status": "running"}), 202


@api_bp.route("/scan/<scan_id>/status", methods=["GET"])
def scan_status(scan_id: str):
    """Get status of a running or completed scan."""
    if scan_id in _running_scans:
        return jsonify(_running_scans[scan_id])
    history = _get_history()
    result = history.get(scan_id)
    if result:
        return jsonify({"status": "completed", "scan_id": scan_id})
    return jsonify({"error": "Scan not found"}), 404


@api_bp.route("/stats", methods=["GET"])
def stats():
    """Return aggregate scanning statistics."""
    history = _get_history()
    return jsonify(history.get_stats())


@api_bp.route("/profiles", methods=["GET"])
def list_profiles():
    """List available scan profiles."""
    from scanner.config.profiles import PROFILES
    return jsonify({name: p.description for name, p in PROFILES.items()})
