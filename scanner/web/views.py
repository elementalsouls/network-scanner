"""Flask views (HTML pages)."""
from flask import Blueprint, render_template, current_app

from scanner.monitoring.history import ScanHistory

views_bp = Blueprint("views", __name__)


def _get_history() -> ScanHistory:
    return current_app.config["SCAN_HISTORY"]


@views_bp.route("/")
def dashboard():
    history = _get_history()
    scans = history.list_scans(limit=10)
    stats = history.get_stats()
    return render_template("dashboard.html", scans=scans, stats=stats)


@views_bp.route("/scan")
def scan_page():
    return render_template("scan.html")


@views_bp.route("/results/<scan_id>")
def results_page(scan_id: str):
    history = _get_history()
    result = history.get(scan_id)
    if result is None:
        return render_template("dashboard.html", error=f"Scan {scan_id} not found", scans=[], stats={}), 404
    return render_template("results.html", result=result, result_dict=result.to_dict())
