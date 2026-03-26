"""Scan history storage using SQLite."""
import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any

from scanner.models.scan_result import ScanResult


class ScanHistory:
    """Persists scan results in a SQLite database."""

    def __init__(self, db_path: str = "scanner.db"):
        self.db_path = db_path
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        """Create tables if they don't exist."""
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT UNIQUE NOT NULL,
                    target TEXT NOT NULL,
                    profile TEXT,
                    start_time TEXT,
                    end_time TEXT,
                    duration REAL,
                    hosts_found INTEGER DEFAULT 0,
                    alive_hosts INTEGER DEFAULT 0,
                    total_open_ports INTEGER DEFAULT 0,
                    ports_scanned INTEGER DEFAULT 0,
                    error TEXT,
                    data TEXT NOT NULL,
                    created_at TEXT DEFAULT (datetime('now'))
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_scans_start_time ON scans(start_time)
            """)
            conn.commit()

    def save(self, result: ScanResult) -> int:
        """Save a ScanResult to the database. Returns row id."""
        data_json = json.dumps(result.to_dict())
        with self._get_connection() as conn:
            cursor = conn.execute(
                """
                INSERT OR REPLACE INTO scans
                    (scan_id, target, profile, start_time, end_time, duration,
                     hosts_found, alive_hosts, total_open_ports, ports_scanned, error, data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result.scan_id,
                    result.target,
                    result.profile,
                    result.start_time.isoformat() if result.start_time else None,
                    result.end_time.isoformat() if result.end_time else None,
                    result.duration,
                    len(result.hosts),
                    len(result.alive_hosts),
                    result.total_open_ports,
                    result.ports_scanned,
                    result.error,
                    data_json,
                ),
            )
            conn.commit()
            return cursor.lastrowid

    def get(self, scan_id: str) -> Optional[ScanResult]:
        """Retrieve a scan result by its scan_id."""
        with self._get_connection() as conn:
            row = conn.execute("SELECT data FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
            if row:
                return ScanResult.from_dict(json.loads(row["data"]))
        return None

    def list_scans(self, limit: int = 50, target: Optional[str] = None) -> List[Dict[str, Any]]:
        """List recent scans (metadata only, no full host data)."""
        query = """
            SELECT scan_id, target, profile, start_time, end_time, duration,
                   hosts_found, alive_hosts, total_open_ports, ports_scanned, error, created_at
            FROM scans
        """
        params: list = []
        if target:
            query += " WHERE target LIKE ?"
            params.append(f"%{target}%")
        query += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        with self._get_connection() as conn:
            rows = conn.execute(query, params).fetchall()
            return [dict(row) for row in rows]

    def delete(self, scan_id: str) -> bool:
        """Delete a scan result. Returns True if deleted."""
        with self._get_connection() as conn:
            cursor = conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
            conn.commit()
            return cursor.rowcount > 0

    def get_stats(self) -> Dict[str, Any]:
        """Return aggregate statistics across all scans."""
        with self._get_connection() as conn:
            row = conn.execute("""
                SELECT
                    COUNT(*) as total_scans,
                    SUM(alive_hosts) as total_alive_hosts,
                    SUM(total_open_ports) as total_open_ports,
                    AVG(duration) as avg_duration,
                    MAX(start_time) as last_scan
                FROM scans
            """).fetchone()
            return dict(row) if row else {}

    def close(self) -> None:
        """No-op: connections are opened per-operation."""
        pass
