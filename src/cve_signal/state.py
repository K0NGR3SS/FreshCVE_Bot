from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import sqlite3


class StateStore:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(path)
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS cves (
                cve_id TEXT PRIMARY KEY,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                notified_at TEXT
            )
            """
        )
        self._connection.commit()

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> StateStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def record_seen(self, cve_id: str, seen_at: datetime | None = None) -> None:
        timestamp = (seen_at or datetime.now(timezone.utc)).isoformat()
        self._connection.execute(
            """
            INSERT INTO cves (cve_id, first_seen, last_seen)
            VALUES (?, ?, ?)
            ON CONFLICT(cve_id) DO UPDATE SET last_seen = excluded.last_seen
            """,
            (cve_id, timestamp, timestamp),
        )
        self._connection.commit()

    def was_notified(self, cve_id: str) -> bool:
        row = self._connection.execute(
            "SELECT notified_at FROM cves WHERE cve_id = ?", (cve_id,)
        ).fetchone()
        return bool(row and row[0])

    def mark_notified(self, cve_id: str, notified_at: datetime | None = None) -> None:
        timestamp = (notified_at or datetime.now(timezone.utc)).isoformat()
        cursor = self._connection.execute(
            "UPDATE cves SET notified_at = ? WHERE cve_id = ?",
            (timestamp, cve_id),
        )
        if cursor.rowcount != 1:
            raise KeyError(f"CVE has not been recorded: {cve_id}")
        self._connection.commit()

