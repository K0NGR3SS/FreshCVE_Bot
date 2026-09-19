from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3

from cve_signal.exploits import canonicalize_url
from cve_signal.models import CVE, Reference


class StateStore:
    def __init__(self, path: Path | str) -> None:
        if str(path) == ":memory:":
            self._connection = sqlite3.connect(":memory:")
        else:
            resolved_path = Path(path)
            resolved_path.parent.mkdir(parents=True, exist_ok=True)
            self._connection = sqlite3.connect(resolved_path)
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
        columns = {
            str(row[1])
            for row in self._connection.execute("PRAGMA table_info(cves)").fetchall()
        }
        if "original_message_id" not in columns:
            self._connection.execute(
                "ALTER TABLE cves ADD COLUMN original_message_id INTEGER"
            )
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS exploit_matches (
                cve_id TEXT NOT NULL,
                url TEXT NOT NULL,
                first_notified TEXT NOT NULL,
                PRIMARY KEY (cve_id, url),
                FOREIGN KEY (cve_id) REFERENCES cves(cve_id)
            )
            """
        )
        self._connection.execute(
            """
            CREATE TABLE IF NOT EXISTS monitored_cves (
                cve_id TEXT PRIMARY KEY,
                payload TEXT NOT NULL,
                next_check_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                last_checked_at TEXT
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

    def mark_notified(
        self,
        cve_id: str,
        notified_at: datetime | None = None,
        *,
        message_id: int | None = None,
    ) -> None:
        timestamp = (notified_at or datetime.now(timezone.utc)).isoformat()
        cursor = self._connection.execute(
            """
            UPDATE cves
            SET notified_at = ?,
                original_message_id = COALESCE(original_message_id, ?)
            WHERE cve_id = ?
            """,
            (timestamp, message_id, cve_id),
        )
        if cursor.rowcount != 1:
            raise KeyError(f"CVE has not been recorded: {cve_id}")
        self._connection.commit()

    def notified_match_urls(self, cve_id: str) -> set[str]:
        rows = self._connection.execute(
            "SELECT url FROM exploit_matches WHERE cve_id = ?", (cve_id,)
        ).fetchall()
        return {canonicalize_url(str(row[0])) for row in rows}

    def original_message_id(self, cve_id: str) -> int | None:
        row = self._connection.execute(
            "SELECT original_message_id FROM cves WHERE cve_id = ?", (cve_id,)
        ).fetchone()
        return int(row[0]) if row and row[0] is not None else None

    def is_monitored(self, cve_id: str) -> bool:
        row = self._connection.execute(
            "SELECT 1 FROM monitored_cves WHERE cve_id = ?", (cve_id,)
        ).fetchone()
        return row is not None

    def record_match_urls(
        self,
        cve_id: str,
        urls: set[str],
        notified_at: datetime | None = None,
    ) -> None:
        if not urls:
            return
        timestamp = (notified_at or datetime.now(timezone.utc)).isoformat()
        self._connection.executemany(
            """
            INSERT OR IGNORE INTO exploit_matches (cve_id, url, first_notified)
            VALUES (?, ?, ?)
            """,
            ((cve_id, canonicalize_url(url), timestamp) for url in urls),
        )
        self._connection.commit()

    def monitor(
        self,
        cve: CVE,
        now: datetime,
        *,
        monitoring_days: int,
        newly_exploited: bool = False,
    ) -> None:
        expires_at = max(
            cve.published + timedelta(days=monitoring_days),
            now + timedelta(days=monitoring_days) if newly_exploited else cve.published,
        )
        self._connection.execute(
            """
            INSERT INTO monitored_cves (cve_id, payload, next_check_at, expires_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(cve_id) DO UPDATE SET
                payload = excluded.payload,
                next_check_at = CASE
                    WHEN excluded.next_check_at < monitored_cves.next_check_at
                    THEN excluded.next_check_at
                    ELSE monitored_cves.next_check_at
                END,
                expires_at = CASE
                    WHEN excluded.expires_at > monitored_cves.expires_at
                    THEN excluded.expires_at
                    ELSE monitored_cves.expires_at
                END
            """,
            (
                cve.cve_id,
                _serialize_cve(cve),
                now.isoformat(),
                expires_at.isoformat(),
            ),
        )
        self._connection.commit()

    def due_monitored(self, now: datetime, *, limit: int | None = None) -> list[CVE]:
        self._connection.execute(
            "DELETE FROM monitored_cves WHERE expires_at < ?", (now.isoformat(),)
        )
        query = """
            SELECT payload FROM monitored_cves
            WHERE next_check_at <= ? AND expires_at >= ?
            ORDER BY next_check_at, cve_id
        """
        parameters: tuple[object, ...] = (now.isoformat(), now.isoformat())
        if limit is not None:
            query += " LIMIT ?"
            parameters += (limit,)
        rows = self._connection.execute(query, parameters).fetchall()
        self._connection.commit()
        return [_deserialize_cve(str(row[0])) for row in rows]

    def schedule_next_check(
        self,
        cve: CVE,
        now: datetime,
        *,
        early_hours: int,
        later_hours: int,
    ) -> None:
        age = now - cve.published
        interval = early_hours if age <= timedelta(hours=48) else later_hours
        self._connection.execute(
            """
            UPDATE monitored_cves
            SET payload = ?, next_check_at = ?, last_checked_at = ?
            WHERE cve_id = ?
            """,
            (
                _serialize_cve(cve),
                (now + timedelta(hours=interval)).isoformat(),
                now.isoformat(),
                cve.cve_id,
            ),
        )
        self._connection.commit()


def _serialize_cve(cve: CVE) -> str:
    payload = asdict(cve)
    payload["published"] = cve.published.isoformat()
    payload["modified"] = cve.modified.isoformat()
    return json.dumps(payload, separators=(",", ":"), sort_keys=True)


def _deserialize_cve(value: str) -> CVE:
    payload = json.loads(value)
    payload["published"] = datetime.fromisoformat(payload["published"])
    payload["modified"] = datetime.fromisoformat(payload["modified"])
    payload["cwes"] = tuple(payload.get("cwes", []))
    payload["products"] = tuple(payload.get("products", []))
    payload["affected_ranges"] = tuple(payload.get("affected_ranges", []))
    payload["references"] = tuple(
        Reference(url=item["url"], tags=tuple(item.get("tags", [])))
        for item in payload.get("references", [])
    )
    return CVE(**payload)
