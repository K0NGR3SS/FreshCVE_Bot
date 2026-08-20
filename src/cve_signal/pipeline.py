from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable

from cve_signal.config import AppConfig
from cve_signal.exploits import ExploitDBClient
from cve_signal.filtering import is_interesting
from cve_signal.nvd import NVDClient
from cve_signal.state import StateStore
from cve_signal.telegram import TelegramClient, format_alert


@dataclass(frozen=True)
class ScanResult:
    fetched: int
    matched: int
    notified: int


def run_scan(
    config: AppConfig,
    state_path: Path,
    *,
    lookback_hours: int | None = None,
    dry_run: bool = False,
    now: datetime | None = None,
    nvd_client: NVDClient | None = None,
    exploit_client: ExploitDBClient | None = None,
    telegram_factory: Callable[[], TelegramClient] = TelegramClient.from_environment,
) -> ScanResult:
    end = now or datetime.now(timezone.utc)
    if end.tzinfo is None:
        end = end.replace(tzinfo=timezone.utc)
    hours = lookback_hours or config.scan.lookback_hours
    start = end - timedelta(hours=hours)

    nvd = nvd_client or NVDClient(config.feeds.nvd_url)
    cves = nvd.fetch_modified(start, end)
    candidates = []

    with StateStore(state_path) as state:
        for cve in cves:
            state.record_seen(cve.cve_id, end)
            if is_interesting(cve, config.scan) and not state.was_notified(cve.cve_id):
                candidates.append(cve)

        if not candidates:
            return ScanResult(fetched=len(cves), matched=0, notified=0)

        exploits = exploit_client or ExploitDBClient(config.feeds.exploitdb_csv_url)
        telegram = None if dry_run else telegram_factory()
        notified = 0

        for cve in candidates:
            matches = exploits.find_matches(
                cve,
                limit=config.scan.maximum_exploit_matches,
            )
            message = format_alert(cve, matches)
            if dry_run:
                print(message)
                print()
            else:
                assert telegram is not None
                telegram.send(message)
                state.mark_notified(cve.cve_id)
                notified += 1

    return ScanResult(
        fetched=len(cves),
        matched=len(candidates),
        notified=notified,
    )

