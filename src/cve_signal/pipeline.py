from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
from typing import Callable

from cve_signal.config import AppConfig
from cve_signal.exploits import ExploitDBClient, ExploitMatch
from cve_signal.filtering import is_interesting
from cve_signal.github_pocs import GitHubPoCClient
from cve_signal.models import CVE
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
    github_client: GitHubPoCClient | None = None,
    telegram_factory: Callable[[], TelegramClient] = TelegramClient.from_environment,
) -> ScanResult:
    end = now or datetime.now(timezone.utc)
    if end.tzinfo is None:
        end = end.replace(tzinfo=timezone.utc)
    hours = max(
        lookback_hours or config.scan.lookback_hours,
        config.scan.maximum_cve_age_hours,
    )
    start = end - timedelta(hours=hours)
    oldest_allowed = end - timedelta(hours=config.scan.maximum_cve_age_hours)

    nvd = nvd_client or NVDClient(config.feeds.nvd_url)
    cves = nvd.fetch_modified(start, end)
    candidates = []

    with StateStore(state_path) as state:
        for cve in cves:
            state.record_seen(cve.cve_id, end)
            if (
                cve.published >= oldest_allowed
                and is_interesting(cve, config.scan)
            ):
                candidates.append(cve)

        if not candidates:
            return ScanResult(fetched=len(cves), matched=0, notified=0)

        exploits = exploit_client or ExploitDBClient(config.feeds.exploitdb_csv_url)
        github = github_client or GitHubPoCClient()
        telegram = None if dry_run else telegram_factory()
        notified = 0

        for cve in candidates:
            matches = _find_exploits(
                cve,
                exploits,
                github,
                config.scan.maximum_exploit_matches,
            )
            was_notified = state.was_notified(cve.cve_id)
            previous_urls = state.notified_match_urls(cve.cve_id)
            new_matches = [match for match in matches if match.url not in previous_urls]
            if was_notified and not new_matches:
                continue

            message = format_alert(
                cve,
                new_matches if was_notified else matches,
                is_update=was_notified,
            )
            if dry_run:
                print(message)
                print()
            else:
                assert telegram is not None
                telegram.send(message)
                state.mark_notified(cve.cve_id, end)
                state.record_match_urls(
                    cve.cve_id,
                    {match.url for match in matches},
                    end,
                )
                notified += 1

    return ScanResult(
        fetched=len(cves),
        matched=len(candidates),
        notified=notified,
    )


def _find_exploits(
    cve: CVE,
    exploitdb: ExploitDBClient,
    github: GitHubPoCClient,
    limit: int,
) -> list[ExploitMatch]:
    matches: list[ExploitMatch] = []
    for source, finder in (
        ("Exploit-DB", exploitdb.find_matches),
        ("GitHub", github.find_matches),
    ):
        try:
            matches.extend(finder(cve, limit=limit))
        except (OSError, ValueError):
            print(f"{source} enrichment unavailable for {cve.cve_id}", file=sys.stderr)

    unique: dict[str, ExploitMatch] = {}
    for match in matches:
        previous = unique.get(match.url)
        if previous is None or match.score > previous.score:
            unique[match.url] = match
    return sorted(unique.values(), key=lambda item: (-item.score, item.title))[:limit]
