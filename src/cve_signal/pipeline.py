from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
from typing import Callable
from urllib.error import HTTPError

from cve_signal.config import AppConfig
from cve_signal.epss import EPSSClient
from cve_signal.exploits import (
    ExploitDBClient,
    ExploitMatch,
    SourceStatus,
    canonicalize_url,
)
from cve_signal.filtering import is_interesting
from cve_signal.github_pocs import GitHubPoCClient
from cve_signal.kev import KEVClient, KEVEntry
from cve_signal.models import CVE
from cve_signal.nvd import NVDClient
from cve_signal.state import StateStore
from cve_signal.telegram import (
    TelegramClient,
    format_alert,
    format_alert_json,
    format_alert_text,
)


@dataclass(frozen=True)
class ScanResult:
    fetched: int
    matched: int
    notified: int
    source_failures: int = 0


@dataclass(frozen=True)
class EnrichmentResult:
    matches: list[ExploitMatch]
    source_statuses: tuple[SourceStatus, ...]


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
    epss_client: EPSSClient | None = None,
    kev_client: KEVClient | None = None,
    telegram_factory: Callable[[], TelegramClient] = TelegramClient.from_environment,
    cve_ids: tuple[str, ...] = (),
    output_format: str = "telegram-html",
    explain: bool = False,
) -> ScanResult:
    end = now or datetime.now(timezone.utc)
    if end.tzinfo is None:
        end = end.replace(tzinfo=timezone.utc)
    hours = lookback_hours or config.scan.lookback_hours
    start = end - timedelta(hours=hours)
    oldest_allowed = end - timedelta(hours=config.scan.maximum_cve_age_hours)

    nvd = nvd_client or NVDClient(config.feeds.nvd_url)
    if cve_ids:
        cves = [
            cve
            for cve_id in cve_ids
            if (cve := nvd.fetch_by_id(cve_id)) is not None
        ]
    else:
        cves = nvd.fetch_modified(start, end)

    kev_entries: dict[str, KEVEntry] = {}
    kev_status: SourceStatus | None = None
    if config.feeds.kev_url and not cve_ids:
        kev = kev_client or KEVClient(config.feeds.kev_url)
        try:
            kev_entries = kev.fetch_added_since(start.date())
            known = {cve.cve_id for cve in cves}
            for cve_id in sorted(set(kev_entries).difference(known)):
                cve = nvd.fetch_by_id(cve_id)
                if cve is not None:
                    cves.append(cve)
            kev_status = SourceStatus("CISA KEV", "ok")
        except (OSError, ValueError) as error:
            kev_status = SourceStatus("CISA KEV", "unavailable", str(error))
            print(f"CISA KEV enrichment unavailable: {error}", file=sys.stderr)

    cves = [_apply_kev(cve, kev_entries.get(cve.cve_id)) for cve in cves]
    unique_cves: dict[str, CVE] = {}
    for cve in cves:
        previous = unique_cves.get(cve.cve_id)
        if previous is None or cve.modified > previous.modified:
            unique_cves[cve.cve_id] = cve
    cves = list(unique_cves.values())
    explicit_ids = {value.upper() for value in cve_ids}

    with StateStore(":memory:" if dry_run else state_path) as state:
        for cve in cves:
            state.record_seen(cve.cve_id, end)
            already_monitored = state.is_monitored(cve.cve_id)
            newly_eligible = (
                (
                    cve.published >= oldest_allowed
                    or cve.cve_id in kev_entries
                    or cve.cve_id in explicit_ids
                )
                and (
                    cve.cve_id in explicit_ids
                    or is_interesting(cve, config.scan)
                )
            )
            if already_monitored or newly_eligible:
                state.monitor(
                    cve,
                    end,
                    monitoring_days=config.scan.monitoring_days,
                    newly_exploited=(
                        cve.cve_id in kev_entries or cve.cve_id in explicit_ids
                    ),
                )

        candidates = state.due_monitored(
            end, limit=config.scan.maximum_cves_per_run
        )

        if not candidates:
            return ScanResult(fetched=len(cves), matched=0, notified=0)

        epss_status: SourceStatus | None = None
        if config.feeds.epss_url:
            epss = epss_client or EPSSClient(config.feeds.epss_url)
            try:
                scores = epss.fetch_scores([cve.cve_id for cve in candidates])
                candidates = [
                    replace(
                        cve,
                        epss_score=scores.get(cve.cve_id, (None, None))[0],
                        epss_percentile=scores.get(cve.cve_id, (None, None))[1],
                    )
                    for cve in candidates
                ]
                epss_status = SourceStatus("EPSS", "ok")
            except (OSError, ValueError, KeyError) as error:
                epss_status = SourceStatus("EPSS", "unavailable", str(error))

        exploits = exploit_client or ExploitDBClient(config.feeds.exploitdb_csv_url)
        github = github_client or GitHubPoCClient(
            candidate_limit=config.scan.github_candidates,
            readme_limit=config.scan.github_readme_checks,
        )
        telegram = None if dry_run else telegram_factory()
        notified = 0
        source_failures = 0

        for cve in candidates:
            enrichment = _find_exploits(
                cve,
                exploits,
                github,
                config.scan.maximum_exploit_matches,
            )
            statuses = enrichment.source_statuses + (
                (epss_status,) if epss_status is not None else ()
            ) + ((kev_status,) if kev_status is not None else ())
            source_failures += sum(
                status.state in {"unavailable", "rate-limited"}
                for status in statuses
            )
            was_notified = state.was_notified(cve.cve_id)
            previous_urls = state.notified_match_urls(cve.cve_id)
            new_matches = [
                match
                for match in enrichment.matches
                if canonicalize_url(match.url) not in previous_urls
            ]
            if was_notified and not new_matches:
                if not dry_run:
                    state.schedule_next_check(
                        cve,
                        end,
                        early_hours=config.scan.early_recheck_hours,
                        later_hours=config.scan.later_recheck_hours,
                    )
                continue

            displayed_matches = new_matches if was_notified else enrichment.matches
            formatter = {
                "telegram-html": format_alert,
                "text": format_alert_text,
                "json": format_alert_json,
            }.get(output_format)
            if formatter is None:
                raise ValueError(f"unsupported output format: {output_format}")
            message = formatter(
                cve,
                displayed_matches,
                is_update=was_notified,
                source_statuses=statuses,
                explain=explain,
            )
            if dry_run:
                print(message)
                if output_format != "json":
                    print()
            else:
                assert telegram is not None
                message_id = telegram.send(
                    message,
                    reply_to_message_id=(
                        state.original_message_id(cve.cve_id) if was_notified else None
                    ),
                )
                state.mark_notified(cve.cve_id, end, message_id=message_id)
                state.record_match_urls(
                    cve.cve_id,
                    {match.url for match in enrichment.matches},
                    end,
                )
                state.schedule_next_check(
                    cve,
                    end,
                    early_hours=config.scan.early_recheck_hours,
                    later_hours=config.scan.later_recheck_hours,
                )
                notified += 1

    return ScanResult(
        fetched=len(cves),
        matched=len(candidates),
        notified=notified,
        source_failures=source_failures,
    )


def _find_exploits(
    cve: CVE,
    exploitdb: ExploitDBClient,
    github: GitHubPoCClient,
    limit: int,
) -> EnrichmentResult:
    matches: list[ExploitMatch] = []
    statuses: list[SourceStatus] = []
    for source, client in (
        ("Exploit-DB", exploitdb),
        ("GitHub", github),
    ):
        try:
            matches.extend(client.find_matches(cve, limit=limit))
            incomplete = bool(getattr(client, "last_search_incomplete", False))
            statuses.append(
                SourceStatus(
                    source,
                    "partial" if incomplete else "ok",
                    "incomplete upstream results" if incomplete else None,
                )
            )
        except HTTPError as error:
            state = "rate-limited" if error.code in {403, 429} else "unavailable"
            statuses.append(SourceStatus(source, state, f"HTTP {error.code}"))
            print(f"{source} enrichment {state} for {cve.cve_id}", file=sys.stderr)
        except (OSError, ValueError) as error:
            statuses.append(SourceStatus(source, "unavailable", str(error)))
            print(f"{source} enrichment unavailable for {cve.cve_id}", file=sys.stderr)

    unique: dict[str, ExploitMatch] = {}
    for match in matches:
        key = canonicalize_url(match.url)
        previous = unique.get(key)
        if previous is None or match.score > previous.score:
            unique[key] = match
    confidence_order = {"confirmed": 0, "strong": 1, "possible": 2}
    ranked = sorted(
        unique.values(),
        key=lambda item: (confidence_order[item.confidence], -item.score, item.title),
    )[:limit]
    return EnrichmentResult(ranked, tuple(statuses))


def _apply_kev(cve: CVE, entry: KEVEntry | None) -> CVE:
    if entry is None:
        return cve
    return replace(
        cve,
        known_exploited=True,
        kev_date_added=entry.date_added,
        kev_due_date=entry.due_date,
        kev_required_action=entry.required_action,
        known_ransomware_use=entry.known_ransomware_use,
    )
