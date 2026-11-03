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
from cve_signal.filtering import is_interesting, passes_alert_gate
from cve_signal.github_pocs import GitHubPoCClient
from cve_signal.intel import Intel, IntelCollector
from cve_signal.kev import KEVClient, KEVEntry
from cve_signal.models import CVE
from cve_signal.nvd import NVDClient
from cve_signal.circl_source import CIRCLVulnerabilityClient
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
    nvd_client: NVDClient | CIRCLVulnerabilityClient | None = None,
    exploit_client: ExploitDBClient | None = None,
    github_client: GitHubPoCClient | None = None,
    epss_client: EPSSClient | None = None,
    kev_client: KEVClient | None = None,
    telegram_factory: Callable[[], TelegramClient] = TelegramClient.from_environment,
    cve_ids: tuple[str, ...] = (),
    output_format: str = "telegram-html",
    explain: bool = False,
    intel_collector: IntelCollector | None = None,
) -> ScanResult:
    end = now or datetime.now(timezone.utc)
    if end.tzinfo is None:
        end = end.replace(tzinfo=timezone.utc)
    hours = lookback_hours or config.scan.lookback_hours
    start = end - timedelta(hours=hours)
    oldest_allowed = end - timedelta(hours=config.scan.maximum_cve_age_hours)
    if config.scan.published_since is not None:
        since = datetime.combine(
            config.scan.published_since, datetime.min.time(), tzinfo=timezone.utc
        )
        # Every CVE published on or after the configured date is eligible,
        # regardless of maximum_cve_age_hours.
        oldest_allowed = since

    nvd = nvd_client or _cve_feed(config)
    intel_source = intel_collector or IntelCollector.from_feeds(config.feeds)
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

        gated = config.scan.alert_gate != "off" and not explicit_ids
        due = state.due_monitored(
            end, limit=None if gated else config.scan.maximum_cves_per_run
        )

        if not due:
            return ScanResult(fetched=len(cves), matched=0, notified=0)

        # KEV status for every due CVE (not only entries added this window),
        # so a monitored CVE is picked up as soon as CISA adds it.
        if gated and config.feeds.kev_url and kev_status is not None:
            if kev_status.state == "ok":
                fetch_all = getattr(kev, "fetch_all", None)
                catalog = fetch_all() if callable(fetch_all) else kev_entries
                due = [_apply_kev(cve, catalog.get(cve.cve_id)) for cve in due]

        epss_status: SourceStatus | None = None
        if config.feeds.epss_url:
            epss = epss_client or EPSSClient(config.feeds.epss_url)
            try:
                scores = epss.fetch_scores([cve.cve_id for cve in due])
                due = [
                    replace(
                        cve,
                        epss_score=scores.get(cve.cve_id, (None, None))[0],
                        epss_percentile=scores.get(cve.cve_id, (None, None))[1],
                    )
                    for cve in due
                ]
                epss_status = SourceStatus("EPSS", "ok")
            except (OSError, ValueError, KeyError) as error:
                epss_status = SourceStatus("EPSS", "unavailable", str(error))
                print(f"EPSS enrichment unavailable: {error}", file=sys.stderr)

        if intel_source is not None:
            due = [_with_record_cvss(cve, intel_source) for cve in due]

        candidates: list[CVE] = []
        for cve in due:
            if (
                gated
                and not state.was_notified(cve.cve_id)
                and not passes_alert_gate(cve, config.scan)
            ):
                # Not enough exploitation signal yet: keep watching it so a
                # later EPSS rise or KEV listing still triggers an alert.
                if not dry_run:
                    state.schedule_next_check(
                        cve,
                        end,
                        early_hours=config.scan.early_recheck_hours,
                        later_hours=config.scan.later_recheck_hours,
                    )
                continue
            candidates.append(cve)
        candidates = candidates[: config.scan.maximum_cves_per_run]
        if gated:
            _print_gate_summary(due, config, len(candidates))

        if not candidates:
            return ScanResult(fetched=len(cves), matched=0, notified=0)

        exploits = exploit_client or ExploitDBClient(config.feeds.exploitdb_csv_url)
        github = github_client or GitHubPoCClient(
            candidate_limit=config.scan.github_candidates,
            readme_limit=config.scan.github_readme_checks,
        )
        intel_by_id: dict[str, Intel] = {}
        if intel_source is not None:
            fresh = [cve.cve_id for cve in candidates if not state.was_notified(cve.cve_id)]
            if fresh:
                intel_by_id = intel_source.collect(fresh)
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
                intel=intel_by_id.get(cve.cve_id) if not was_notified else None,
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


class _FallbackFeed:
    """Primary CVE feed (CIRCL) with NVD as a safety net."""

    def __init__(self, primary, fallback, name: str) -> None:
        self.primary = primary
        self.fallback = fallback
        self.name = name

    def _call(self, method: str, *args):
        try:
            return getattr(self.primary, method)(*args)
        except (OSError, ValueError, KeyError, TypeError) as error:
            if self.fallback is None:
                raise
            print(
                f"{self.name} unavailable ({error}); falling back to NVD",
                file=sys.stderr,
            )
            return getattr(self.fallback, method)(*args)

    def fetch_modified(self, start, end):
        return self._call("fetch_modified", start, end)

    def fetch_by_id(self, cve_id):
        return self._call("fetch_by_id", cve_id)


def _cve_feed(config: AppConfig):
    feeds = config.feeds
    if feeds.cve_source != "circl":
        return NVDClient(feeds.nvd_url)
    fallback = NVDClient(feeds.nvd_url) if feeds.fallback_to_nvd and feeds.nvd_url else None
    print(f"CVE source: CIRCL Vulnerability-Lookup ({feeds.circl_cve_url})", file=sys.stderr)
    return _FallbackFeed(
        CIRCLVulnerabilityClient(feeds.circl_cve_url), fallback, "CIRCL Vulnerability-Lookup"
    )


def _print_gate_summary(due: list[CVE], config: AppConfig, passed: int) -> None:
    scan = config.scan
    severe = [
        cve
        for cve in due
        if not scan.severities or (cve.cvss_severity or "").upper() in scan.severities
    ]
    kev = [cve for cve in severe if cve.known_exploited]
    hot = [
        cve
        for cve in severe
        if cve.epss_score is not None and cve.epss_score >= scan.minimum_epss
    ]
    no_epss = sum(cve.epss_score is None for cve in severe)
    print(
        f"alert gate ({scan.alert_gate}, EPSS >= {scan.minimum_epss:.0%}): "
        f"checked={len(due)} high/critical={len(severe)} in_kev={len(kev)} "
        f"epss_ok={len(hot)} epss_missing={no_epss} passed={passed}"
    )
    closest = sorted(
        {cve.cve_id: cve for cve in kev + hot}.values(),
        key=lambda cve: -(cve.epss_score or 0.0),
    )[:5]
    for cve in closest:
        epss = f"{cve.epss_score:.1%}" if cve.epss_score is not None else "n/a"
        print(
            f"  near miss: {cve.cve_id} {cve.cvss_severity} "
            f"KEV={'yes' if cve.known_exploited else 'no'} EPSS={epss}"
        )


def _with_record_cvss(cve: CVE, collector: IntelCollector) -> CVE:
    # NVD often lags behind; use the CVSS from the CVE record (CNA or CISA
    # Vulnrichment) for KEV entries that NVD has not scored yet.
    if cve.cvss_score is not None or not cve.known_exploited:
        return cve
    fallback = collector.record_cvss(cve.cve_id)
    if fallback is None:
        return cve
    score, severity, version, vector = fallback
    return replace(
        cve,
        cvss_score=score,
        cvss_severity=severity or _severity_from_score(score),
        cvss_version=version,
        cvss_vector=vector,
    )


def _severity_from_score(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW" if score > 0 else "NONE"


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
