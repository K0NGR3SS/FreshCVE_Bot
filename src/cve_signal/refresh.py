"""Refresh CISA KEV and EPSS for CVEs already posted to the Telegram channel.

For every CVE the bot has posted, the current KEV status and EPSS score are
fetched. When they differ from what the channel last saw, the bot replies to
its original post with a short update. The first refresh compares against
"no data" (most posts were made before EPSS existed for the CVE); later
refreshes compare against the previous update.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import html
from pathlib import Path
import sys
from typing import Any, Callable

from cve_signal.config import AppConfig
from cve_signal.state import StateStore
from cve_signal.telegram import TelegramClient


@dataclass(frozen=True)
class RefreshResult:
    posted: int
    checked: int
    changed: int
    sent: int
    kev_new: int
    epss_new: int


@dataclass(frozen=True)
class ScoreChange:
    cve_id: str
    message_id: int
    old_epss: float | None
    new_epss: float | None
    percentile: float | None
    old_kev: bool
    new_kev: bool
    kev_date_added: str | None


def run_refresh(
    config: AppConfig,
    state_path: Path,
    *,
    dry_run: bool = False,
    epss_client: Any = None,
    kev_client: Any = None,
    telegram_factory: Callable[[], TelegramClient] = TelegramClient.from_environment,
    min_epss_delta: float = 0.05,
    limit: int | None = None,
    now: datetime | None = None,
) -> RefreshResult:
    from cve_signal.pipeline import _epss_feed, _kev_feed

    now = now or datetime.now(timezone.utc)
    if not Path(state_path).exists():
        print(f"refresh: no state at {state_path}; nothing has been posted yet")
        return RefreshResult(0, 0, 0, 0, 0, 0)

    # The real state is read even in a dry run (posted CVEs live there); a dry
    # run only skips sending and recording.
    with StateStore(state_path) as state:
        entries = state.notified_entries()
        if not entries:
            print("refresh: no posted CVEs with a Telegram message id")
            return RefreshResult(0, 0, 0, 0, 0, 0)
        cve_ids = [cve_id for cve_id, _message_id, _cve in entries]

        kev = kev_client or _kev_feed(config)
        catalog: dict[str, Any] = {}
        if kev is not None:
            try:
                catalog = kev.fetch_all()
            except (OSError, ValueError) as error:
                print(f"refresh: CISA KEV unavailable: {error}", file=sys.stderr)
        epss = epss_client or _epss_feed(config)
        scores: dict[str, tuple[float, float]] = {}
        if epss is not None:
            try:
                scores = epss.fetch_scores(cve_ids)
            except (OSError, ValueError, KeyError) as error:
                print(f"refresh: EPSS unavailable: {error}", file=sys.stderr)

        changes: list[ScoreChange] = []
        for cve_id, message_id, stored in entries:
            report = state.last_score_report(cve_id)
            if report is not None:
                old_epss, _old_pct, old_kev = report
            else:
                old_epss, old_kev = None, False
            entry = catalog.get(cve_id)
            new_kev = entry is not None or bool(stored and stored.known_exploited)
            new_epss, percentile = scores.get(cve_id, (None, None))
            if new_epss is None and report is not None:
                new_epss = old_epss  # a missing score is not a change
            if _changed(old_epss, new_epss, old_kev, new_kev, config.scan.minimum_epss, min_epss_delta):
                changes.append(
                    ScoreChange(
                        cve_id=cve_id,
                        message_id=message_id,
                        old_epss=old_epss,
                        new_epss=new_epss,
                        percentile=percentile,
                        old_kev=old_kev,
                        new_kev=new_kev,
                        kev_date_added=getattr(entry, "date_added", None)
                        or (stored.kev_date_added if stored else None),
                    )
                )

        kev_new = sum(change.new_kev and not change.old_kev for change in changes)
        epss_new = sum(change.old_epss is None and change.new_epss is not None for change in changes)
        print(
            f"refresh: posted={len(entries)} with_epss={len(scores)} in_kev="
            f"{sum(cve_id in catalog for cve_id in cve_ids)} changed={len(changes)} "
            f"(kev_new={kev_new} epss_new={epss_new})"
        )
        selected = changes[:limit] if limit else changes
        telegram = None if dry_run or not selected else telegram_factory()
        sent = 0
        for change in selected:
            message = format_score_update(change, threshold=config.scan.minimum_epss)
            if dry_run:
                print(message, end="\n\n")
                continue
            assert telegram is not None
            telegram.send(message, reply_to_message_id=change.message_id)
            state.record_score_report(
                change.cve_id,
                epss=change.new_epss,
                epss_percentile=change.percentile,
                kev=change.new_kev,
                reported_at=now,
            )
            sent += 1
        if limit and len(changes) > limit:
            print(f"refresh: {len(changes) - limit} more updates left for the next run")

    return RefreshResult(len(entries), len(cve_ids), len(changes), sent, kev_new, epss_new)


def _changed(
    old_epss: float | None,
    new_epss: float | None,
    old_kev: bool,
    new_kev: bool,
    threshold: float,
    min_delta: float,
) -> bool:
    if new_kev and not old_kev:
        return True
    if new_epss is None:
        return False
    if old_epss is None:
        return True
    if (old_epss >= threshold) != (new_epss >= threshold):
        return True
    return abs(new_epss - old_epss) >= min_delta


def format_score_update(change: ScoreChange, *, threshold: float) -> str:
    cve = html.escape(change.cve_id)
    lines = [f'🔄 <b>Обновление KEV / EPSS</b> · <a href="https://nvd.nist.gov/vuln/detail/{cve}">{cve}</a>']
    if change.new_kev and not change.old_kev:
        added = f" (добавлена {html.escape(change.kev_date_added)})" if change.kev_date_added else ""
        lines.append(f"CISA KEV: нет → <b>ДА</b>{added}")
    else:
        lines.append(f"CISA KEV: {'ДА' if change.new_kev else 'нет'}")
    epss_line = f"EPSS: {_pct(change.old_epss)} → <b>{_pct(change.new_epss)}</b>"
    if change.percentile is not None:
        epss_line += f" ({change.percentile * 100:.0f}th pct)"
    lines.append(epss_line)
    if change.new_kev and change.new_epss is not None and change.new_epss >= threshold:
        lines.append(f"⚠️ В KEV и EPSS ≥ {threshold:.0%}")
    return "\n".join(lines)


def _pct(value: float | None) -> str:
    return "n/a" if value is None else f"{value * 100:.1f}%"
