from __future__ import annotations

from contextlib import redirect_stdout
from dataclasses import replace
from datetime import datetime, timezone
import io
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from cve_signal.config import AppConfig, FeedConfig
from cve_signal.kev import KEVEntry
from cve_signal.refresh import run_refresh
from cve_signal.state import StateStore
from test_core import scan_config
from test_delivery import RecordingTelegram, interesting_cve


NOW = datetime(2026, 11, 5, 10, 0, tzinfo=timezone.utc)


class Scores:
    def __init__(self, scores):
        self.scores = scores

    def fetch_scores(self, ids):
        return {cve_id: value for cve_id, value in self.scores.items() if cve_id in ids}


class Catalog:
    def __init__(self, entries=None):
        self.entries = entries or {}

    def fetch_all(self):
        return self.entries


def config() -> AppConfig:
    return AppConfig(
        scan=replace(scan_config(), minimum_epss=0.2),
        feeds=FeedConfig(nvd_url="https://nvd.test", exploitdb_csv_url="https://x.test"),
    )


def seed(state_path: Path, cve_ids_and_messages) -> None:
    with StateStore(state_path) as state:
        for cve_id, message_id in cve_ids_and_messages:
            cve = replace(interesting_cve(), cve_id=cve_id, known_exploited=False, epss_score=None)
            state.record_seen(cve_id, NOW)
            state.monitor(cve, NOW, monitoring_days=30)
            state.mark_notified(cve_id, NOW, message_id=message_id)


class RefreshTests(unittest.TestCase):
    def run_refresh(self, state_path, telegram, *, epss, kev=None, dry_run=False):
        with redirect_stdout(io.StringIO()) as out:
            result = run_refresh(
                config(),
                state_path,
                dry_run=dry_run,
                epss_client=Scores(epss),
                kev_client=Catalog(kev),
                telegram_factory=lambda: telegram,
                now=NOW,
            )
        return result, out.getvalue()

    def test_replies_once_then_only_on_change(self) -> None:
        with TemporaryDirectory() as temp_dir:
            state_path = Path(temp_dir) / "state.sqlite3"
            seed(state_path, [("CVE-2026-0001", 11), ("CVE-2026-0002", 12), ("CVE-2026-0003", 13)])
            telegram = RecordingTelegram()

            first, _ = self.run_refresh(
                state_path, telegram, epss={"CVE-2026-0001": (0.05, 0.6), "CVE-2026-0002": (0.31, 0.97)}
            )
            self.assertEqual((first.posted, first.changed, first.sent, first.epss_new), (3, 2, 2, 2))
            self.assertEqual(telegram.reply_ids, [11, 12])
            self.assertIn("EPSS: n/a → <b>31.0%</b>", telegram.messages[1])

            # Same scores: nothing new to report.
            second, _ = self.run_refresh(
                state_path, telegram, epss={"CVE-2026-0001": (0.06, 0.6), "CVE-2026-0002": (0.31, 0.97)}
            )
            self.assertEqual(second.sent, 0)

            # EPSS crosses 20% for 0001 and 0002 enters KEV.
            kev = {"CVE-2026-0002": KEVEntry("CVE-2026-0002", "2026-11-04", None, None, None)}
            third, _ = self.run_refresh(
                state_path, telegram,
                epss={"CVE-2026-0001": (0.22, 0.9), "CVE-2026-0002": (0.31, 0.97)}, kev=kev,
            )
            self.assertEqual((third.sent, third.kev_new), (2, 1))
            self.assertIn("EPSS: 5.0% → <b>22.0%</b>", telegram.messages[2])
            self.assertIn("CISA KEV: нет → <b>ДА</b> (добавлена 2026-11-04)", telegram.messages[3])
            self.assertIn("В KEV и EPSS ≥ 20%", telegram.messages[3])
            self.assertEqual(telegram.reply_ids[2:], [11, 12])

    def test_dry_run_sends_and_records_nothing(self) -> None:
        with TemporaryDirectory() as temp_dir:
            state_path = Path(temp_dir) / "state.sqlite3"
            seed(state_path, [("CVE-2026-0001", 11)])
            telegram = RecordingTelegram()
            result, output = self.run_refresh(
                state_path, telegram, epss={"CVE-2026-0001": (0.4, 0.98)}, dry_run=True
            )
            self.assertEqual((result.changed, result.sent), (1, 0))
            self.assertEqual(telegram.messages, [])
            self.assertIn("CVE-2026-0001", output)
            again, _ = self.run_refresh(state_path, telegram, epss={"CVE-2026-0001": (0.4, 0.98)})
            self.assertEqual(again.sent, 1)  # the dry run did not record a report

    def test_missing_state_is_not_an_error(self) -> None:
        with TemporaryDirectory() as temp_dir:
            result, output = self.run_refresh(Path(temp_dir) / "none.sqlite3", RecordingTelegram(), epss={})
        self.assertEqual(result.posted, 0)
        self.assertIn("nothing has been posted", output)


if __name__ == "__main__":
    unittest.main()
