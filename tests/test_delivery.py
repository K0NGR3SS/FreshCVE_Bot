from __future__ import annotations

from datetime import datetime, timezone
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
import json
import unittest

from cve_signal.config import AppConfig, FeedConfig
from cve_signal.exploits import ExploitDBClient, ExploitMatch
from cve_signal.github_pocs import GitHubPoCClient
from cve_signal.models import CVE, Reference
from cve_signal.pipeline import run_scan
from cve_signal.telegram import TelegramClient, format_alert
from test_core import scan_config


def interesting_cve() -> CVE:
    timestamp = datetime(2026, 8, 20, 9, 0, tzinfo=timezone.utc)
    return CVE(
        cve_id="CVE-2026-12345",
        description="Cloudflare Example Proxy allows remote code execution.",
        published=timestamp,
        modified=timestamp,
        cvss_score=9.8,
        cvss_severity="CRITICAL",
        cvss_version="3.1",
        cwes=("CWE-94",),
        products=("cloudflare example proxy 1.2",),
        references=(
            Reference(
                "https://www.exploit-db.com/exploits/99999",
                ("Exploit",),
            ),
        ),
        known_exploited=True,
    )


EXPLOIT_DB_CSV = b"""id,file,description,date_published,author,type,platform,port,date_added,date_updated,verified,codes,tags,aliases
99999,exploits/linux/webapps/99999.py,Cloudflare Example Proxy 1.2 RCE,2026-08-20,researcher,webapps,linux,443,2026-08-20,2026-08-20,1,CVE-2026-12345,,
11111,exploits/linux/webapps/11111.py,Unrelated Product RCE,2025-01-01,researcher,webapps,linux,80,2025-01-01,2025-01-01,1,,,
"""


class StaticNVDClient:
    def __init__(self, cves: list[CVE]) -> None:
        self.cves = cves

    def fetch_modified(self, start: datetime, end: datetime) -> list[CVE]:
        return self.cves


class RecordingTelegram:
    def __init__(self) -> None:
        self.messages: list[str] = []

    def send(self, message: str) -> None:
        self.messages.append(message)


class StaticGitHubPoCClient:
    def __init__(self, matches=None) -> None:
        self.matches = matches or []

    def find_matches(self, _cve, limit=5):
        return self.matches[:limit]


class ExploitMatchingTests(unittest.TestCase):
    def test_prefers_direct_and_exact_matches_without_duplicates(self) -> None:
        client = ExploitDBClient(
            "https://example.test/exploits.csv",
            fetcher=lambda _url, _timeout: EXPLOIT_DB_CSV,
        )
        matches = client.find_matches(interesting_cve(), limit=5)

        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].url, "https://www.exploit-db.com/exploits/99999")
        self.assertEqual(matches[0].reason, "linked directly from the CVE record")

    def test_github_search_returns_only_canonical_public_repository_links(self) -> None:
        requests = []
        response = {
            "items": [
                {
                    "name": "CVE-2026-12345",
                    "full_name": "researcher/CVE-2026-12345",
                    "description": "Proof of concept",
                    "html_url": "https://malicious.example/not-github",
                    "private": False,
                    "fork": False,
                    "archived": False,
                    "stargazers_count": 42,
                    "topics": ["poc", "cve"],
                },
                {
                    "name": "unrelated-fork",
                    "full_name": "someone/unrelated-fork",
                    "description": "CVE-2026-12345 exploit",
                    "private": False,
                    "fork": True,
                    "archived": False,
                    "stargazers_count": 100,
                    "topics": [],
                },
            ]
        }

        def opener(request, _timeout):
            requests.append(request)
            return json.dumps(response).encode()

        client = GitHubPoCClient(
            "github-token",
            search_url="https://api.github.test/search/repositories",
            opener=opener,
        )
        matches = client.find_matches(interesting_cve())

        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].url, "https://github.com/researcher/CVE-2026-12345")
        self.assertEqual(matches[0].source, "GitHub")
        self.assertEqual(matches[0].exploit_type, "PoC candidate")
        self.assertEqual(requests[0].get_header("Authorization"), "Bearer github-token")
        self.assertIn("CVE-2026-12345", requests[0].full_url)


class TelegramTests(unittest.TestCase):
    def test_formats_safe_html_alert(self) -> None:
        message = format_alert(interesting_cve(), [])
        self.assertIn("CVE-2026-12345", message)
        self.assertIn("CVSS 9.8", message)
        self.assertIn("CISA KEV", message)
        self.assertLessEqual(len(message), 4000)

    def test_posts_to_bot_api(self) -> None:
        requests = []

        def sender(request, _timeout):
            requests.append(request)
            return json.dumps({"ok": True}).encode()

        client = TelegramClient("token", "-100123", sender=sender)
        client.send("test")

        self.assertEqual(len(requests), 1)
        self.assertNotIn("token", requests[0].data.decode())


class PipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.config = AppConfig(
            scan=scan_config(),
            feeds=FeedConfig(
                nvd_url="https://example.test/nvd",
                exploitdb_csv_url="https://example.test/exploits.csv",
            ),
        )

    def test_sends_once_then_deduplicates(self) -> None:
        telegram = RecordingTelegram()
        exploit_client = ExploitDBClient(
            self.config.feeds.exploitdb_csv_url,
            fetcher=lambda _url, _timeout: EXPLOIT_DB_CSV,
        )

        with TemporaryDirectory() as temp_dir:
            state_path = Path(temp_dir) / "state.sqlite3"
            kwargs = {
                "now": datetime(2026, 8, 20, 10, 0, tzinfo=timezone.utc),
                "nvd_client": StaticNVDClient([interesting_cve()]),
                "exploit_client": exploit_client,
                "github_client": StaticGitHubPoCClient(),
                "telegram_factory": lambda: telegram,
            }
            first = run_scan(self.config, state_path, **kwargs)
            second = run_scan(self.config, state_path, **kwargs)

        self.assertEqual(first.notified, 1)
        self.assertEqual(second.notified, 0)
        self.assertEqual(len(telegram.messages), 1)

    def test_empty_run_never_creates_telegram_client(self) -> None:
        with TemporaryDirectory() as temp_dir:
            result = run_scan(
                self.config,
                Path(temp_dir) / "state.sqlite3",
                now=datetime(2026, 8, 20, 10, 0, tzinfo=timezone.utc),
                nvd_client=StaticNVDClient([]),
                telegram_factory=lambda: self.fail("Telegram should not be initialized"),
            )

        self.assertEqual(result.notified, 0)

    def test_includes_github_poc_candidate_in_telegram_alert(self) -> None:
        telegram = RecordingTelegram()
        github_match = ExploitMatch(
            title="researcher/CVE-2026-12345",
            url="https://github.com/researcher/CVE-2026-12345",
            source="GitHub",
            score=115.0,
            reason="exact CVE ID in repository name",
            exploit_type="PoC candidate",
        )
        exploit_client = ExploitDBClient(
            self.config.feeds.exploitdb_csv_url,
            fetcher=lambda _url, _timeout: EXPLOIT_DB_CSV,
        )

        with TemporaryDirectory() as temp_dir:
            run_scan(
                self.config,
                Path(temp_dir) / "state.sqlite3",
                now=datetime(2026, 8, 20, 10, 0, tzinfo=timezone.utc),
                nvd_client=StaticNVDClient([interesting_cve()]),
                exploit_client=exploit_client,
                github_client=StaticGitHubPoCClient([github_match]),
                telegram_factory=lambda: telegram,
            )

        self.assertIn("https://github.com/researcher/CVE-2026-12345", telegram.messages[0])
        self.assertIn("PoC candidate", telegram.messages[0])

    def test_ignores_old_cve_that_was_only_recently_modified(self) -> None:
        old_cve = replace(
            interesting_cve(),
            published=datetime(2025, 1, 1, tzinfo=timezone.utc),
            modified=datetime(2026, 8, 20, 9, 30, tzinfo=timezone.utc),
        )
        with TemporaryDirectory() as temp_dir:
            result = run_scan(
                self.config,
                Path(temp_dir) / "state.sqlite3",
                now=datetime(2026, 8, 20, 10, 0, tzinfo=timezone.utc),
                nvd_client=StaticNVDClient([old_cve]),
                telegram_factory=lambda: self.fail("Telegram should not be initialized"),
            )

        self.assertEqual(result.matched, 0)
        self.assertEqual(result.notified, 0)


if __name__ == "__main__":
    unittest.main()
