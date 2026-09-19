from __future__ import annotations

from datetime import date, datetime, timezone
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
import base64
from contextlib import redirect_stdout
import io
import json
import unittest
from urllib.parse import parse_qs, urlsplit

from cve_signal.config import AppConfig, FeedConfig
from cve_signal.epss import EPSSClient
from cve_signal.exploits import ExploitDBClient, ExploitMatch, SourceStatus
from cve_signal.github_pocs import GitHubPoCClient
from cve_signal.kev import KEVClient, KEVEntry
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

    def fetch_by_id(self, cve_id: str) -> CVE | None:
        return next((cve for cve in self.cves if cve.cve_id == cve_id), None)


class RecordingTelegram:
    def __init__(self) -> None:
        self.messages: list[str] = []
        self.reply_ids: list[int | None] = []

    def send(self, message: str, *, reply_to_message_id=None) -> int:
        self.messages.append(message)
        self.reply_ids.append(reply_to_message_id)
        return len(self.messages) * 100


class StaticGitHubPoCClient:
    def __init__(self, matches=None) -> None:
        self.matches = matches or []

    def find_matches(self, _cve, limit=5):
        return self.matches[:limit]


class StaticEPSSClient:
    def fetch_scores(self, cve_ids):
        return {cve_id: (0.42, 0.97) for cve_id in cve_ids}


class StaticKEVClient:
    def fetch_added_since(self, _since):
        return {
            "CVE-2026-12345": KEVEntry(
                cve_id="CVE-2026-12345",
                date_added="2026-08-20",
                due_date="2026-09-01",
                required_action="Apply updates",
                known_ransomware_use="Known",
            )
        }


class ExploitMatchingTests(unittest.TestCase):
    def test_prefers_direct_and_exact_matches_without_duplicates(self) -> None:
        client = ExploitDBClient(
            "https://example.test/exploits.csv",
            fetcher=lambda _url, _timeout: EXPLOIT_DB_CSV,
        )
        matches = client.find_matches(interesting_cve(), limit=5)

        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].url, "https://www.exploit-db.com/exploits/99999")
        self.assertEqual(matches[0].reason, "direct CVE exploit reference")
        self.assertEqual(matches[0].confidence, "confirmed")

    def test_matches_cve_variants_in_exploitdb_metadata(self) -> None:
        csv_payload = b"""id,file,description,codes,aliases,tags,platform,type
22222,exploits/webapps/CVE_2026_12345.py,Generic proxy exploit,,,,linux,webapps
"""
        client = ExploitDBClient(
            "https://example.test/exploits.csv",
            fetcher=lambda _url, _timeout: csv_payload,
        )

        matches = client.find_matches(interesting_cve())

        self.assertEqual(len(matches), 2)
        database_match = next(match for match in matches if match.url.endswith("/22222"))
        self.assertEqual(database_match.reason, "exact CVE match")

    def test_does_not_match_a_longer_cve_identifier(self) -> None:
        csv_payload = b"""id,file,description,codes,aliases,tags,platform,type
33333,exploit.py,Generic exploit,CVE-2026-123456,,,linux,webapps
"""
        cve = replace(interesting_cve(), references=())
        client = ExploitDBClient(
            "https://example.test/exploits.csv",
            fetcher=lambda _url, _timeout: csv_payload,
        )

        self.assertEqual(client.find_matches(cve), [])

    def test_recognizes_untagged_github_poc_reference(self) -> None:
        cve = replace(
            interesting_cve(),
            references=(
                Reference("https://github.com/researcher/CVE_2026_12345-PoC"),
            ),
        )
        client = ExploitDBClient(
            "https://example.test/exploits.csv",
            fetcher=lambda _url, _timeout: b"id,description\n",
        )

        matches = client.find_matches(cve)

        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].source, "GitHub")

    def test_rejects_product_only_exploitdb_match_with_wrong_vulnerability(self) -> None:
        cve = replace(interesting_cve(), references=())
        csv_payload = b"""id,description,date_published,platform,type,codes,aliases,tags
44444,Cloudflare Example Proxy SQL injection,2026-08-20,linux,webapps,,,
"""
        client = ExploitDBClient(
            "https://example.test/exploits.csv",
            fetcher=lambda _url, _timeout: csv_payload,
        )

        self.assertEqual(client.find_matches(cve), [])

    def test_rejects_generic_url_that_only_contains_exploit_word(self) -> None:
        cve = replace(
            interesting_cve(),
            references=(Reference("https://example.com/blog/exploit-myths"),),
        )
        client = ExploitDBClient(
            "https://example.test/exploits.csv",
            fetcher=lambda _url, _timeout: b"id,description\n",
        )

        self.assertEqual(client.find_matches(cve), [])

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
                {
                    "name": "example-proxy-rce-poc",
                    "full_name": "researcher/example-proxy-rce-poc",
                    "description": "Proof of concept implementation",
                    "private": False,
                    "fork": False,
                    "archived": False,
                    "stargazers_count": 1,
                    "topics": ["poc"],
                },
            ]
        }

        def opener(request, _timeout):
            requests.append(request)
            if request.full_url.endswith("/researcher/example-proxy-rce-poc/readme"):
                content = base64.b64encode(
                    b"CVE-2026-12345 proof of concept exploit"
                ).decode()
                return json.dumps({"encoding": "base64", "content": content}).encode()
            return json.dumps(response).encode()

        client = GitHubPoCClient(
            "github-token",
            search_url="https://api.github.test/search/repositories",
            repository_api_url="https://api.github.test/repos",
            opener=opener,
        )
        matches = client.find_matches(interesting_cve())

        self.assertEqual(len(matches), 2)
        self.assertEqual(matches[0].url, "https://github.com/researcher/CVE-2026-12345")
        self.assertEqual(matches[0].source, "GitHub")
        self.assertEqual(matches[0].exploit_type, "Unverified PoC")
        self.assertEqual(requests[0].get_header("Authorization"), "Bearer github-token")
        self.assertIn("CVE-2026-12345", requests[0].full_url)
        query = parse_qs(urlsplit(requests[0].full_url).query)["q"][0]
        self.assertIn("in:name,description,topics,readme", query)
        readme_match = next(match for match in matches if "example-proxy" in match.url)
        self.assertIn("verified in README", readme_match.reason)

    def test_rejects_generic_github_collection_found_through_readme(self) -> None:
        response = {
            "items": [
                {
                    "name": "exploit-database",
                    "full_name": "someone/exploit-database",
                    "description": "A large exploit collection",
                    "private": False,
                    "fork": False,
                    "archived": False,
                    "stargazers_count": 500,
                    "topics": ["exploits"],
                }
            ]
        }

        def opener(request, _timeout):
            if request.full_url.endswith("/someone/exploit-database/readme"):
                content = base64.b64encode(
                    b"Index entry for CVE-2026-12345 proof of concept"
                ).decode()
                return json.dumps({"encoding": "base64", "content": content}).encode()
            return json.dumps(response).encode()

        client = GitHubPoCClient("token", opener=opener)

        self.assertEqual(client.find_matches(interesting_cve()), [])


class TelegramTests(unittest.TestCase):
    def test_formats_safe_html_alert(self) -> None:
        message = format_alert(interesting_cve(), [])
        self.assertIn("CVE-2026-12345", message)
        self.assertIn("CVSS 9.8", message)
        self.assertIn("CISA KEV", message)
        self.assertNotIn("exact CVE match", message)
        self.assertLessEqual(len(message), 4000)

    def test_distinguishes_source_failure_from_no_matches(self) -> None:
        message = format_alert(
            interesting_cve(),
            [],
            source_statuses=(
                SourceStatus("GitHub", "rate-limited"),
                SourceStatus("Exploit-DB", "ok"),
            ),
        )

        self.assertIn("GitHub rate limited", message)
        self.assertNotIn("Exploit evidence:</b> none found", message)

    def test_long_alert_preserves_complete_html_entities(self) -> None:
        matches = [
            ExploitMatch(
                title="PoC <candidate> " + ("x" * 500),
                url="https://github.com/researcher/repo-" + ("x" * 900),
                source="GitHub",
                score=80,
                reason="README evidence " + ("y" * 500),
            )
            for _ in range(5)
        ]

        message = format_alert(interesting_cve(), matches)

        self.assertLessEqual(len(message), 3900)
        self.assertEqual(message.count("<a "), message.count("</a>"))
        self.assertNotRegex(message, r"&(?:amp|lt|gt|quot)?$")

    def test_posts_to_bot_api(self) -> None:
        requests = []

        def sender(request, _timeout):
            requests.append(request)
            return json.dumps({"ok": True, "result": {"message_id": 77}}).encode()

        client = TelegramClient("token", "-100123", sender=sender)
        message_id = client.send("test", reply_to_message_id=42)

        self.assertEqual(len(requests), 1)
        self.assertNotIn("token", requests[0].data.decode())
        self.assertEqual(message_id, 77)
        body = parse_qs(requests[0].data.decode())
        self.assertEqual(json.loads(body["reply_parameters"][0])["message_id"], 42)


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

    def test_dry_run_does_not_create_or_change_state_file(self) -> None:
        with TemporaryDirectory() as temp_dir:
            state_path = Path(temp_dir) / "state.sqlite3"
            with redirect_stdout(io.StringIO()):
                run_scan(
                    self.config,
                    state_path,
                    dry_run=True,
                    now=datetime(2026, 8, 20, 10, 0, tzinfo=timezone.utc),
                    nvd_client=StaticNVDClient([interesting_cve()]),
                    exploit_client=ExploitDBClient(
                        self.config.feeds.exploitdb_csv_url,
                        fetcher=lambda _url, _timeout: EXPLOIT_DB_CSV,
                    ),
                    github_client=StaticGitHubPoCClient(),
                )

            self.assertFalse(state_path.exists())

    def test_includes_github_poc_candidate_in_telegram_alert(self) -> None:
        telegram = RecordingTelegram()
        github_match = ExploitMatch(
            title="researcher/CVE-2026-12345",
            url="https://github.com/researcher/CVE-2026-12345",
            source="GitHub",
            score=115.0,
            reason="exact CVE ID in repository name",
            exploit_type="PoC candidate",
            confidence="strong",
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
        self.assertIn("exact CVE ID in repository name", telegram.messages[0])

    def test_sends_follow_up_when_a_poc_appears_later(self) -> None:
        telegram = RecordingTelegram()
        github_client = StaticGitHubPoCClient()
        exploit_client = ExploitDBClient(
            self.config.feeds.exploitdb_csv_url,
            fetcher=lambda _url, _timeout: EXPLOIT_DB_CSV,
        )
        github_match = ExploitMatch(
            title="researcher/CVE-2026-12345",
            url="https://github.com/researcher/CVE-2026-12345",
            source="GitHub",
            score=115.0,
            reason="exact CVE ID in repository name",
            exploit_type="PoC candidate",
            confidence="strong",
        )

        with TemporaryDirectory() as temp_dir:
            state_path = Path(temp_dir) / "state.sqlite3"
            kwargs = {
                "now": datetime(2026, 8, 20, 10, 0, tzinfo=timezone.utc),
                "nvd_client": StaticNVDClient([interesting_cve()]),
                "exploit_client": exploit_client,
                "github_client": github_client,
                "telegram_factory": lambda: telegram,
            }
            first = run_scan(self.config, state_path, **kwargs)
            github_client.matches = [github_match]
            second = run_scan(self.config, state_path, **kwargs)
            third = run_scan(self.config, state_path, **kwargs)

        self.assertEqual((first.notified, second.notified, third.notified), (1, 1, 0))
        self.assertEqual(len(telegram.messages), 2)
        self.assertIn("NEW STRONG EXPLOIT SIGNAL", telegram.messages[1])
        self.assertIn(github_match.url, telegram.messages[1])
        self.assertEqual(telegram.reply_ids, [None, 100])

    def test_rechecks_monitored_cve_after_nvd_window(self) -> None:
        telegram = RecordingTelegram()
        github_client = StaticGitHubPoCClient()
        exploit_client = ExploitDBClient(
            self.config.feeds.exploitdb_csv_url,
            fetcher=lambda _url, _timeout: EXPLOIT_DB_CSV,
        )
        github_match = ExploitMatch(
            title="researcher/CVE-2026-12345",
            url="https://github.com/researcher/CVE-2026-12345",
            source="GitHub",
            score=115.0,
            reason="exact CVE ID in repository name",
            exploit_type="Unverified PoC",
            confidence="strong",
        )

        with TemporaryDirectory() as temp_dir:
            state_path = Path(temp_dir) / "state.sqlite3"
            common = {
                "exploit_client": exploit_client,
                "github_client": github_client,
                "telegram_factory": lambda: telegram,
            }
            run_scan(
                self.config,
                state_path,
                now=datetime(2026, 8, 20, 10, 0, tzinfo=timezone.utc),
                nvd_client=StaticNVDClient([interesting_cve()]),
                **common,
            )
            github_client.matches = [github_match]
            follow_up = run_scan(
                self.config,
                state_path,
                now=datetime(2026, 8, 24, 10, 0, tzinfo=timezone.utc),
                nvd_client=StaticNVDClient([]),
                **common,
            )

        self.assertEqual(follow_up.notified, 1)
        self.assertIn(github_match.url, telegram.messages[1])

    def test_new_kev_entry_revives_old_cve_and_adds_epss(self) -> None:
        old_cve = replace(
            interesting_cve(),
            published=datetime(2025, 1, 1, tzinfo=timezone.utc),
            modified=datetime(2025, 1, 1, tzinfo=timezone.utc),
            known_exploited=False,
        )
        config = replace(
            self.config,
            feeds=replace(
                self.config.feeds,
                epss_url="https://example.test/epss",
                kev_url="https://example.test/kev.json",
            ),
        )
        telegram = RecordingTelegram()
        exploit_client = ExploitDBClient(
            config.feeds.exploitdb_csv_url,
            fetcher=lambda _url, _timeout: EXPLOIT_DB_CSV,
        )

        with TemporaryDirectory() as temp_dir:
            result = run_scan(
                config,
                Path(temp_dir) / "state.sqlite3",
                now=datetime(2026, 8, 20, 10, 0, tzinfo=timezone.utc),
                nvd_client=StaticNVDClient([old_cve]),
                exploit_client=exploit_client,
                github_client=StaticGitHubPoCClient(),
                epss_client=StaticEPSSClient(),
                kev_client=StaticKEVClient(),
                telegram_factory=lambda: telegram,
            )

        self.assertEqual(result.notified, 1)
        self.assertIn("CISA KEV", telegram.messages[0])
        self.assertIn("EPSS 42.0%", telegram.messages[0])
        self.assertIn("KEV due:</b> 2026-09-01", telegram.messages[0])

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


class FeedEnrichmentTests(unittest.TestCase):
    def test_fetches_epss_scores_in_batch(self) -> None:
        def opener(request, _timeout):
            self.assertIn("CVE-2026-12345", request.full_url)
            return json.dumps(
                {
                    "data": [
                        {
                            "cve": "CVE-2026-12345",
                            "epss": "0.42",
                            "percentile": "0.97",
                        }
                    ]
                }
            ).encode()

        scores = EPSSClient("https://example.test/epss", opener=opener).fetch_scores(
            ["CVE-2026-12345"]
        )

        self.assertEqual(scores["CVE-2026-12345"], (0.42, 0.97))

    def test_filters_kev_feed_by_date_added(self) -> None:
        payload = {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2026-12345",
                    "dateAdded": "2026-08-20",
                    "dueDate": "2026-09-01",
                    "requiredAction": "Apply updates",
                    "knownRansomwareCampaignUse": "Known",
                },
                {"cveID": "CVE-2020-0001", "dateAdded": "2020-01-01"},
            ]
        }
        client = KEVClient(
            "https://example.test/kev.json",
            opener=lambda _request, _timeout: json.dumps(payload).encode(),
        )

        entries = client.fetch_added_since(date(2026, 8, 19))

        self.assertEqual(set(entries), {"CVE-2026-12345"})
        self.assertEqual(entries["CVE-2026-12345"].known_ransomware_use, "Known")


if __name__ == "__main__":
    unittest.main()
