from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from urllib.parse import parse_qs, urlsplit

from cve_signal.config import ScanConfig
from cve_signal.filtering import is_interesting
from cve_signal.models import CVE, Reference
from cve_signal.nvd import NVDClient, parse_cve
from cve_signal.state import StateStore


NVD_FIXTURE = {
    "id": "CVE-2026-12345",
    "published": "2026-08-20T08:00:00.000Z",
    "lastModified": "2026-08-20T09:00:00.000Z",
    "descriptions": [
        {
            "lang": "en",
            "value": "Cloudflare Example Proxy allows remote code execution.",
        }
    ],
    "metrics": {
        "cvssMetricV31": [
            {
                "type": "Primary",
                "cvssData": {
                    "version": "3.1",
                    "baseScore": 9.8,
                    "baseSeverity": "CRITICAL",
                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "attackVector": "NETWORK",
                    "privilegesRequired": "NONE",
                    "userInteraction": "NONE",
                },
            }
        ]
    },
    "weaknesses": [
        {"description": [{"lang": "en", "value": "CWE-94"}]}
    ],
    "configurations": [
        {
            "nodes": [
                {
                    "cpeMatch": [
                        {
                            "vulnerable": True,
                            "criteria": "cpe:2.3:a:cloudflare:example_proxy:1.2:*:*:*:*:*:*:*",
                        }
                    ]
                }
            ]
        }
    ],
    "references": [
        {"url": "https://example.com/advisory", "tags": ["Vendor Advisory"]}
    ],
    "cisaExploitAdd": "2026-08-20",
}


def scan_config() -> ScanConfig:
    return ScanConfig(
        lookback_hours=6,
        maximum_cve_age_hours=48,
        minimum_cvss=7.0,
        maximum_cvss=10.0,
        maximum_exploit_matches=5,
        technology_keywords=("cloudflare", "aws"),
        vulnerability_keywords=("remote code execution", "ssrf"),
        web_cwes=frozenset({"CWE-94", "CWE-918"}),
        exclude_keywords=(),
    )


class NVDParsingTests(unittest.TestCase):
    def test_parses_normalized_fields(self) -> None:
        cve = parse_cve(NVD_FIXTURE)

        self.assertEqual(cve.cve_id, "CVE-2026-12345")
        self.assertEqual(cve.cvss_score, 9.8)
        self.assertEqual(cve.cvss_version, "3.1")
        self.assertEqual(cve.cwes, ("CWE-94",))
        self.assertIn("cloudflare example proxy 1.2", cve.products)
        self.assertTrue(cve.known_exploited)
        self.assertEqual(cve.attack_vector, "Network")
        self.assertEqual(cve.affected_ranges, ("cloudflare example proxy 1.2",))

    def test_treats_timezone_less_nvd_timestamps_as_utc(self) -> None:
        fixture = {
            **NVD_FIXTURE,
            "published": "2026-08-20T08:00:00.000",
            "lastModified": "2026-08-20T09:00:00.000",
        }
        cve = parse_cve(fixture)

        self.assertEqual(cve.published.tzinfo, timezone.utc)
        self.assertEqual(cve.modified.tzinfo, timezone.utc)

    def test_parses_cpe_version_ranges_for_display(self) -> None:
        fixture = {
            **NVD_FIXTURE,
            "configurations": [
                {
                    "nodes": [
                        {
                            "cpeMatch": [
                                {
                                    "vulnerable": True,
                                    "criteria": "cpe:2.3:a:cloudflare:example_proxy:*:*:*:*:*:*:*:*",
                                    "versionStartIncluding": "1.2",
                                    "versionEndExcluding": "1.4.3",
                                }
                            ]
                        }
                    ]
                }
            ],
        }

        cve = parse_cve(fixture)

        self.assertEqual(
            cve.affected_ranges,
            ("cloudflare example proxy >= 1.2 and < 1.4.3",),
        )

    def test_client_uses_modified_window_and_api_key_header(self) -> None:
        requests = []

        def opener(request, _timeout):
            requests.append(request)
            return b'{"totalResults": 0, "vulnerabilities": []}'

        client = NVDClient(
            "https://example.test/cves",
            api_key="test-key",
            opener=opener,
        )
        client.fetch_modified(
            datetime(2026, 8, 20, 8, 0, tzinfo=timezone.utc),
            datetime(2026, 8, 20, 9, 0, tzinfo=timezone.utc),
        )

        self.assertEqual(len(requests), 1)
        query = parse_qs(urlsplit(requests[0].full_url).query)
        self.assertEqual(query["lastModStartDate"], ["2026-08-20T08:00:00.000Z"])
        self.assertEqual(query["lastModEndDate"], ["2026-08-20T09:00:00.000Z"])
        self.assertEqual(requests[0].get_header("Apikey"), "test-key")


class FilteringTests(unittest.TestCase):
    def test_accepts_high_severity_cloud_web_cve(self) -> None:
        self.assertTrue(is_interesting(parse_cve(NVD_FIXTURE), scan_config()))

    def test_rejects_low_severity_cve(self) -> None:
        original = parse_cve(NVD_FIXTURE)
        cve = CVE(
            **{**original.__dict__, "cvss_score": 6.9, "known_exploited": False},
        )
        self.assertFalse(is_interesting(cve, scan_config()))

    def test_keeps_known_exploited_cve_even_when_unscored(self) -> None:
        original = parse_cve(NVD_FIXTURE)
        cve = CVE(**{**original.__dict__, "cvss_score": None})

        self.assertTrue(is_interesting(cve, scan_config()))

    def test_rejects_unrelated_technology(self) -> None:
        cve = CVE(
            cve_id="CVE-2026-1",
            description="A desktop editor allows remote code execution.",
            published=datetime.now(timezone.utc),
            modified=datetime.now(timezone.utc),
            cvss_score=9.0,
            cvss_severity="CRITICAL",
            cvss_version="3.1",
            cwes=("CWE-94",),
            products=("example desktop editor",),
            references=(Reference("https://example.com"),),
        )
        self.assertFalse(is_interesting(cve, scan_config()))


class StateStoreTests(unittest.TestCase):
    def test_tracks_notification_separately_from_seen(self) -> None:
        with TemporaryDirectory() as temp_dir:
            with StateStore(Path(temp_dir) / "state.sqlite3") as state:
                state.record_seen("CVE-2026-12345")
                self.assertFalse(state.was_notified("CVE-2026-12345"))
                state.mark_notified("CVE-2026-12345")
                self.assertTrue(state.was_notified("CVE-2026-12345"))

    def test_tracks_notified_exploit_urls_per_cve(self) -> None:
        with TemporaryDirectory() as temp_dir:
            with StateStore(Path(temp_dir) / "state.sqlite3") as state:
                state.record_seen("CVE-2026-12345")
                state.record_match_urls(
                    "CVE-2026-12345",
                    {"https://github.com/researcher/CVE-2026-12345"},
                )

                self.assertEqual(
                    state.notified_match_urls("CVE-2026-12345"),
                    {"https://github.com/researcher/CVE-2026-12345"},
                )

    def test_canonicalizes_equivalent_github_urls(self) -> None:
        with TemporaryDirectory() as temp_dir:
            with StateStore(Path(temp_dir) / "state.sqlite3") as state:
                state.record_seen("CVE-2026-12345")
                state.record_match_urls(
                    "CVE-2026-12345",
                    {"https://www.github.com/researcher/repo/tree/main/?utm_source=test"},
                )

                self.assertEqual(
                    state.notified_match_urls("CVE-2026-12345"),
                    {"https://github.com/researcher/repo"},
                )

    def test_round_trips_monitored_cve(self) -> None:
        cve = parse_cve(NVD_FIXTURE)
        now = cve.published
        with TemporaryDirectory() as temp_dir:
            with StateStore(Path(temp_dir) / "state.sqlite3") as state:
                state.monitor(cve, now, monitoring_days=30)

                due = state.due_monitored(now)

        self.assertEqual(due, [cve])


if __name__ == "__main__":
    unittest.main()
