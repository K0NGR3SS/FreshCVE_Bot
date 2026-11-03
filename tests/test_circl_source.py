from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import json
import unittest
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlsplit

from cve_signal.circl_source import (
    CIRCLVulnerabilityClient,
    parse_circl_record,
    parse_cve5,
)
from cve_signal.config import AppConfig, FeedConfig
from cve_signal.pipeline import _FallbackFeed, _cve_feed
from test_core import NVD_FIXTURE, scan_config


def cve5_record(cve_id: str = "CVE-2026-12345", *, kev: bool = False) -> dict:
    adp_metrics = [
        {
            "other": {
                "type": "ssvc",
                "content": {"options": [{"Exploitation": "none"}]},
            }
        },
        {
            "cvssV3_1": {
                "baseScore": 8.8,
                "baseSeverity": "HIGH",
                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                "attackVector": "NETWORK",
                "privilegesRequired": "LOW",
                "userInteraction": "NONE",
            }
        },
    ]
    if kev:
        adp_metrics.append({"other": {"type": "kev", "content": {"dateAdded": "2026-11-02"}}})
    return {
        "dataType": "CVE_RECORD",
        "cveMetadata": {
            "cveId": cve_id,
            "state": "PUBLISHED",
            "datePublished": "2026-11-02T10:00:00.000Z",
            "dateUpdated": "2026-11-02T12:00:00.000Z",
        },
        "containers": {
            "cna": {
                "descriptions": [{"lang": "en", "value": "Bitrix24 allows remote code execution."}],
                "affected": [
                    {
                        "vendor": "1C-Bitrix",
                        "product": "Bitrix24",
                        "versions": [
                            {"status": "affected", "version": "0", "lessThan": "24.100.0"}
                        ],
                    }
                ],
                "problemTypes": [{"descriptions": [{"cweId": "CWE-94"}]}],
                "references": [{"url": "https://example.test/advisory", "tags": ["vendor-advisory"]}],
            },
            "adp": [{"providerMetadata": {"shortName": "CISA-ADP"}, "metrics": adp_metrics}],
        },
    }


class FakeCIRCL:
    def __init__(self, pages: list[list[dict]] | None = None, single: dict | None = None):
        self.pages = pages or []
        self.single = single
        self.urls: list[str] = []

    def __call__(self, request, _timeout) -> bytes:
        url = request.full_url
        self.urls.append(url)
        parts = urlsplit(url)
        if parts.path.endswith("/vulnerability/"):
            page = int(parse_qs(parts.query)["page"][0])
            data = self.pages[page - 1] if page <= len(self.pages) else []
            return json.dumps(data).encode()
        if self.single is None:
            raise HTTPError(url, 404, "Not Found", hdrs=None, fp=None)
        return json.dumps(self.single).encode()


class ParseTests(unittest.TestCase):
    def test_cve5_record_is_parsed_when_nvd_has_not_processed_it(self) -> None:
        cve = parse_cve5(cve5_record(kev=True))

        self.assertEqual(cve.cve_id, "CVE-2026-12345")
        self.assertEqual((cve.cvss_score, cve.cvss_severity), (8.8, "HIGH"))
        self.assertEqual(cve.attack_vector, "Network")
        self.assertEqual(cve.cwes, ("CWE-94",))
        self.assertEqual(cve.products, ("1c-bitrix bitrix24",))
        self.assertIn("1c-bitrix bitrix24 < 24.100.0", cve.affected_ranges)
        self.assertTrue(cve.known_exploited)
        self.assertEqual(cve.kev_date_added, "2026-11-02")

    def test_nvd_meta_is_preferred(self) -> None:
        record = cve5_record()
        record["vulnerability-lookup:meta"] = {"nvd": json.dumps({"cve": NVD_FIXTURE})}
        cve = parse_circl_record(record)

        self.assertEqual(cve.cvss_score, 9.8)  # NVD score, not the ADP 8.8
        self.assertEqual(cve.modified, datetime(2026, 8, 20, 9, 0, tzinfo=timezone.utc))

    def test_record_fills_gaps_in_nvd_data(self) -> None:
        nvd = {**NVD_FIXTURE, "metrics": {}}
        record = cve5_record(kev=True)
        record["vulnerability-lookup:meta"] = {"nvd": {"cve": nvd}}
        cve = parse_circl_record(record)

        self.assertEqual((cve.cvss_score, cve.cvss_severity), (8.8, "HIGH"))
        self.assertTrue(cve.known_exploited)

    def test_rejected_record_is_skipped(self) -> None:
        record = cve5_record()
        record["cveMetadata"]["state"] = "REJECTED"
        self.assertIsNone(parse_circl_record(record))


class ClientTests(unittest.TestCase):
    def test_pages_until_short_page_and_dedupes(self) -> None:
        first = [cve5_record(f"CVE-2026-{index:05d}") for index in range(100)]
        second = [cve5_record("CVE-2026-00000"), cve5_record("CVE-2026-99999")]
        web = FakeCIRCL(pages=[first, second])
        client = CIRCLVulnerabilityClient("https://circl.test/api", opener=web)

        cves = client.fetch_modified(
            datetime(2026, 11, 2, tzinfo=timezone.utc),
            datetime(2026, 11, 3, tzinfo=timezone.utc),
        )

        self.assertEqual(len(cves), 101)
        self.assertEqual(len(web.urls), 2)
        query = parse_qs(urlsplit(web.urls[0]).query)
        self.assertEqual(query["source"], ["nvd"])
        self.assertEqual(query["since"], ["2026-11-02T00:00:00Z"])
        self.assertEqual(query["with_meta"], ["true"])
        self.assertEqual(query["per_page"], ["100"])

    def test_fetch_by_id(self) -> None:
        web = FakeCIRCL(single=cve5_record())
        client = CIRCLVulnerabilityClient("https://circl.test/api", opener=web)

        self.assertEqual(client.fetch_by_id("CVE-2026-12345").cve_id, "CVE-2026-12345")
        self.assertTrue(web.urls[0].endswith("/vulnerability/CVE-2026-12345?with_meta=true"))
        self.assertIsNone(
            CIRCLVulnerabilityClient("https://circl.test/api", opener=FakeCIRCL()).fetch_by_id(
                "CVE-2026-00001"
            )
        )


class FeedSelectionTests(unittest.TestCase):
    def test_falls_back_to_nvd_when_circl_fails(self) -> None:
        class Broken:
            def fetch_modified(self, start, end):
                raise OSError("down")

        class Backup:
            def fetch_modified(self, start, end):
                return ["from-nvd"]

        feed = _FallbackFeed(Broken(), Backup(), "CIRCL")
        self.assertEqual(feed.fetch_modified(None, None), ["from-nvd"])

    def test_config_selects_circl(self) -> None:
        config = AppConfig(
            scan=scan_config(),
            feeds=FeedConfig(
                nvd_url="https://nvd.test",
                exploitdb_csv_url="https://exploitdb.test",
                cve_source="circl",
            ),
        )
        feed = _cve_feed(config)
        self.assertIsInstance(feed, _FallbackFeed)
        self.assertIsInstance(feed.primary, CIRCLVulnerabilityClient)
        nvd_only = _cve_feed(replace(config, feeds=replace(config.feeds, cve_source="nvd")))
        self.assertNotIsInstance(nvd_only, _FallbackFeed)


if __name__ == "__main__":
    unittest.main()


from datetime import date

from cve_signal.circl_source import (
    CIRCLEPSSClient,
    CIRCLKEVClient,
    parse_epss_payload,
)
from cve_signal.pipeline import _epss_feed, _kev_feed


def kev_item(cve_id: str, first_seen: str, exploited: bool = True) -> dict:
    return {
        "vulnerability": {"vulnId": cve_id},
        "status": {"exploited": exploited, "status_updated_at": "2026-01-01T00:00:00"},
        "timestamps": {"first_seen_at": f"{first_seen}T00:00:00Z"},
    }


class RouteWeb:
    def __init__(self, routes):
        self.routes = routes
        self.urls = []

    def __call__(self, request, _timeout):
        url = request.full_url
        self.urls.append(url)
        for fragment, payload in self.routes.items():
            if fragment in url:
                if isinstance(payload, Exception):
                    raise payload
                return json.dumps(payload).encode()
        raise HTTPError(url, 404, "Not Found", hdrs=None, fp=None)


class CIRCLEPSSTests(unittest.TestCase):
    def test_parses_first_format(self) -> None:
        payload = {"data": [{"cve": "CVE-2026-1", "epss": "0.25", "percentile": "0.97"}]}
        self.assertEqual(parse_epss_payload(payload, "CVE-2026-1"), (0.25, 0.97))
        self.assertIsNone(parse_epss_payload({"data": []}, "CVE-2026-1"))

    def test_fetch_scores_skips_missing(self) -> None:
        web = RouteWeb(
            {"/epss/CVE-2026-1": {"data": [{"cve": "CVE-2026-1", "epss": "0.3", "percentile": "0.9"}]}}
        )
        client = CIRCLEPSSClient("https://circl.test/api", opener=web)
        self.assertEqual(
            client.fetch_scores(["CVE-2026-1", "CVE-2026-2"]), {"CVE-2026-1": (0.3, 0.9)}
        )

    def test_total_failure_raises_for_fallback(self) -> None:
        web = RouteWeb({"/epss/": OSError("down")})
        client = CIRCLEPSSClient("https://circl.test/api", opener=web)
        with self.assertRaises(OSError):
            client.fetch_scores(["CVE-2026-1"])

    def test_epss_from_record_meta(self) -> None:
        record = cve5_record()
        record["vulnerability-lookup:meta"] = {"epss": {"epss": 0.42, "percentile": 0.99}}
        cve = parse_circl_record(record)
        self.assertEqual((cve.epss_score, cve.epss_percentile), (0.42, 0.99))


class CIRCLKEVTests(unittest.TestCase):
    def test_catalog_and_recent_entries(self) -> None:
        web = RouteWeb(
            {
                "/kev/": {
                    "metadata": {"count": 3},
                    "data": [
                        kev_item("CVE-2026-1", "2026-11-02"),
                        kev_item("CVE-2020-2", "2020-05-01"),
                        kev_item("CVE-2021-3", "2021-01-01", exploited=False),
                    ],
                }
            }
        )
        client = CIRCLKEVClient("https://circl.test/api", opener=web)

        self.assertEqual(set(client.fetch_all()), {"CVE-2026-1", "CVE-2020-2"})
        self.assertEqual(set(client.fetch_added_since(date(2026, 11, 1))), {"CVE-2026-1"})
        self.assertIn("vulnerability_lookup_origin=405284c2", web.urls[0])
        self.assertEqual(len(web.urls), 1)  # catalog cached per run

    def test_resync_burst_disables_new_entry_detection(self) -> None:
        data = [kev_item(f"CVE-2026-{index}", "2026-11-02") for index in range(100)]
        client = CIRCLKEVClient(
            "https://circl.test/api", opener=RouteWeb({"/kev/": {"data": data}})
        )
        self.assertEqual(client.fetch_added_since(date(2026, 11, 1)), {})
        self.assertEqual(len(client.fetch_all()), 100)

    def test_feeds_select_circl_with_direct_fallback(self) -> None:
        config = AppConfig(
            scan=scan_config(),
            feeds=FeedConfig(
                nvd_url="https://nvd.test",
                exploitdb_csv_url="https://exploitdb.test",
                epss_url="https://first.test/epss",
                kev_url="https://cisa.test/kev.json",
                epss_source="circl",
                kev_source="circl",
            ),
        )
        epss = _epss_feed(config)
        kev = _kev_feed(config)
        self.assertIsInstance(epss.primary, CIRCLEPSSClient)
        self.assertIsNotNone(epss.fallback)
        self.assertIsInstance(kev.primary, CIRCLKEVClient)
        direct = replace(config, feeds=replace(config.feeds, epss_source="direct"))
        self.assertNotIsInstance(_epss_feed(direct), _FallbackFeed)
