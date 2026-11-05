from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from urllib.error import HTTPError
import zipfile

from cve_signal.intel import (
    BDUClient,
    CIRCLClient,
    CVEOrgClient,
    EUVDClient,
    GHSAClient,
    Intel,
    IntelCollector,
    OSVClient,
)
from cve_signal.pipeline import run_scan
from cve_signal.telegram import format_alert, format_alert_json, format_alert_text
from test_delivery import (
    EXPLOIT_DB_CSV,
    RecordingTelegram,
    StaticGitHubPoCClient,
    StaticNVDClient,
    interesting_cve,
)
from cve_signal.config import AppConfig, FeedConfig
from cve_signal.exploits import ExploitDBClient
from test_core import scan_config

CVE_ID = "CVE-2026-12345"

CVE_RECORD = {
    "dataType": "CVE_RECORD",
    "containers": {
        "cna": {
            "descriptions": [
                {"lang": "en", "value": "Vendor <b>detailed</b> text about the flaw."}
            ],
            "solutions": [{"lang": "en", "value": "Upgrade to 1.2.4 or later."}],
            "affected": [
                {
                    "vendor": "Example",
                    "product": "Proxy",
                    "versions": [
                        {
                            "status": "affected",
                            "version": "1.0",
                            "lessThan": "1.2.4",
                            "changes": [{"at": "1.2.4", "status": "unaffected"}],
                        }
                    ],
                }
            ],
        },
        "adp": [
            {
                "providerMetadata": {"shortName": "CISA-ADP"},
                "metrics": [
                    {
                        "other": {
                            "type": "ssvc",
                            "content": {
                                "options": [
                                    {"Exploitation": "active"},
                                    {"Automatable": "yes"},
                                    {"Technical Impact": "total"},
                                ]
                            },
                        }
                    },
                    {
                        "cvssV3_1": {
                            "baseScore": 9.1,
                            "baseSeverity": "CRITICAL",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                        }
                    },
                ],
            }
        ],
    },
}

GHSA_RESPONSE = [
    {
        "ghsa_id": "GHSA-aaaa-bbbb-cccc",
        "html_url": "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
        "summary": "Proxy RCE",
        "vulnerabilities": [
            {
                "package": {"ecosystem": "npm", "name": "example-proxy"},
                "first_patched_version": "1.2.4",
            }
        ],
    }
]

OSV_DEBIAN = {
    "id": f"DEBIAN-{CVE_ID}",
    "affected": [
        {
            "package": {"ecosystem": "Debian:12", "name": "example-proxy"},
            "ranges": [
                {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.2.4-1"}]}
            ],
        }
    ],
}

EUVD_RESPONSE = {
    "items": [
        {"id": "EUVD-2026-0001", "aliases": "CVE-2026-99999\n"},
        {
            "id": "EUVD-2026-0002",
            "aliases": f"{CVE_ID}\n",
            "exploitedSince": "Nov 1, 2026, 12:00:00 AM",
        },
    ],
    "total": 2,
}

CIRCL_SIGHTINGS = {
    "metadata": {"count": 3},
    "data": [{"type": "seen"}, {"type": "seen"}, {"type": "exploited"}],
}

BDU_XML = f"""<?xml version="1.0" encoding="UTF-8"?>
<vulnerabilities>
  <vul>
    <identifier>BDU:2026-00001</identifier>
    <name>Уязвимость другого продукта</name>
    <identifiers><identifier type="CVE">CVE-2026-00001</identifier></identifiers>
  </vul>
  <vul>
    <identifier>BDU:2026-01234</identifier>
    <name>Уязвимость прокси-сервера Example</name>
    <description>Уязвимость позволяет нарушителю выполнить произвольный код.</description>
    <solution>Обновить программное обеспечение до версии 1.2.4.</solution>
    <exploit_status>Существует в открытом доступе</exploit_status>
    <fix_status>Уязвимость устранена</fix_status>
    <identifiers><identifier type="CVE" link="https://nvd.nist.gov">{CVE_ID}</identifier></identifiers>
  </vul>
</vulnerabilities>
""".encode("utf-8")


def _zip(data: bytes) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("export/export.xml", data)
    return buffer.getvalue()


class FakeWeb:
    """Routes requests by URL substring; unknown URLs return 404."""

    def __init__(self, routes: dict[str, object]) -> None:
        self.routes = routes
        self.urls: list[str] = []

    def __call__(self, request, _timeout) -> bytes:
        url = request.full_url
        self.urls.append(url)
        for fragment, payload in self.routes.items():
            if fragment in url:
                if isinstance(payload, Exception):
                    raise payload
                if isinstance(payload, bytes):
                    return payload
                return json.dumps(payload).encode()
        raise HTTPError(url, 404, "Not Found", hdrs=None, fp=None)


def full_collector(web: FakeWeb) -> IntelCollector:
    return IntelCollector(
        cveorg=CVEOrgClient("https://cve.test/api/cve", opener=web),
        ghsa=GHSAClient("https://gh.test/advisories", token="t", opener=web),
        osv=OSVClient("https://osv.test/v1/vulns", opener=web),
        bdu=BDUClient("https://bdu.test/vulxml.zip", opener=web),
        euvd=EUVDClient("https://euvd.test/api", opener=web),
        circl=CIRCLClient("https://circl.test/api", opener=web),
    )


def default_web() -> FakeWeb:
    return FakeWeb(
        {
            f"cve.test/api/cve/{CVE_ID}": CVE_RECORD,
            "gh.test/advisories": GHSA_RESPONSE,
            f"osv.test/v1/vulns/DEBIAN-{CVE_ID}": OSV_DEBIAN,
            "bdu.test/vulxml.zip": _zip(BDU_XML),
            "euvd.test/api/vulnerabilities": EUVD_RESPONSE,
            "circl.test/api/sighting/": CIRCL_SIGHTINGS,
        }
    )


class IntelCollectorTests(unittest.TestCase):
    def test_collects_every_source(self) -> None:
        intel = full_collector(default_web()).collect([CVE_ID])[CVE_ID]

        self.assertEqual(intel.vendor_description, "Vendor detailed text about the flaw.")
        self.assertEqual(intel.vendor_solution, "Upgrade to 1.2.4 or later.")
        self.assertEqual(intel.vendor_affected, ["Example Proxy 1.0 … < 1.2.4"])
        self.assertEqual(
            (intel.ssvc_exploitation, intel.ssvc_automatable, intel.ssvc_technical_impact),
            ("active", "yes", "total"),
        )
        self.assertEqual(intel.fallback_cvss[0], 9.1)
        self.assertIn("Proxy 1.2.4", intel.fixed_versions)
        self.assertIn("npm example-proxy 1.2.4", intel.fixed_versions)
        self.assertIn("Debian:12 example-proxy 1.2.4-1", intel.fixed_versions)
        self.assertEqual(intel.ghsa[0][0], "GHSA-aaaa-bbbb-cccc")
        self.assertEqual(intel.bdu_id, "BDU:2026-01234")
        self.assertIn("произвольный код", intel.bdu_description)
        self.assertIn("1.2.4", intel.bdu_solution)
        self.assertEqual(intel.euvd_id, "EUVD-2026-0002")
        self.assertEqual(intel.sightings, {"seen": 2, "exploited": 1})
        self.assertTrue(all(status.state == "ok" for status in intel.statuses))

    def test_source_failure_is_recorded_not_raised(self) -> None:
        web = default_web()
        web.routes["gh.test/advisories"] = HTTPError("u", 403, "rate", hdrs=None, fp=None)
        web.routes["bdu.test/vulxml.zip"] = OSError("geo blocked")
        intel = full_collector(web).collect([CVE_ID])[CVE_ID]

        states = {status.source: status.state for status in intel.statuses}
        self.assertEqual(states["GitHub Advisory"], "rate-limited")
        self.assertEqual(states["BDU FSTEC"], "unavailable")
        self.assertEqual(states["CVE.org"], "ok")
        self.assertIsNone(intel.bdu_id)
        self.assertEqual(intel.euvd_id, "EUVD-2026-0002")

    def test_bdu_download_happens_once_per_run(self) -> None:
        web = default_web()
        collector = full_collector(web)
        collector.collect([CVE_ID, "CVE-2026-00001"])
        self.assertEqual(sum("bdu.test" in url for url in web.urls), 1)

    def test_circl_record_is_fallback_when_cveorg_fails(self) -> None:
        web = default_web()
        web.routes[f"cve.test/api/cve/{CVE_ID}"] = OSError("down")
        web.routes[f"circl.test/api/vulnerability/{CVE_ID}"] = CVE_RECORD
        intel = full_collector(web).collect([CVE_ID])[CVE_ID]
        self.assertEqual(intel.vendor_description, "Vendor detailed text about the flaw.")

    def test_record_cvss_fallback(self) -> None:
        self.assertEqual(full_collector(default_web()).record_cvss(CVE_ID)[:2], (9.1, "CRITICAL"))


class IntelFormattingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.intel = full_collector(default_web()).collect([CVE_ID])[CVE_ID]

    def test_html_alert_includes_intel_blocks_and_links(self) -> None:
        message = format_alert(interesting_cve(), [], intel=self.intel)
        for expected in (
            "БДУ ФСТЭК BDU:2026-01234:",
            "Устранение (БДУ):",
            "Vendor description:",
            "CISA SSVC:</b> exploitation active · automatable yes · impact total",
            "Fixed in:",
            "GHSA-aaaa-bbbb-cccc",
            "EUVD:</b> EUVD-2026-0002",
            "Sightings (CIRCL):</b> seen 2 · exploited 1",
            'href="https://bdu.fstec.ru/vul/2026-01234"',
        ):
            self.assertIn(expected, message)
        self.assertLessEqual(len(message), 3900)

    def test_long_intel_stays_within_telegram_budget(self) -> None:
        intel = replace(
            self.intel,
            bdu_description="а" * 5000,
            vendor_description="b" * 5000,
            vendor_solution="c" * 5000,
            fixed_versions=[f"pkg{i} 1.{i}" for i in range(50)],
        )
        message = format_alert(interesting_cve(), [], intel=intel)
        self.assertLessEqual(len(message), 3900)
        self.assertIn("Exploit evidence", message)

    def test_text_and_json_formats(self) -> None:
        text = format_alert_text(interesting_cve(), [], intel=self.intel)
        self.assertIn("БДУ ФСТЭК BDU:2026-01234:", text)
        payload = json.loads(format_alert_json(interesting_cve(), [], intel=self.intel))
        self.assertEqual(payload["intel"]["bdu"]["id"], "BDU:2026-01234")
        self.assertEqual(payload["intel"]["ssvc"]["exploitation"], "active")

    def test_same_vendor_description_is_not_repeated(self) -> None:
        cve = interesting_cve()
        intel = Intel(CVE_ID, vendor_description=cve.description)
        self.assertNotIn("Vendor description", format_alert(cve, [], intel=intel))


class PipelineIntelTests(unittest.TestCase):
    def test_initial_alert_is_enriched(self) -> None:
        config = AppConfig(
            scan=scan_config(),
            feeds=FeedConfig(
                nvd_url="https://nvd.test",
                exploitdb_csv_url="https://exploitdb.test/files.csv",
            ),
        )
        telegram = RecordingTelegram()
        with TemporaryDirectory() as temp_dir:
            result = run_scan(
                config,
                Path(temp_dir) / "state.sqlite3",
                now=datetime(2026, 8, 20, 10, 0, tzinfo=timezone.utc),
                nvd_client=StaticNVDClient([interesting_cve()]),
                exploit_client=ExploitDBClient(
                    config.feeds.exploitdb_csv_url,
                    fetcher=lambda _url, _timeout: EXPLOIT_DB_CSV,
                ),
                github_client=StaticGitHubPoCClient(),
                telegram_factory=lambda: telegram,
                intel_collector=full_collector(default_web()),
            )
        self.assertEqual(result.notified, 1)
        self.assertIn("BDU:2026-01234", telegram.messages[0])
        self.assertIn("CISA SSVC", telegram.messages[0])


if __name__ == "__main__":
    unittest.main()
