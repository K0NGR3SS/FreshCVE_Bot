"""Extra vulnerability intelligence used to enrich alerts.

Sources (all free):
- CVE.org CVE Services API: CNA description, solutions, affected versions,
  CISA Vulnrichment (ADP) SSVC decision points and CVSS fallback.
- GitHub Advisory Database: open-source advisories and first patched versions.
- OSV.dev: fixed versions per ecosystem and Linux distribution.
- BDU FSTEC (bdu.fstec.ru): Russian description and remediation.
- EUVD (ENISA): EUVD identifier and exploitation flag.
- CIRCL Vulnerability-Lookup: sightings (seen / exploited / patched ...).

Every source is optional and best effort: a failure is recorded as a
SourceStatus and never stops the alert from being sent.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import io
import json
import os
from pathlib import Path
import re
import ssl
import sys
from typing import Any, Callable, Iterable
from urllib.error import HTTPError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen
import xml.etree.ElementTree as ElementTree
import zipfile

from cve_signal.exploits import SourceStatus


Opener = Callable[[Request, float], bytes]

_USER_AGENT = "cve-signal/0.3 (+https://github.com/Smithds90/FreshCVE_Bot)"
_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


@dataclass
class Intel:
    cve_id: str
    vendor_description: str | None = None
    vendor_solution: str | None = None
    vendor_affected: list[str] = field(default_factory=list)
    ssvc_exploitation: str | None = None
    ssvc_automatable: str | None = None
    ssvc_technical_impact: str | None = None
    fallback_cvss: tuple[float, str | None, str | None, str | None] | None = None
    ghsa: list[tuple[str, str, str]] = field(default_factory=list)
    fixed_versions: list[str] = field(default_factory=list)
    bdu_id: str | None = None
    bdu_description: str | None = None
    bdu_solution: str | None = None
    bdu_exploit_status: str | None = None
    bdu_fix_status: str | None = None
    euvd_id: str | None = None
    euvd_exploited_since: str | None = None
    sightings: dict[str, int] = field(default_factory=dict)
    statuses: list[SourceStatus] = field(default_factory=list)

    def add_fixed(self, value: str) -> None:
        if value and value not in self.fixed_versions:
            self.fixed_versions.append(value)

    @property
    def has_ssvc(self) -> bool:
        return any(
            (self.ssvc_exploitation, self.ssvc_automatable, self.ssvc_technical_impact)
        )


# ---------------------------------------------------------------- helpers


def _open_request(request: Request, timeout: float) -> bytes:
    with urlopen(request, timeout=timeout) as response:
        return response.read()


def _get_json(
    opener: Opener,
    url: str,
    *,
    timeout: float,
    headers: dict[str, str] | None = None,
) -> Any | None:
    request = Request(
        url,
        headers={"Accept": "application/json", "User-Agent": _USER_AGENT, **(headers or {})},
    )
    try:
        return json.loads(opener(request, timeout))
    except HTTPError as error:
        if error.code == 404:
            return None
        raise


def _english(items: Iterable[dict[str, Any]] | None) -> str | None:
    values = [item for item in items or () if item.get("value")]
    if not values:
        return None
    chosen = next(
        (item for item in values if str(item.get("lang", "")).lower().startswith("en")),
        values[0],
    )
    return _clean(str(chosen["value"]))


def _clean(value: str | None) -> str | None:
    if value is None:
        return None
    text = re.sub(r"<[^>]+>", " ", value)
    text = re.sub(r"\s+", " ", text).strip()
    return text or None


def _status(source: str, error: Exception) -> SourceStatus:
    if isinstance(error, HTTPError):
        state = "rate-limited" if error.code in {403, 429} else "unavailable"
        detail = f"HTTP {error.code}"
    else:
        state, detail = "unavailable", str(error)[:200]
    print(f"{source} enrichment {state}: {detail}", file=sys.stderr)
    return SourceStatus(source, state, detail)


# ------------------------------------------------------- CVE.org + CISA ADP


class CVEOrgClient:
    source = "CVE.org"

    def __init__(self, base_url: str, *, timeout: float = 20.0, opener: Opener | None = None):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._opener = opener or _open_request

    def enrich(self, intel: Intel) -> None:
        record = _get_json(
            self._opener, f"{self.base_url}/{quote(intel.cve_id)}", timeout=self.timeout
        )
        if record:
            apply_cve_record(intel, record)


def apply_cve_record(intel: Intel, record: dict[str, Any]) -> None:
    containers = record.get("containers", {})
    cna = containers.get("cna", {}) or {}
    intel.vendor_description = intel.vendor_description or _english(cna.get("descriptions"))
    solution = _english(cna.get("solutions")) or _english(cna.get("workarounds"))
    intel.vendor_solution = intel.vendor_solution or solution
    if not intel.vendor_affected:
        intel.vendor_affected = list(_affected_versions(cna.get("affected", [])))[:6]
    for fixed in _fixed_from_affected(cna.get("affected", [])):
        intel.add_fixed(fixed)

    metrics_sources = [cna.get("metrics", [])]
    for adp in containers.get("adp", []) or []:
        metrics = adp.get("metrics", []) or []
        metrics_sources.append(metrics)
        for metric in metrics:
            other = metric.get("other") or {}
            if str(other.get("type", "")).lower() != "ssvc":
                continue
            for option in (other.get("content") or {}).get("options", []) or []:
                for key, value in option.items():
                    name = key.lower().replace(" ", "")
                    if name == "exploitation":
                        intel.ssvc_exploitation = str(value)
                    elif name == "automatable":
                        intel.ssvc_automatable = str(value)
                    elif name == "technicalimpact":
                        intel.ssvc_technical_impact = str(value)
    if intel.fallback_cvss is None:
        intel.fallback_cvss = _best_record_cvss(metrics_sources)


def _best_record_cvss(
    sources: list[list[dict[str, Any]]],
) -> tuple[float, str | None, str | None, str | None] | None:
    for key, version in (
        ("cvssV4_0", "4.0"),
        ("cvssV3_1", "3.1"),
        ("cvssV3_0", "3.0"),
    ):
        for metrics in sources:
            for metric in metrics or []:
                data = metric.get(key)
                if data and data.get("baseScore") is not None:
                    severity = data.get("baseSeverity")
                    return (
                        float(data["baseScore"]),
                        str(severity).upper() if severity else None,
                        version,
                        data.get("vectorString"),
                    )
    return None


def _affected_versions(affected: list[dict[str, Any]]) -> Iterable[str]:
    for item in affected or []:
        name = " ".join(
            str(part)
            for part in (item.get("vendor"), item.get("product") or item.get("packageName"))
            if part and str(part).lower() not in {"n/a", "unknown"}
        )
        if not name:
            continue
        for version in item.get("versions", []) or []:
            if version.get("status") != "affected":
                continue
            start = str(version.get("version", ""))
            if version.get("lessThan"):
                bound = f"< {version['lessThan']}"
                text = f"{start} … {bound}" if start not in {"", "0", "*"} else bound
            elif version.get("lessThanOrEqual"):
                bound = f"<= {version['lessThanOrEqual']}"
                text = f"{start} … {bound}" if start not in {"", "0", "*"} else bound
            else:
                text = start
            if text:
                yield f"{name} {text}"


def _fixed_from_affected(affected: list[dict[str, Any]]) -> Iterable[str]:
    for item in affected or []:
        product = item.get("product") or item.get("packageName")
        if not product or str(product).lower() == "n/a":
            continue
        for version in item.get("versions", []) or []:
            for change in version.get("changes", []) or []:
                if change.get("status") == "unaffected" and change.get("at"):
                    yield f"{product} {change['at']}"


# ------------------------------------------------------------------- GHSA


class GHSAClient:
    source = "GitHub Advisory"

    def __init__(
        self,
        base_url: str,
        *,
        token: str | None = None,
        timeout: float = 20.0,
        opener: Opener | None = None,
    ):
        self.base_url = base_url
        self.token = token if token is not None else os.getenv("GITHUB_TOKEN")
        self.timeout = timeout
        self._opener = opener or _open_request

    def enrich(self, intel: Intel) -> None:
        headers = {"Accept": "application/vnd.github+json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        url = f"{self.base_url}?{urlencode({'cve_id': intel.cve_id, 'per_page': 5})}"
        payload = _get_json(self._opener, url, timeout=self.timeout, headers=headers) or []
        for advisory in payload:
            ghsa_id = str(advisory.get("ghsa_id", ""))
            if not ghsa_id:
                continue
            intel.ghsa.append(
                (ghsa_id, str(advisory.get("html_url", "")), _clean(advisory.get("summary")) or "")
            )
            for vulnerability in advisory.get("vulnerabilities", []) or []:
                package = vulnerability.get("package") or {}
                patched = vulnerability.get("first_patched_version")
                if isinstance(patched, dict):
                    patched = patched.get("identifier")
                if patched and package.get("name"):
                    ecosystem = package.get("ecosystem") or ""
                    intel.add_fixed(f"{ecosystem} {package['name']} {patched}".strip())


# -------------------------------------------------------------------- OSV


class OSVClient:
    source = "OSV"

    def __init__(self, base_url: str, *, timeout: float = 20.0, opener: Opener | None = None):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._opener = opener or _open_request

    def enrich(self, intel: Intel) -> None:
        ids = [intel.cve_id, f"DEBIAN-{intel.cve_id}", f"UBUNTU-{intel.cve_id}"]
        ids.extend(ghsa_id for ghsa_id, _url, _summary in intel.ghsa[:2])
        for osv_id in ids:
            record = _get_json(
                self._opener, f"{self.base_url}/{quote(osv_id)}", timeout=self.timeout
            )
            if record:
                apply_osv_record(intel, record)


def apply_osv_record(intel: Intel, record: dict[str, Any]) -> None:
    for affected in record.get("affected", []) or []:
        package = affected.get("package") or {}
        name = package.get("name")
        if not name:
            continue
        ecosystem = str(package.get("ecosystem", ""))
        for range_item in affected.get("ranges", []) or []:
            if range_item.get("type") == "GIT":
                continue
            for event in range_item.get("events", []) or []:
                fixed = event.get("fixed")
                if fixed:
                    intel.add_fixed(f"{ecosystem} {name} {fixed}".strip())


# --------------------------------------------------------------- BDU FSTEC


class BDUClient:
    """Indexes the BDU FSTEC XML export (vulxml.zip) by CVE identifier."""

    source = "BDU FSTEC"

    def __init__(
        self,
        url: str,
        *,
        ca_file: str | None = None,
        timeout: float = 180.0,
        opener: Opener | None = None,
    ):
        self.url = url
        self.ca_file = ca_file
        self.timeout = timeout
        self._opener = opener or self._open_with_ca

    def _open_with_ca(self, request: Request, timeout: float) -> bytes:
        context = None
        if self.ca_file and Path(self.ca_file).is_file():
            # bdu.fstec.ru is signed by the Russian Trusted Root CA. Trust it
            # for this download only, on top of the system store.
            context = ssl.create_default_context()
            context.load_verify_locations(cafile=self.ca_file)
        with urlopen(request, timeout=timeout, context=context) as response:
            return response.read()

    def lookup(self, cve_ids: Iterable[str]) -> dict[str, dict[str, str]]:
        wanted = {value.upper() for value in cve_ids}
        if not wanted:
            return {}
        request = Request(self.url, headers={"User-Agent": _USER_AGENT})
        data = self._opener(request, self.timeout)
        return parse_bdu_export(data, wanted)


def parse_bdu_export(data: bytes, wanted: set[str]) -> dict[str, dict[str, str]]:
    if data[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            names = [name for name in archive.namelist() if name.lower().endswith(".xml")]
            if not names:
                raise ValueError("BDU archive has no XML file")
            with archive.open(names[0]) as handle:
                return _parse_bdu_xml(handle, wanted)
    return _parse_bdu_xml(io.BytesIO(data), wanted)


def _parse_bdu_xml(handle: Any, wanted: set[str]) -> dict[str, dict[str, str]]:
    results: dict[str, dict[str, str]] = {}
    for _event, element in ElementTree.iterparse(handle, events=("end",)):
        if _local(element.tag) != "vul":
            continue
        text = " ".join(part for part in element.itertext() if part)
        matched = {value.upper() for value in _CVE_PATTERN.findall(text)} & wanted
        if matched:
            fields: dict[str, str] = {}
            for child in element:
                tag = _local(child.tag)
                if tag in {
                    "identifier",
                    "name",
                    "description",
                    "solution",
                    "severity",
                    "exploit_status",
                    "fix_status",
                } and tag not in fields:
                    value = _clean("".join(child.itertext()))
                    if value:
                        fields[tag] = value
            for cve_id in matched:
                results.setdefault(cve_id, fields)
        element.clear()
    return results


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].lower()


def apply_bdu(intel: Intel, fields: dict[str, str] | None) -> None:
    if not fields:
        return
    intel.bdu_id = fields.get("identifier")
    intel.bdu_description = fields.get("description") or fields.get("name")
    intel.bdu_solution = fields.get("solution")
    intel.bdu_exploit_status = fields.get("exploit_status")
    intel.bdu_fix_status = fields.get("fix_status")


# ------------------------------------------------------------------- EUVD


class EUVDClient:
    source = "EUVD"

    def __init__(self, base_url: str, *, timeout: float = 20.0, opener: Opener | None = None):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._opener = opener or _open_request

    def enrich(self, intel: Intel) -> None:
        query = urlencode({"text": intel.cve_id, "page": 0, "size": 10})
        payload = _get_json(
            self._opener, f"{self.base_url}/vulnerabilities?{query}", timeout=self.timeout
        )
        items = (payload or {}).get("items", []) if isinstance(payload, dict) else payload or []
        for item in items:
            aliases = {value.upper() for value in _CVE_PATTERN.findall(str(item.get("aliases", "")))}
            if intel.cve_id.upper() in aliases:
                intel.euvd_id = str(item.get("id")) if item.get("id") else None
                exploited = item.get("exploitedSince")
                intel.euvd_exploited_since = str(exploited) if exploited else None
                return


# ------------------------------------------------------------------ CIRCL


class CIRCLClient:
    source = "CIRCL"

    def __init__(self, base_url: str, *, timeout: float = 20.0, opener: Opener | None = None):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._opener = opener or _open_request

    def enrich(self, intel: Intel) -> None:
        query = urlencode({"vuln_id": intel.cve_id, "per_page": 100})
        payload = _get_json(
            self._opener, f"{self.base_url}/sighting/?{query}", timeout=self.timeout
        )
        for item in (payload or {}).get("data", []) or []:
            kind = str(item.get("type", "")).lower()
            if kind == "exploided":
                kind = "exploited"
            if kind:
                intel.sightings[kind] = intel.sightings.get(kind, 0) + 1
        # The CVE record mirrored by CIRCL is a fallback when CVE.org failed.
        if intel.vendor_description is None:
            record = _get_json(
                self._opener,
                f"{self.base_url}/vulnerability/{quote(intel.cve_id)}",
                timeout=self.timeout,
            )
            if isinstance(record, dict) and "containers" in record:
                apply_cve_record(intel, record)


# -------------------------------------------------------------- collector


class IntelCollector:
    def __init__(
        self,
        *,
        cveorg: CVEOrgClient | None = None,
        ghsa: GHSAClient | None = None,
        osv: OSVClient | None = None,
        bdu: BDUClient | None = None,
        euvd: EUVDClient | None = None,
        circl: CIRCLClient | None = None,
    ) -> None:
        # Order matters: GHSA ids feed the OSV lookups, CVE.org runs before
        # the CIRCL fallback.
        self.clients = [client for client in (cveorg, ghsa, osv, euvd, circl) if client]
        self.bdu = bdu
        self._bdu_cache: dict[str, dict[str, str]] = {}
        self._bdu_status: SourceStatus | None = None

    @classmethod
    def from_feeds(cls, feeds: Any) -> IntelCollector | None:
        collector = cls(
            cveorg=CVEOrgClient(feeds.cveorg_url) if feeds.cveorg_url else None,
            ghsa=GHSAClient(feeds.ghsa_url) if feeds.ghsa_url else None,
            osv=OSVClient(feeds.osv_url) if feeds.osv_url else None,
            bdu=BDUClient(feeds.bdu_url, ca_file=feeds.bdu_ca_file) if feeds.bdu_url else None,
            euvd=EUVDClient(feeds.euvd_url) if feeds.euvd_url else None,
            circl=CIRCLClient(feeds.circl_url) if feeds.circl_url else None,
        )
        return collector if collector.clients or collector.bdu else None

    def record_cvss(self, cve_id: str) -> tuple[float, str | None, str | None, str | None] | None:
        """CVSS published in the CVE record (CNA or CISA ADP), for NVD gaps."""
        intel = Intel(cve_id.upper())
        for client in self.clients:
            if isinstance(client, (CVEOrgClient, CIRCLClient)):
                try:
                    if isinstance(client, CIRCLClient):
                        record = _get_json(
                            client._opener,
                            f"{client.base_url}/vulnerability/{quote(intel.cve_id)}",
                            timeout=client.timeout,
                        )
                        if isinstance(record, dict) and "containers" in record:
                            apply_cve_record(intel, record)
                    else:
                        client.enrich(intel)
                except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
                    _status(client.source, error)
                if intel.fallback_cvss is not None:
                    return intel.fallback_cvss
        return None

    def collect(self, cve_ids: Iterable[str]) -> dict[str, Intel]:
        ids = [value.upper() for value in cve_ids]
        if self.bdu is not None and self._bdu_status is None:
            try:
                self._bdu_cache = self.bdu.lookup(ids)
                self._bdu_status = SourceStatus(self.bdu.source, "ok")
            except (OSError, ValueError, zipfile.BadZipFile, ElementTree.ParseError) as error:
                self._bdu_status = _status(self.bdu.source, error)
        results: dict[str, Intel] = {}
        for cve_id in ids:
            intel = Intel(cve_id)
            for client in self.clients:
                try:
                    client.enrich(intel)
                    intel.statuses.append(SourceStatus(client.source, "ok"))
                except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
                    intel.statuses.append(_status(client.source, error))
            if self.bdu is not None:
                apply_bdu(intel, self._bdu_cache.get(cve_id))
                if self._bdu_status is not None:
                    intel.statuses.append(self._bdu_status)
            results[cve_id] = intel
        return results
