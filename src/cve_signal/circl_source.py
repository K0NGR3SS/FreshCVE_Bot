"""CIRCL Vulnerability-Lookup as the primary CVE feed.

The public instance (https://vulnerability.circl.lu) aggregates NVD, the
CVE List (CVE.org, incl. CISA Vulnrichment), GitHub advisories, EUVD and more.

``GET /api/vulnerability/?source=nvd&since=...&date_sort=updated`` pages through
CVEs that NVD changed since a date. Each item is the CVE List (CVE JSON 5)
record; with ``with_meta=true`` the raw NVD item is attached under
``vulnerability-lookup:meta.nvd``. The NVD item is preferred because it carries
CPE configurations, NVD CVSS and CISA KEV fields; when NVD has not processed a
CVE yet, the CVE JSON 5 record (CNA and CISA ADP metrics) is used instead.

The client exposes the same ``fetch_modified`` / ``fetch_by_id`` interface as
``NVDClient`` so the pipeline can use either.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
import json
import sys
import time
from typing import Any, Callable, Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode
from urllib.request import Request, urlopen

from cve_signal.models import CVE, Reference
from cve_signal.nvd import parse_cve


Opener = Callable[[Request, float], bytes]

_USER_AGENT = "cve-signal/0.3 (+https://github.com/Smithds90/FreshCVE_Bot)"
_PER_PAGE = 100


class CIRCLVulnerabilityClient:
    def __init__(
        self,
        base_url: str,
        *,
        source: str = "nvd",
        timeout: float = 60.0,
        max_pages: int = 200,
        page_delay: float = 1.0,
        opener: Opener | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.source = source
        self.timeout = timeout
        self.max_pages = max_pages
        self.page_delay = page_delay if opener is None else 0.0
        self._opener = opener or _open_request

    # ------------------------------------------------------------ public API

    def fetch_modified(self, start: datetime, end: datetime) -> list[CVE]:
        start = _as_utc(start)
        end = _as_utc(end)
        if start >= end:
            raise ValueError("start must be before end")
        results: dict[str, CVE] = {}
        for page in range(1, self.max_pages + 1):
            params = {
                "source": self.source,
                "since": start.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "date_sort": "updated",
                "sort_order": "desc",
                "per_page": str(_PER_PAGE),
                "page": str(page),
                "with_meta": "true",
            }
            payload = self._request_json(f"{self.base_url}/vulnerability/?{urlencode(params)}")
            items = payload if isinstance(payload, list) else []
            for item in items:
                if not isinstance(item, dict):
                    continue
                cve = parse_circl_record(item)
                if cve is None or cve.modified > end:
                    continue
                previous = results.get(cve.cve_id)
                if previous is None or cve.modified > previous.modified:
                    results[cve.cve_id] = cve
            if len(items) < _PER_PAGE:
                break
            if self.page_delay:
                time.sleep(self.page_delay)
        else:
            print(
                f"CIRCL: stopped after {self.max_pages} pages; window may be incomplete",
                file=sys.stderr,
            )
        return list(results.values())

    def fetch_by_id(self, cve_id: str) -> CVE | None:
        payload = self._request_json(
            f"{self.base_url}/vulnerability/{quote(cve_id)}?with_meta=true"
        )
        if not isinstance(payload, dict) or not payload:
            return None
        return parse_circl_record(payload)

    # -------------------------------------------------------------- helpers

    def _request_json(self, url: str) -> Any:
        request = Request(url, headers={"Accept": "application/json", "User-Agent": _USER_AGENT})
        for attempt in range(6):
            try:
                return json.loads(self._opener(request, self.timeout))
            except HTTPError as error:
                if error.code == 404:
                    return None
                if error.code != 429 and error.code < 500:
                    raise
                if attempt == 5:
                    raise
                retry_after = error.headers.get("Retry-After") if error.headers else None
                delay = float(retry_after) if retry_after and retry_after.isdigit() else 5 * 2**attempt
            except (URLError, TimeoutError):
                if attempt == 5:
                    raise
                delay = 5 * 2**attempt
            if self.page_delay or self._opener is _open_request:
                time.sleep(min(delay, 60))
        raise RuntimeError("CIRCL request retry loop exited unexpectedly")


def parse_circl_record(record: dict[str, Any]) -> CVE | None:
    """Build a CVE from a CIRCL record: NVD data first, CVE JSON 5 as fallback."""
    meta = record.get("vulnerability-lookup:meta") or {}
    nvd_item = _decode(meta.get("nvd")) if isinstance(meta, dict) else None
    from_record = parse_cve5(record) if "cveMetadata" in record else None

    cve: CVE | None = None
    if isinstance(nvd_item, dict):
        raw = nvd_item.get("cve", nvd_item)
        if isinstance(raw, dict) and raw.get("id"):
            cve = _merge(parse_cve(raw), from_record)
    if cve is None and isinstance(record.get("cve"), dict) and record["cve"].get("id"):
        cve = parse_cve(record["cve"])
    if cve is None:
        cve = from_record
    epss = _decode(meta.get("epss")) if isinstance(meta, dict) else None
    if cve is not None and isinstance(epss, dict):
        try:
            cve = replace(
                cve,
                epss_score=float(epss["epss"]),
                epss_percentile=float(epss["percentile"]),
            )
        except (KeyError, TypeError, ValueError):
            pass
    return cve


def _merge(nvd: CVE, record: CVE | None) -> CVE:
    if record is None:
        return nvd
    updates: dict[str, Any] = {}
    if nvd.cvss_score is None and record.cvss_score is not None:
        updates.update(
            cvss_score=record.cvss_score,
            cvss_severity=record.cvss_severity,
            cvss_version=record.cvss_version,
            cvss_vector=record.cvss_vector,
            attack_vector=nvd.attack_vector or record.attack_vector,
            privileges_required=nvd.privileges_required or record.privileges_required,
            user_interaction=nvd.user_interaction or record.user_interaction,
        )
    if not nvd.known_exploited and record.known_exploited:
        updates.update(known_exploited=True, kev_date_added=record.kev_date_added)
    if not nvd.cwes and record.cwes:
        updates["cwes"] = record.cwes
    if not nvd.products and record.products:
        updates["products"] = record.products
    if not nvd.affected_ranges and record.affected_ranges:
        updates["affected_ranges"] = record.affected_ranges
    return replace(nvd, **updates) if updates else nvd


def parse_cve5(record: dict[str, Any]) -> CVE | None:
    metadata = record.get("cveMetadata") or {}
    cve_id = str(metadata.get("cveId", "")).upper()
    if not cve_id or str(metadata.get("state", "")).upper() == "REJECTED":
        return None
    containers = record.get("containers") or {}
    cna = containers.get("cna") or {}
    adps = [adp for adp in containers.get("adp", []) or [] if isinstance(adp, dict)]

    published = _parse_datetime(metadata.get("datePublished")) or _parse_datetime(
        metadata.get("dateReserved")
    )
    modified = _parse_datetime(metadata.get("dateUpdated")) or published
    if published is None or modified is None:
        return None

    description = _english(cna.get("descriptions")) or "No description available."
    score, severity, version, vector, attack, privileges, interaction = _best_cvss(
        [cna.get("metrics", [])] + [adp.get("metrics", []) for adp in adps]
    )
    cwes = sorted(
        {
            str(desc.get("cweId")).upper()
            for container in [cna, *adps]
            for problem in container.get("problemTypes", []) or []
            for desc in problem.get("descriptions", []) or []
            if str(desc.get("cweId", "")).upper().startswith("CWE-")
        }
    )
    products = sorted(
        {
            " ".join(
                str(part).lower()
                for part in (item.get("vendor"), item.get("product"))
                if part and str(part).lower() not in {"n/a", "unknown"}
            )
            for item in cna.get("affected", []) or []
        }
        - {""}
    )
    references = tuple(
        Reference(url=str(item["url"]), tags=tuple(str(tag) for tag in item.get("tags", []) or []))
        for item in cna.get("references", []) or []
        if item.get("url")
    )
    kev_added = None
    for adp in adps:
        for metric in adp.get("metrics", []) or []:
            other = metric.get("other") or {}
            if str(other.get("type", "")).lower() == "kev":
                kev_added = (other.get("content") or {}).get("dateAdded") or "unknown"

    return CVE(
        cve_id=cve_id,
        description=description,
        published=published,
        modified=modified,
        cvss_score=score,
        cvss_severity=severity,
        cvss_version=version,
        cwes=tuple(cwes),
        products=tuple(products),
        references=references,
        known_exploited=kev_added is not None,
        cvss_vector=vector,
        attack_vector=attack,
        privileges_required=privileges,
        user_interaction=interaction,
        affected_ranges=tuple(sorted(set(_affected_ranges(cna.get("affected", []) or [])))),
        kev_date_added=kev_added if kev_added not in {None, "unknown"} else None,
    )


def _best_cvss(
    metric_lists: list[list[dict[str, Any]]],
) -> tuple[float | None, str | None, str | None, str | None, str | None, str | None, str | None]:
    for key, version in (
        ("cvssV4_0", "4.0"),
        ("cvssV3_1", "3.1"),
        ("cvssV3_0", "3.0"),
        ("cvssV2_0", "2.0"),
    ):
        for metrics in metric_lists:
            for metric in metrics or []:
                data = metric.get(key) if isinstance(metric, dict) else None
                if not data or data.get("baseScore") is None:
                    continue
                score = float(data["baseScore"])
                severity = data.get("baseSeverity")
                return (
                    score,
                    str(severity).upper() if severity else _severity(score),
                    version,
                    data.get("vectorString"),
                    _metric(data.get("attackVector") or data.get("accessVector")),
                    _metric(data.get("privilegesRequired") or data.get("authentication")),
                    _metric(data.get("userInteraction")),
                )
    return None, None, None, None, None, None, None


def _affected_ranges(affected: Iterable[dict[str, Any]]) -> Iterable[str]:
    for item in affected:
        name = " ".join(
            str(part).lower()
            for part in (item.get("vendor"), item.get("product"))
            if part and str(part).lower() not in {"n/a", "unknown"}
        )
        if not name:
            continue
        for version in item.get("versions", []) or []:
            if version.get("status") != "affected":
                continue
            start = str(version.get("version", ""))
            bound = (
                f"< {version['lessThan']}"
                if version.get("lessThan")
                else f"<= {version['lessThanOrEqual']}"
                if version.get("lessThanOrEqual")
                else ""
            )
            if bound and start not in {"", "0", "*"}:
                yield f"{name} >= {start} and {bound}"
            elif bound:
                yield f"{name} {bound}"
            elif start and start not in {"*", "n/a"}:
                yield f"{name} {start}"


def _severity(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW" if score > 0 else "NONE"


def _metric(value: object) -> str | None:
    return str(value).replace("_", " ").title() if value else None


def _english(items: Iterable[dict[str, Any]] | None) -> str | None:
    values = [item for item in items or () if item.get("value")]
    if not values:
        return None
    chosen = next(
        (item for item in values if str(item.get("lang", "")).lower().startswith("en")),
        values[0],
    )
    return str(chosen["value"]).strip()


def _decode(value: Any) -> Any:
    if isinstance(value, (bytes, bytearray)):
        value = value.decode("utf-8", errors="replace")
    if isinstance(value, str):
        try:
            return json.loads(value)
        except ValueError:
            return None
    return value


def _parse_datetime(value: Any) -> datetime | None:
    if not value:
        return None
    text = str(value).strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _open_request(request: Request, timeout: float) -> bytes:
    with urlopen(request, timeout=timeout) as response:
        return response.read()


# ------------------------------------------------------------------ EPSS


class CIRCLEPSSClient:
    """EPSS scores served by CIRCL (``/api/epss/<CVE>``, FIRST response format)."""

    def __init__(
        self,
        base_url: str,
        *,
        timeout: float = 20.0,
        workers: int = 8,
        opener: Opener | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.workers = workers
        self._opener = opener or _open_request

    def fetch_scores(self, cve_ids: list[str]) -> dict[str, tuple[float, float]]:
        from concurrent.futures import ThreadPoolExecutor

        ids = sorted({value.upper() for value in cve_ids})
        if not ids:
            return {}
        failures: list[Exception] = []

        def one(cve_id: str) -> tuple[str, tuple[float, float] | None]:
            try:
                return cve_id, self._score(cve_id)
            except (OSError, ValueError) as error:
                failures.append(error)
                return cve_id, None

        with ThreadPoolExecutor(max_workers=max(1, self.workers)) as pool:
            results = dict(pool.map(one, ids))
        if failures and len(failures) == len(ids):
            raise OSError(f"CIRCL EPSS unavailable: {failures[0]}")
        return {cve_id: score for cve_id, score in results.items() if score is not None}

    def _score(self, cve_id: str) -> tuple[float, float] | None:
        request = Request(
            f"{self.base_url}/epss/{quote(cve_id)}",
            headers={"Accept": "application/json", "User-Agent": _USER_AGENT},
        )
        try:
            payload = json.loads(self._opener(request, self.timeout))
        except HTTPError as error:
            if error.code == 404:
                return None
            raise
        return parse_epss_payload(payload, cve_id)


def parse_epss_payload(payload: Any, cve_id: str) -> tuple[float, float] | None:
    for item in (payload or {}).get("data", []) if isinstance(payload, dict) else []:
        if str(item.get("cve", cve_id)).upper() != cve_id.upper():
            continue
        try:
            return float(item["epss"]), float(item["percentile"])
        except (KeyError, TypeError, ValueError):
            return None
    return None


# ------------------------------------------------------------------- KEV

CISA_KEV_CATALOG_UUID = "405284c2-e461-4670-8979-7fd2c9755a60"


class CIRCLKEVClient:
    """The CISA KEV catalog as mirrored by CIRCL (GCVE-BCP-07 entries)."""

    def __init__(
        self,
        base_url: str,
        *,
        catalog_uuid: str = CISA_KEV_CATALOG_UUID,
        timeout: float = 60.0,
        opener: Opener | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.catalog_uuid = catalog_uuid
        self.timeout = timeout
        self._opener = opener or _open_request
        self._catalog: dict[str, Any] | None = None
        self.max_daily_additions = 30

    def fetch_all(self) -> dict[str, Any]:
        if self._catalog is None:
            self._catalog = self._download()
        return self._catalog

    def fetch_added_since(self, since: Any) -> dict[str, Any]:
        since_text = since.isoformat()
        recent = {
            cve_id: entry
            for cve_id, entry in self.fetch_all().items()
            if entry.date_added >= since_text
        }
        # CISA adds a handful of entries a day. A burst means the mirror's
        # timestamps reflect a re-sync rather than CISA's dateAdded, so they
        # cannot tell which entries are new; membership is still used.
        if len(recent) > self.max_daily_additions:
            print(
                f"CIRCL CISA KEV: {len(recent)} entries dated since {since_text}; "
                "treating timestamps as sync times and skipping new-entry detection",
                file=sys.stderr,
            )
            return {}
        return recent

    def _download(self) -> dict[str, Any]:
        from cve_signal.kev import KEVEntry

        entries: dict[str, Any] = {}
        for page in range(1, 51):
            query = urlencode(
                {
                    "vulnerability_lookup_origin": self.catalog_uuid,
                    "per_page": 1000,
                    "page": page,
                }
            )
            request = Request(
                f"{self.base_url}/kev/?{query}",
                headers={"Accept": "application/json", "User-Agent": _USER_AGENT},
            )
            payload = json.loads(self._opener(request, self.timeout))
            items = payload.get("data", []) if isinstance(payload, dict) else []
            for item in items:
                if not isinstance(item, dict):
                    continue
                status = item.get("status") or {}
                if status.get("exploited") is False:
                    continue
                cve_id = str((item.get("vulnerability") or {}).get("vulnId", "")).upper()
                if not cve_id.startswith("CVE-"):
                    continue
                timestamps = item.get("timestamps") or {}
                added = next(
                    (
                        str(timestamps[key])[:10]
                        for key in ("first_seen_at", "asserted_at", "recorded_at")
                        if timestamps.get(key)
                    ),
                    str(status.get("status_updated_at", ""))[:10],
                )
                entries[cve_id] = KEVEntry(
                    cve_id=cve_id,
                    date_added=added or "1970-01-01",
                    due_date=None,
                    required_action=None,
                    known_ransomware_use=None,
                )
            if len(items) < 1000:
                break
        if not entries:
            raise ValueError("CIRCL returned an empty CISA KEV catalog")
        return entries
