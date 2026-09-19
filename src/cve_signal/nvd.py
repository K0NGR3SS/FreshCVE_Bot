from __future__ import annotations

from datetime import datetime, timezone
import json
import os
import time
from typing import Any, Callable, Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit, urlunsplit
from urllib.request import Request, urlopen

from cve_signal.models import CVE, Reference


JsonOpener = Callable[[Request, float], bytes]


class NVDClient:
    def __init__(
        self,
        base_url: str,
        api_key: str | None = None,
        *,
        timeout: float = 30.0,
        opener: JsonOpener | None = None,
    ) -> None:
        self.base_url = base_url
        self.api_key = api_key or os.getenv("NVD_API_KEY")
        self.timeout = timeout
        self._opener = opener or _open_request

    def fetch_modified(self, start: datetime, end: datetime) -> list[CVE]:
        start = _as_utc(start)
        end = _as_utc(end)
        if start >= end:
            raise ValueError("start must be before end")

        common_params = {
            "lastModStartDate": _nvd_datetime(start),
            "lastModEndDate": _nvd_datetime(end),
            "noRejected": "",
            "resultsPerPage": "2000",
        }
        results: list[CVE] = []
        start_index = 0

        while True:
            params = {**common_params, "startIndex": str(start_index)}
            payload = self._request_json(params)
            vulnerabilities = payload.get("vulnerabilities", [])
            results.extend(parse_cve(item["cve"]) for item in vulnerabilities)

            start_index += len(vulnerabilities)
            total_results = int(payload.get("totalResults", 0))
            if not vulnerabilities or start_index >= total_results:
                break

        return results

    def fetch_by_id(self, cve_id: str) -> CVE | None:
        payload = self._request_json({"cveId": cve_id, "noRejected": ""})
        vulnerabilities = payload.get("vulnerabilities", [])
        if not vulnerabilities:
            return None
        return parse_cve(vulnerabilities[0]["cve"])

    def _request_json(self, params: dict[str, str]) -> dict[str, Any]:
        url = _with_query(self.base_url, params)
        headers = {
            "Accept": "application/json",
            "User-Agent": (
                "cve-signal/0.2 (+https://github.com/K0NGR3SS/CVE2Exploit)"
            ),
        }
        if self.api_key:
            headers["apiKey"] = self.api_key
        request = Request(url, headers=headers)

        for attempt in range(3):
            try:
                return json.loads(self._opener(request, self.timeout))
            except HTTPError as error:
                if error.code != 429 and error.code < 500:
                    raise
                if attempt == 2:
                    raise
            except URLError:
                if attempt == 2:
                    raise
            time.sleep(2**attempt)
        raise RuntimeError("NVD request retry loop exited unexpectedly")


def parse_cve(raw: dict[str, Any]) -> CVE:
    (
        score,
        severity,
        version,
        vector,
        attack_vector,
        privileges_required,
        user_interaction,
    ) = _best_cvss(raw.get("metrics", {}))
    descriptions = raw.get("descriptions", [])
    description = next(
        (item["value"] for item in descriptions if item.get("lang") == "en"),
        descriptions[0]["value"] if descriptions else "No description available.",
    )
    cwes = tuple(
        sorted(
            {
                desc["value"].upper()
                for weakness in raw.get("weaknesses", [])
                for desc in weakness.get("description", [])
                if desc.get("value", "").upper().startswith("CWE-")
            }
        )
    )
    references = tuple(
        Reference(
            url=item["url"],
            tags=tuple(str(tag) for tag in item.get("tags", [])),
        )
        for item in raw.get("references", [])
        if item.get("url")
    )

    return CVE(
        cve_id=raw["id"],
        description=description,
        published=_parse_datetime(raw["published"]),
        modified=_parse_datetime(raw["lastModified"]),
        cvss_score=score,
        cvss_severity=severity,
        cvss_version=version,
        cwes=cwes,
        products=tuple(sorted(set(_iter_products(raw.get("configurations", []))))),
        references=references,
        known_exploited=bool(raw.get("cisaExploitAdd")),
        cvss_vector=vector,
        attack_vector=attack_vector,
        privileges_required=privileges_required,
        user_interaction=user_interaction,
        affected_ranges=tuple(
            sorted(set(_iter_affected_ranges(raw.get("configurations", []))))
        ),
        kev_date_added=raw.get("cisaExploitAdd"),
        kev_due_date=raw.get("cisaActionDue"),
        kev_required_action=raw.get("cisaRequiredAction"),
        known_ransomware_use=raw.get("cisaKnownRansomwareCampaignUse"),
    )


def _best_cvss(
    metrics: dict[str, Any],
) -> tuple[
    float | None,
    str | None,
    str | None,
    str | None,
    str | None,
    str | None,
    str | None,
]:
    for metric_name in (
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2",
    ):
        candidates = metrics.get(metric_name, [])
        if not candidates:
            continue
        metric = next(
            (item for item in candidates if item.get("type") == "Primary"),
            candidates[0],
        )
        data = metric.get("cvssData", {})
        score = data.get("baseScore")
        severity = data.get("baseSeverity") or metric.get("baseSeverity")
        version = data.get("version")
        if score is not None:
            return (
                float(score),
                str(severity).upper() if severity else None,
                str(version) if version else None,
                str(data.get("vectorString")) if data.get("vectorString") else None,
                _normalized_metric(
                    data.get("attackVector") or data.get("accessVector")
                ),
                _normalized_metric(
                    data.get("privilegesRequired") or data.get("authentication")
                ),
                _normalized_metric(data.get("userInteraction")),
            )
    return None, None, None, None, None, None, None


def _normalized_metric(value: object) -> str | None:
    return str(value).replace("_", " ").title() if value else None


def _iter_products(configurations: Iterable[dict[str, Any]]) -> Iterable[str]:
    for configuration in configurations:
        yield from _products_from_nodes(configuration.get("nodes", []))


def _products_from_nodes(nodes: Iterable[dict[str, Any]]) -> Iterable[str]:
    for node in nodes:
        for match in node.get("cpeMatch", []):
            if not match.get("vulnerable", False):
                continue
            criteria = match.get("criteria", "")
            parts = criteria.split(":")
            if len(parts) >= 6:
                vendor, product, version = (
                    unquote(part).replace("_", " ") for part in parts[3:6]
                )
                label = " ".join(
                    part
                    for part in (vendor, product, version)
                    if part not in {"*", "-"}
                )
                if label:
                    yield label
        yield from _products_from_nodes(node.get("children", []))


def _iter_affected_ranges(configurations: Iterable[dict[str, Any]]) -> Iterable[str]:
    for configuration in configurations:
        yield from _ranges_from_nodes(configuration.get("nodes", []))


def _ranges_from_nodes(nodes: Iterable[dict[str, Any]]) -> Iterable[str]:
    for node in nodes:
        for match in node.get("cpeMatch", []):
            if not match.get("vulnerable", False):
                continue
            parts = str(match.get("criteria", "")).split(":")
            if len(parts) < 6:
                continue
            vendor, product, version = (
                unquote(part).replace("_", " ") for part in parts[3:6]
            )
            name = " ".join(part for part in (vendor, product) if part not in {"*", "-"})
            if not name:
                continue
            if version not in {"*", "-"}:
                yield f"{name} {version}"
                continue
            bounds = []
            for field, operator in (
                ("versionStartIncluding", ">="),
                ("versionStartExcluding", ">"),
                ("versionEndIncluding", "<="),
                ("versionEndExcluding", "<"),
            ):
                if match.get(field):
                    bounds.append(f"{operator} {match[field]}")
            yield f"{name} {' and '.join(bounds)}" if bounds else name
        yield from _ranges_from_nodes(node.get("children", []))


def _open_request(request: Request, timeout: float) -> bytes:
    with urlopen(request, timeout=timeout) as response:
        return response.read()


def _with_query(url: str, params: dict[str, str]) -> str:
    parts = urlsplit(url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query.update(params)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _nvd_datetime(value: datetime) -> str:
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _parse_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)
