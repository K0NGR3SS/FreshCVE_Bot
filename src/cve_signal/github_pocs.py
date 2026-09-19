from __future__ import annotations

import json
import base64
import math
import os
import re
from typing import Any, Callable
from urllib.parse import quote, urlencode
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from cve_signal.exploits import ExploitMatch
from cve_signal.models import CVE


JsonOpener = Callable[[Request, float], bytes]

_GITHUB_SEARCH_URL = "https://api.github.com/search/repositories"
_FULL_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_POC_TOPICS = {"cve", "exploit", "poc", "proof-of-concept", "security"}
_EXPLOIT_HINTS = (
    "exploit",
    "exploits",
    "proof of concept",
    "proof-of-concept",
    "poc",
    "pocs",
    "rce",
)
_AGGREGATOR_HINTS = (
    "awesome",
    "collection",
    "database",
    "feed",
    "list",
    "scanner",
)


class GitHubPoCClient:
    def __init__(
        self,
        token: str | None = None,
        *,
        search_url: str = _GITHUB_SEARCH_URL,
        repository_api_url: str = "https://api.github.com/repos",
        candidate_limit: int = 50,
        readme_limit: int = 10,
        timeout: float = 20.0,
        opener: JsonOpener | None = None,
    ) -> None:
        self.token = token if token is not None else os.getenv("GITHUB_TOKEN")
        self.search_url = search_url
        self.repository_api_url = repository_api_url.rstrip("/")
        self.candidate_limit = min(max(candidate_limit, 10), 100)
        self.readme_limit = min(max(readme_limit, 0), self.candidate_limit)
        self.timeout = timeout
        self._opener = opener or _open_request
        self.last_search_incomplete = False

    def find_matches(self, cve: CVE, limit: int = 5) -> list[ExploitMatch]:
        query = (
            f'"{cve.cve_id}" in:name,description,topics,readme '
            "fork:false archived:false is:public"
        )
        per_page = self.candidate_limit
        params = {
            "q": query,
            "per_page": per_page,
        }
        url = f"{self.search_url}?{urlencode(params)}"
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": (
                "cve-signal/0.2 (+https://github.com/K0NGR3SS/CVE2Exploit)"
            ),
            "X-GitHub-Api-Version": "2026-03-10",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        payload = json.loads(self._opener(Request(url, headers=headers), self.timeout))
        self.last_search_incomplete = bool(payload.get("incomplete_results"))
        matches = []
        readme_checks = 0
        for item in payload.get("items", []):
            readme = None
            if (
                not _metadata_has_identifier(cve.cve_id, item)
                and readme_checks < self.readme_limit
            ):
                readme = self._fetch_readme(str(item.get("full_name", "")), headers)
                readme_checks += 1
            match = _repository_match(cve, item, readme=readme)
            if match is not None:
                matches.append(match)
        return sorted(matches, key=lambda item: (-item.score, item.title))[:limit]

    def _fetch_readme(self, full_name: str, headers: dict[str, str]) -> str | None:
        if not _FULL_NAME_PATTERN.fullmatch(full_name):
            return None
        path = "/".join(quote(part, safe="") for part in full_name.split("/"))
        request = Request(
            f"{self.repository_api_url}/{path}/readme",
            headers=headers,
        )
        try:
            payload = json.loads(self._opener(request, self.timeout))
            if payload.get("encoding") != "base64" or not payload.get("content"):
                return None
            return base64.b64decode(payload["content"]).decode("utf-8", errors="replace")
        except HTTPError as error:
            if error.code in {403, 429}:
                raise
            return None
        except (OSError, ValueError, KeyError):
            return None


def _repository_match(
    cve: CVE,
    item: dict[str, Any],
    *,
    readme: str | None = None,
) -> ExploitMatch | None:
    full_name = str(item.get("full_name", ""))
    if (
        not _FULL_NAME_PATTERN.fullmatch(full_name)
        or item.get("private", False)
        or item.get("fork", False)
        or item.get("archived", False)
    ):
        return None

    identifier = _compact(cve.cve_id)
    name = str(item.get("name", "")).lower()
    description = str(item.get("description") or "").lower()
    topics = {str(topic).lower() for topic in (item.get("topics") or [])}
    searchable_summary = " ".join((name, description, *topics))
    aggregator = any(hint in searchable_summary for hint in _AGGREGATOR_HINTS)

    if _has_identifier(name, identifier):
        score = 115.0
        reason = "exact CVE ID in repository name"
        confidence = "strong"
    elif _has_identifier(description, identifier):
        score = 100.0
        reason = "exact CVE ID in repository description"
        confidence = "strong"
    elif _has_identifier(" ".join(topics), identifier):
        score = 96.0
        reason = "exact CVE ID in repository topics"
        confidence = "strong"
    elif (
        readme
        and _has_identifier(readme, identifier)
        and (_has_exploit_hint(readme) or _has_exploit_hint(searchable_summary))
        and not aggregator
    ):
        score = 84.0
        reason = "exact CVE and PoC signals verified in README"
        confidence = "possible"
    else:
        return None

    if topics.intersection(_POC_TOPICS):
        score += 3.0
    try:
        stars = max(int(item.get("stargazers_count", 0)), 0)
    except (TypeError, ValueError):
        stars = 0
    score += min(math.log2(stars + 1), 5.0)
    if aggregator:
        score -= 25.0
        confidence = "possible"
        reason += "; generic collection signals"
    created_at = str(item.get("created_at") or "") or None
    if created_at and created_at[:10] < cve.published.date().isoformat():
        score -= 6.0

    return ExploitMatch(
        title=full_name,
        url=f"https://github.com/{full_name}",
        source="GitHub",
        score=score,
        reason=reason,
        exploit_type="Unverified PoC",
        confidence=confidence,
        stars=stars,
        created_at=created_at,
        updated_at=str(item.get("pushed_at") or item.get("updated_at") or "") or None,
    )


def _metadata_has_identifier(cve_id: str, item: dict[str, Any]) -> bool:
    identifier = _compact(cve_id)
    values = (
        str(item.get("name", "")),
        str(item.get("description") or ""),
        " ".join(str(topic) for topic in (item.get("topics") or [])),
    )
    return any(_has_identifier(value, identifier) for value in values)


def _compact(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def _has_identifier(value: str, identifier: str) -> bool:
    parsed = re.fullmatch(r"cve(\d{4})(\d{4,})", identifier)
    if parsed is None:
        return False
    year, number = parsed.groups()
    pattern = rf"(?<![a-z0-9])cve[^a-z0-9]*{year}[^a-z0-9]*{number}(?!\d)"
    return bool(re.search(pattern, value.lower()))


def _has_exploit_hint(value: str) -> bool:
    normalized = re.sub(r"[^a-z0-9]+", " ", value.lower()).strip()
    return any(
        re.search(rf"\b{re.escape(hint)}\b", normalized)
        for hint in _EXPLOIT_HINTS
    )


def _open_request(request: Request, timeout: float) -> bytes:
    with urlopen(request, timeout=timeout) as response:
        return response.read()
