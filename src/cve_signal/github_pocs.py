from __future__ import annotations

import json
import math
import os
import re
from typing import Any, Callable
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from cve_signal.exploits import ExploitMatch
from cve_signal.models import CVE


JsonOpener = Callable[[Request, float], bytes]

_GITHUB_SEARCH_URL = "https://api.github.com/search/repositories"
_FULL_NAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_POC_TOPICS = {"cve", "exploit", "poc", "proof-of-concept", "security"}


class GitHubPoCClient:
    def __init__(
        self,
        token: str | None = None,
        *,
        search_url: str = _GITHUB_SEARCH_URL,
        timeout: float = 20.0,
        opener: JsonOpener | None = None,
    ) -> None:
        self.token = token if token is not None else os.getenv("GITHUB_TOKEN")
        self.search_url = search_url
        self.timeout = timeout
        self._opener = opener or _open_request

    def find_matches(self, cve: CVE, limit: int = 5) -> list[ExploitMatch]:
        query = f"{cve.cve_id} in:name,description fork:false archived:false is:public"
        url = f"{self.search_url}?{urlencode({'q': query, 'sort': 'updated', 'order': 'desc', 'per_page': limit})}"
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "cve-signal/0.1 (+https://github.com/K0NGR3SS/cve-signal)",
            "X-GitHub-Api-Version": "2026-03-10",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        payload = json.loads(self._opener(Request(url, headers=headers), self.timeout))
        matches = [
            match
            for item in payload.get("items", [])
            if (match := _repository_match(cve.cve_id, item)) is not None
        ]
        return sorted(matches, key=lambda item: (-item.score, item.title))[:limit]


def _repository_match(cve_id: str, item: dict[str, Any]) -> ExploitMatch | None:
    full_name = str(item.get("full_name", ""))
    if (
        not _FULL_NAME_PATTERN.fullmatch(full_name)
        or item.get("private", False)
        or item.get("fork", False)
        or item.get("archived", False)
    ):
        return None

    identifier = cve_id.lower()
    name = str(item.get("name", "")).lower()
    description = str(item.get("description") or "").lower()
    if identifier in name:
        score = 115.0
        reason = "exact CVE ID in repository name"
    elif identifier in description:
        score = 100.0
        reason = "exact CVE ID in repository description"
    else:
        return None

    topics = {str(topic).lower() for topic in item.get("topics", [])}
    if topics.intersection(_POC_TOPICS):
        score += 3.0
    stars = max(int(item.get("stargazers_count", 0)), 0)
    score += min(math.log2(stars + 1), 5.0)

    return ExploitMatch(
        title=full_name,
        url=f"https://github.com/{full_name}",
        source="GitHub",
        score=score,
        reason=reason,
        exploit_type="PoC candidate",
    )


def _open_request(request: Request, timeout: float) -> bytes:
    with urlopen(request, timeout=timeout) as response:
        return response.read()

