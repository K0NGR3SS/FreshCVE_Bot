from __future__ import annotations

import json
from typing import Callable
from urllib.parse import urlencode
from urllib.request import Request, urlopen


JsonOpener = Callable[[Request, float], bytes]


class EPSSClient:
    def __init__(
        self,
        base_url: str,
        *,
        timeout: float = 20.0,
        opener: JsonOpener | None = None,
    ) -> None:
        self.base_url = base_url
        self.timeout = timeout
        self._opener = opener or _open_request

    def fetch_scores(self, cve_ids: list[str]) -> dict[str, tuple[float, float]]:
        scores: dict[str, tuple[float, float]] = {}
        for start in range(0, len(cve_ids), 100):
            batch = cve_ids[start : start + 100]
            if not batch:
                continue
            query = urlencode({"cve": ",".join(batch)})
            request = Request(
                f"{self.base_url}?{query}",
                headers={"Accept": "application/json", "User-Agent": "cve-signal/0.2"},
            )
            payload = json.loads(self._opener(request, self.timeout))
            for item in payload.get("data", []):
                cve_id = str(item.get("cve", "")).upper()
                if not cve_id:
                    continue
                try:
                    scores[cve_id] = (
                        float(item["epss"]),
                        float(item["percentile"]),
                    )
                except (KeyError, TypeError, ValueError):
                    continue
        return scores


def _open_request(request: Request, timeout: float) -> bytes:
    with urlopen(request, timeout=timeout) as response:
        return response.read()
