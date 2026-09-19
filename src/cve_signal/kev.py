from __future__ import annotations

from dataclasses import dataclass
from datetime import date
import json
from typing import Callable
from urllib.request import Request, urlopen


JsonOpener = Callable[[Request, float], bytes]


@dataclass(frozen=True)
class KEVEntry:
    cve_id: str
    date_added: str
    due_date: str | None
    required_action: str | None
    known_ransomware_use: str | None


class KEVClient:
    def __init__(
        self,
        url: str,
        *,
        timeout: float = 20.0,
        opener: JsonOpener | None = None,
    ) -> None:
        self.url = url
        self.timeout = timeout
        self._opener = opener or _open_request

    def fetch_added_since(self, since: date) -> dict[str, KEVEntry]:
        request = Request(
            self.url,
            headers={"Accept": "application/json", "User-Agent": "cve-signal/0.2"},
        )
        payload = json.loads(self._opener(request, self.timeout))
        entries: dict[str, KEVEntry] = {}
        for item in payload.get("vulnerabilities", []):
            cve_id = str(item.get("cveID", "")).upper()
            date_added = str(item.get("dateAdded", ""))
            if not cve_id or not date_added:
                continue
            try:
                added = date.fromisoformat(date_added)
            except ValueError:
                continue
            if added < since:
                continue
            entries[cve_id] = KEVEntry(
                cve_id=cve_id,
                date_added=date_added,
                due_date=item.get("dueDate"),
                required_action=item.get("requiredAction"),
                known_ransomware_use=item.get("knownRansomwareCampaignUse"),
            )
        return entries


def _open_request(request: Request, timeout: float) -> bytes:
    with urlopen(request, timeout=timeout) as response:
        return response.read()
