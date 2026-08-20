from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class Reference:
    url: str
    tags: tuple[str, ...] = ()


@dataclass(frozen=True)
class CVE:
    cve_id: str
    description: str
    published: datetime
    modified: datetime
    cvss_score: float | None
    cvss_severity: str | None
    cvss_version: str | None
    cwes: tuple[str, ...]
    products: tuple[str, ...]
    references: tuple[Reference, ...]
    known_exploited: bool = False

