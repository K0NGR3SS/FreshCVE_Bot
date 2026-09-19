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
    cvss_vector: str | None = None
    attack_vector: str | None = None
    privileges_required: str | None = None
    user_interaction: str | None = None
    affected_ranges: tuple[str, ...] = ()
    kev_date_added: str | None = None
    kev_due_date: str | None = None
    kev_required_action: str | None = None
    known_ransomware_use: str | None = None
    epss_score: float | None = None
    epss_percentile: float | None = None
