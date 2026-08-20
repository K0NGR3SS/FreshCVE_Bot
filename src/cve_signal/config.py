from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import tomllib


@dataclass(frozen=True)
class ScanConfig:
    lookback_hours: int
    maximum_cve_age_hours: int
    minimum_cvss: float
    maximum_cvss: float
    maximum_exploit_matches: int
    technology_keywords: tuple[str, ...]
    vulnerability_keywords: tuple[str, ...]
    web_cwes: frozenset[str]
    exclude_keywords: tuple[str, ...]


@dataclass(frozen=True)
class FeedConfig:
    nvd_url: str
    exploitdb_csv_url: str


@dataclass(frozen=True)
class AppConfig:
    scan: ScanConfig
    feeds: FeedConfig


def load_config(path: Path) -> AppConfig:
    with path.open("rb") as config_file:
        raw = tomllib.load(config_file)

    scan = raw["scan"]
    feeds = raw["feeds"]
    return AppConfig(
        scan=ScanConfig(
            lookback_hours=int(scan["lookback_hours"]),
            maximum_cve_age_hours=int(scan["maximum_cve_age_hours"]),
            minimum_cvss=float(scan["minimum_cvss"]),
            maximum_cvss=float(scan["maximum_cvss"]),
            maximum_exploit_matches=int(scan["maximum_exploit_matches"]),
            technology_keywords=tuple(scan["technology_keywords"]),
            vulnerability_keywords=tuple(scan["vulnerability_keywords"]),
            web_cwes=frozenset(scan["web_cwes"]),
            exclude_keywords=tuple(scan["exclude_keywords"]),
        ),
        feeds=FeedConfig(
            nvd_url=str(feeds["nvd_url"]),
            exploitdb_csv_url=str(feeds["exploitdb_csv_url"]),
        ),
    )
