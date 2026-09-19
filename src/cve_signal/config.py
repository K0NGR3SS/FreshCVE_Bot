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
    monitoring_days: int = 30
    early_recheck_hours: int = 3
    later_recheck_hours: int = 24
    github_candidates: int = 50
    github_readme_checks: int = 10
    maximum_cves_per_run: int = 25


@dataclass(frozen=True)
class FeedConfig:
    nvd_url: str
    exploitdb_csv_url: str
    epss_url: str | None = None
    kev_url: str | None = None


@dataclass(frozen=True)
class AppConfig:
    scan: ScanConfig
    feeds: FeedConfig


def load_config(path: Path) -> AppConfig:
    with path.open("rb") as config_file:
        raw = tomllib.load(config_file)

    scan = raw["scan"]
    feeds = raw["feeds"]
    config = AppConfig(
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
            monitoring_days=int(scan.get("monitoring_days", 30)),
            early_recheck_hours=int(scan.get("early_recheck_hours", 3)),
            later_recheck_hours=int(scan.get("later_recheck_hours", 24)),
            github_candidates=int(scan.get("github_candidates", 50)),
            github_readme_checks=int(scan.get("github_readme_checks", 10)),
            maximum_cves_per_run=int(scan.get("maximum_cves_per_run", 25)),
        ),
        feeds=FeedConfig(
            nvd_url=str(feeds["nvd_url"]),
            exploitdb_csv_url=str(feeds["exploitdb_csv_url"]),
            epss_url=str(feeds["epss_url"]) if feeds.get("epss_url") else None,
            kev_url=str(feeds["kev_url"]) if feeds.get("kev_url") else None,
        ),
    )
    _validate(config)
    return config


def _validate(config: AppConfig) -> None:
    scan = config.scan
    if scan.lookback_hours <= 0 or scan.maximum_cve_age_hours <= 0:
        raise ValueError("scan windows must be positive")
    if not 0 <= scan.minimum_cvss <= scan.maximum_cvss <= 10:
        raise ValueError("CVSS bounds must satisfy 0 <= minimum <= maximum <= 10")
    if scan.maximum_exploit_matches <= 0:
        raise ValueError("maximum_exploit_matches must be positive")
    if scan.monitoring_days <= 0:
        raise ValueError("monitoring_days must be positive")
    if scan.early_recheck_hours <= 0 or scan.later_recheck_hours <= 0:
        raise ValueError("recheck intervals must be positive")
    if not 10 <= scan.github_candidates <= 100:
        raise ValueError("github_candidates must be between 10 and 100")
    if not 0 <= scan.github_readme_checks <= scan.github_candidates:
        raise ValueError(
            "github_readme_checks must be between 0 and github_candidates"
        )
    if scan.maximum_cves_per_run <= 0:
        raise ValueError("maximum_cves_per_run must be positive")
    malformed_cwes = [value for value in scan.web_cwes if not value.startswith("CWE-")]
    if malformed_cwes:
        raise ValueError("web_cwes entries must start with CWE-")
