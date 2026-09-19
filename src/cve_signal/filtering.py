from __future__ import annotations

import re

from cve_signal.config import ScanConfig
from cve_signal.models import CVE


def is_interesting(cve: CVE, config: ScanConfig) -> bool:
    if cve.cvss_score is None and not cve.known_exploited:
        return False
    if (
        cve.cvss_score is not None
        and not config.minimum_cvss <= cve.cvss_score <= config.maximum_cvss
        and not cve.known_exploited
    ):
        return False

    haystack = " ".join((cve.description, *cve.products)).lower()
    if any(_contains(haystack, keyword) for keyword in config.exclude_keywords):
        return False

    technology_match = any(
        _contains(haystack, keyword) for keyword in config.technology_keywords
    )
    vulnerability_match = bool(config.web_cwes.intersection(cve.cwes)) or any(
        _contains(haystack, keyword) for keyword in config.vulnerability_keywords
    ) or cve.known_exploited
    return technology_match and vulnerability_match


def _contains(haystack: str, keyword: str) -> bool:
    escaped = re.escape(keyword.lower()).replace(r"\ ", r"\s+")
    return bool(re.search(rf"(?<![a-z0-9]){escaped}(?![a-z0-9])", haystack))
