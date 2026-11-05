from __future__ import annotations

import html
import json
import os
import re
import time
from datetime import timezone
from typing import Callable, Sequence
from urllib.error import HTTPError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen

from cve_signal.exploits import ExploitMatch, SourceStatus
from cve_signal.intel import Intel
from cve_signal.models import CVE


TelegramSender = Callable[[Request, float], bytes]


class TelegramClient:
    def __init__(
        self,
        token: str,
        chat_id: str,
        *,
        timeout: float = 30.0,
        sender: TelegramSender | None = None,
        min_interval: float = 3.1,
    ) -> None:
        if not token or not chat_id:
            raise ValueError("Telegram token and chat ID are required")
        self._token = token
        self._chat_id = chat_id
        self.timeout = timeout
        self._sender = sender or _send_request
        # Telegram allows ~20 messages per minute in a channel.
        self.min_interval = min_interval if sender is None else 0.0

    @classmethod
    def from_environment(cls) -> TelegramClient:
        return cls(
            token=os.environ.get("TELEGRAM_BOT_TOKEN", ""),
            chat_id=os.environ.get("TELEGRAM_CHAT_ID", ""),
        )

    def send(
        self,
        message: str,
        *,
        reply_to_message_id: int | None = None,
    ) -> int | None:
        url = f"https://api.telegram.org/bot{self._token}/sendMessage"
        params = {
            "chat_id": self._chat_id,
            "text": message,
            "parse_mode": "HTML",
            "disable_web_page_preview": "true",
        }
        if reply_to_message_id is not None:
            params["reply_parameters"] = json.dumps(
                {"message_id": reply_to_message_id, "allow_sending_without_reply": True}
            )
        body = urlencode(params).encode("utf-8")
        request = Request(
            url,
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        response: dict = {}
        for _attempt in range(5):
            try:
                response = json.loads(self._sender(request, self.timeout))
            except HTTPError as error:
                if error.code != 429:
                    raise
                try:
                    response = json.loads(error.read() or b"{}")
                except ValueError:
                    response = {}
            retry_after = (response.get("parameters") or {}).get("retry_after")
            if response.get("ok") or response.get("error_code") != 429:
                break
            time.sleep(min(float(retry_after or 5), 120) + 1)
        if self.min_interval:
            time.sleep(self.min_interval)
        if not response.get("ok"):
            description = response.get("description", "unknown error")
            raise RuntimeError(f"Telegram rejected the message: {description}")
        message_id = response.get("result", {}).get("message_id")
        return int(message_id) if message_id is not None else None


def format_alert(
    cve: CVE,
    matches: list[ExploitMatch],
    *,
    is_update: bool = False,
    source_statuses: Sequence[SourceStatus] = (),
    explain: bool = False,
    intel: Intel | None = None,
) -> str:
    severity = cve.cvss_severity or "UNSCORED"
    score = f"{cve.cvss_score:.1f}" if cve.cvss_score is not None else "N/A"
    confidence = _overall_confidence(matches)
    headline = _headline(confidence, is_update)
    description = _truncate(cve.description, 650)
    affected = _affected_text(cve)
    cwes = _limited_join(cve.cwes, 4, "CWE not specified")
    nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve.cve_id}"

    icon = "🔎" if is_update else "🚨"
    risk_parts = [f"CVSS {score}", _kev_text(cve), _epss_text(cve)]

    blocks = [
        f"{icon} <b>{html.escape(severity)} · {html.escape(headline)}</b>",
        f'<b><a href="{nvd_url}">{html.escape(cve.cve_id)}</a></b>',
        " · ".join(html.escape(part) for part in risk_parts),
        "",
        html.escape(description),
        "",
        f"<b>Attack:</b> {html.escape(_attack_text(cve))}",
        f"<b>Affected:</b> {html.escape(affected)}",
        f"<b>CWE:</b> {html.escape(cwes)}",
        "<b>Published:</b> "
        + cve.published.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    ]
    if cve.kev_due_date:
        blocks.append(f"<b>KEV due:</b> {html.escape(cve.kev_due_date)}")
    if cve.known_ransomware_use and cve.known_ransomware_use.lower() == "known":
        blocks.append("<b>Ransomware use:</b> Known")
    if cve.kev_required_action:
        blocks.append(
            f"<b>Required action:</b> {html.escape(_truncate(cve.kev_required_action, 240))}"
        )

    if intel is not None:
        for block in _intel_html_blocks(cve, intel):
            if _html_length(blocks + ["", block]) > 2900:
                break
            blocks.extend(("", block))

    if matches:
        label = "New exploit evidence" if is_update else "Exploit evidence"
        blocks.extend(("", f"<b>{label} ({len(matches)}):</b>"))
        added = 0
        for index, match in enumerate(matches, start=1):
            line = _html_match(index, match, explain=explain)
            if _html_length(blocks + [line]) > 3800:
                break
            blocks.append(line)
            added += 1
        omitted = len(matches) - added
        if omitted:
            notice = f"… +{omitted} more match{'es' if omitted != 1 else ''}"
            if _html_length(blocks + [notice]) <= 3800:
                blocks.append(notice)
    else:
        blocks.extend(
            (
                "",
                "<b>Exploit evidence:</b> "
                + html.escape(_no_match_text(source_statuses)),
            )
        )

    degraded = [
        status
        for status in source_statuses
        if status.state in {"partial", "unavailable", "rate-limited"}
    ]
    if degraded:
        degraded_block = "<b>Source status:</b> " + html.escape(
            ", ".join(
                f"{status.source} {status.state.replace('-', ' ')}"
                for status in degraded
            )
        )
        if _html_length(blocks + ["", degraded_block]) <= 3800:
            blocks.extend(("", degraded_block))
    if any(match.source == "GitHub" for match in matches):
        warning = "⚠️ GitHub PoCs are unverified. Review before running."
        if _html_length(blocks + ["", warning]) <= 3800:
            blocks.extend(("", warning))

    links = [f'<a href="{nvd_url}">NVD</a>']
    vendor_advisory = _vendor_advisory_url(cve)
    if vendor_advisory:
        links.append(
            f'<a href="{html.escape(vendor_advisory, quote=True)}">Vendor advisory</a>'
        )
    if cve.known_exploited:
        links.append(
            '<a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog">CISA KEV</a>'
        )
    if intel is not None:
        links.extend(_intel_links(intel))
    if _html_length(blocks + [" · ".join(links)]) <= 3900:
        blocks.extend(("", " · ".join(links)))

    message = "\n".join(blocks)
    if len(message) > 3900:
        raise ValueError("alert exceeded safe Telegram HTML budget")
    return message


def _kev_text(cve: CVE) -> str:
    if cve.known_exploited:
        added = f" (added {cve.kev_date_added})" if cve.kev_date_added else ""
        return f"CISA KEV: YES{added}"
    return "CISA KEV: no"


def _epss_text(cve: CVE) -> str:
    if cve.epss_score is None:
        return "EPSS: n/a"
    text = f"EPSS: {cve.epss_score * 100:.1f}%"
    if cve.epss_percentile is not None:
        text += f" ({cve.epss_percentile * 100:.0f}th pct)"
    return text


def format_alert_text(
    cve: CVE,
    matches: list[ExploitMatch],
    *,
    is_update: bool = False,
    source_statuses: Sequence[SourceStatus] = (),
    explain: bool = False,
    intel: Intel | None = None,
) -> str:
    severity = cve.cvss_severity or "UNSCORED"
    score = f"{cve.cvss_score:.1f}" if cve.cvss_score is not None else "N/A"
    lines = [
        f"{severity} · {_headline(_overall_confidence(matches), is_update)}",
        f"{cve.cve_id} · CVSS {score}",
        _truncate(cve.description, 650),
        f"Attack: {_attack_text(cve)}",
        f"Affected: {_affected_text(cve)}",
    ]
    lines.append(_kev_text(cve))
    lines.append(_epss_text(cve))
    if cve.kev_due_date:
        lines.append(f"KEV due: {cve.kev_due_date}")
    if cve.known_ransomware_use and cve.known_ransomware_use.lower() == "known":
        lines.append("Ransomware use: Known")
    if cve.kev_required_action:
        lines.append(f"Required action: {_truncate(cve.kev_required_action, 240)}")
    if intel is not None:
        lines.extend(_intel_text_lines(cve, intel))
    if matches:
        lines.append("Exploit evidence:")
        lines.extend(
            f"{index}. [{match.confidence}] {match.title} — {match.source} — "
            f"{match.reason}{f' — score {match.score:.1f}' if explain else ''}\n   {match.url}"
            for index, match in enumerate(matches, start=1)
        )
    else:
        lines.append(f"Exploit evidence: {_no_match_text(source_statuses)}")
    return "\n".join(lines)


def format_alert_json(
    cve: CVE,
    matches: list[ExploitMatch],
    *,
    is_update: bool = False,
    source_statuses: Sequence[SourceStatus] = (),
    explain: bool = False,
    intel: Intel | None = None,
) -> str:
    payload = {
        "cve_id": cve.cve_id,
        "update": is_update,
        "description": cve.description,
        "published": cve.published.isoformat(),
        "modified": cve.modified.isoformat(),
        "severity": cve.cvss_severity,
        "cvss": cve.cvss_score,
        "cvss_vector": cve.cvss_vector,
        "cwes": list(cve.cwes),
        "epss": cve.epss_score,
        "epss_percentile": cve.epss_percentile,
        "known_exploited": cve.known_exploited,
        "kev": {
            "date_added": cve.kev_date_added,
            "due_date": cve.kev_due_date,
            "required_action": cve.kev_required_action,
            "known_ransomware_use": cve.known_ransomware_use,
        },
        "attack": {
            "vector": cve.attack_vector,
            "privileges_required": cve.privileges_required,
            "user_interaction": cve.user_interaction,
        },
        "affected": list(cve.affected_ranges or cve.products),
        "intel": _intel_json(intel),
        "matches": [
            {
                "title": match.title,
                "url": match.url,
                "source": match.source,
                "confidence": match.confidence,
                "reason": match.reason,
                **({"score": match.score} if explain else {}),
            }
            for match in matches
        ],
        "sources": [
            {"source": status.source, "state": status.state, "detail": status.detail}
            for status in source_statuses
        ],
    }
    return json.dumps(payload, separators=(",", ":"), sort_keys=True)


def _html_match(index: int, match: ExploitMatch, *, explain: bool) -> str:
    badge = {"confirmed": "✅ Confirmed", "strong": "🔎 Strong", "possible": "⚠️ Possible"}[
        match.confidence
    ]
    metadata = [badge, match.source]
    if match.platform:
        metadata.append(match.platform)
    if match.exploit_type:
        metadata.append(match.exploit_type)
    if match.stars is not None:
        metadata.append(f"{match.stars}★")
    metadata.append(match.reason)
    if explain:
        metadata.append(f"score {match.score:.1f}")
    title = html.escape(_truncate(match.title, 150))
    url = match.url.strip()
    parts = urlsplit(url)
    if parts.scheme in {"http", "https"} and parts.netloc:
        title = f'<a href="{html.escape(url, quote=True)}">{title}</a>'
    return f"{index}. {title}\n   {html.escape(' · '.join(metadata))}"


def _overall_confidence(matches: Sequence[ExploitMatch]) -> str | None:
    for confidence in ("confirmed", "strong", "possible"):
        if any(match.confidence == confidence for match in matches):
            return confidence
    return None


def _headline(confidence: str | None, is_update: bool) -> str:
    if confidence == "confirmed":
        return "NEW CONFIRMED EXPLOIT" if is_update else "CONFIRMED EXPLOIT"
    if confidence == "strong":
        return "NEW STRONG EXPLOIT SIGNAL" if is_update else "STRONG EXPLOIT SIGNAL"
    if confidence == "possible":
        return "NEW POSSIBLE POC" if is_update else "POSSIBLE POC"
    return "CVE UPDATE" if is_update else "NEW CVE"


def _attack_text(cve: CVE) -> str:
    labels = []
    if cve.attack_vector:
        labels.append(cve.attack_vector)
    if cve.privileges_required:
        labels.append(f"Privileges: {cve.privileges_required}")
    if cve.user_interaction:
        labels.append(f"User interaction: {cve.user_interaction}")
    return " · ".join(labels) if labels else "Not specified"


def _affected_text(cve: CVE) -> str:
    values = cve.affected_ranges or cve.products
    return _limited_join(values, 3, "Not specified")


def _limited_join(values: Sequence[str], limit: int, empty: str) -> str:
    if not values:
        return empty
    visible = list(values[:limit])
    text = ", ".join(visible)
    if len(values) > limit:
        text += f" (+{len(values) - limit} more)"
    return _truncate(text, 500)


def _no_match_text(statuses: Sequence[SourceStatus]) -> str:
    searched = [
        status
        for status in statuses
        if status.source in {"Exploit-DB", "GitHub"}
    ]
    if searched and all(status.state == "ok" for status in searched):
        return "none found"
    if searched:
        degraded = ", ".join(
            f"{status.source} {status.state.replace('-', ' ')}"
            for status in searched
            if status.state != "ok"
        )
        return f"no match returned; {degraded}" if degraded else "none found"
    return "search status unavailable"


def _vendor_advisory_url(cve: CVE) -> str | None:
    for reference in cve.references:
        if not any(tag.lower() == "vendor advisory" for tag in reference.tags):
            continue
        parts = urlsplit(reference.url)
        if parts.scheme in {"http", "https"} and parts.netloc:
            return reference.url
    return None


def _intel_fields(cve: CVE, intel: Intel) -> list[tuple[str, str]]:
    """Ordered (label, plain text) pairs shared by the HTML and text formats."""
    fields: list[tuple[str, str]] = []
    if intel.bdu_description:
        label = f"БДУ ФСТЭК {intel.bdu_id}" if intel.bdu_id else "БДУ ФСТЭК"
        fields.append((label, _truncate(intel.bdu_description, 450)))
    if intel.bdu_solution:
        fields.append(("Устранение (БДУ)", _truncate(intel.bdu_solution, 300)))
    status_parts = [part for part in (intel.bdu_exploit_status, intel.bdu_fix_status) if part]
    if status_parts:
        fields.append(("Статус (БДУ)", _truncate(" · ".join(status_parts), 200)))
    if intel.vendor_description and _differs(intel.vendor_description, cve.description):
        fields.append(("Vendor description", _truncate(intel.vendor_description, 450)))
    if intel.vendor_solution:
        fields.append(("Vendor solution", _truncate(intel.vendor_solution, 300)))
    if intel.has_ssvc:
        parts = []
        if intel.ssvc_exploitation:
            parts.append(f"exploitation {intel.ssvc_exploitation}")
        if intel.ssvc_automatable:
            parts.append(f"automatable {intel.ssvc_automatable}")
        if intel.ssvc_technical_impact:
            parts.append(f"impact {intel.ssvc_technical_impact}")
        fields.append(("CISA SSVC", " · ".join(parts)))
    if intel.fixed_versions:
        fields.append(("Fixed in", _limited_join(intel.fixed_versions, 6, "")))
    if intel.ghsa:
        fields.append(
            ("GitHub Advisory", "; ".join(
                f"{ghsa_id}{f' — {_truncate(summary, 120)}' if summary else ''}"
                for ghsa_id, _url, summary in intel.ghsa[:2]
            ))
        )
    if intel.euvd_id:
        exploited = f" · exploited since {intel.euvd_exploited_since}" if intel.euvd_exploited_since else ""
        fields.append(("EUVD", f"{intel.euvd_id}{exploited}"))
    if intel.sightings:
        fields.append(
            ("Sightings (CIRCL)", " · ".join(
                f"{kind} {count}"
                for kind, count in sorted(intel.sightings.items(), key=lambda item: -item[1])
            ))
        )
    return fields


def _differs(left: str, right: str) -> bool:
    return _normalized_text(left) != _normalized_text(right)


def _normalized_text(value: str) -> str:
    return re.sub(r"\W+", " ", value).strip().lower()


def _intel_html_blocks(cve: CVE, intel: Intel) -> list[str]:
    return [
        f"<b>{html.escape(label)}:</b> {html.escape(value)}"
        for label, value in _intel_fields(cve, intel)
    ]


def _intel_text_lines(cve: CVE, intel: Intel) -> list[str]:
    return [f"{label}: {value}" for label, value in _intel_fields(cve, intel)]


def _intel_links(intel: Intel) -> list[str]:
    links = []
    if intel.ghsa and intel.ghsa[0][1].startswith("https://"):
        links.append(f'<a href="{html.escape(intel.ghsa[0][1], quote=True)}">GHSA</a>')
    if intel.bdu_id:
        number = intel.bdu_id.split(":", 1)[-1]
        links.append(f'<a href="https://bdu.fstec.ru/vul/{html.escape(number, quote=True)}">БДУ</a>')
    if intel.euvd_id:
        links.append(
            f'<a href="https://euvd.enisa.europa.eu/vulnerability/{html.escape(intel.euvd_id, quote=True)}">EUVD</a>'
        )
    if intel.sightings or intel.vendor_description:
        links.append(
            f'<a href="https://vulnerability.circl.lu/vuln/{html.escape(intel.cve_id, quote=True)}">CIRCL</a>'
        )
    return links


def _intel_json(intel: Intel | None) -> dict | None:
    if intel is None:
        return None
    return {
        "vendor_description": intel.vendor_description,
        "vendor_solution": intel.vendor_solution,
        "vendor_affected": intel.vendor_affected,
        "ssvc": {
            "exploitation": intel.ssvc_exploitation,
            "automatable": intel.ssvc_automatable,
            "technical_impact": intel.ssvc_technical_impact,
        },
        "fixed_versions": intel.fixed_versions,
        "ghsa": [{"id": a, "url": b, "summary": c} for a, b, c in intel.ghsa],
        "bdu": {
            "id": intel.bdu_id,
            "description": intel.bdu_description,
            "solution": intel.bdu_solution,
            "exploit_status": intel.bdu_exploit_status,
            "fix_status": intel.bdu_fix_status,
        },
        "euvd": {"id": intel.euvd_id, "exploited_since": intel.euvd_exploited_since},
        "sightings": intel.sightings,
        "sources": [
            {"source": status.source, "state": status.state, "detail": status.detail}
            for status in intel.statuses
        ],
    }


def _html_length(blocks: Sequence[str]) -> int:
    return len("\n".join(blocks))


def _truncate(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return value[: limit - 1].rstrip() + "…"


def _send_request(request: Request, timeout: float) -> bytes:
    with urlopen(request, timeout=timeout) as response:
        return response.read()
