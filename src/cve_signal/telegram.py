from __future__ import annotations

import html
import json
import os
from typing import Callable
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from cve_signal.exploits import ExploitMatch
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
    ) -> None:
        if not token or not chat_id:
            raise ValueError("Telegram token and chat ID are required")
        self._token = token
        self._chat_id = chat_id
        self.timeout = timeout
        self._sender = sender or _send_request

    @classmethod
    def from_environment(cls) -> TelegramClient:
        return cls(
            token=os.environ.get("TELEGRAM_BOT_TOKEN", ""),
            chat_id=os.environ.get("TELEGRAM_CHAT_ID", ""),
        )

    def send(self, message: str) -> None:
        url = f"https://api.telegram.org/bot{self._token}/sendMessage"
        body = urlencode(
            {
                "chat_id": self._chat_id,
                "text": message,
                "parse_mode": "HTML",
                "disable_web_page_preview": "true",
            }
        ).encode("utf-8")
        request = Request(
            url,
            data=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        response = json.loads(self._sender(request, self.timeout))
        if not response.get("ok"):
            raise RuntimeError(f"Telegram rejected the message: {response.get('description', 'unknown error')}")


def format_alert(cve: CVE, matches: list[ExploitMatch]) -> str:
    severity = cve.cvss_severity or "UNKNOWN"
    score = f"{cve.cvss_score:.1f}" if cve.cvss_score is not None else "N/A"
    kev = " · CISA KEV" if cve.known_exploited else ""
    description = _truncate(cve.description, 900)
    products = ", ".join(cve.products[:3]) or "Not specified"
    cwes = ", ".join(cve.cwes) or "Not specified"
    nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve.cve_id}"

    lines = [
        f'🚨 <b><a href="{nvd_url}">{html.escape(cve.cve_id)}</a></b>',
        f"<b>{html.escape(severity)}</b> · CVSS {score}{kev}",
        "",
        html.escape(description),
        "",
        f"<b>Affected:</b> {html.escape(products)}",
        f"<b>CWE:</b> {html.escape(cwes)}",
    ]

    if matches:
        lines.extend(("", f"<b>Public exploit matches ({len(matches)}):</b>"))
        for index, match in enumerate(matches, start=1):
            metadata = " · ".join(
                value for value in (match.source, match.platform, match.exploit_type) if value
            )
            lines.append(
                f'{index}. <a href="{html.escape(match.url, quote=True)}">'
                f"{html.escape(_truncate(match.title, 180))}</a>"
                f" — {html.escape(metadata)}"
            )
    else:
        lines.extend(("", "<b>Public exploit matches:</b> none found"))

    return _truncate("\n".join(lines), 4000)


def _truncate(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return value[: limit - 1].rstrip() + "…"


def _send_request(request: Request, timeout: float) -> bytes:
    with urlopen(request, timeout=timeout) as response:
        return response.read()

