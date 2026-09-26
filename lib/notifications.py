"""Multi-channel alert system: Discord, Telegram, Email.

All sends are best-effort with a single retry, fully mockable via
``requests``. No network activity happens at import time. Secret values
(tokens, webhooks) are never logged.
"""
from __future__ import annotations

import logging
import smtplib
import time
from email.message import EmailMessage
from typing import Any

import requests

from lib.logger import get_logger

logger = get_logger("notifications")

_HTTP_TIMEOUT = (5, 15)          # (connect, read) seconds
_MAX_RETRIES = 2                  # initial try + 1 retry
_RETRY_CAP_SECONDS = 5.0

# Severity → Discord embed color (int).
SEVERITY_COLORS = {
    "P1": 0xE74C3C,  # red
    "P2": 0xE67E22,  # orange
    "P3": 0xF1C40F,  # yellow
    "P4": 0x95A5A6,  # gray
    "CRITICAL": 0xE74C3C,
    "HIGH": 0xE67E22,
    "MEDIUM": 0xF1C40F,
    "LOW": 0x95A5A6,
}


class NotificationError(Exception):
    """Internal marker for failed sends (logged, not raised out)."""


class NotificationFormatter:
    """Builds Discord embeds / Telegram / email bodies from findings."""

    @staticmethod
    def severity_color(severity: str) -> int:
        return SEVERITY_COLORS.get(str(severity).upper(), 0x95A5A6)

    @staticmethod
    def finding_embed(finding: dict[str, Any]) -> dict[str, Any]:
        """Discord rich-embed payload for a finding."""
        fields = [
            {"name": "Type", "value": str(finding.get("vuln_type", "?")), "inline": True},
            {"name": "Severity", "value": str(finding.get("severity", "?")), "inline": True},
            {"name": "Confidence", "value": f"{finding.get('confidence', '?')}%", "inline": True},
            {"name": "Endpoint", "value": (str(finding.get("endpoint", "?")) or "?")[:1000]},
            {"name": "Payload", "value": (str(finding.get("payload", "")) or "-")[:1000]},
            {"name": "Proof", "value": (str(finding.get("response_snippet", "")) or "-")[:1000]},
            {"name": "Tools", "value": ", ".join(finding.get("tools_found", []) or []) or "-", "inline": True},
        ]
        return {
            "title": (
                f"[{finding.get('severity', '?')}] {finding.get('vuln_type', 'finding')}"
                f" — {finding.get('target', '')}"
            )[:256],
            "color": NotificationFormatter.severity_color(str(finding.get("severity", ""))),
            "fields": fields,
            "footer": {"text": "NEXUS Framework — detection + PoC only"},
        }

    @staticmethod
    def finding_message(finding: dict[str, Any]) -> str:
        """Telegram-style plain-text message for a finding."""
        tools = ", ".join(finding.get("tools_found", []) or []) or "-"
        return (
            f"[{finding.get('severity', '?')}] {finding.get('vuln_type', 'finding')}\n"
            f"Target: {finding.get('target', '?')}\n"
            f"Endpoint: {finding.get('endpoint', '?')}\n"
            f"Payload: {finding.get('payload', '-')}\n"
            f"Confidence: {finding.get('confidence', '?')}% | Tools: {tools}\n"
            f"Proof: {(str(finding.get('response_snippet', '')) or '-')[:400]}"
        )

    @staticmethod
    def cve_embed(cve: dict[str, Any]) -> dict[str, Any]:
        """Discord embed for a CVE alert (incl. KEV/EPSS when present)."""
        fields = [
            {"name": "Severity", "value": str(cve.get("severity", "?")), "inline": True},
            {"name": "Affected Tech", "value": (str(cve.get("tech_matched", "-")) or "-")[:1000], "inline": True},
        ]
        if "kev" in cve:
            fields.append({
                "name": "Known Exploited (KEV)",
                "value": "yes" if cve.get("kev") else "no",
                "inline": True,
            })
        if cve.get("epss") is not None:
            try:
                fields.append({
                    "name": "EPSS",
                    "value": f"{float(cve.get('epss', 0.0)):.2f}",
                    "inline": True,
                })
            except (TypeError, ValueError):
                pass
        fields.append({"name": "Description", "value": (str(cve.get("description", "")) or "-")[:1000]})
        return {
            "title": f"[{str(cve.get('severity', '?')).upper()}] {cve.get('cve_id', '?')}",
            "color": NotificationFormatter.severity_color(str(cve.get("severity", ""))),
            "fields": fields,
            "footer": {"text": "NEXUS CVE alert — detection PoCs attached"},
        }

    @staticmethod
    def cve_message(cve: dict[str, Any]) -> str:
        """Telegram-style plain-text message for a CVE alert."""
        extras = ""
        if cve.get("kev"):
            extras += " (KEV)"
        if cve.get("epss") is not None:
            try:
                extras += f" EPSS {float(cve.get('epss', 0.0)):.2f}"
            except (TypeError, ValueError):
                pass
        return (
            f"[{str(cve.get('severity', '?')).upper()}] {cve.get('cve_id', '?')}{extras}\n"
            f"Affected: {cve.get('tech_matched', '-')}\n"
            f"{str(cve.get('description', ''))[:600]}"
        )


def _post_with_retry(url: str, json_payload: dict[str, Any]) -> bool:
    """POST with best-effort retry; returns True on 2xx. Never raises."""
    if not url:
        logger.debug("no endpoint configured; skipping send")
        return False
    last_error: Exception | None = None
    for _attempt in range(_MAX_RETRIES):
        try:
            resp = requests.post(url, json=json_payload, timeout=_HTTP_TIMEOUT)
            if resp.status_code in (200, 204):
                return True
            if resp.status_code == 429:
                retry_after = 1.0
                for header in ("Retry-After", "retry-after"):
                    if header in resp.headers:
                        try:
                            retry_after = float(resp.headers[header])
                        except ValueError:
                            pass
                        break
                time.sleep(min(retry_after, _RETRY_CAP_SECONDS))
                continue
            last_error = NotificationError(f"HTTP {resp.status_code} from {url.split('?')[0]}")
        except requests.RequestException as exc:
            last_error = exc
    if last_error:
        logger.warning("send failed: %s", last_error)
    return False


class Notifier:
    """Sends alerts through Discord webhooks, Telegram bot API, and SMTP."""

    def __init__(self, cfg: Any):
        self.cfg = cfg
        self.formatter = NotificationFormatter()

    # -- Discord ------------------------------------------------------------

    def send_finding(self, finding: dict[str, Any]) -> bool:
        """Send a finding alert to the Discord findings webhook."""
        payload = {
            "username": "NEXUS",
            "embeds": [self.formatter.finding_embed(finding)],
        }
        return _post_with_retry(self.cfg.webhook("findings"), payload)

    def send_cve(self, cve: dict[str, Any]) -> bool:
        """Send a CVE alert to the Discord CVE webhook."""
        payload = {
            "username": "NEXUS-CVE",
            "embeds": [self.formatter.cve_embed(cve)],
        }
        return _post_with_retry(self.cfg.webhook("cve"), payload)

    def send_metrics(self, metrics: dict[str, Any]) -> bool:
        """Send a scan-metrics summary to the Discord metrics webhook."""
        lines = [f"{key}: {value}" for key, value in sorted(metrics.items())]
        payload = {
            "username": "NEXUS-Metrics",
            "embeds": [
                {
                    "title": "Scan metrics",
                    "color": 0x3498DB,
                    "description": "\n".join(lines)[:4000] or "no metrics",
                }
            ],
        }
        return _post_with_retry(self.cfg.webhook("metrics"), payload)

    def send_info_alert(self, title: str, body: str) -> bool:
        """Send an informational intel alert (drift / new tech / methodology)."""
        payload = {
            "username": "NEXUS-Intel",
            "embeds": [
                {
                    "title": str(title)[:256],
                    "color": 0x5865F2,
                    "description": str(body)[:4000] or "-",
                    "footer": {"text": "NEXUS intel alert"},
                }
            ],
        }
        return _post_with_retry(self.cfg.webhook("findings"), payload)

    def send_info_telegram(self, title: str, body: str) -> bool:
        """Send an informational intel alert through the Telegram bot."""
        token, chat_id = self.cfg.telegram()
        if not token or not chat_id:
            return False
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        return _post_with_retry(url, {"chat_id": chat_id, "text": f"{title}\n{body}"[:4000]})

    def send_digest(self, title: str, findings: list[dict[str, Any]]) -> bool:
        """Send a consolidated digest of findings (roadmap G4)."""
        lines = [
            f"[{f.get('severity', '?')}] {f.get('vuln_type', '?')} — {f.get('endpoint', '?')}"
            for f in findings[:20]
        ]
        payload = {
            "username": "NEXUS",
            "embeds": [{
                "title": str(title)[:256],
                "color": 0x3498DB,
                "description": ("\n".join(lines) or "no findings")[:4000],
                "footer": {"text": f"{len(findings)} finding(s)"},
            }],
        }
        return _post_with_retry(self.cfg.webhook("findings"), payload)

    # -- Telegram ----------------------------------------------------------

    def send_finding_telegram(self, finding: dict[str, Any]) -> bool:
        """Send a finding alert through the Telegram bot."""
        token, chat_id = self.cfg.telegram()
        if not token or not chat_id:
            logger.debug("telegram credentials unset; skipping send")
            return False
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        return _post_with_retry(
            url,
            {"chat_id": chat_id, "text": self.formatter.finding_message(finding)},
        )

    def send_cve_telegram(self, cve: dict[str, Any]) -> bool:
        """Send a CVE alert through the Telegram bot."""
        token, chat_id = self.cfg.telegram()
        if not token or not chat_id:
            logger.debug("telegram credentials unset; skipping send")
            return False
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        return _post_with_retry(
            url,
            {"chat_id": chat_id, "text": self.formatter.cve_message(cve)},
        )


def smtp_send(
    host: str,
    port: int,
    user: str,
    password: str,
    from_addr: str,
    to_addrs: list[str],
    subject: str,
    body: str,
    attachments: list[tuple[str, bytes]] | None = None,
) -> bool:
    """Send an email with optional binary attachments. Best-effort."""
    smtp_logger = logging.getLogger("nexus.notifications.smtp")
    if not host or not to_addrs:
        smtp_logger.debug("SMTP not configured; skipping email send")
        return False
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_addr or user
    msg["To"] = ", ".join(to_addrs)
    msg.set_content(body)
    for filename, blob in attachments or []:
        _name, _, ext = filename.rpartition(".")
        msg.add_attachment(
            blob,
            maintype="application",
            subtype=(ext or "octet-stream").lower(),
            filename=filename,
        )
    try:
        with smtplib.SMTP(host, int(port), timeout=15) as server:
            try:
                server.starttls()
            except smtplib.SMTPException:
                pass  # server may not support STARTTLS
            if user and password:
                server.login(user, password)
            server.send_message(msg)
        return True
    except (smtplib.SMTPException, OSError) as exc:
        smtp_logger.warning("email send failed: %s", exc)
        return False


class EmailAlerter:
    """Convenience wrapper binding SMTP config from a Config object."""

    def __init__(self, cfg: Any):
        self.host = str(cfg.email.get("smtp_host", "") or "")
        self.port = int(cfg.email.get("smtp_port", 587) or 587)
        self.user = str(cfg.email.get("smtp_user", "") or "")
        self.password = str(cfg.email.get("smtp_pass", "") or "")
        self.from_addr = str(cfg.email.get("from_addr", "") or "")
        raw_to = cfg.email.get("to_addrs", "") or ""
        self.to_addrs = [a.strip() for a in str(raw_to).split(",") if a.strip()]

    def send(
        self,
        subject: str,
        body: str,
        attachments: list[tuple[str, bytes]] | None = None,
    ) -> bool:
        return smtp_send(
            self.host,
            self.port,
            self.user,
            self.password,
            self.from_addr,
            self.to_addrs,
            subject,
            body,
            attachments,
        )
