"""Regression tests: notification secrets never reach logs or errors.

Injects unique fake secrets into every notification path (Discord webhook,
canary/PTB Discord, Telegram bot token, query-string credentials, bearer
and userinfo) across success, HTTP-error, connection-error, rate-limit and
malformed-response outcomes and proves none of them appear in captured log
output (as formatted by :class:`RedactingFormatter`) or in the raw record
messages.
"""
from __future__ import annotations

import logging
from contextlib import contextmanager

import pytest
import requests

from lib import notifications as nt
from lib.logger import RedactingFormatter
from lib.notifications import Notifier, _post_with_retry, smtp_send
from lib.redaction import REDACTED, redact_text

# -- unique fake secrets ---------------------------------------------------

DISCORD_TOKEN = "FAKEdiscordTOKEN_abcDEF1234567890xyz"
DISCORD_URL = f"https://discord.com/api/webhooks/123456789/{DISCORD_TOKEN}"
CANARY_TOKEN = "FAKEcanaryDiscordTOKEN_abcDEF0987654321"
CANARY_URL = f"https://canary.discord.com/api/webhooks/987654321/{CANARY_TOKEN}"
TELEGRAM_TOKEN = "8123456789:FAKEtelegramBOTTOKENabcdefGHIjklMNOpqr"
TELEGRAM_URL = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
QUERY_SECRET = "FAKE_QUERY_SECRET_value123"
QUERY_URL = f"https://alerts.example.com/hook?api_key={QUERY_SECRET}"
BEARER_SECRET = "FAKE_BEARER_SECRET_abcdef1234567890"
SMTP_SECRET = "FAKE_SMTP_PASSWORD_987654321"

ALL_SECRETS = (
    DISCORD_TOKEN, CANARY_TOKEN, TELEGRAM_TOKEN, QUERY_SECRET, BEARER_SECRET,
    SMTP_SECRET,
)


# -- log capture -----------------------------------------------------------


class _RecordingHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:  # pragma: no cover - trivial
        self.records.append(record)


@contextmanager
def capture_nexus_logs():
    root = logging.getLogger("nexus")
    handler = _RecordingHandler()
    previous = root.level
    root.setLevel(logging.DEBUG)
    root.addHandler(handler)
    try:
        yield handler
    finally:
        root.removeHandler(handler)
        root.setLevel(previous)


def _formatted(handler: _RecordingHandler) -> str:
    fmt = RedactingFormatter("%(message)s")
    return "\n".join(fmt.format(r) for r in handler.records)


def _raw(handler: _RecordingHandler) -> str:
    return "\n".join(str(r.getMessage()) for r in handler.records)


def _assert_clean(handler: _RecordingHandler) -> str:
    logs = _formatted(handler)
    for secret in ALL_SECRETS:
        assert secret not in logs, f"{secret!r} leaked into formatted logs"
        assert secret not in _raw(handler), f"{secret!r} leaked into raw log record"
    return logs


class _Resp:
    def __init__(self, status_code: int, headers: dict | None = None):
        self.status_code = status_code
        self.headers = headers or {}


# -- _post_with_retry: HTTP errors -----------------------------------------


def test_discord_http_error_no_token_in_logs(monkeypatch):
    monkeypatch.setattr(nt.requests, "post", lambda *a, **k: _Resp(400))
    with capture_nexus_logs() as h:
        assert _post_with_retry(DISCORD_URL, {"x": 1}) is False
    logs = _assert_clean(h)
    assert "discord.com" in logs and "status=400" in logs and "category=http_error" in logs


def test_canary_discord_http_error_no_token_in_logs(monkeypatch):
    # The pre-existing logger regex only matched discord.com/discordapp.com.
    monkeypatch.setattr(nt.requests, "post", lambda *a, **k: _Resp(403))
    with capture_nexus_logs() as h:
        assert _post_with_retry(CANARY_URL, {"x": 1}) is False
    _assert_clean(h)


def test_telegram_http_error_no_token_in_logs(monkeypatch):
    monkeypatch.setattr(nt.requests, "post", lambda *a, **k: _Resp(401))
    with capture_nexus_logs() as h:
        assert _post_with_retry(TELEGRAM_URL, {"x": 1}) is False
    logs = _assert_clean(h)
    assert "api.telegram.org" in logs and "status=401" in logs


# -- _post_with_retry: connection / exception errors -----------------------


def test_connection_error_message_with_full_url_no_leak(monkeypatch):
    def boom(*a, **k):
        raise requests.ConnectionError(
            "HTTPSConnectionPool(host='api.telegram.org', port=443): "
            f"Max retries exceeded with url: /bot{TELEGRAM_TOKEN}/sendMessage"
        )

    monkeypatch.setattr(nt.requests, "post", boom)
    with capture_nexus_logs() as h:
        assert _post_with_retry(TELEGRAM_URL, {"x": 1}) is False
    logs = _assert_clean(h)
    assert "category=connection_error" in logs


def test_discord_connection_error_url_no_leak(monkeypatch):
    def boom(*a, **k):
        raise requests.ConnectionError(f"failed to reach {DISCORD_URL}")

    monkeypatch.setattr(nt.requests, "post", boom)
    with capture_nexus_logs() as h:
        assert _post_with_retry(DISCORD_URL, {"x": 1}) is False
    _assert_clean(h)


def test_timeout_error_no_leak(monkeypatch):
    def boom(*a, **k):
        raise requests.Timeout(f"timed out connecting to {DISCORD_URL}")

    monkeypatch.setattr(nt.requests, "post", boom)
    with capture_nexus_logs() as h:
        assert _post_with_retry(DISCORD_URL, {"x": 1}) is False
    _assert_clean(h)


# -- _post_with_retry: ssrf / retry / malformed ----------------------------


def test_ssrf_blocked_no_query_secret_leak(monkeypatch):
    called = {"n": 0}

    def boom(*a, **k):  # pragma: no cover - must not run
        called["n"] += 1
        raise AssertionError("no network expected")

    monkeypatch.setattr(nt.requests, "post", boom)
    with capture_nexus_logs() as h:
        assert _post_with_retry(QUERY_URL.replace("alerts.example.com", "169.254.169.254"), {}) is False
    assert called["n"] == 0
    _assert_clean(h)


def test_rate_limited_then_success_no_leak(monkeypatch):
    monkeypatch.setattr(nt.time, "sleep", lambda *a, **k: None)
    seq = [_Resp(429, {"Retry-After": "0"}), _Resp(204)]

    def post(*a, **k):
        return seq.pop(0)

    monkeypatch.setattr(nt.requests, "post", post)
    with capture_nexus_logs() as h:
        assert _post_with_retry(DISCORD_URL, {"x": 1}) is True
    _assert_clean(h)


def test_malformed_response_does_not_raise_or_leak(monkeypatch):
    monkeypatch.setattr(nt.requests, "post", lambda *a, **k: object())
    with capture_nexus_logs() as h:
        assert _post_with_retry(DISCORD_URL, {"x": 1}) is False
    logs = _assert_clean(h)
    assert "category=malformed_response" in logs


# -- Notifier end-to-end ---------------------------------------------------


class _FakeCfg:
    def __init__(self, findings="", cve="", metrics="", tg=("", "")):
        self._w = {"findings": findings, "cve": cve, "metrics": metrics}
        self.email = {}
        self.env = {}
        self._tg = tg

    def webhook(self, kind):
        return self._w.get(kind, "")

    def telegram(self):
        return self._tg


def test_notifier_send_finding_connection_error_no_leak(monkeypatch):
    def boom(*a, **k):
        raise requests.ConnectionError(f"cannot POST {DISCORD_URL}")

    monkeypatch.setattr(nt.requests, "post", boom)
    notifier = Notifier(_FakeCfg(findings=DISCORD_URL))
    with capture_nexus_logs() as h:
        assert notifier.send_finding({"vuln_type": "xss", "severity": "P1"}) is False
    _assert_clean(h)


def test_notifier_telegram_failure_no_leak(monkeypatch):
    monkeypatch.setattr(nt.requests, "post", lambda *a, **k: _Resp(500))
    notifier = Notifier(_FakeCfg(tg=(TELEGRAM_TOKEN, "999")))
    with capture_nexus_logs() as h:
        assert notifier.send_finding_telegram({"vuln_type": "xss", "severity": "P2"}) is False
    _assert_clean(h)


def test_notifier_send_cve_telegram_no_leak(monkeypatch):
    def boom(*a, **k):
        raise requests.ConnectionError(f"url: /bot{TELEGRAM_TOKEN}/sendMessage")

    monkeypatch.setattr(nt.requests, "post", boom)
    notifier = Notifier(_FakeCfg(tg=(TELEGRAM_TOKEN, "999")))
    with capture_nexus_logs() as h:
        assert notifier.send_cve_telegram({"cve_id": "CVE-1"}) is False
    _assert_clean(h)


# -- SMTP ------------------------------------------------------------------


def test_smtp_failure_redacts_password(monkeypatch):
    class _SMTP:
        def __init__(self, *a, **k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def starttls(self):
            pass

        def login(self, user, pw):
            raise OSError(f"auth rejected for user={user} pass={SMTP_SECRET}")

    monkeypatch.setattr(nt.smtplib, "SMTP", _SMTP)
    with capture_nexus_logs() as h:
        ok = smtp_send("smtp.example.com", 587, "u", SMTP_SECRET,
                       "from@x.com", ["to@x.com"], "subject", "body")
    assert ok is False
    _assert_clean(h)


# -- redaction unit coverage -----------------------------------------------


@pytest.mark.parametrize(
    "text",
    [
        TELEGRAM_URL,
        DISCORD_URL,
        CANARY_URL,
        f"Authorization: Bearer {BEARER_SECRET}",
        f"GET {QUERY_URL}",
        f"https://user:{SMTP_SECRET}@internal.example.com/path",
    ],
)
def test_redact_text_masks_known_secret_shapes(text):
    out = redact_text(text)
    assert REDACTED in out or "user:***" in out
    for secret in ALL_SECRETS:
        assert secret not in out


def test_redact_text_masks_url_encoded_secret():
    encoded = "https://api.example.com/v1?token=abc%2Fdef%2Bghi%3D"
    out = redact_text(encoded)
    assert "abc%2Fdef" not in out
    assert REDACTED in out


def test_redact_text_masks_userinfo():
    out = redact_text("https://admin:hunter2@host.example.com/x")
    assert "hunter2" not in out
    assert "admin:" not in out


def test_redacting_formatter_masks_telegram_url_in_record():
    fmt = RedactingFormatter("%(message)s")
    record = logging.LogRecord(
        "nexus.notifications", logging.WARNING, __file__, 1,
        f"send failed: {TELEGRAM_URL}", None, None,
    )
    out = fmt.format(record)
    assert TELEGRAM_TOKEN not in out
    assert REDACTED in out
