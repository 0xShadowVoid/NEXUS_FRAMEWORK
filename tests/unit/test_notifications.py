"""Unit tests for the notification layer (all transports mocked)."""
from __future__ import annotations

from lib.notifications import EmailAlerter, NotificationFormatter, Notifier, smtp_send


class _FakeCfg:
    def __init__(self, findings="", cve="", metrics="", tg=("", ""), email=None):
        self._w = {"findings": findings, "cve": cve, "metrics": metrics}
        self._tg = tg
        self.email = email or {}

    def webhook(self, kind):
        return self._w.get(kind, "")

    def telegram(self):
        return self._tg


def test_severity_colors():
    f = NotificationFormatter()
    assert f.severity_color("P1") == 0xE74C3C
    assert f.severity_color("P4") == 0x95A5A6
    assert f.severity_color("unknown") == 0x95A5A6


def test_finding_embed_structure():
    embed = NotificationFormatter.finding_embed({
        "vuln_type": "xss", "severity": "P2", "confidence": 90,
        "endpoint": "https://x/a", "payload": "<img>", "response_snippet": "proof",
        "tools_found": ["nuclei"], "target": "x.com",
    })
    assert embed["color"] == 0xE67E22
    names = [fld["name"] for fld in embed["fields"]]
    assert "Endpoint" in names and "Payload" in names


def test_discord_send_uses_requests(monkeypatch):
    calls = {}

    class _Resp:
        status_code = 204
        headers = {}

    def fake_post(url, json=None, timeout=None):
        calls["url"] = url
        calls["json"] = json
        return _Resp()

    monkeypatch.setattr("lib.notifications.requests.post", fake_post)
    cfg = _FakeCfg(findings="https://discord.com/api/webhooks/1/abc")
    notifier = Notifier(cfg)
    assert notifier.send_finding({"vuln_type": "xss", "severity": "P1", "tools_found": []}) is True
    assert calls["url"].endswith("/api/webhooks/1/abc")
    assert "embeds" in calls["json"]


def test_discord_unset_webhook_skips_without_network(monkeypatch):
    def boom(*a, **k):
        raise AssertionError("no network expected")

    monkeypatch.setattr("lib.notifications.requests.post", boom)
    notifier = Notifier(_FakeCfg())  # all webhooks empty
    assert notifier.send_finding({"vuln_type": "xss", "severity": "P1"}) is False
    assert notifier.send_cve({"cve_id": "CVE-1"}) is False


def test_telegram_send(monkeypatch):
    calls = {}

    class _Resp:
        status_code = 200
        headers = {}

    monkeypatch.setattr(
        "lib.notifications.requests.post",
        lambda url, json=None, timeout=None: (calls.update(url=url), _Resp())[1],
    )
    cfg = _FakeCfg(tg=("123456:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh", "999"))
    notifier = Notifier(cfg)
    assert notifier.send_finding_telegram({"vuln_type": "xss", "severity": "P2"}) is True
    assert "sendMessage" in calls["url"]


def test_telegram_unset_skips():
    notifier = Notifier(_FakeCfg(tg=("", "")))
    assert notifier.send_finding_telegram({"vuln_type": "xss"}) is False


def test_smtp_unset_returns_false():
    assert smtp_send("", 587, "", "", "", [], "s", "b") is False


def test_smtp_send_with_attachments(monkeypatch):
    sent = {}

    class _SMTP:
        def __init__(self, host, port, timeout=None):
            sent["host"] = host
            sent["port"] = port

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def starttls(self):
            sent["tls"] = True

        def login(self, user, pw):
            sent["login"] = (user, pw)

        def send_message(self, msg):
            sent["message"] = msg

    monkeypatch.setattr("lib.notifications.smtplib.SMTP", _SMTP)
    ok = smtp_send(
        "smtp.example.com", 587, "u", "p", "from@x.com", ["to@x.com"],
        "subject", "body", [("cve.py", b"print('x')")],
    )
    assert ok is True
    assert sent["host"] == "smtp.example.com"
    assert any(p.get_filename() == "cve.py" for p in sent["message"].iter_attachments())


def test_email_alerter_binds_config():
    cfg = _FakeCfg(email={
        "smtp_host": "h", "smtp_port": 587, "smtp_user": "u",
        "smtp_pass": "p", "from_addr": "f@x", "to_addrs": "a@x, b@x",
    })
    alerter = EmailAlerter(cfg)
    assert alerter.to_addrs == ["a@x", "b@x"]
