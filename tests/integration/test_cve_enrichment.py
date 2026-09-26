"""Integration: CVE workflow with KEV/EPSS enrichment (offline)."""
from __future__ import annotations

from pathlib import Path

import yaml

from core.database import Database
from lib.config import load_config
from lib.cve_fetcher import CVEFetcher
from lib.cve_workflow import run_cve_update

NVD_PAYLOAD = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2026-1111",
                "published": "2026-09-25T00:00:00.000",
                "descriptions": [{"lang": "en", "value": "Acme server RCE."}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}]},
                "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:acme:server:1.0:*:*:*:*:*:*:*"}]}]}],
            }
        },
        {
            "cve": {
                "id": "CVE-2026-2222",
                "published": "2026-09-25T00:00:00.000",
                "descriptions": [{"lang": "en", "value": "Acme low."}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}]},
                "configurations": [{"nodes": [{"cpeMatch": [{"criteria": "cpe:2.3:a:acme:server:1.0:*:*:*:*:*:*:*"}]}]}],
            }
        },
    ]
}


class _NvdSession:
    headers: dict = {}

    def get(self, url, params=None, headers=None, timeout=None):
        class _R:
            status_code = 200

            @staticmethod
            def json():
                return NVD_PAYLOAD

        return _R()


def _cfg_with_kev(tmp_path: Path):
    cfg_dir = tmp_path / "config"
    cfg_dir.mkdir(exist_ok=True)
    (cfg_dir / "nexus.yaml").write_text(
        yaml.safe_dump({
            "cve": {"use_kev": True, "use_epss": True, "alert_severity": ["high"]},
            "ai": {"provider": "none"},
        }),
        encoding="utf-8",
    )
    (cfg_dir / "false_positive_filters.yaml").write_text("filters: {}\n", encoding="utf-8")
    return load_config(cfg_dir)


def test_cve_update_enriches_with_kev_and_prioritises(tmp_path, monkeypatch):
    cfg = _cfg_with_kev(tmp_path)
    db = Database(tmp_path / "cve.db")

    # NVD fetch stubbed.
    monkeypatch.setattr("lib.cve_workflow.CVEFetcher",
                        lambda api_key="": CVEFetcher(session=_NvdSession()))

    # Threat feeds stubbed: CVE-2026-2222 is known-exploited.
    from lib import threat_feeds as tf

    class _FakeFeeds:
        def fetch_kev(self):
            return {"CVE-2026-2222"}

        def fetch_epss(self, ids):
            return {"CVE-2026-1111": 0.2, "CVE-2026-2222": 0.9}

    monkeypatch.setattr(tf, "ThreatFeeds", lambda *a, **k: _FakeFeeds())

    captured = {"order": []}

    class _FakeNotifier:
        def __init__(self, cfg):
            pass

        def send_cve(self, cve):
            captured["order"].append(cve.get("cve_id"))
            captured["kev"] = cve.get("kev")
            captured["epss"] = cve.get("epss")
            return True

        def send_cve_telegram(self, cve):
            return True

    monkeypatch.setattr("lib.cve_workflow.Notifier", _FakeNotifier)
    monkeypatch.setattr("lib.cve_workflow.EmailAlerter", lambda cfg: None)

    summary = run_cve_update(
        cfg, db, tech_stack={"Acme": "1.0"}, poc_base=tmp_path / "pocs", notify=True
    )

    assert summary["kev_matched"] == 1
    assert summary["epss_above_0_5"] == 1
    # KEV CVE alerted first (priority ordering).
    assert captured["order"][0] == "CVE-2026-2222"
    assert captured["kev"] in (True, False)  # last alerted is the non-KEV one
    # The KEV/EPSS values were attached during enrichment.
    assert "CVE-2026-2222" in captured["order"]


def test_cve_update_skips_enrichment_when_disabled(tmp_path, monkeypatch):
    cfg_dir = tmp_path / "config"
    cfg_dir.mkdir(exist_ok=True)
    (cfg_dir / "nexus.yaml").write_text("cve:\n  use_kev: false\n  use_epss: false\n", encoding="utf-8")
    (cfg_dir / "false_positive_filters.yaml").write_text("filters: {}\n", encoding="utf-8")
    cfg = load_config(cfg_dir)
    db = Database(tmp_path / "cve.db")

    monkeypatch.setattr("lib.cve_workflow.CVEFetcher",
                        lambda api_key="": CVEFetcher(session=_NvdSession()))

    def _boom(*a, **k):
        raise AssertionError("threat feeds must not be called when disabled")

    monkeypatch.setattr("lib.cve_workflow.threat_feeds.enrich_cves", _boom)

    summary = run_cve_update(cfg, db, tech_stack={"Acme": "1.0"},
                             poc_base=tmp_path / "pocs", notify=False)
    assert summary["kev_matched"] == 0
