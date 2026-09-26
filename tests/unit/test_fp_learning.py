"""FP filter learning feedback loop — unit tests."""
from __future__ import annotations

import yaml

from lib.false_positive_filter import FalsePositiveFilter

BASE = {
    "filters": {
        "xss": {"strictness": "aggressive", "confidence_threshold": 90, "auto_filter": []},
    }
}


def test_learn_from_fp_review_adds_pattern():
    fpf = FalsePositiveFilter(BASE)
    learning = fpf.learn_from_review(
        {"vuln_type": "xss", "response_snippet": "ReflectedMarkerXYZ in page", "payload": ""},
        "FP",
    )
    assert learning and learning["learned_pattern"] == "ReflectedMarkerXYZ"
    state, reason = fpf.classify({
        "vuln_type": "xss", "confidence": 99, "endpoint": "https://x",
        "response_snippet": "ReflectedMarkerXYZ in page",
    })
    assert state == "FALSE_POSITIVE"


def test_learn_from_tp_review_adds_nothing():
    fpf = FalsePositiveFilter(BASE)
    assert fpf.learn_from_review({"vuln_type": "xss", "response_snippet": "abc"}, "TP") is None
    assert fpf.rules["xss"]["patterns"] == []


def test_learn_requires_evidence():
    fpf = FalsePositiveFilter(BASE)
    assert fpf.learn_from_review({"vuln_type": "xss", "response_snippet": "", "payload": ""}, "FP") is None


def test_unknown_type_not_learned():
    fpf = FalsePositiveFilter(BASE)
    assert fpf.learn_from_review({"vuln_type": "nosuch", "response_snippet": "whatever"}, "FP") is None


def test_no_duplicate_patterns():
    fpf = FalsePositiveFilter(BASE)
    finding = {"vuln_type": "xss", "response_snippet": "DuplicateMarker here", "payload": ""}
    fpf.learn_from_review(finding, "FP")
    fpf.learn_from_review(finding, "FP")
    assert len(fpf.rules["xss"]["patterns"]) == 1


def test_persisted_yaml_roundtrip(tmp_path):
    """Coordinator.reject_finding writes the learned rule back to YAML."""
    filters = tmp_path / "false_positive_filters.yaml"
    filters.write_text(yaml.safe_dump(BASE), encoding="utf-8")
    data = yaml.safe_load(filters.read_text(encoding="utf-8"))
    fpf = FalsePositiveFilter(data)
    fpf.learn_from_review({"vuln_type": "xss", "response_snippet": "PersistedMarker long-enough", "payload": ""}, "FP")
    rule = data["filters"]["xss"]
    rule.setdefault("auto_filter", []).append("PersistedMarker")
    filters.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    reloaded = yaml.safe_load(filters.read_text(encoding="utf-8"))
    assert "PersistedMarker" in reloaded["filters"]["xss"]["auto_filter"]
