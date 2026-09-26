"""Analysis pipeline: raw findings → dedup → score → chains → filters → outputs.

Runs the full Phase 3 (ANALYZE) flow over raw probe findings and writes
``findings.json``, ``chains.json``, ``high_value_findings.json`` and
``metrics.json`` into the scan's ``processed/`` directory, then persists
everything to the database.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.database import Database
from core.sanitizer import sanitize_finding
from lib.chainer import detect_chains
from lib.config import Config, TargetConfig
from lib.deduplicator import deduplicate
from lib.false_positive_filter import FalsePositiveFilter
from lib.logger import get_logger
from lib.scope_validator import validate_finding_scope
from lib.severity_scorer import SeverityScorer, severity_rank

logger = get_logger("analyzer")

HIGH_VALUE_SEVERITIES = ("P1", "P2")


def _host_of(endpoint: str) -> str:
    from urllib.parse import urlsplit

    raw = str(endpoint or "")
    if "://" in raw:
        try:
            return urlsplit(raw).hostname or ""
        except ValueError:
            return ""
    return raw.split("/")[0].split(":")[0]


def _repro_hints(finding: dict[str, Any]) -> dict[str, str]:
    """Build a raw-request sketch + cURL repro line (roadmap F3)."""
    endpoint = str(finding.get("endpoint", "") or "")
    payload = str(finding.get("payload", "") or "")
    host = _host_of(endpoint)
    raw_request = f"GET {endpoint or '/'} HTTP/1.1\nHost: {host or 'TARGET'}\nUser-Agent: NEXUS/1.1"
    curl = f'curl -sk "{endpoint}"'
    if payload:
        curl += f"   # payload: {payload}"
    return {"raw_request": raw_request, "curl": curl}


class Analyzer:
    """Phase 3 orchestrator."""

    def __init__(self, cfg: Config, db: Database):
        self.cfg = cfg
        self.db = db
        self.scorer = SeverityScorer(cfg.filters)
        self.fp_filter = FalsePositiveFilter(cfg.filters)

    def run(
        self,
        raw_findings: list[dict[str, Any]],
        target_config: TargetConfig,
        scan_id: int,
        results_dir: Path,
        urls_discovered: int = 0,
        endpoints_tested: int = 0,
        duration_seconds: int = 0,
        min_severity: str = "",
        exclude: list[str] | None = None,
        exclude_p4: bool = False,
    ) -> dict[str, Any]:
        """Analyze raw findings and persist + emit outputs.

        Returns the metrics summary dict.
        """
        processed_dir = results_dir / "processed"
        processed_dir.mkdir(parents=True, exist_ok=True)

        # 1. Dedup (fuzzy merge, multi-tool confidence boost).
        deduped, dedup_report = deduplicate(raw_findings)

        # 2. Scope filter — OOS findings are marked, never submitted.
        scoped: list[dict[str, Any]] = []
        oos_count = 0
        for f in deduped:
            host_ok = validate_finding_scope(str(f.get("endpoint", "")), target_config)
            f["in_scope"] = bool(host_ok)
            if not host_ok:
                oos_count += 1
                f["valid"] = False
                f["validity_reason"] = "OUT_OF_SCOPE"
            scoped.append(f)

        # 3. Severity + confidence.
        for f in scoped:
            severity, confidence = self.scorer.score(f)
            f["severity"] = severity
            f["confidence"] = confidence

        # 4. False-positive classification.
        for f in scoped:
            state, reason = self.fp_filter.classify(f)
            f["fp_state"] = state
            f["fp_reason"] = reason
            if f.get("valid") is not False:  # OOS / disproved verdicts stay final
                if state == "FALSE_POSITIVE":
                    f["valid"] = False
                    f["validity_reason"] = reason
                elif state == "VALID":
                    f["valid"] = True
                    f["validity_reason"] = reason
                else:  # POTENTIAL
                    f["valid"] = None
                    f["validity_reason"] = reason

        # 4b. Verification state + corroboration (roadmap A1/A2).
        for f in scoped:
            tools = {str(t).lower() for t in (f.get("tools_found") or [])}
            f["corroborated"] = len(tools) >= 2
            f["verified"] = bool((f.get("verification") or {}).get("verified", False))
            f.setdefault("repro", _repro_hints(f))

        # 4c. Raw request / cURL repro hints for every finding (roadmap F3).
        for f in scoped:
            f.setdefault("repro", _repro_hints(f))

        # 5. Severity filtering (--min-severity / --exclude / --exclude-p4).
        exclude_set = {str(s).upper() for s in (exclude or [])}
        if exclude_p4:
            exclude_set.add("P4")
        min_rank = severity_rank(min_severity) if min_severity else None
        kept: list[dict[str, Any]] = []
        for f in scoped:
            sev = str(f.get("severity", ""))
            if sev in exclude_set:
                continue
            if min_rank is not None and severity_rank(sev) > min_rank:
                continue
            kept.append(f)
        filtered_out = len(scoped) - len(kept)
        scoped = kept

        # 6. Chain detection over in-scope findings.
        in_scope_findings = [f for f in scoped if f.get("in_scope")]
        chains = detect_chains(in_scope_findings)

        # 6. Persist to DB.
        finding_ids = self.db.insert_findings(scan_id, scoped)
        for f, fid in zip(scoped, finding_ids):
            f["id"] = fid
        chain_ids: list[int] = []
        for chain in chains:
            member_ids = [
                f["id"] for f in in_scope_findings if f.get("endpoint") in chain.get("members", [])
            ]
            chain_ids.append(
                self.db.insert_chain(
                    scan_id=scan_id,
                    finding_ids=member_ids,
                    chain_type=chain["chain_type"],
                    impact=chain["impact"],
                    steps=chain["steps"],
                    combined_severity=chain.get("combined_severity", ""),
                )
            )

        # 7. Sanitize evidence for output files.
        out_findings = [sanitize_finding(f) for f in scoped]

        # 8. Metrics.
        by_sev: dict[str, int] = {}
        valid_count = fp_count = potential_count = 0
        for f in scoped:
            by_sev[f.get("severity", "?")] = by_sev.get(f.get("severity", "?"), 0) + 1
            if f.get("valid") is True:
                valid_count += 1
            elif f.get("valid") is None and f.get("in_scope"):
                potential_count += 1
            elif f.get("valid") is False and f.get("in_scope"):
                fp_count += 1

        metrics = {
            "target": target_config.domain,
            "scan_id": scan_id,
            "urls_discovered": urls_discovered,
            "endpoints_tested": endpoints_tested,
            "findings_total": len(scoped),
            "findings_valid": valid_count,
            "findings_potential": potential_count,
            "false_positives": fp_count,
            "findings_oos": oos_count,
            "filtered_out": filtered_out,
            "by_severity": by_sev,
            "chains_detected": len(chains),
            "verified": len([f for f in scoped if f.get("verified")]),
            "corroborated": len([f for f in scoped if f.get("corroborated")]),
            "dedup": {
                "input_count": dedup_report.get("input_count", 0),
                "output_count": dedup_report.get("output_count", 0),
                "duplicates_merged": dedup_report.get("duplicates_merged", 0),
            },
            "duration_seconds": duration_seconds,
        }

        # 9. Write outputs (sanitized evidence only).
        (processed_dir / "findings.json").write_text(
            json.dumps(out_findings, indent=2, default=str), encoding="utf-8"
        )
        (processed_dir / "chains.json").write_text(
            json.dumps(chains, indent=2, default=str), encoding="utf-8"
        )
        high_value = [
            f for f in out_findings
            if f.get("severity") in HIGH_VALUE_SEVERITIES
            and f.get("valid") is not False
            and (f.get("verified") or f.get("corroborated"))
        ]
        high_chains = [c for c in chains if c.get("combined_severity") in HIGH_VALUE_SEVERITIES]
        (processed_dir / "high_value_findings.json").write_text(
            json.dumps({"findings": high_value, "chains": high_chains}, indent=2, default=str),
            encoding="utf-8",
        )
        (processed_dir / "metrics.json").write_text(
            json.dumps(metrics, indent=2, default=str), encoding="utf-8"
        )

        # 9b. Submission drafts for high-value findings (roadmap E5).
        from core.reporter import render_draft

        draft_dir = results_dir / "reports" / "drafts"
        draft_dir.mkdir(parents=True, exist_ok=True)
        for i, f in enumerate(out_findings, start=1):
            if f.get("severity") in HIGH_VALUE_SEVERITIES and f.get("valid") is not False:
                name = f"draft-{i:03d}-{str(f.get('vuln_type', 'finding'))}.md"
                (draft_dir / name).write_text(
                    render_draft(target_config.platform, target_config.domain, f, metrics=metrics),
                    encoding="utf-8",
                )

        # 10. Update scan record.
        self.db.update_scan(
            scan_id,
            status="completed",
            duration_seconds=duration_seconds,
            findings_total=len(scoped),
            findings_valid=valid_count,
            findings_oos=oos_count,
        )

        logger.info(
            "analysis complete: %d findings (%d valid, %d FP, %d OOS), %d chains",
            len(scoped), valid_count, fp_count, oos_count, len(chains),
        )
        return metrics
