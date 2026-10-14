"""NETWORK phase orchestrator (Pass 5) — scope-first, bounded discovery.

Wiring only, on existing NEXUS primitives:

- authorization via the existing scope validator (explicit ip/CIDR grants;
  loopback/link-local/private/metadata need a grant AND ``allow_private``);
- bounded engine (``phases/network/engine.py``) — conservative ports, low
  concurrency, per-connect budget, cancellation + kill switch;
- graph ingestion via the filtration pipeline; evidence via the Evidence
  Engine (sanitized, asset-linked); findings via the lifecycle (candidates
  seeded deterministically — AI never validates);
- checkpoint/resume through the existing phase state machine;
- explicit accounting: checked / open / closed / filtered / skipped / untested.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import socket
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from lib.config import Config, TargetConfig
from lib.filtration import FiltrationPipeline, normalize_asset
from lib.logger import get_logger
from lib.ops_guard import KillSwitch
from lib.scope_validator import (
    _canonical_ip,
    ip_allowed_for_target,
    is_ip_literal,
    validate_target_scope,
)
from phases.network.engine import NetSettings, NetworkEngine, PortResult, parse_ports

logger = get_logger("net_orchestrator")

MAX_CIDR_HOSTS = 64          # CIDR expansion cap (remainder counted as skipped)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _settings_from_cfg(cfg: Config) -> NetSettings:
    raw: dict[str, Any] = {}
    try:
        raw = ((cfg.phases or {}).get("network", {}) or {}) if cfg is not None else {}
    except Exception:  # pragma: no cover - defensive
        raw = {}
    max_ports = max(1, min(int(raw.get("max_ports", 512) or 512), 4096))
    ports, over_cap = parse_ports(raw.get("ports", []), max_ports)
    return NetSettings(
        ports=tuple(ports),
        concurrency=max(1, min(int(raw.get("concurrency", 16) or 16), 64)),
        connect_timeout=max(0.2, min(float(raw.get("connect_timeout", 1.5) or 1.5), 10.0)),
        probe_timeout=max(0.2, min(float(raw.get("probe_timeout", 2.0) or 2.0), 10.0)),
        max_ports_per_ip=max_ports,
        allow_private=bool(raw.get("allow_private", False)),
        over_cap=over_cap,
    )


def _resolve_ips(host: str) -> list[str]:
    canon = host.strip().strip("[]")
    if is_ip_literal(canon):
        ip = _canonical_ip(canon.split("/")[0])
        return [str(ip)] if ip is not None else []
    ips: set[str] = set()
    try:
        infos = socket.getaddrinfo(canon, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except OSError:
        return []
    for info in infos:
        addr = str(info[4][0]).split("%")[0]
        ip = _canonical_ip(addr)
        if ip is not None:
            ips.add(str(ip))
    return sorted(ips)


def _ip_scope_targets(target_config: TargetConfig) -> tuple[list[str], int]:
    """Explicit ip/CIDR in-scope entries → literal hosts (CIDR capped)."""
    out: list[str] = []
    skipped = 0
    for entry in target_config.in_scope:
        e = (entry or "").strip()
        if not e:
            continue
        try:
            network = ipaddress.ip_network(e, strict=False)
        except ValueError:
            continue
        if network.num_addresses == 1:
            out.append(str(network.network_address))
            continue
        hosts_iter = network.hosts()
        take: list[str] = []
        for host in hosts_iter:
            if len(take) >= MAX_CIDR_HOSTS:
                break
            take.append(str(host))
        skipped += max(0, (network.num_addresses - 2) - len(take))
        out.extend(take)
    return out, skipped


def _plan_hash(pairs: list[tuple[str, str]], ports: list[int]) -> str:
    blob = json.dumps(
        {"pairs": sorted(pairs), "ports": ports}, sort_keys=True, default=str
    )
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


def run_network(
    cfg: Config,
    target_config: TargetConfig,
    results_dir: Path,
    db: Any | None = None,
    scan_id: int | None = None,
    http_get: Any | None = None,
) -> dict[str, Any]:
    """Run the scoped network assessment phase."""
    settings = _settings_from_cfg(cfg)
    results_dir = Path(results_dir)
    accounting = {"checked": 0, "open": 0, "closed": 0, "filtered": 0, "skipped": 0, "untested": 0}
    notes: list[str] = []
    rejected: list[str] = []

    # ---- authorization BEFORE any connection ---------------------------------
    ip_targets, cidr_skipped = _ip_scope_targets(target_config)
    if cidr_skipped:
        notes.append(f"CIDR expansion capped: {cidr_skipped} host(s) not scheduled")
    candidates = [target_config.domain, *ip_targets]
    pairs: list[tuple[str, str]] = []            # (display_host, ip)
    seen_ips: set[str] = set()
    for cand in candidates:
        if not cand:
            continue
        if is_ip_literal(cand):
            ok, why = ip_allowed_for_target(
                cand, target_config,
                allow_private=settings.allow_private, require_grant=True,
            )
            ip = _canonical_ip(cand.split("/")[0])
            if ok and ip is not None:
                key = str(ip)
                if key not in seen_ips:
                    seen_ips.add(key)
                    pairs.append((key, key))
            else:
                rejected.append(f"{cand}: {why}")
            continue
        try:
            validate_target_scope(cand, target_config)
        except Exception as exc:
            rejected.append(f"{cand}: {exc}")
            continue
        ips = _resolve_ips(cand)
        if not ips:
            rejected.append(f"{cand}: no addresses resolved")
            continue
        for ip in ips:
            ok, why = ip_allowed_for_target(
                ip, target_config, allow_private=settings.allow_private
            )
            if ok:
                key = str(ip)
                if key not in seen_ips:
                    seen_ips.add(key)
                    pairs.append((cand, key))
            else:
                rejected.append(f"{cand} -> {ip}: {why}")

    if not pairs:
        return {
            "status": "blocked",
            "phase_state": "blocked",
            "reason": "; ".join(rejected[:5]) or "no authorized network targets",
            "ports": accounting,
            "rejected": rejected[:20],
        }

    ports = list(settings.ports)
    accounting["skipped"] += int(settings.over_cap) * len(pairs)
    if settings.over_cap:
        notes.append(f"{settings.over_cap} port(s) beyond max_ports cap were skipped")

    # ---- checkpoint / resume ---------------------------------------------------
    plan_hash = _plan_hash(pairs, ports)
    resume_done: dict[str, str] = {}
    if db is not None and scan_id is not None:
        try:
            prior = db.get_phase_run(scan_id, "network") or {}
            cp = json.loads(prior.get("checkpoint") or "{}")
            if cp.get("plan_hash") == plan_hash:
                resume_done = {str(k): str(v) for k, v in (cp.get("done") or {}).items()}
        except Exception:
            resume_done = {}

    killswitch = KillSwitch()
    cancel_event = threading.Event()
    engine = NetworkEngine(settings, cancel_event=cancel_event, killed=killswitch.killed)

    def _authorized(ip: str, _port: int) -> bool:
        ok, _why = ip_allowed_for_target(
            ip, target_config, allow_private=settings.allow_private
        )
        return ok

    all_results: list[PortResult] = []
    interrupted = False
    for _display, ip in pairs:
        per_ip: dict[int, PortResult] = {}
        todo: list[int] = []
        for port in ports:
            prior_state = resume_done.get(f"{ip}:{port}")
            if prior_state in ("open", "closed", "filtered"):
                per_ip[port] = PortResult(ip, port, prior_state)   # resumed: not re-scanned
            else:
                todo.append(port)
        for res in engine.scan(ip, todo, per_task_check=_authorized):
            per_ip[res.port] = res
        for port in ports:                                        # ordered accounting
            res = per_ip.get(port)
            if res is None:
                continue
            all_results.append(res)
            if res.state == "open":
                accounting["open"] += 1
                accounting["checked"] += 1
            elif res.state == "closed":
                accounting["closed"] += 1
                accounting["checked"] += 1
            elif res.state == "filtered":
                accounting["filtered"] += 1
                accounting["checked"] += 1
            elif res.state == "skipped":
                accounting["skipped"] += 1
            else:
                accounting["untested"] += 1
        if engine.cancelled():
            interrupted = True
            break

    # ---- service identification (open ports; honors cancellation) ----------------
    for res in all_results:
        if res.state == "open" and not engine.cancelled():
            engine.identify(res)
    open_results = [r for r in all_results if r.state == "open"]

    # ---- graph + evidence + findings ----------------------------------------------
    evidence_ids: list[int] = []
    finding_ids: list[int] = []
    asset_links = 0
    if db is not None and scan_id is not None:
        try:
            pipeline = FiltrationPipeline(db, target_config, scan_id)
            pipeline.ingest("net-engine", "network", sorted({ip for _d, ip in pairs}), kind="ip")
            pipeline.ingest(
                "net-engine", "network",
                [f"{ip}:{p}" for _d, ip in pairs for p in ports], kind="port",
            )
            services = sorted({f"{r.ip}:{r.port}/{r.service or 'unknown'}" for r in open_results})
            if services:
                pipeline.ingest("net-engine", "network", services, kind="service")
        except Exception as exc:
            logger.warning("network graph ingestion failed: %s", exc)

        for res in open_results:
            display = next((d for d, ip in pairs if ip == res.ip), res.ip)
            try:
                eid = db.insert_evidence(
                    scan_id,
                    url=f"{display}:{res.port}",
                    method="TCP",
                    tool="net-engine",
                    source="network",
                    response_body=(
                        res.banner
                        or f"{res.service or 'service'}: {json.dumps(res.meta, default=str)[:400]}"
                    ),
                )
                evidence_ids.append(eid)
                try:
                    asset = db.get_asset("ip", normalize_asset("ip", res.ip))
                    if asset and db.set_evidence_asset(eid, int(asset["id"])):
                        asset_links += 1
                except Exception:
                    pass
                if res.meta.get("legacy_tls"):
                    fid = db.insert_finding(
                        scan_id, f"{display}:{res.port}", "tls-legacy", "P3", 85,
                        response_snippet=(res.banner or "legacy TLS negotiated")[:400],
                    )
                    from core import lifecycle as lifecycle_mod

                    lifecycle_mod.seed_from_analysis(
                        db, fid, {"in_scope": True, "valid": True, "fp_state": "VALID"}
                    )
                    try:
                        db.set_evidence_finding(eid, fid)
                    except Exception:
                        pass
                    finding_ids.append(fid)
            except Exception as exc:
                logger.debug("network evidence/finding failed for %s:%s: %s", res.ip, res.port, exc)

    # ---- snapshot + checkpoint -----------------------------------------------------
    snapshot = {
        "target": target_config.domain,
        "generated": _now(),
        "pairs": [{"display": d, "ip": ip} for d, ip in pairs],
        "ports": [r.to_dict() for r in all_results],
        "accounting": accounting,
        "rejected": rejected[:50],
        "notes": notes,
        "evidence_ids": evidence_ids,
        "finding_ids": finding_ids,
        "asset_links": asset_links,
    }
    snapshot_path = results_dir / "network" / "network.json"
    try:
        snapshot_path.parent.mkdir(parents=True, exist_ok=True)
        snapshot_path.write_text(json.dumps(snapshot, indent=2, default=str), encoding="utf-8")
    except OSError as exc:
        logger.warning("network snapshot write failed: %s", exc)

    if db is not None and scan_id is not None:
        try:
            from core.phase_registry import PhaseRecord, PhaseStateMachine

            machine = PhaseStateMachine(
                db, scan_id,
                PhaseRecord(name="network", runner="phases.network.net_orchestrator:run_network"),
            )
            machine.checkpoint({
                "plan_hash": plan_hash,
                "done": {f"{r.ip}:{r.port}": r.state for r in all_results
                         if r.state in ("open", "closed", "filtered")},
                "generated": _now(),
            })
        except Exception as exc:
            logger.debug("network checkpoint failed: %s", exc)

    partial = bool(interrupted or engine.cancelled())
    return {
        "status": "partial" if partial else "completed",
        "phase_state": "partial" if partial else "completed",
        "target": target_config.domain,
        "total": len(open_results),
        "ports": accounting,
        "services": sorted({r.service for r in open_results if r.service}),
        "rejected": rejected[:20],
        "notes": notes,
        "evidence": len(evidence_ids),
        "findings": len(finding_ids),
        "snapshot": str(snapshot_path),
    }


# ---- tool-registry parsers (config/tools.yaml references) --------------------------

def run_naabu(raw: Any) -> list[dict[str, Any]]:
    """Parse naabu ``host:port`` output into port records."""
    text = raw if isinstance(raw, str) else "\n".join(str(x) for x in (raw or []))
    out: list[dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        host, _, port_s = line.rpartition(":")
        try:
            port = int(port_s)
        except ValueError:
            continue
        out.append({"host": host, "port": port, "state": "open", "tool": "naabu"})
    return out


def run_nmap(raw: Any) -> list[dict[str, Any]]:
    """Parse minimal nmap XML (``<port>`` elements) into port records."""
    import re

    text = raw if isinstance(raw, str) else "\n".join(str(x) for x in (raw or []))
    out: list[dict[str, Any]] = []
    for match in re.finditer(r'<port protocol="(\w+)" portid="(\d+)">(.*?)</port>', text, re.S):
        proto, port_s, body = match.groups()
        state = re.search(r'<state state="(\w+)"', body)
        service = re.search(r'<service name="([^"]*)"', body)
        out.append({
            "host": "",
            "port": int(port_s),
            "proto": proto,
            "state": state.group(1) if state else "unknown",
            "service": service.group(1) if service else "",
            "tool": "nmap",
        })
    return out
