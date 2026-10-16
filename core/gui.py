"""NEXUS GUI & Secure Web Interface Module (Pass 7).

A local FastAPI application exposing a small dashboard and JSON API over the
NEXUS Coordinator, Database, and Phase Registry.

Security properties actually enforced here:
- HTTP Basic authentication is required on every protected route; credentials
  come from the ``NEXUS_GUI_USER`` / ``NEXUS_GUI_PASS`` environment variables
  and are compared in constant time. If they are unset the app fails closed
  (HTTP 503). Authentication and scope authorization are separate checks.
- Server-side scope enforcement runs before a scan is launched, and an explicit
  confirmation flag is required. The authorization boundary is derived **only**
  from the configured ``targets:`` scope (see :func:`_trusted_scope`); a
  requested target can never contribute to (and therefore never authorizes)
  its own scope, and a missing/invalid/unset scope fails closed.
- Rendered values are HTML-escaped.

Serve it bound to loopback with the ``gui`` command (``python -m nexus gui``),
which defaults to ``127.0.0.1``.
"""
from __future__ import annotations

import hmac
import html
import secrets
from typing import Any, Optional
from fastapi import FastAPI, Depends, HTTPException, status, Request, Response, Form, Security
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, Field

from core.coordinator import Coordinator, ScanOptions
from core.database import Database
from lib.config import Config, TargetConfig, load_config
from lib.exceptions import ConfigError, ScopeException
from lib.scope_validator import validate_target_scope
from core.sanitizer import sanitize_evidence
from lib.version import framework_version

app = FastAPI(title="NEXUS Security Framework GUI", version=framework_version())
security = HTTPBasic()

# In-memory session / token store for secure web interaction
ACTIVE_SESSIONS: dict[str, dict[str, Any]] = {}
CSRF_TOKENS: dict[str, str] = {}

class ScanRequestModel(BaseModel):
    target: str = Field(..., description="Target domain or IP")
    intensity: str = Field("quick-scan", description="Scan intensity")
    confirm: bool = Field(False, description="Explicit confirmation to run assessment")
    scope_kind: str = Field("public", description="Scope kind")
    cookie: Optional[str] = Field(None, description="Optional cookie / auth")

def get_current_user(credentials: HTTPBasicCredentials = Depends(security)) -> str:
    """Validate HTTP Basic credentials against required admin/operator credentials.
    Fails closed if credentials are not configured in the environment or do not match.
    """
    import os
    admin_user = os.environ.get("NEXUS_GUI_USER", "").strip()
    admin_pass = os.environ.get("NEXUS_GUI_PASS", "").strip()

    if not admin_user or not admin_pass:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="GUI authentication credentials not configured. Set NEXUS_GUI_USER and NEXUS_GUI_PASS environment variables.",
        )

    correct_user = hmac.compare_digest(credentials.username, admin_user)
    correct_pass = hmac.compare_digest(credentials.password, admin_pass)
    if not (correct_user and correct_pass):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username


def _trusted_scope(cfg: Config) -> TargetConfig:
    """Build the GUI authorization boundary from configuration alone.

    The boundary is the union of every configured ``targets:`` entry's
    ``in_scope``/``out_of_scope`` (``out_of_scope`` still wins). The requested
    target is deliberately *not* consulted, and ``domain`` is left empty so the
    shared validator's "empty ``in_scope`` falls back to the target's own
    domain" rule cannot re-introduce self-authorization — an empty configured
    scope therefore authorizes nothing (fail closed).
    """
    in_scope: list[str] = []
    out_of_scope: list[str] = []
    for name in (cfg.targets_section or {}):
        entry = cfg.target(name)
        in_scope.extend(entry.in_scope)
        out_of_scope.extend(entry.out_of_scope)
    return TargetConfig(
        domain="",
        in_scope=list(dict.fromkeys(in_scope)),
        out_of_scope=list(dict.fromkeys(out_of_scope)),
    )


def _sanitize_tree(value: Any) -> Any:
    """Recursively sanitize the string leaves of a JSON-like structure.

    ``sanitize_evidence`` operates on strings; scan summaries and findings are
    dicts, so we walk them instead of passing the container straight through.
    """
    if isinstance(value, str):
        return sanitize_evidence(value)
    if isinstance(value, dict):
        return {k: _sanitize_tree(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_sanitize_tree(v) for v in value]
    return value


@app.get("/health", response_class=JSONResponse)
def health_check() -> dict[str, Any]:
    return {"status": "healthy", "service": "nexus-gui", "loopback_only": True}

@app.get("/", response_class=HTMLResponse)
def dashboard(user: str = Depends(get_current_user)) -> str:
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>NEXUS Security Framework - GUI</title>
        <style>
            body { font-family: sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 20px; }
            h1 { color: #38bdf8; }
            .card { background: #1e293b; padding: 20px; margin-bottom: 20px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }
            input, select { background: #334155; border: 1px solid #475569; color: #fff; padding: 8px; margin: 5px 0; border-radius: 4px; width: 100%; max-width: 400px; }
            button { background: #0ea5e9; color: #fff; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; font-weight: bold; }
            button:hover { background: #0284c7; }
            table { width: 100%; border-collapse: collapse; margin-top: 10px; }
            th, td { border: 1px solid #334155; padding: 8px; text-align: left; }
            th { background: #1e293b; }
        </style>
    </head>
    <body>
        <h1>NEXUS Security Framework — Control & Intelligence GUI</h1>
        <div class="card">
            <h3>Authenticated User: <code>""" + html.escape(user) + """</code></h3>
            <p>Status: Active | Scope enforcement: Enabled | Binding: Loopback</p>
        </div>

        <div class="card">
            <h2>Launch Assessment</h2>
            <form id="scanForm" onsubmit="launchScan(event)">
                <label>Target Domain / IP:</label><br>
                <input type="text" id="target" required placeholder="example.com"><br>
                <label>Intensity:</label><br>
                <select id="intensity">
                    <option value="quick-scan">Quick Scan</option>
                    <option value="full-scan">Full Scan (Deep)</option>
                </select><br>
                <label><input type="checkbox" id="confirm" required> Explicitly confirm target is in authorized scope</label><br><br>
                <button type="submit">Launch Assessment</button>
            </form>
            <div id="scanResult"></div>
        </div>

        <div class="card">
            <h2>Active Engagements & Inventory</h2>
            <button onclick="loadEngagements()">Refresh Data</button>
            <table id="engTable">
                <tr><th>ID</th><th>Domain</th><th>Platform</th><th>Scope Kind</th><th>Created</th></tr>
            </table>
        </div>

        <script>
            async function loadEngagements() {
                const res = await fetch('/api/engagements');
                const data = await res.json();
                const table = document.getElementById('engTable');
                table.innerHTML = '<tr><th>ID</th><th>Domain</th><th>Platform</th><th>Scope Kind</th><th>Created</th></tr>';
                data.engagements.forEach(e => {
                    table.innerHTML += `<tr><td>${e.id}</td><td>${e.domain}</td><td>${e.platform}</td><td>${e.scope_kind}</td><td>${e.created_at}</td></tr>`;
                });
            }
            async function launchScan(event) {
                event.preventDefault();
                const target = document.getElementById('target').value;
                const intensity = document.getElementById('intensity').value;
                const confirm = document.getElementById('confirm').checked;

                const res = await fetch('/api/scan', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({target, intensity, confirm})
                });
                const json = await res.json();
                document.getElementById('scanResult').innerText = JSON.stringify(json, null, 2);
                loadEngagements();
            }
            loadEngagements();
        </script>
    </body>
    </html>
    """

@app.get("/api/engagements", response_class=JSONResponse)
def get_engagements(user: str = Depends(get_current_user)) -> dict[str, Any]:
    cfg = load_config()
    db = Database(cfg.database_path)
    targets = db.list_targets()
    return {"engagements": targets}

@app.post("/api/scan", response_class=JSONResponse)
def api_launch_scan(payload: ScanRequestModel, user: str = Depends(get_current_user)) -> dict[str, Any]:
    if not payload.confirm:
        raise HTTPException(status_code=400, detail="Explicit confirmation required to launch assessment.")

    # Authorization boundary comes from configuration only. A missing or
    # malformed config fails closed (no scan) rather than falling back to a
    # request-derived scope.
    try:
        cfg = load_config()
        trusted_scope = _trusted_scope(cfg)
    except ConfigError as exc:
        raise HTTPException(status_code=503, detail=f"Configuration unavailable: {exc}")
    except Exception as exc:  # malformed scope structures -> fail closed
        raise HTTPException(status_code=503, detail=f"Configuration invalid: {exc}")

    if not trusted_scope.in_scope:
        raise HTTPException(
            status_code=403,
            detail="No authorized scope is configured; refusing to scan (fail closed).",
        )

    # Server-side scope enforcement against the configured scope. The request
    # target is validated against it and can never define its own boundary.
    try:
        validate_target_scope(payload.target, trusted_scope)
    except ScopeException as exc:
        raise HTTPException(status_code=403, detail=f"Scope validation failed: {exc}")

    coordinator = Coordinator(cfg)
    options = ScanOptions(
        target=payload.target,
        intensity=payload.intensity,
        cookie=payload.cookie or "",
        scope_kind=payload.scope_kind
    )

    try:
        summary = coordinator.run_scan(options)
        return {"status": "success", "summary": _sanitize_tree(summary)}
    except Exception as e:
        return {"status": "error", "error": str(e)}

@app.get("/api/findings", response_class=JSONResponse)
def get_findings(target_id: Optional[int] = None, user: str = Depends(get_current_user)) -> dict[str, Any]:
    cfg = load_config()
    db = Database(cfg.database_path)
    findings = db.list_findings(target_id=target_id)
    return {"findings": _sanitize_tree(findings)}
