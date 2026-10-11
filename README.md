# NEXUS — Unified Bug Bounty Automation Framework (2.0.1)

Modular Python security automation framework for authorized vulnerability discovery, reconnaissance, probing, analysis, hunting, and evidence management.

---

## Architecture Overview

- **NEXUS Executes:** Orchestrates multi-phase workflows (`DISCOVER` → `PROBE` → `ANALYZE` → `HUNT` → `CONTROL` → `SCALE`) with strict scope enforcement, deduplication, and severity scoring.
- **NEMESIS Reasons:** AI-assisted triage, threat intelligence correlation, and autonomous agent loops.
- **Help Me Learn Explains:** Detailed beginner guides, developer glossaries, and methodology references (`docs/`).

---

## Installation

### From Source
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
pip install .
```

### From Built Wheel
```powershell
pip install dist/nexus_framework-2.0.1-py3-none-any.whl
```

---

## First-Run Configuration & Secure GUI Startup

1. Copy configuration templates:
   ```powershell
   Copy-Item config\.keys.env.example config\.keys.env
   ```
2. Configure administrator credentials for the local web GUI via environment variables:
   ```powershell
   $env:NEXUS_GUI_USER = "admin"
   $env:NEXUS_GUI_PASS = "your-secure-password"
   ```
   *(If unset, the GUI fails closed with HTTP 503 Service Unavailable).*
3. Start local GUI / services on loopback (`127.0.0.1` by default):
   ```powershell
   python -m nexus serve
   ```

---

## Scope Configuration & Authorized Testing
NEXUS enforces strict engagement scope validation (`lib/scope_validator.py`). Out-of-scope targets are blocked before any network traffic occurs. Ensure all targets are explicitly listed in `config/nexus.yaml`.

---

## CLI Examples
```powershell
python -m nexus hunt example.com
python -m nexus check-tools
python -m nexus export example.com --format zip
```

---

## Testing & Verification
Verified test suite result: **483 passed, 11 skipped, 0 failed**.
```powershell
python -m pytest tests -q -p no:cacheprovider
```

---

## License
Custom permission-based license (see [LICENSE](LICENSE)).
