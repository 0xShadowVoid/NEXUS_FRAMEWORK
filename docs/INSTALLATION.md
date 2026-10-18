# Installation

## Requirements

| Requirement | Value |
|---|---|
| Python | 3.11+ (developed and tested on 3.13) |
| OS | Windows, Linux, macOS |
| Core dependencies | PyYAML, python-dotenv, requests, croniter, py7zr, fastapi, uvicorn, pydantic (installed automatically) |
| External security tools | Optional; see [TOOLS_REFERENCE.md](TOOLS_REFERENCE.md) |

## Option A — from source (recommended)

```powershell
git clone https://github.com/0xShadowVoid/NEXUS_FRAMEWORK.git
cd NEXUS_FRAMEWORK

python -m venv venv
.\venv\Scripts\Activate.ps1        # Windows
# source venv/bin/activate         # Linux / macOS

pip install --upgrade pip
pip install .
```

`pip install .` installs the `nexus-framework` package (module `nexus`, entry point `nexus`)
plus the bundled configuration (`config/`), NEMESIS skills (`skills/`), and report templates
(`templates/`).

## Option B — from a built wheel

```powershell
pip install dist/nexus_framework-2.0.2-py3-none-any.whl
```

The wheel contains: `nexus.py`, the `lib/`, `core/`, `phases/` packages, and the data
directories `config/`, `skills/`, `templates/`.

## Option C — Docker

```powershell
docker compose up
```

The image is Python 3.11-slim based; external security tools are **not** bundled and must be
added by the operator. Config, results, and logs are expected as bind mounts
(see `docker-compose.yml`).

## Verify the install

```powershell
python -m nexus --version     # NEXUS 2.0.2 "Apex"
python -m nexus doctor        # environment, config, and tool diagnostics
```

If `--version` reports a different version than `VERSION`, you are running a mixed
environment — reinstall in a clean virtual environment (below).

## Clean-venv reinstall (fix a broken/mixed environment)

```powershell
deactivate                              # if a venv is active
Remove-Item -Recurse -Force venv
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install .
python -m nexus --version
```

## Offline machines

The core runtime needs the packages in `requirements.txt` only. Download wheels once on a
connected machine and install locally:

```powershell
pip download -r requirements.txt -d wheels/
# copy wheels/ to the offline machine, then:
pip install --no-index --find-links wheels/ .
```

## Notes

- `config/.keys.env` (secrets) is created by you from `config/.keys.env.example`; it is
  git-ignored and never packaged with values.
- Python 3.13 is used for development; 3.11/3.12 work but are exercised mainly by CI (3.11).
