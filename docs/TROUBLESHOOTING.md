# Troubleshooting

First line of diagnosis for everything:

```powershell
python -m nexus doctor
```

## Common symptoms

| Symptom | Cause | Fix |
|---|---|---|
| `tool not found` in logs | optional external binary not installed | install it, or ignore — NEXUS skips missing tools by design (`check-tools` shows what's available) |
| `scope error: ... out of scope` | host not in the active target's `in_scope` | add it to `in_scope` in `config/nexus.yaml`, or scan the right target key |
| Nothing scanned, no errors | target key typo / empty scope | `doctor` prints resolved targets; verify `in_scope` |
| No alerts sent | webhooks/email unconfigured | fill `DISCORD_*`/`TELEGRAM_*`/SMTP values in `config/.keys.env` |
| AI features inactive | no provider key in pool | `python -m nexus ai-set-key --provider <p> --key <k>`; `ai-keys` to verify |
| GUI returns HTTP 503 | admin credentials unset (fail-closed) | set `NEXUS_GUI_USER` and `NEXUS_GUI_PASS` in the environment before serving the GUI |
| `ConfigError` at startup | malformed YAML or missing config dir | run `doctor`; check the last edit to `config/nexus.yaml` (indentation!) |
| `${VAR}` resolving to empty | variable not set in `.keys.env` or environment | add it to `config/.keys.env`; missing values degrade gracefully, they don't crash |
| `--version` differs from repo `VERSION` | mixed environment (old install + new source) | clean-venv reinstall — see [INSTALLATION.md](INSTALLATION.md) |
| Cloud phase says `skipped` | provider SDKs absent (or `providers: []`) | install SDKs and set `phases.cloud.providers` + per-provider `accounts` allowlists; without them the phase stays off by design |
| Network phase says `skipped` | gate not satisfied | requires extended/deep profile **and** `scope_kind` containing `ip` (explicit IP scope) |
| Findings stuck at `candidate` | not verified yet | run the verify phase (`hunt` does); or `python -m nexus verify <id>` |
| Windows: `python -m nexus` says "No module named nexus" | running outside repo/virtualenv with a Python that excludes cwd | `cd` into the repo root and use the venv, or install with `pip install .` and use the `nexus` script |
| Very old `nexus.db` fails | rare legacy schema | backups first, then let migrations run once on open; report persistent failures as an issue |

## Diagnostics toolkit

| Command | Use |
|---|---|
| `python -m nexus doctor` | environment, config, scope, DB, and tools overview |
| `python -m nexus check-tools` | installed vs missing external binaries |
| `python -m nexus self-scan` | verify no secrets are committed |
| `python -m pytest tests -q -p no:cacheprovider` | full offline test suite |

## Still stuck

Open an issue at <https://github.com/0xShadowVoid/NEXUS_FRAMEWORK> with: `doctor` output
(redact anything private), your OS + Python version, and the exact command you ran.
Security-sensitive problems: follow [SECURITY.md](SECURITY.md) (no public exploit details).
