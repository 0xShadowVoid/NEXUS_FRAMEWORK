# Secret Scanning & Pre-Commit Hook (roadmap H1)

NEXUS ships an offline, dependency-free secret scanner and a Git pre-commit
hook that blocks a commit when **staged** content contains a likely credential.

## Scanner

`lib/selfscan.py` (working tree) and `lib/secretscan.py` (staged index + commit
history) share one set of regex signatures — no external tools, no network:

| Signature | Example shape |
|---|---|
| `discord_webhook` | `https://discord.com/api/webhooks/<id>/<token>` |
| `telegram_bot_token` | `<8-12 digits>:<30+ chars>` |
| `openai_key` | `sk-…` |
| `github_token` | `gh[pousr]_…` |
| `aws_access_key` | `AKIA…` |
| `google_api_key` | `AIza…` |
| `slack_token` | `xox[baprs]-…` |
| `private_key` | `-----BEGIN … PRIVATE KEY-----` |
| `generic_bearer` | `Authorization: Bearer …` |

Findings are always **masked** (`…******`); a raw secret is never written to
stdout, logs, or test output.

## CLI

```bash
python -m nexus secretscan --staged              # scan the git index (default)
python -m nexus secretscan --history             # scan committed history (all refs)
python -m nexus secretscan --tree [PATH]         # scan the working tree
python -m nexus secretscan --staged --json       # machine-readable report
```

Exit codes: **0** clean, **1** findings (blocking), **2** scan error
(**fail-closed** — never treated as clean). `--staged` scans the index, so
partially staged and unstaged changes are handled correctly: an unstaged secret
is never scanned, and no finding ever suggests it was.

## Install / update the hook

Hooks live in `scripts/hooks/` (committed, versioned) and are activated per
checkout with one reproducible command:

```bash
python -m nexus hooks install     # sets core.hooksPath -> scripts/hooks
python -m nexus hooks status      # show whether the hook is armed
python -m nexus hooks uninstall   # disable it (unsets core.hooksPath)
```

Or by hand (any OS, including Windows Git Bash):

```bash
git config core.hooksPath "$(pwd)/scripts/hooks"
```

Update: pull the repo — the hook is a normal tracked file, so updates propagate
with no re-install. `core.hooksPath` is **local** config (never committed), so
each developer opts in once.

The hook works from any repository that points `core.hooksPath` at this
checkout: it resolves the NEXUS install from its own path and scans the
repository being committed.

## What the hook does

1. Finds a working Python 3.11+ interpreter (`NEXUS_PYTHON`, then
   `python3`/`python`/`py -3` — each is *executed* to prove it works; a broken
   Microsoft Store `python3` alias is skipped).
2. Runs `python -m nexus secretscan --staged` against the repository being
   committed.
3. Blocks the commit (non-zero) on any finding or scan error, with a masked
   report and remediation steps.

If the interpreter, NEXUS, or git cannot be resolved, the commit is **blocked**
(fail-closed) rather than allowed. The hook never stages or modifies files.

Bypass for a single, reviewed commit: `git commit --no-verify`.

## False-positive exceptions

Add reviewed exceptions to `.nexus-secret-allowlist` at the repo root
(committed, so the exceptions stay auditable):

```
# <path-glob>[:<kind>]    # why this is not a secret
docs/examples/*            # documentation placeholders only
tools/fixtures/keys.txt:aws_access_key   # synthetic AWS key in a fixture
```

* `path-glob` is matched with `fnmatch`; a trailing `/` matches a directory.
* `kind` (optional) scopes the exception to one signature.
* The `# reason` is **required** — an entry without one is ignored and reported
  as invalid, so an unreviewed exception can never hide a secret.

Files under `tests/`, `tests/`-like dirs (`test`, `fixtures`) and names
containing `example`/`sample`/`placeholder`/`template` are skipped by the
scanner policy (they legitimately hold fake markers).

## CI

`.github/workflows/ci.yml` runs on every push and pull request:

* `python nexus.py self-scan` — blocks secrets committed in the tree;
* `python nexus.py secretscan --history` — scans proposed changes across all
  refs (full history is fetched);
* `sh -n scripts/hooks/pre-commit` — syntax-checks the hook.

## Limitations

* Regex signatures catch **shaped** credentials, not high-entropy strings in
  arbitrary formats; they are a safety net, not a substitute for review or
  secret rotation.
* History scanning reads added lines per commit (bounded by `--max-commits`);
  it is practical for normal repositories but not for enormous monorepos.
* Binary and >2 MB files are skipped (reported in the JSON `skipped` list).
* The hook is opt-in per clone (`core.hooksPath` is local config); enable it in
  every checkout you commit from.
