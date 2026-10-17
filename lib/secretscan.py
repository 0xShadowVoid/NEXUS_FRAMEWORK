"""Staged-content & history secret scanning (roadmap H1).

Reuses the detection signatures in :mod:`lib.selfscan` (no external
dependency, works offline) and adds the pieces a pre-commit hook needs:

* scan the **staged index** (``git ls-files -s`` + ``git cat-file`` blobs),
  not the working tree — so partially staged and unstaged changes are handled
  correctly and an unstaged secret is never mistaken for a scanned one;
* handle deleted/renamed/symlink/submodule/binary/oversized files safely;
* a documented, auditable exception file (:data:`DEFAULT_ALLOWLIST_NAME`);
* masked output (a raw secret is never printed) and **fail-closed** errors.

Fail-closed means: a git/scan failure is reported as an error (non-zero) rather
than being treated as "clean". The scanner never stages or modifies files.
"""
from __future__ import annotations

import fnmatch
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from lib.logger import get_logger
from lib.selfscan import (
    BINARY_SUFFIXES,
    MAX_FILE_BYTES,
    is_allowlisted,
    scan_text,
)

logger = get_logger("secretscan")

DEFAULT_ALLOWLIST_NAME = ".nexus-secret-allowlist"
_BINARY_SNIFF_BYTES = 8000
_GIT_TIMEOUT = 60


class SecretScanError(RuntimeError):
    """A scan could not be completed (git failure, bad repo, etc.)."""


@dataclass
class AllowEntry:
    """One reviewed exception from the allowlist file."""

    pattern: str
    kind: str = ""
    reason: str = ""
    line: int = 0

    def matches(self, finding: dict) -> bool:
        if self.kind and self.kind != finding.get("kind"):
            return False
        path = str(finding.get("file", ""))
        if fnmatch.fnmatch(path, self.pattern) or path == self.pattern:
            return True
        return path.startswith(self.pattern.rstrip("/") + "/")


@dataclass
class Allowlist:
    """Parsed allowlist: valid exceptions + rejected (reason-less) entries."""

    path: str = ""
    entries: list[AllowEntry] = field(default_factory=list)
    invalid: list[dict] = field(default_factory=list)

    def suppress(self, findings: list[dict]) -> tuple[list[dict], list[dict]]:
        kept: list[dict] = []
        suppressed: list[dict] = []
        for finding in findings:
            entry = next((e for e in self.entries if e.matches(finding)), None)
            if entry is None:
                kept.append(finding)
            else:
                suppressed.append({**finding, "exception": entry.pattern, "reason": entry.reason})
        return kept, suppressed


def _git(root: Path, args: list[str], *, binary: bool = False) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(
            ["git", *args], cwd=str(root), capture_output=True, text=not binary, timeout=_GIT_TIMEOUT
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SecretScanError(f"git {' '.join(args)} failed: {exc.__class__.__name__}") from exc


def find_repo_root(start: Path | None = None) -> Path:
    """Return the git work-tree root, or raise :class:`SecretScanError`."""
    here = Path(start or Path.cwd())
    proc = _git(here, ["rev-parse", "--show-toplevel"])
    if proc.returncode != 0:
        detail = (proc.stderr or "").strip() or "not a git repository"
        raise SecretScanError(detail)
    root = (proc.stdout or "").strip()
    if not root:
        raise SecretScanError("git returned an empty repository root")
    return Path(root)


def load_allowlist(path: Path | None = None) -> Allowlist:
    """Parse the exception file. Entries require a ``# reason`` (auditable)."""
    result = Allowlist()
    if path is None or not Path(path).is_file():
        return result
    result.path = str(path)
    for lineno, raw in enumerate(Path(path).read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        entry, _, reason = line.partition("#")
        entry, reason = entry.strip(), reason.strip()
        pattern, _, kind = entry.partition(":")
        pattern, kind = pattern.strip(), kind.strip()
        if not pattern or not reason:
            result.invalid.append({"line": lineno, "entry": entry,
                                   "error": "missing reason (add ' # why this is not a secret')"})
            continue
        result.entries.append(AllowEntry(pattern=pattern, kind=kind, reason=reason, line=lineno))
    return result


def _index_entries(root: Path) -> dict[str, tuple[str, str]]:
    """Map staged path -> (mode, blob-sha) from ``git ls-files -s``."""
    proc = _git(root, ["ls-files", "-s", "-z"])
    if proc.returncode != 0:
        raise SecretScanError((proc.stderr or "git ls-files failed").strip())
    entries: dict[str, tuple[str, str]] = {}
    for record in (proc.stdout or "").split("\0"):
        if not record:
            continue
        meta, _, path = record.partition("\t")
        bits = meta.split()
        if len(bits) >= 3:
            entries[path] = (bits[0], bits[1])
    return entries


def _staged_paths(root: Path) -> list[str]:
    """Paths changed in the index vs HEAD (added/copied/modified/renamed)."""
    proc = _git(root, ["diff", "--cached", "--name-only", "-z",
                       "--diff-filter=ACMR", "-M", "-C"])
    if proc.returncode != 0:
        raise SecretScanError((proc.stderr or "git diff --cached failed").strip())
    return [p for p in (proc.stdout or "").split("\0") if p]


def _read_blob(root: Path, sha: str) -> bytes:
    proc = _git(root, ["cat-file", "blob", sha], binary=True)
    if proc.returncode != 0:
        raise SecretScanError(f"git cat-file blob {sha[:12]} failed")
    return proc.stdout or b""


def scan_staged(root: Path | None = None, *, allowlist_path: Path | None = None) -> dict:
    """Scan the staged index; returns findings + provenance of what was scanned."""
    root = Path(root) if root else find_repo_root()
    allowlist = load_allowlist(allowlist_path if allowlist_path is not None
                               else root / DEFAULT_ALLOWLIST_NAME)
    index = _index_entries(root)
    scanned: list[str] = []
    skipped: list[dict] = []
    raw: list[dict] = []

    for path in _staged_paths(root):
        info = index.get(path)
        if info is None:
            skipped.append({"path": path, "reason": "not in index (deleted?)"})
            continue
        mode, sha = info
        if mode == "120000":
            skipped.append({"path": path, "reason": "symlink"})
            continue
        if mode == "160000":
            skipped.append({"path": path, "reason": "submodule"})
            continue
        if not mode.startswith("100"):
            skipped.append({"path": path, "reason": f"mode {mode}"})
            continue
        if Path(path).suffix.lower() in BINARY_SUFFIXES or is_allowlisted(Path(root / path), root):
            skipped.append({"path": path, "reason": "binary/allowlisted path"})
            continue
        blob = _read_blob(root, sha)
        if len(blob) > MAX_FILE_BYTES:
            skipped.append({"path": path, "reason": "oversized"})
            continue
        if b"\x00" in blob[:_BINARY_SNIFF_BYTES]:
            skipped.append({"path": path, "reason": "binary content"})
            continue
        scanned.append(path)
        raw.extend(scan_text(blob.decode("utf-8", errors="replace"), path=path))

    findings, suppressed = allowlist.suppress(raw)
    logger.info("secretscan: staged=%d scanned=%d findings=%d suppressed=%d",
                len(_staged_paths(root)), len(scanned), len(findings), len(suppressed))
    return {
        "mode": "staged", "root": str(root), "findings": findings, "suppressed": suppressed,
        "scanned": sorted(scanned), "skipped": skipped,
        "allowlist": {"path": allowlist.path, "entries": len(allowlist.entries),
                      "invalid": allowlist.invalid},
    }


def _scan_patch(root: Path, text: str) -> list[dict]:
    """Scan the added lines of a unified diff, tracking the current path.

    Only ``+`` lines are inspected, and files under the fixture/example policy
    (:func:`lib.selfscan.is_allowlisted`) are skipped - so history scanning
    uses the same allowlist as the working-tree scan.
    """
    findings: list[dict] = []
    path = ""
    for line in text.splitlines():
        if line.startswith("+++ "):
            target = line[4:].strip()
            path = "" if target == "/dev/null" else (target[2:] if target.startswith("b/") else target)
            continue
        if line.startswith(("--- ", "diff --git ", "@@", "index ", "new file", "deleted file",
                            "similarity index", "rename ", "old mode", "new mode")):
            continue
        if not path or not line.startswith("+"):
            continue
        try:
            if is_allowlisted(Path(root) / path, root):
                continue
        except (ValueError, OSError):
            pass
        findings.extend(scan_text(line[1:], path=path))
    return findings


def scan_history(root: Path | None = None, *, max_commits: int = 0,
                 allowlist_path: Path | None = None) -> dict:
    """Scan committed history (all refs). ``max_commits=0`` means no limit."""
    root = Path(root) if root else find_repo_root()
    allowlist = load_allowlist(allowlist_path if allowlist_path is not None
                               else root / DEFAULT_ALLOWLIST_NAME)
    proc = _git(root, ["rev-list", "--all"])
    if proc.returncode != 0:
        raise SecretScanError((proc.stderr or "git rev-list failed").strip())
    commits = [c for c in (proc.stdout or "").splitlines() if c]
    if max_commits and max_commits > 0:
        commits = commits[:max_commits]

    raw: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    for sha in commits:
        show = _git(root, ["show", "--no-color", "--format=", "--unified=0", sha], binary=True)
        if show.returncode != 0:
            raise SecretScanError(f"git show {sha[:12]} failed")
        text = (show.stdout or b"").decode("utf-8", errors="replace")
        for finding in _scan_patch(root, text):
            key = (finding["file"], finding["kind"], finding["detail"])
            if key not in seen:
                seen.add(key)
                raw.append(finding)

    findings, suppressed = allowlist.suppress(raw)
    logger.info("secretscan: history commits=%d findings=%d suppressed=%d",
                len(commits), len(findings), len(suppressed))
    return {
        "mode": "history", "root": str(root), "commits": len(commits),
        "findings": findings, "suppressed": suppressed, "scanned": [], "skipped": [],
        "allowlist": {"path": allowlist.path, "entries": len(allowlist.entries),
                      "invalid": allowlist.invalid},
    }


def format_findings(report: dict) -> str:
    """Human-readable, masked summary (never contains a raw secret value)."""
    lines = [f"NEXUS secret scan ({report.get('mode')}): {len(report.get('findings', []))} finding(s)"]
    for finding in report.get("findings", []):
        lines.append(f"  {finding.get('file')}:{finding.get('line')}: "
                     f"{finding.get('kind')} — {finding.get('detail')}")
    if report.get("suppressed"):
        lines.append(f"  ({len(report['suppressed'])} suppressed by "
                     f"{report.get('allowlist', {}).get('path') or DEFAULT_ALLOWLIST_NAME})")
    if report.get("allowlist", {}).get("invalid"):
        lines.append(f"  WARNING: {len(report['allowlist']['invalid'])} allowlist entr(ies) ignored "
                     "(missing reason)")
    return "\n".join(lines)
