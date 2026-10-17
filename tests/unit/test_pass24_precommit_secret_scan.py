"""Unit tests for the pre-commit secret scan (roadmap H1).

Uses a throwaway git repository and the real hook script end-to-end. All
credentials are synthetic. No network access.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from lib.secretscan import (
    SecretScanError,
    load_allowlist,
    scan_history,
    scan_staged,
)
from lib.selfscan import is_allowlisted, scan_text, scan_tree

GIT = shutil.which("git")
PY = sys.executable
NEXUS_ROOT = Path(__file__).resolve().parents[2]
HOOK_DIR = (NEXUS_ROOT / "scripts" / "hooks").as_posix()

pytestmark = pytest.mark.skipif(GIT is None, reason="git is required")

# Synthetic, non-functional credential (openai_key signature: sk- + 20+ chars).
SECRET = "sk-abcdefghijklmnopqrstuvwxyz0123456789ABCD"


# --- helpers --------------------------------------------------------------


def _env() -> dict[str, str]:
    env = dict(os.environ)
    env["NEXUS_PYTHON"] = PY.replace("\\", "/")   # deterministic interpreter
    return env


def _run(args, cwd, env=None) -> subprocess.CompletedProcess:
    return subprocess.run(args, cwd=str(cwd), capture_output=True, text=True,
                          env=env or _env(), check=False)


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return _run([GIT, *args], repo)


def _cli(repo: Path, *args: str, env=None) -> subprocess.CompletedProcess:
    return _run([PY, "-m", "nexus", *args, "--root", str(repo)], NEXUS_ROOT, env=env)


def make_repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.email", "t@t.t")
    _git(repo, "config", "user.name", "t")
    _git(repo, "config", "commit.gpgsign", "false")
    _git(repo, "config", "core.hooksPath", HOOK_DIR)
    return repo


def write(repo: Path, name: str, content: str) -> None:
    (repo / name).write_text(content, encoding="utf-8")


def commit(repo: Path, *files: str, message: str = "c", no_verify: bool = False):
    _git(repo, "add", *files)
    args = ["commit", "-m", message]
    if no_verify:
        args.append("--no-verify")
    return _run([GIT, *args], repo)


def _combined(proc: subprocess.CompletedProcess) -> str:
    return f"{proc.stdout}\n{proc.stderr}"


# --- end-to-end hook ------------------------------------------------------


def test_clean_staged_content_commits(tmp_path):
    repo = make_repo(tmp_path)
    write(repo, "clean.py", "print('hello')\n")
    proc = commit(repo, "clean.py", message="first clean commit")
    assert proc.returncode == 0
    assert _git(repo, "log", "--oneline").stdout.strip() != ""


def test_staged_secret_blocks_commit_and_redacts(tmp_path):
    repo = make_repo(tmp_path)
    write(repo, "leak.py", f'KEY = "{SECRET}"\n')
    proc = commit(repo, "leak.py")
    assert proc.returncode != 0
    out = _combined(proc)
    assert SECRET not in out                      # redaction
    assert "openai_key" in out
    assert "blocked" in out
    assert _git(repo, "log", "--oneline").stdout.strip() == ""   # no commit


def test_unstaged_secret_is_not_scanned_or_claimed(tmp_path):
    repo = make_repo(tmp_path)
    write(repo, "clean.py", "print('hi')\n")
    _git(repo, "add", "clean.py")
    write(repo, "untracked_leak.py", f'K = "{SECRET}"\n')   # never staged
    result = scan_staged(repo, allowlist_path=repo / ".nexus-secret-allowlist")
    assert result["mode"] == "staged"
    assert result["findings"] == []
    assert "untracked_leak.py" not in result["scanned"]
    assert SECRET not in str(result)              # nothing raw leaked
    assert _cli(repo, "secretscan", "--staged").returncode == 0


def test_partially_staged_scans_only_index(tmp_path):
    repo = make_repo(tmp_path)
    write(repo, "app.py", "print('v1')\n")
    _git(repo, "add", "app.py")                   # index holds clean v1
    write(repo, "app.py", f'KEY = "{SECRET}"\n')  # working tree holds the secret
    assert _cli(repo, "secretscan", "--staged").returncode == 0    # index is clean
    _git(repo, "add", "app.py")                   # now stage the secret
    blocked = _cli(repo, "secretscan", "--staged")
    assert blocked.returncode == 1
    assert SECRET not in _combined(blocked)


def test_renamed_file_is_scanned(tmp_path):
    repo = make_repo(tmp_path)
    write(repo, "old.py", "print('ok')\n")
    commit(repo, "old.py")
    _git(repo, "mv", "old.py", "new.py")
    write(repo, "new.py", f'KEY = "{SECRET}"\n')
    _git(repo, "add", "new.py")
    result = scan_staged(repo)
    assert any(f["file"] == "new.py" for f in result["findings"])


def test_deleted_file_is_ignored(tmp_path):
    repo = make_repo(tmp_path)
    write(repo, "gone.py", "print('x')\n")
    commit(repo, "gone.py")
    _git(repo, "rm", "gone.py")
    result = scan_staged(repo)
    assert result["findings"] == []


def test_binary_and_oversized_files_skipped(tmp_path):
    repo = make_repo(tmp_path)
    (repo / "blob.dat").write_bytes(f"K={SECRET}".encode() + b"\x00\x01\x02")
    write(repo, "big.txt", f'K = "{SECRET}"\n' + "x" * (3 * 1024 * 1024))
    _git(repo, "add", "blob.dat", "big.txt")
    result = scan_staged(repo)
    assert result["findings"] == []
    reasons = {s["path"]: s["reason"] for s in result["skipped"]}
    assert reasons["blob.dat"] == "binary content"
    assert reasons["big.txt"] == "oversized"


# --- redaction & allowlist exceptions -------------------------------------


def test_redaction_masks_secret_in_stdout(tmp_path):
    repo = make_repo(tmp_path)
    write(repo, "leak.py", f'TOKEN = "{SECRET}"\n')
    _git(repo, "add", "leak.py")
    proc = _cli(repo, "secretscan", "--staged")
    out = _combined(proc)
    assert proc.returncode == 1
    assert SECRET not in out
    assert "openai_key" in out


def test_allowlist_exception_with_reason_suppresses(tmp_path):
    repo = make_repo(tmp_path)
    write(repo, ".nexus-secret-allowlist", "leak.py:openai_key   # reviewed fixture only\n")
    write(repo, "leak.py", f'KEY = "{SECRET}"\n')
    _git(repo, "add", "leak.py")
    result = scan_staged(repo)
    assert result["findings"] == []
    assert len(result["suppressed"]) == 1
    assert result["suppressed"][0]["reason"] == "reviewed fixture only"


def test_allowlist_entry_without_reason_is_invalid(tmp_path):
    repo = make_repo(tmp_path)
    write(repo, ".nexus-secret-allowlist", "leak.py:openai_key\n")   # no reason
    write(repo, "leak.py", f'KEY = "{SECRET}"\n')
    _git(repo, "add", "leak.py")
    result = scan_staged(repo)
    assert len(result["findings"]) == 1                 # not suppressed
    assert len(result["allowlist"]["invalid"]) == 1


def test_allowlist_kind_scoping(tmp_path):
    repo = make_repo(tmp_path)
    write(repo, ".nexus-secret-allowlist", "x.py:aws_access_key   # only aws allowed\n")
    write(repo, "x.py", f'KEY = "{SECRET}"\n')          # this is an openai_key
    _git(repo, "add", "x.py")
    result = scan_staged(repo)
    assert len(result["findings"]) == 1                 # kind mismatch -> not suppressed


# --- fail-closed ----------------------------------------------------------


def test_missing_interpreter_fails_closed(tmp_path):
    repo = make_repo(tmp_path)
    write(repo, "clean.py", "print('hi')\n")
    _git(repo, "add", "clean.py")
    env = dict(os.environ)
    env.pop("NEXUS_PYTHON", None)
    env["PATH"] = str(Path(GIT).parent)                 # git only, no python/py
    proc = _run([GIT, "commit", "-m", "c"], repo, env=env)
    assert proc.returncode != 0
    assert "NEXUS pre-commit" in _combined(proc)


def test_scan_outside_repo_fails_closed(tmp_path):
    not_a_repo = tmp_path / "plain"
    not_a_repo.mkdir()
    env = _env()
    env["GIT_CEILING_DIRECTORIES"] = str(tmp_path)   # don't discover a parent repo
    proc = _cli(not_a_repo, "secretscan", "--staged", env=env)
    assert proc.returncode == 2
    assert "fail-closed" in _combined(proc).lower()


def test_scan_history_outside_repo_errors(tmp_path, monkeypatch):
    plain = tmp_path / "plain"
    plain.mkdir()
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))
    with pytest.raises(SecretScanError):
        scan_history(plain)


# --- history scan ---------------------------------------------------------


def test_history_scan_detects_committed_secret(tmp_path):
    repo = make_repo(tmp_path)
    write(repo, "base.txt", "ok\n")
    commit(repo, "base.txt")
    write(repo, "leaked.py", f'KEY = "{SECRET}"\n')
    commit(repo, "leaked.py", no_verify=True)           # bypass to seed history
    result = scan_history(repo)
    assert any(f["file"] == "leaked.py" for f in result["findings"])
    assert SECRET not in str(result)


def test_history_scan_ignores_test_fixtures(tmp_path):
    repo = make_repo(tmp_path)
    (repo / "tests").mkdir()
    (repo / "tests" / "fixture.py").write_text(f'K = "{SECRET}"\n', encoding="utf-8")
    commit(repo, "tests/fixture.py", no_verify=True)
    assert scan_history(repo)["findings"] == []


# --- self-scan compatibility ----------------------------------------------


def test_selfscan_still_works_and_shares_core(tmp_path):
    write(tmp_path, "app.py", 'HOOK = "https://discord.com/api/webhooks/123456789/abcdefghijklmnop"\n')
    findings = scan_tree(tmp_path)
    assert any(f["kind"] == "discord_webhook" for f in findings)
    # scan_text is the shared core used by the tree scan.
    assert scan_text('K = "sk-abcdefghijklmnopqrstuvwxyz0123"', path="x")[0]["kind"] == "openai_key"
    assert is_allowlisted(tmp_path / "tests" / "t.py", tmp_path) is True


# --- hooks install / status / uninstall -----------------------------------


def test_hooks_install_status_uninstall(tmp_path):
    repo = make_repo(tmp_path)
    _git(repo, "config", "--unset", "core.hooksPath")   # start clean

    install = _run([PY, "-m", "nexus", "hooks", "install", "--repo", str(repo)], NEXUS_ROOT)
    assert install.returncode == 0
    armed = _git(repo, "config", "--get", "core.hooksPath").stdout.strip()
    assert armed == HOOK_DIR

    status = _run([PY, "-m", "nexus", "hooks", "status", "--repo", str(repo)], NEXUS_ROOT)
    assert '"armed": true' in status.stdout

    uninstall = _run([PY, "-m", "nexus", "hooks", "uninstall", "--repo", str(repo)], NEXUS_ROOT)
    assert uninstall.returncode == 0
    assert _git(repo, "config", "--get", "core.hooksPath").returncode != 0


def test_load_allowlist_parsing(tmp_path):
    path = tmp_path / "al"
    path.write_text(
        "# comment\n\n"
        "docs/examples/*   # placeholders\n"
        "fixtures/keys.txt:aws_access_key  # synthetic\n"
        "bad_entry_no_reason\n",
        encoding="utf-8",
    )
    al = load_allowlist(path)
    assert len(al.entries) == 2
    assert al.entries[1].kind == "aws_access_key"
    assert len(al.invalid) == 1
