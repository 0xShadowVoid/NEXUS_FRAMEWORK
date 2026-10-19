"""Run the real-browser integration tests and fail if any of them skip.

``tests/integration/test_pass4_browser_real.py`` needs the optional Playwright
backend (``pip install playwright`` **and** ``playwright install chromium``).
When the backend is absent the whole file skips cleanly — correct for the
default offline run, but useless for an opt-in browser check. This runner
asserts that every test in the file actually executes (0 skipped) and that the
run passes; otherwise it exits non-zero.

Usage::

    python scripts/run_browser_tests.py [extra pytest args]

Any extra arguments are forwarded to pytest (for example, a private
``--basetemp`` on hosts with a shared/denied system temp directory):

    python scripts/run_browser_tests.py --basetemp=%TEMP%\\nexus-browser

Prerequisites, expected runtime, and failure interpretation are documented in
docs/NEXUS_DEPENDENCY_MATRIX.md (section 4).
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

TARGET = "tests/integration/test_pass4_browser_real.py"
REPO = Path(__file__).resolve().parent.parent


def _run_pytest(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "-m", "pytest", TARGET, *args, *sys.argv[1:], "-p", "no:cacheprovider"],
        cwd=REPO,
        capture_output=True,
        text=True,
    )


def _count(output: str, word: str) -> int:
    match = re.search(rf"(\d+) {word}\b", output)
    return int(match.group(1)) if match else 0


def main() -> int:
    collected = _run_pytest("--collect-only", "-q")
    sys.stdout.write(collected.stdout)
    sys.stderr.write(collected.stderr)
    if collected.returncode != 0:
        print("collection failed — is pytest installed?", file=sys.stderr)
        return collected.returncode

    expected = sum(1 for line in collected.stdout.splitlines() if "::" in line)
    if expected == 0:
        print("no real-browser tests were collected", file=sys.stderr)
        return 1

    run = _run_pytest("-q", "-rs")
    sys.stdout.write(run.stdout)
    sys.stderr.write(run.stderr)

    passed = _count(run.stdout, "passed")
    skipped = _count(run.stdout, "skipped")
    failed = _count(run.stdout, "failed") + _count(run.stdout, "error")

    if run.returncode != 0 or failed:
        print(f"real-browser run failed: passed={passed} skipped={skipped} failed={failed}", file=sys.stderr)
        return run.returncode or 1

    if skipped or passed != expected:
        print(
            "real-browser suite must execute every test without skipping "
            f"(expected={expected} passed={passed} skipped={skipped}). "
            "Install the backend: pip install playwright && playwright install chromium",
            file=sys.stderr,
        )
        return 1

    print(f"ok: {passed} real-browser tests executed, 0 skipped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
