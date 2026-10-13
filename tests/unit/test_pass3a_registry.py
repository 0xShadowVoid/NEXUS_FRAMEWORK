"""PASS 3A focused tests: ToolRegistry → real execution (offline/local)."""

from __future__ import annotations

import shutil

import time

from pathlib import Path

import pytest

from lib.config import load_config

from lib.tool_registry import ToolEntry, ToolRegistry, get_registry

from phases.probe import probe_orchestrator

from phases.probe.tool_runner import ToolRunner

CONFIG_DIR = Path(__file__).resolve().parent.parent.parent / "config"

class _FakeCfg:

    """Minimal Config stand-in for provider-availability checks."""

    def __init__(self, providers=()):

        self._providers = set(providers)

    def provider_available(self, provider):

        return provider in self._providers

def _reg(*entries: ToolEntry) -> ToolRegistry:

    return ToolRegistry(entries={e.name: e for e in entries})

# -- resolve() gates ----------------------------------------------------------

def test_resolve_profile_skip_only_and_target_tools():

    reg = get_registry(reload=True)

    quick = {e.name for e in reg.resolve(intensity="quick-scan")}

    deep = {e.name for e in reg.resolve(intensity="full-scan")}

    assert {"nuclei", "dalfox"} <= quick

    assert quick <= deep  # deep profile is a superset by design

    no_nuclei = {e.name for e in reg.resolve(intensity="quick-scan", skip=["nuclei"])}

    assert "nuclei" not in no_nuclei

    only = {e.name for e in reg.resolve(intensity="quick-scan", only=["dalfox"])}

    assert only == {"dalfox"}

    targeted = {e.name for e in reg.resolve(intensity="quick-scan", target_tools=["nuclei"])}

    assert targeted == {"nuclei"}

def test_resolve_key_missing_provider_excluded_only_with_cfg():

    reg = get_registry()

    chaos = reg.get("chaos")

    assert chaos is not None and chaos.requires_provider

    assert "chaos" in {e.name for e in reg.resolve(intensity="full-scan")}

    # with cfg but no key → truthfully excluded

    assert "chaos" not in {

        e.name for e in reg.resolve(intensity="full-scan", cfg=_FakeCfg())

    }

    # with cfg and the key → included

    assert "chaos" in {

        e.name for e in reg.resolve(intensity="full-scan", cfg=_FakeCfg(["chaos"]))

    }

    assert reg.availability(chaos, _FakeCfg()) == "key-missing"

    # With the key set the gate opens; the result then reflects binary

    # presence truthfully ("installed" or "missing", never "key-missing").

    assert reg.availability(chaos, _FakeCfg(["chaos"])) != "key-missing"

def test_unresolved_dependencies_reported():

    sub = ToolEntry(name="sub", phase="discover")

    dep = ToolEntry(name="dep", phase="discover", requires_tools=("sub",))

    reg = ToolRegistry(entries={"sub": sub, "dep": dep})

    assert reg.unresolved_dependencies([sub, dep]) == {}

    assert reg.unresolved_dependencies([dep]) == {"dep": ["sub"]}

# -- ToolRunner choke point ---------------------------------------------------

def test_runner_skips_disabled_tool(monkeypatch):

    disabled = ToolEntry(name="not-a-real-tool", enabled=False)

    monkeypatch.setattr("lib.tool_registry.get_registry", lambda *a, **k: _reg(disabled))

    res = ToolRunner(timeout=5).run("not-a-real-tool", ["--help"])

    assert res.status == "skipped"  # blocked before PATH lookup / execution

def test_runner_skips_key_missing_provider_when_cfg_present(monkeypatch):

    needs_key = ToolEntry(name="definitely-missing-tool", requires_provider="shodan")

    monkeypatch.setattr("lib.tool_registry.get_registry", lambda *a, **k: _reg(needs_key))

    res = ToolRunner(timeout=5, cfg=_FakeCfg()).run("definitely-missing-tool", ["-h"])

    assert res.status == "skipped"  # key-missing → truthful skip

    # Without cfg the provider check is skipped → legacy not_found behaviour

    res2 = ToolRunner(timeout=5).run("definitely-missing-tool", ["-h"])

    assert res2.status == "not_found"

def test_runner_honours_registry_timeout(monkeypatch):

    if not shutil.which("python"):

        pytest.skip("python not on PATH")

    monkeypatch.setattr(

        "lib.tool_registry.get_registry",

        lambda *a, **k: _reg(ToolEntry(name="python", timeout=1)),

    )

    runner = ToolRunner(timeout=30)  # runner default would allow 30s

    started = time.monotonic()

    res = runner.run("python", ["-c", "import time; time.sleep(8)"])

    elapsed = time.monotonic() - started

    assert res.status == "timeout"

    assert elapsed < 6  # registry timeout (1s) won over the runner default

def test_runner_honours_registry_retries_in_deep_mode(monkeypatch):

    if not shutil.which("python"):

        pytest.skip("python not on PATH")

    monkeypatch.setattr(

        "lib.tool_registry.get_registry",

        lambda *a, **k: _reg(ToolEntry(name="python", retries=2)),

    )

    runner = ToolRunner(timeout=10, deep_mode=True)  # legacy deep default is 3

    res = runner.run("python", ["-c", "import sys; sys.exit(3)"])

    assert res.status == "error"

    assert res.attempts == 2  # registry value overrides the ×3 default

def test_runner_legacy_attempts_without_registry_entry(monkeypatch):

    if not shutil.which("python"):

        pytest.skip("python not on PATH")

    monkeypatch.setattr("lib.tool_registry.get_registry", lambda *a, **k: _reg())

    runner = ToolRunner(timeout=10, deep_mode=True)

    res = runner.run("python", ["-c", "import sys; sys.exit(3)"])

    assert res.attempts == 3  # legacy deep retry contract preserved

# -- probe selection ----------------------------------------------------------

def test_probe_registry_gate_controls_nuclei_branch(monkeypatch, tmp_path):

    cfg = load_config(CONFIG_DIR)

    tc = cfg.target("example.com")

    calls = {"nuclei": 0}

    def sentinel(*args, **kwargs):

        calls["nuclei"] += 1

        return []

    monkeypatch.setattr("phases.probe.probe_orchestrator.run_nuclei", sentinel)

    # 1) nuclei disabled in the registry → branch never runs

    monkeypatch.setattr(

        "lib.tool_registry.get_registry",

        lambda *a, **k: _reg(ToolEntry(name="nuclei", enabled=False, phase="probe")),

    )

    out = probe_orchestrator.run_probe(cfg, tc, tmp_path / "r1", urls=[], tech={}, deep=False)

    assert out == []

    assert calls["nuclei"] == 0

    # 2) default registry → nuclei branch runs (positive control). The

    # module-import binding `get_registry` is the original function and is

    # unaffected by the lib.tool_registry attribute patches above.

    monkeypatch.setattr(

        "lib.tool_registry.get_registry", lambda *a, **k: get_registry(reload=True)

    )

    out2 = probe_orchestrator.run_probe(cfg, tc, tmp_path / "r2", urls=[], tech={}, deep=False)

    assert out2 == []

    assert calls["nuclei"] == 1

    assert (tmp_path / "r2" / "scans" / "checkpoint.json").exists()

# -- Step 3: safety enforcement (wired throttle/budget/guard) -----------------

def test_runner_budget_is_enforced(monkeypatch):

    if not shutil.which("python"):

        pytest.skip("python not on PATH")

    from lib import ops_guard

    monkeypatch.setattr("lib.tool_registry.get_registry", lambda *a, **k: _reg())

    ops_guard.set_request_budget(1)

    try:

        res1 = ToolRunner(timeout=10).run("python", ["-c", "print(1)"])

        assert res1.status == "ok"

        res2 = ToolRunner(timeout=10).run("python", ["-c", "print(2)"])

        assert res2.status == "skipped"

        assert "budget" in res2.stderr

    finally:

        ops_guard.set_request_budget(None)

def test_runner_throttles_through_shared_rate_limiter(monkeypatch):

    if not shutil.which("python"):

        pytest.skip("python not on PATH")

    monkeypatch.setattr("lib.tool_registry.get_registry", lambda *a, **k: _reg())

    limiter = ToolRunner.shared_rate_limiter()

    calls = {"n": 0}

    orig_acquire = limiter.acquire

    def spy(key, rate=None):

        calls["n"] += 1

        return orig_acquire(key, rate)

    monkeypatch.setattr(limiter, "acquire", spy)

    res = ToolRunner(timeout=10, rate_limit="100/second", rate_key="p3a-throttle").run(

        "python", ["-c", "print(1)"]

    )

    assert res.status == "ok"

    assert calls["n"] >= 1  # throttle hook actually invoked per attempt

def test_runner_blocked_command_never_executes(monkeypatch):

    monkeypatch.setattr(

        "phases.probe.tool_runner.validate_tool_command",

        lambda cmd: (False, "blocked-by-test"),

    )

    monkeypatch.setattr("lib.tool_registry.get_registry", lambda *a, **k: _reg())

    res = ToolRunner(timeout=5).run("python", ["-c", "print(1)"])

    assert res.status == "skipped"