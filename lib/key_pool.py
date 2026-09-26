"""Multi-key pool with rotation + failover.

Supports multiple API keys per provider so that an empty, dead,
or rate-limited key is skipped automatically in favour of the next
available one.

Environment layout (per provider, e.g. OPENAI):

    OPENAI_API_KEY=sk-aaa
    OPENAI_API_KEY_2=sk-bbb
    OPENAI_API_KEY_3=sk-ccc

Comma-separated values are also accepted:

    OPENAI_API_KEY=sk-aaa,sk-bbb,sk-ccc

Keys are masked whenever they appear in ``repr``/logs.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Iterable

MAX_KEY_SLOTS = 10          # PROVIDER_API_KEY .. PROVIDER_API_KEY_10
DEFAULT_RATE_LIMIT_COOLDOWN = 60  # seconds to sideline a 429'd key


def mask_key(key: str) -> str:
    """Return a masked representation safe for logs/CLI output."""
    k = (key or "").strip()
    if not k:
        return "(empty)"
    if len(k) <= 8:
        return k[0] + "***" + k[-1]
    return f"{k[:4]}…{k[-4:]} (len={len(k)})"


@dataclass
class KeyState:
    """Runtime state for a single key."""

    key: str
    status: str = "active"          # active | dead | rate_limited
    failures: int = 0
    cooldown_until: float = 0.0

    def usable(self, now: float | None = None) -> bool:
        now = now if now is not None else time.monotonic()
        if self.status == "dead":
            return False
        if self.status == "rate_limited" and now < self.cooldown_until:
            return False
        return self.status in ("active", "rate_limited")


def discover_keys(env: dict[str, str], provider: str) -> list[str]:
    """Collect all keys for *provider* from *env*, in slot order."""
    prefix = provider.upper().replace("-", "_")
    keys: list[str] = []

    primary = env.get(f"{prefix}_API_KEY", "") or ""
    for chunk in primary.split(","):
        cleaned = chunk.strip()
        if cleaned:
            keys.append(cleaned)

    for slot in range(2, MAX_KEY_SLOTS + 1):
        value = env.get(f"{prefix}_API_KEY_{slot}", "") or ""
        for chunk in value.split(","):
            cleaned = chunk.strip()
            if cleaned:
                keys.append(cleaned)

    # Deduplicate preserving order.
    seen: set[str] = set()
    out: list[str] = []
    for k in keys:
        if k not in seen:
            seen.add(k)
            out.append(k)
    return out


class KeyPool:
    """Rotating pool of keys for one provider."""

    def __init__(self, provider: str, keys: Iterable[str]):
        self.provider = provider
        self.states: list[KeyState] = [KeyState(key=k) for k in keys if k and k.strip()]
        self._cursor = 0

    def __len__(self) -> int:
        return len(self.states)

    def __bool__(self) -> bool:
        return bool(self.states)

    @property
    def empty(self) -> bool:
        return not self.states

    def active_count(self) -> int:
        return sum(1 for s in self.states if s.usable())

    def next_key(self) -> str | None:
        """Return the next usable key, rotating the cursor. None if none."""
        if not self.states:
            return None
        now = time.monotonic()
        n = len(self.states)
        for offset in range(n):
            idx = (self._cursor + offset) % n
            state = self.states[idx]
            if state.usable(now):
                self._cursor = (idx + 1) % n
                return state.key
            if state.status == "rate_limited" and now >= state.cooldown_until:
                state.status = "active"
                self._cursor = (idx + 1) % n
                return state.key
        return None

    def mark_ok(self, key: str) -> None:
        state = self._find(key)
        if state:
            state.status = "active"
            state.failures = 0
            state.cooldown_until = 0.0

    def mark_dead(self, key: str) -> None:
        """Mark a key permanently dead (401/403/invalid)."""
        state = self._find(key)
        if state:
            state.status = "dead"
            state.failures += 1

    def mark_rate_limited(self, key: str, cooldown_seconds: int = DEFAULT_RATE_LIMIT_COOLDOWN) -> None:
        state = self._find(key)
        if state:
            state.status = "rate_limited"
            state.failures += 1
            state.cooldown_until = time.monotonic() + cooldown_seconds

    def reset(self) -> None:
        """Reset all non-dead keys to active (used between runs)."""
        for state in self.states:
            if state.status != "dead":
                state.status = "active"
                state.cooldown_until = 0.0

    def describe(self) -> list[dict]:
        """Masked description for CLI status output."""
        return [
            {
                "provider": self.provider,
                "index": i + 1,
                "key": mask_key(s.key),
                "status": s.status,
                "failures": s.failures,
            }
            for i, s in enumerate(self.states)
        ]

    def _find(self, key: str) -> KeyState | None:
        for state in self.states:
            if state.key == key:
                return state
        return None


def set_key_in_env_file(keys_path, provider: str, key: str) -> tuple[str, str]:
    """Add an API key for *provider* to the .keys.env file.

    Fills the first empty slot (``PROVIDER_API_KEY`` then
    ``PROVIDER_API_KEY_2`` … ``_10``); creates the file if missing.
    Makes a ``.bak`` backup before modifying. Returns (slot_name, path).
    """
    from pathlib import Path

    path = Path(keys_path)
    prefix = provider.upper().replace("-", "_")
    slots = [f"{prefix}_API_KEY"] + [f"{prefix}_API_KEY_{i}" for i in range(2, MAX_KEY_SLOTS + 1)]

    lines: list[str] = []
    if path.exists():
        lines = path.read_text(encoding="utf-8").splitlines()
        path.with_suffix(path.suffix + ".bak").write_text(
            path.read_text(encoding="utf-8"), encoding="utf-8"
        )

    existing: dict[str, int] = {}
    for idx, line in enumerate(lines):
        stripped = line.strip()
        for slot in slots:
            if stripped.startswith(f"{slot}=") or stripped.startswith(f"{slot} ="):
                existing[slot] = idx

    chosen = ""
    for slot in slots:
        idx = existing.get(slot)
        if idx is None:
            chosen = slot
            lines.append(f"{slot}={key}")
            break
        current = lines[idx].split("=", 1)[1].strip() if "=" in lines[idx] else ""
        if not current:
            chosen = slot
            lines[idx] = f"{slot}={key}"
            break
    if not chosen:
        raise ValueError(f"no free key slot for provider {provider!r} (max {MAX_KEY_SLOTS})")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return chosen, str(path)


class KeyPoolRegistry:
    """Registry of per-provider KeyPools built from an env mapping."""

    def __init__(self, env: dict[str, str], providers: Iterable[str]):
        self._pools: dict[str, KeyPool] = {}
        for provider in providers:
            self._pools[provider] = KeyPool(provider, discover_keys(env, provider))

    def get(self, provider: str) -> KeyPool:
        if provider not in self._pools:
            self._pools[provider] = KeyPool(provider, [])
        return self._pools[provider]

    def providers_with_keys(self) -> list[str]:
        return [p for p, pool in self._pools.items() if len(pool) > 0]

    def describe_all(self) -> list[dict]:
        out: list[dict] = []
        for provider in sorted(self._pools):
            out.extend(self._pools[provider].describe())
        return out
