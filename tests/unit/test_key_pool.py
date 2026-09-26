"""Unit tests for the AI key pool (multi-key failover)."""
from __future__ import annotations

from lib.key_pool import (
    KeyPool,
    KeyPoolRegistry,
    discover_keys,
    mask_key,
    set_key_in_env_file,
)


def test_discover_keys_slots_and_comma_separated():
    env = {
        "OPENAI_API_KEY": "sk-a,sk-b",
        "OPENAI_API_KEY_2": "sk-c",
        "OPENAI_API_KEY_3": "",
    }
    assert discover_keys(env, "openai") == ["sk-a", "sk-b", "sk-c"]


def test_discover_keys_dedup():
    env = {"GLM_API_KEY": "g1,g1,g2"}
    assert discover_keys(env, "glm") == ["g1", "g2"]


def test_mask_key():
    assert mask_key("") == "(empty)"
    assert "…" in mask_key("sk-1234567890abcdef")


def test_pool_rotation():
    pool = KeyPool("openai", ["k1", "k2", "k3"])
    assert pool.next_key() == "k1"
    assert pool.next_key() == "k2"
    assert pool.next_key() == "k3"
    assert pool.next_key() == "k1"


def test_pool_skips_dead_key():
    pool = KeyPool("openai", ["k1", "k2"])
    pool.mark_dead("k1")
    assert pool.next_key() == "k2"
    assert pool.next_key() == "k2"  # k1 stays dead
    assert pool.active_count() == 1


def test_pool_rate_limited_then_recovers():
    pool = KeyPool("openai", ["k1", "k2"])
    pool.mark_rate_limited("k1", cooldown_seconds=999)
    assert pool.next_key() == "k2"
    assert pool.next_key() == "k2"
    pool.mark_rate_limited("k2", cooldown_seconds=999)
    assert pool.next_key() is None  # both sidelined


def test_pool_mark_ok_resets():
    pool = KeyPool("openai", ["k1"])
    pool.mark_rate_limited("k1", 999)
    pool.mark_ok("k1")
    assert pool.next_key() == "k1"


def test_pool_empty():
    pool = KeyPool("openai", [])
    assert pool.empty is True
    assert pool.next_key() is None


def test_registry_providers_with_keys():
    env = {"OPENAI_API_KEY": "a", "DEEPSEEK_API_KEY": "b"}
    reg = KeyPoolRegistry(env, ["openai", "glm", "deepseek", "gemini"])
    assert set(reg.providers_with_keys()) == {"openai", "deepseek"}
    described = reg.describe_all()
    assert any(d["provider"] == "openai" for d in described)


def test_set_key_in_env_file_fills_slots(tmp_path):
    keys = tmp_path / ".keys.env"
    keys.write_text("OPENAI_API_KEY=\n", encoding="utf-8")
    slot, path = set_key_in_env_file(keys, "openai", "sk-first")
    assert slot == "OPENAI_API_KEY"
    slot2, _ = set_key_in_env_file(keys, "openai", "sk-second")
    assert slot2 == "OPENAI_API_KEY_2"
    content = keys.read_text(encoding="utf-8")
    assert "sk-first" in content and "sk-second" in content
    assert (tmp_path / ".keys.env.bak").exists()
