"""Configuration loading for NEXUS.

Loads ``config/nexus.yaml``, ``config/false_positive_filters.yaml`` and
``config/.keys.env`` (via python-dotenv, falling back to the process
environment). ``${VAR}`` references inside nexus.yaml are substituted
from .keys.env first, then OS environment. Missing variables resolve to
the empty string so the framework degrades gracefully offline; use
:func:`validate_keys` when strict validation is required.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv

from lib.exceptions import ConfigError
from lib.paths import CONFIG_DIR, REPO_ROOT

_ENV_REF_RE = re.compile(r"\$\{([A-Z0-9_]+)\}")

KNOWN_ENV_KEYS = [
    "DISCORD_FINDINGS_WEBHOOK",
    "DISCORD_CVE_WEBHOOK",
    "DISCORD_METRICS_WEBHOOK",
    "TELEGRAM_BOT_TOKEN",
    "TELEGRAM_CHAT_ID",
    "SMTP_HOST",
    "SMTP_PORT",
    "SMTP_USER",
    "SMTP_PASS",
    "ALERT_EMAIL_FROM",
    "ALERT_EMAIL_TO",
    "HACKERONE_API_USERNAME",
    "HACKERONE_API_TOKEN",
    "BUGCROWD_API_KEY",
    "NVD_API_KEY",
    "OPENAI_API_KEY",
    "GLM_API_KEY",
    "DEEPSEEK_API_KEY",
    "GEMINI_API_KEY",
    "KIMI_API_KEY",
    "OPENROUTER_API_KEY",
    "CUSTOM_API_KEY",
    "CUSTOM_BASE_URL",
    "GITHUB_TOKEN",
    "DISCORD_BOT_TOKEN",
    "C2_OWNER_ID",
    "INTIGRITI_API_KEY",
    "YESWEHACK_API_KEY",
]

WEBHOOK_URL_RE = re.compile(
    r"^https://(discord|discordapp)\.com/api/webhooks/\d+/[\w.-]+$"
)


def _substitute_env(value: Any, env: dict[str, str]) -> Any:
    """Recursively replace ``${VAR}`` references in strings/structures."""
    if isinstance(value, str):
        def _repl(m: re.Match[str]) -> str:
            return env.get(m.group(1), "")

        return _ENV_REF_RE.sub(_repl, value)
    if isinstance(value, dict):
        return {k: _substitute_env(v, env) for k, v in value.items()}
    if isinstance(value, list):
        return [_substitute_env(v, env) for v in value]
    return value


@dataclass
class TargetConfig:
    """Per-target settings resolved from the ``targets:`` section."""

    domain: str
    platform: str = "generic"
    program_type: str = "bb"            # bb | vdp | internal | pentest ...
    scope_kind: str = "public"          # public | private | vdp | freelance | pentest | external
    intensity: str = "quick-scan"
    tools: list[str] = field(default_factory=list)
    rate_limit: str = "50/minute"
    cookie: str = ""
    in_scope: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "platform": self.platform,
            "program_type": self.program_type,
            "scope_kind": self.scope_kind,
            "intensity": self.intensity,
            "tools": list(self.tools),
            "rate_limit": self.rate_limit,
            "cookie": self.cookie,
            "in_scope": list(self.in_scope),
            "out_of_scope": list(self.out_of_scope),
        }


class Config:
    """Loaded NEXUS configuration."""

    def __init__(self, main: dict[str, Any], filters: dict[str, Any], env: dict[str, str]):
        self._main = main
        self.filters = filters
        self.env = env

    # -- sections ---------------------------------------------------------

    @property
    def scanning(self) -> dict[str, Any]:
        return self._main.get("scanning", {})

    @property
    def phases(self) -> dict[str, Any]:
        return self._main.get("phases", {})

    @property
    def targets_section(self) -> dict[str, Any]:
        return self._main.get("targets", {})

    @property
    def webhooks(self) -> dict[str, Any]:
        return self._main.get("webhooks", {})

    @property
    def email(self) -> dict[str, Any]:
        return self._main.get("email", {})

    @property
    def ai(self) -> dict[str, Any]:
        return self._main.get("ai", {})

    @property
    def cve(self) -> dict[str, Any]:
        return self._main.get("cve", {})

    @property
    def c2_bot(self) -> dict[str, Any]:
        return self._main.get("c2_bot", {})

    @property
    def schedules(self) -> dict[str, Any]:
        return self._main.get("schedules", {})

    @property
    def database_path(self) -> Path:
        raw = self._main.get("database", {}).get("path", "nexus.db")
        p = Path(raw)
        return p if p.is_absolute() else REPO_ROOT / p

    # -- helpers ----------------------------------------------------------

    def default_intensity(self) -> str:
        return str(self.scanning.get("default_intensity", "quick-scan"))

    def tool_timeout(self) -> int:
        return int(self.scanning.get("tool_timeout_seconds", 300))

    def rate_limit_default(self) -> str:
        return str(self.scanning.get("rate_limit_default", "50/minute"))

    def target_names(self) -> list[str]:
        return list(self.targets_section.keys())

    def target(self, domain: str) -> TargetConfig:
        """Build a TargetConfig for *domain*, applying overrides."""
        raw = self.targets_section.get(domain, {}) or {}
        return TargetConfig(
            domain=domain,
            platform=str(raw.get("platform", "generic")),
            program_type=str(raw.get("type", "bb")),
            scope_kind=str(raw.get("scope", "public")),
            intensity=str(raw.get("intensity", self.default_intensity())),
            tools=list(raw.get("tools", [])),
            rate_limit=str(raw.get("rate_limit", self.rate_limit_default())),
            cookie=str(raw.get("cookie", "")),
            in_scope=list(raw.get("in_scope", [domain])),
            out_of_scope=list(raw.get("out_of_scope", [])),
        )

    def webhook(self, kind: str) -> str:
        """Return a Discord webhook URL or '' when unset."""
        discord = self.webhooks.get("discord", {}) or {}
        return str(discord.get(kind, "") or "")

    def telegram(self) -> tuple[str, str]:
        tg = self.webhooks.get("telegram", {}) or {}
        return str(tg.get("bot_token", "") or ""), str(tg.get("chat_id", "") or "")


def load_config(config_dir: Path | None = None) -> Config:
    """Load nexus.yaml + false_positive_filters.yaml + .keys.env."""
    cfg_dir = config_dir or CONFIG_DIR
    main_path = cfg_dir / "nexus.yaml"
    filters_path = cfg_dir / "false_positive_filters.yaml"
    keys_path = cfg_dir / ".keys.env"

    if not main_path.exists():
        raise ConfigError(f"main config not found: {main_path}")
    if not filters_path.exists():
        raise ConfigError(f"filters config not found: {filters_path}")

    # .keys.env → env mapping (falls back to process env when absent).
    env: dict[str, str] = {}
    if keys_path.exists():
        load_dotenv(dotenv_path=str(keys_path), override=False)
    for key in KNOWN_ENV_KEYS:
        val = os.environ.get(key, "")
        if val:
            env[key] = val

    try:
        main = yaml.safe_load(main_path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {main_path}: {exc}") from exc
    try:
        filters = yaml.safe_load(filters_path.read_text(encoding="utf-8")) or {}
    except yaml.YAMLError as exc:
        raise ConfigError(f"invalid YAML in {filters_path}: {exc}") from exc

    main = _substitute_env(main, env)
    return Config(main=main, filters=filters, env=env)


def validate_keys(cfg: Config) -> dict[str, Any]:
    """Report on required keys.

    Returns ``{'valid': bool, 'missing': [...], 'invalid': [...]}``.
    Missing alert keys degrade gracefully; invalid formats are flagged.
    Never returns or logs secret values.
    """
    missing: list[str] = []
    invalid: list[str] = []

    for key in KNOWN_ENV_KEYS:
        if not cfg.env.get(key):
            missing.append(key)

    for kind in ("findings", "cve", "metrics"):
        url = cfg.webhook(kind)
        if url and not WEBHOOK_URL_RE.match(url):
            invalid.append(f"DISCORD_{kind.upper()}_WEBHOOK")

    tg_token, _tg_chat = cfg.telegram()
    if tg_token and not re.match(r"^\d+:[\w-]{30,}$", tg_token):
        invalid.append("TELEGRAM_BOT_TOKEN")

    return {
        "valid": len(invalid) == 0,
        "missing": missing,
        "invalid": invalid,
    }
