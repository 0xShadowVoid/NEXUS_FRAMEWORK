"""Provider-agnostic AI analysis client with MULTI-KEY FAILOVER.

Supports any OpenAI-compatible chat API: OpenAI / GLM / DeepSeek / Gemini /
Kimi (Moonshot) / OpenRouter / custom self-hosted endpoints.
Multiple API keys per provider are supported and rotated automatically:
an empty, dead (401/403), or rate-limited (429) key is skipped and the next
key — or next provider — is tried.

Key env layout (per provider, e.g. OPENAI):
    OPENAI_API_KEY=sk-aaa
    OPENAI_API_KEY_2=sk-bbb
    OPENAI_API_KEY_3=sk-ccc          (or comma-separated in slot 1)

All calls go through ``requests`` with timeouts; failures degrade
gracefully (return None + log) so scans never block on AI availability.
Prompts never include secrets.
"""
from __future__ import annotations

import json
from typing import Any

import requests

from lib.key_pool import KeyPoolRegistry, mask_key
from lib.logger import get_logger

logger = get_logger("ai_analyzer")

_TIMEOUT = (5, 60)  # (connect, read)

# provider → default chat-completions base URL (OpenAI-compatible path appended)
_PROVIDER_BASE = {
    "openai": "https://api.openai.com/v1",
    "glm": "https://open.bigmodel.cn/api/paas/v4",
    "deepseek": "https://api.deepseek.com/v1",
    "gemini": "https://generativelanguage.googleapis.com/v1beta/openai",
    "kimi": "https://api.moonshot.cn/v1",
    "openrouter": "https://openrouter.ai/api/v1",
    "ollama": "http://localhost:11434/v1",   # local models, OpenAI-compatible
    "custom": "",  # any OpenAI-compatible endpoint — set ai.base_url or <PROVIDER>_BASE_URL
}

_PROVIDER_DEFAULT_MODEL = {
    "openai": "gpt-4o-mini",
    "glm": "glm-4-flash",
    "deepseek": "deepseek-chat",
    "gemini": "gemini-1.5-flash",
    "kimi": "moonshot-v1-8k",
    "openrouter": "openrouter/auto",
    "ollama": "llama3.1",
    "custom": "",
}

ALL_PROVIDERS = tuple(_PROVIDER_BASE.keys())

# Providers that need no API key (local endpoints).
_KEYLESS_PROVIDERS = {"ollama"}

_SYSTEM_PROMPT = (
    "You are a security-finding analysis assistant for an authorized bug "
    "bounty program. You categorize findings, suggest vulnerability chains, "
    "and explain scanner errors. You never request exploitation steps beyond "
    "proof of concept, and you never request extraction of target data. "
    "Answer strictly in JSON when asked."
)


class AIAnalyzer:
    """Chat-completion client with per-provider multi-key failover."""

    def __init__(
        self,
        env: dict[str, str],
        providers: list[str] | None = None,
        model: str = "",
        base_urls: dict[str, str] | None = None,
        enabled: bool = True,
        strong_model: str = "",
        max_calls: int = 0,
    ):
        self.env = env or {}
        self.enabled = enabled
        # Provider order: requested order, else all known providers.
        self.providers = [p for p in (providers or list(ALL_PROVIDERS)) if p in _PROVIDER_BASE]
        self.global_model = model
        self.base_urls = dict(base_urls or {})
        self.strong_model = strong_model
        self.max_calls = int(max_calls or 0)
        self._calls = 0
        self.pools = KeyPoolRegistry(self.env, ALL_PROVIDERS)
        self.stats: dict[str, int] = {"attempts": 0, "successes": 0, "failovers": 0, "dead_keys": 0}

    # -- construction -------------------------------------------------------

    @classmethod
    def from_config(cls, ai_cfg: dict[str, Any], env: dict[str, str]) -> "AIAnalyzer":
        """Build from the ``ai:`` config section + env mapping.

        Config keys:
            enabled (bool)
            provider (primary)
            fallback_providers (list)   # tried after the primary
            model
            base_url
        """
        primary = str(ai_cfg.get("provider", "openai") or "openai").lower()
        fallbacks = [str(p).lower() for p in (ai_cfg.get("fallback_providers") or [])]
        providers = [primary] + [p for p in fallbacks if p != primary]
        base_url = str(ai_cfg.get("base_url", "") or "")
        base_urls = {primary: base_url} if base_url else {}
        return cls(
            env=env,
            providers=providers,
            model=str(ai_cfg.get("model", "") or ""),
            base_urls=base_urls,
            enabled=bool(ai_cfg.get("enabled", True)),
            strong_model=str(ai_cfg.get("strong_model", "") or ""),
            max_calls=int(ai_cfg.get("max_calls", 0) or 0),
        )

    # -- availability -------------------------------------------------------

    def provider_has_keys(self, provider: str) -> bool:
        return len(self.pools.get(provider)) > 0

    def available(self) -> bool:
        """True when AI is enabled and at least one provider is usable."""
        if not self.enabled:
            return False
        if any(self.provider_has_keys(p) for p in self.providers):
            return True
        return any(
            p in _KEYLESS_PROVIDERS and self.base_url_for(p) and self.model_for(p)
            for p in self.providers
        )

    def model_for(self, provider: str) -> str:
        return self.global_model or _PROVIDER_DEFAULT_MODEL.get(provider, "")

    def base_url_for(self, provider: str) -> str:
        """Resolve base URL: config override → <PROVIDER>_BASE_URL env → built-in."""
        env_key = f"{provider.upper().replace('-', '_')}_BASE_URL"
        if self.env.get(env_key):
            return self.env[env_key]
        return self.base_urls.get(provider) or _PROVIDER_BASE.get(provider, "")

    # -- core call with failover -------------------------------------------

    def _try_key(self, provider: str, key: str, user_prompt: str) -> tuple[bool, dict[str, Any] | None]:
        """Attempt one request with one key. Returns (retry_with_next_key, parsed)."""
        url = self.base_url_for(provider).rstrip("/") + "/chat/completions"
        headers = {"Authorization": f"Bearer {key}"}
        body = {
            "model": self.model_for(provider),
            "messages": [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.1,
        }
        try:
            resp = requests.post(url, headers=headers, json=body, timeout=_TIMEOUT)
        except requests.RequestException as exc:
            logger.warning("AI request error (%s, key %s): %s", provider, mask_key(key), exc)
            return True, None  # transport error → try next key/provider

        if resp.status_code == 200:
            self.pools.get(provider).mark_ok(key)
            self.stats["successes"] += 1
            try:
                content = resp.json()["choices"][0]["message"]["content"]
                return False, self._parse_json(content)
            except (KeyError, IndexError, json.JSONDecodeError, ValueError) as exc:
                logger.warning("AI response parse error: %s", exc)
                return False, None

        if resp.status_code in (401, 403):
            # Dead key: retire it and try the next one.
            self.pools.get(provider).mark_dead(key)
            self.stats["dead_keys"] += 1
            self.stats["failovers"] += 1
            logger.warning("AI key rejected by %s (HTTP %d) — failing over", provider, resp.status_code)
            return True, None

        if resp.status_code == 429:
            self.pools.get(provider).mark_rate_limited(key)
            self.stats["failovers"] += 1
            logger.warning("AI key rate-limited by %s — failing over", provider)
            return True, None

        logger.warning("AI request failed: HTTP %d (%s)", resp.status_code, provider)
        return True, None  # other errors → try next provider

    def _chat(self, user_prompt: str) -> dict[str, Any] | None:
        """Run a prompt across providers/keys with failover. Returns JSON or None."""
        if not self.enabled:
            logger.debug("AI disabled in config; skipping")
            return None
        if self.max_calls and self._calls >= self.max_calls:
            logger.warning("AI call budget exceeded (%d)", self.max_calls)
            return None
        if not self.available():
            logger.debug("no AI provider has keys configured; skipping")
            return None

        for provider in self.providers:
            # Keyless local providers (e.g. Ollama) need no API key.
            if provider in _KEYLESS_PROVIDERS:
                if not self.base_url_for(provider) or not self.model_for(provider):
                    continue
                self._calls += 1
                self.stats["attempts"] += 1
                retry, parsed = self._try_key(provider, "", user_prompt)
                if not retry:
                    return parsed
                continue
            pool = self.pools.get(provider)
            if not len(pool):
                continue
            if not self.base_url_for(provider) or not self.model_for(provider):
                logger.debug("provider %r missing base_url/model; skipping", provider)
                continue
            tried = 0
            while tried < len(pool) + 1:
                key = pool.next_key()
                if key is None:
                    break
                tried += 1
                self._calls += 1
                self.stats["attempts"] += 1
                retry, parsed = self._try_key(provider, key, user_prompt)
                if not retry:
                    return parsed
        logger.warning("AI analysis unavailable: all providers/keys exhausted")
        return None

    def route(self, task: str = "triage") -> dict[str, str]:
        """Pick a provider/model by task (roadmap C2). 'reason' uses the strong model."""
        provider = self.providers[0] if self.providers else ""
        if not provider:
            return {"provider": "", "model": ""}
        model = self.model_for(provider)
        if task == "reason" and self.strong_model:
            model = self.strong_model
        return {"provider": provider, "model": model}

    def disprove_finding(self, finding: dict[str, Any]) -> dict[str, Any] | None:
        """Adversarial FP check (roadmap C3): returns {'likely_fp': bool, 'reason': str}."""
        prompt = (
            "Act as a skeptical triager. Argue whether this finding is a false positive. "
            "Reply as JSON {\"likely_fp\": bool, \"reason\": str}:\n"
            + json.dumps(
                {
                    "vuln_type": finding.get("vuln_type"),
                    "endpoint": finding.get("endpoint"),
                    "payload": finding.get("payload"),
                    "response_snippet": (str(finding.get("response_snippet", "")) or "")[:500],
                    "tools_found": finding.get("tools_found"),
                },
                default=str,
            )
        )
        return self._chat(prompt)

    @staticmethod
    def _parse_json(content: str) -> dict[str, Any] | None:
        """Parse JSON out of a model reply (tolerates code fences)."""
        text = (content or "").strip()
        if not text:
            return None
        if text.startswith("```"):
            text = text.strip("`")
            if text.lower().startswith("json"):
                text = text[4:]
        try:
            parsed = json.loads(text.strip())
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            pass
        start, end = text.find("{"), text.rfind("}")
        if 0 <= start < end:
            try:
                parsed = json.loads(text[start : end + 1])
                if isinstance(parsed, dict):
                    return parsed
            except json.JSONDecodeError:
                pass
        return None

    # -- public API ---------------------------------------------------------

    def plan_steps(self, objective: str, skills: list[Any] | None = None) -> dict[str, Any] | None:
        """Plan agent steps for an objective (roadmap C1). Returns {'steps': [...]}."""
        catalogue = [
            {"name": getattr(s, "name", ""), "description": getattr(s, "description", ""),
             "tools": getattr(s, "tools", [])}
            for s in (skills or [])
        ]
        prompt = (
            "Plan the minimal ordered steps to satisfy an authorized bug-bounty objective. "
            "Allowed actions: scan, discover, dork, cve-update, status, report, schedules, verify. "
            "Reply as JSON {\"steps\": [{\"action\": str, \"target\": str, \"why\": str}]}.\n"
            f"Objective: {objective}\n"
            f"Skills: {json.dumps(catalogue, default=str)}"
        )
        return self._chat(prompt)

    def categorize_finding(self, finding: dict[str, Any]) -> dict[str, Any] | None:
        """Categorize a finding → {'category', 'severity_hint', 'reason'}."""
        prompt = (
            "Categorize this security finding and reply as JSON "
            '{"category": str, "severity_hint": "P1"|"P2"|"P3"|"P4", "reason": str}:\n'
            + json.dumps(
                {
                    "vuln_type": finding.get("vuln_type"),
                    "endpoint": finding.get("endpoint"),
                    "payload": finding.get("payload"),
                    "response_snippet": (str(finding.get("response_snippet", "")) or "")[:500],
                },
                default=str,
            )
        )
        return self._chat(prompt)

    def suggest_chains(self, findings: list[dict[str, Any]]) -> dict[str, Any] | None:
        """Suggest vulnerability chains across findings (advisory only)."""
        slim = [
            {"vuln_type": f.get("vuln_type"), "endpoint": f.get("endpoint"), "severity": f.get("severity")}
            for f in findings[:30]
        ]
        prompt = (
            "Given these findings, suggest plausible vulnerability chains. Reply as JSON "
            '{"chains": [{"chain_type": str, "finding_indexes": [int], "impact": str}]}\n'
            + json.dumps(slim, default=str)
        )
        return self._chat(prompt)

    def analyze_error(self, error_text: str) -> dict[str, Any] | None:
        """Explain a scanner error → {'cause', 'action'}."""
        prompt = (
            "A security scanner produced this error. Explain the cause and next action. Reply as JSON "
            '{"cause": str, "action": str}:\n' + (error_text or "")[:2000]
        )
        return self._chat(prompt)

    def write_narrative(self, findings: list[dict[str, Any]], metrics: dict[str, Any] | None = None) -> dict[str, Any] | None:
        """Draft an executive summary + bullets for a report (roadmap C4)."""
        slim = [
            {"severity": f.get("severity"), "vuln_type": f.get("vuln_type"),
             "endpoint": f.get("endpoint")}
            for f in findings[:20]
        ]
        prompt = (
            "Write an executive summary for these findings. Reply as JSON "
            '{"summary": str, "bullets": [str]}:\n'
            + json.dumps({"metrics": metrics or {}, "findings": slim}, default=str)
        )
        return self._chat(prompt)

    # -- diagnostics --------------------------------------------------------

    def key_status(self) -> list[dict]:
        """Masked status of all configured keys (for CLI output)."""
        return self.pools.describe_all()

    def status_summary(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "providers": self.providers,
            "providers_with_keys": self.pools.providers_with_keys(),
            "stats": dict(self.stats),
        }
