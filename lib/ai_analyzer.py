"""Provider-agnostic AI analysis client with MULTI-KEY FAILOVER.

Supports any OpenAI-compatible chat API: OpenAI / GLM / DeepSeek / Gemini /
Kimi (Moonshot) / OpenRouter / custom self-hosted endpoints. Multiple API
keys per provider are supported and rotated automatically: an empty, dead
(401), rate-limited (429), quota-exhausted, or temporarily failing key is
skipped in favour of the next key — or the next provider.

Failover is driven by :mod:`lib.ai_errors`: each HTTP status/exception is
classified and a per-class policy decides whether to retire the key, cool
it down, skip the provider, or retry with exponential backoff. Permanent
errors are never retried blindly, and keys are never rotated to evade a
genuine quota or usage restriction.

Key env layout (per provider, e.g. OPENAI):
    OPENAI_API_KEY=sk-aaa
    OPENAI_API_KEY_2=sk-bbb
    OPENAI_API_KEY_3=sk-ccc          (or comma-separated in slot 1)

All calls go through ``requests`` with timeouts; failures degrade
gracefully (return None + log) so scans never block on AI availability.
Prompts never include secrets, and provider responses are treated as
untrusted input (JSON is parsed defensively, never executed).
"""
from __future__ import annotations

import json
import time
from typing import Any
from urllib.parse import urlsplit

import requests

from lib.ai_errors import (
    AIErrorClass,
    classify_exception,
    classify_status,
    decision_for,
)
from lib.ai_providers import (
    PROVIDER_SPECS,
    ProviderUnsupportedError,
    is_runtime_provider,
    supports_reasoning_effort,
    validate_reasoning_effort,
)
from lib.key_pool import KeyPoolRegistry, mask_key
from lib.logger import get_logger
from lib.ssrf_guard import is_safe_url

logger = get_logger("ai_analyzer")

_TIMEOUT = (5, 60)  # (connect, read)
BACKOFF_CAP_SECONDS = 8.0

# provider → default chat-completions base URL (OpenAI-compatible path appended)
_PROVIDER_BASE = {
    name: spec.base_url
    for name, spec in PROVIDER_SPECS.items()
    if spec.integration == "openai-compatible-http"
}

_PROVIDER_DEFAULT_MODEL = {
    name: spec.default_model
    for name, spec in PROVIDER_SPECS.items()
    if spec.integration == "openai-compatible-http"
}

ALL_PROVIDERS = tuple(_PROVIDER_BASE.keys())

# Built-in provider hosts: explicit SSRF guard allowlist (Pass 3B). Custom
# base URLs are operator-configured and validated with ``local_ok=True``
# (local AI endpoints are permitted by design; metadata hosts stay blocked).
_SSRF_ALLOW = {urlsplit(u).hostname for u in _PROVIDER_BASE.values() if u} - {None}

# Providers that need no API key (local endpoints).
_KEYLESS_PROVIDERS = {name for name, spec in PROVIDER_SPECS.items() if spec.keyless}

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
        *,
        reasoning_effort: str = "",
        timeout: tuple[int, int] | None = None,
        max_retries: int = 2,
        backoff_base: float = 0.5,
        model_map: dict[str, str] | None = None,
    ):
        self.env = env or {}
        self.enabled = enabled
        # Provider order: requested order, else all known providers.
        self.providers = [p for p in (providers or list(ALL_PROVIDERS)) if p in _PROVIDER_BASE]
        self.global_model = model
        self.base_urls = dict(base_urls or {})
        self.model_map = {
            str(k): str(v) for k, v in (model_map or {}).items() if str(v or "")
        }
        self.strong_model = strong_model
        self.max_calls = int(max_calls or 0)
        self.max_retries = max(0, int(max_retries))
        self.backoff_base = max(0.0, float(backoff_base))
        self.timeout = tuple(timeout) if timeout else _TIMEOUT
        self.reasoning_effort = self._validate_effort(reasoning_effort)
        self._calls = 0
        self._disabled_providers: set[str] = set()
        self.pools = KeyPoolRegistry(self.env, ALL_PROVIDERS)
        self.stats: dict[str, Any] = {
            "attempts": 0,
            "successes": 0,
            "failovers": 0,
            "dead_keys": 0,
            "errors": {c.value: 0 for c in AIErrorClass},
        }

    def _validate_effort(self, effort: str) -> str:
        """Validate reasoning effort against every provider in the chain."""
        value = validate_reasoning_effort(self.providers[0] if self.providers else "openai", effort)
        if value:
            unsupported = [p for p in self.providers if not supports_reasoning_effort(p, value)]
            if unsupported:
                raise ProviderUnsupportedError(
                    "reasoning_effort is not supported by provider(s): "
                    + ", ".join(unsupported)
                )
        return value

    # -- construction -------------------------------------------------------

    @classmethod
    def from_config(cls, ai_cfg: dict[str, Any], env: dict[str, str]) -> "AIAnalyzer":
        """Build from the ``ai:`` config section + env mapping.

        Config keys:
            enabled (bool)
            provider (primary)
            fallback_providers (list)   # tried after the primary
            model
            strong_model
            max_calls
            max_retries
            reasoning_effort            # off|low|medium|high (provider-dependent)
            timeout_seconds
            base_url
        """
        primary = str(ai_cfg.get("provider", "openai") or "openai").lower()
        fallbacks = [str(p).lower() for p in (ai_cfg.get("fallback_providers") or [])]
        providers = [primary] + [p for p in fallbacks if p != primary]
        base_url = str(ai_cfg.get("base_url", "") or "")
        base_urls = {primary: base_url} if base_url else {}
        timeout_seconds = int(ai_cfg.get("timeout_seconds", 0) or 0)
        timeout = (5, timeout_seconds) if timeout_seconds else None
        return cls(
            env=env,
            providers=providers,
            model=str(ai_cfg.get("model", "") or ""),
            base_urls=base_urls,
            enabled=bool(ai_cfg.get("enabled", True)),
            strong_model=str(ai_cfg.get("strong_model", "") or ""),
            max_calls=int(ai_cfg.get("max_calls", 0) or 0),
            reasoning_effort=str(ai_cfg.get("reasoning_effort", "") or ""),
            timeout=timeout,
            max_retries=int(ai_cfg.get("max_retries", 2) or 0),
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
        return (
            self.model_map.get(provider)
            or self.global_model
            or _PROVIDER_DEFAULT_MODEL.get(provider, "")
        )

    def base_url_for(self, provider: str) -> str:
        """Resolve base URL: config override → <PROVIDER>_BASE_URL env → built-in."""
        env_key = f"{provider.upper().replace('-', '_')}_BASE_URL"
        if self.env.get(env_key):
            return self.env[env_key]
        return self.base_urls.get(provider) or _PROVIDER_BASE.get(provider, "")

    # -- one key attempt ----------------------------------------------------

    def _try_key(
        self, provider: str, key: str, user_prompt: str
    ) -> tuple[bool, dict[str, Any] | None, AIErrorClass | None]:
        """Attempt one request with one key.

        Returns ``(ok, parsed, error_class)``. On success ``error_class`` is
        None; on failure ``ok`` is False and ``error_class`` classifies why.
        """
        url = self.base_url_for(provider).rstrip("/") + "/chat/completions"
        headers = {"Authorization": f"Bearer {key}"}
        body: dict[str, Any] = {
            "model": self.model_for(provider),
            "messages": [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.1,
        }
        if self.reasoning_effort and supports_reasoning_effort(provider, self.reasoning_effort):
            body["reasoning_effort"] = self.reasoning_effort

        safe, reason = is_safe_url(url, allow=_SSRF_ALLOW, local_ok=True)
        if not safe:
            logger.warning("ssrf guard blocked AI endpoint (%s): %s", provider, reason)
            return False, None, AIErrorClass.PERMISSION
        try:
            resp = requests.post(url, headers=headers, json=body, timeout=self.timeout)
        except requests.RequestException as exc:
            logger.warning("AI request error (%s, key %s): %s", provider, mask_key(key), exc)
            return False, None, classify_exception(exc)

        if resp.status_code == 200:
            self.pools.get(provider).mark_ok(key)
            self.stats["successes"] += 1
            try:
                content = resp.json()["choices"][0]["message"]["content"]
                return True, self._parse_json(content), None
            except (KeyError, IndexError, json.JSONDecodeError, ValueError) as exc:
                logger.warning("AI response parse error: %s", exc)
                return True, None, None

        body_text = ""
        try:
            body_text = resp.text or ""
        except Exception:  # pragma: no cover - defensive
            body_text = ""
        error_class = classify_status(resp.status_code, body_text)
        logger.warning(
            "AI request failed (%s HTTP %d, class=%s)",
            provider, resp.status_code, error_class.value,
        )
        return False, None, error_class

    # -- per-provider failover loop -----------------------------------------

    def _run_provider(
        self, provider: str, user_prompt: str
    ) -> tuple[bool, dict[str, Any] | None]:
        if provider in _KEYLESS_PROVIDERS:
            if not self.base_url_for(provider) or not self.model_for(provider):
                return False, None
            self._calls += 1
            self.stats["attempts"] += 1
            ok, parsed, error_class = self._try_key(provider, "", user_prompt)
            if not ok and error_class is not None:
                self.stats["errors"][error_class.value] += 1
            return ok, parsed

        pool = self.pools.get(provider)
        if not len(pool):
            return False, None
        if not self.base_url_for(provider) or not self.model_for(provider):
            logger.debug("provider %r missing base_url/model; skipping", provider)
            return False, None

        max_attempts = len(pool) + self.max_retries
        attempts = 0
        backoff = self.backoff_base
        outage_streak = 0
        while attempts < max_attempts:
            key = pool.next_key()
            if key is None:
                break
            attempts += 1
            self._calls += 1
            self.stats["attempts"] += 1
            ok, parsed, error_class = self._try_key(provider, key, user_prompt)
            if ok:
                return True, parsed

            assert error_class is not None
            self.stats["errors"][error_class.value] += 1
            decision = decision_for(error_class)

            if decision.retire_key:
                pool.mark_dead(key)
                self.stats["dead_keys"] += 1
                self.stats["failovers"] += 1
            elif decision.cool_key:
                if error_class == AIErrorClass.QUOTA_EXHAUSTED:
                    pool.mark_quota(key)
                else:
                    pool.mark_rate_limited(key)
                self.stats["failovers"] += 1

            if decision.skip_provider:
                self._disabled_providers.add(provider)
                self.stats["failovers"] += 1
                break

            if decision.retry:
                if error_class == AIErrorClass.OUTAGE:
                    outage_streak += 1
                else:
                    outage_streak = 0
                if outage_streak > self.max_retries:
                    self._disabled_providers.add(provider)
                    break
                if backoff:
                    time.sleep(backoff)
                    backoff = min(backoff * 2, BACKOFF_CAP_SECONDS)
                continue

            continue  # key retired/cooled → try the next key
        return False, None

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
            if provider in self._disabled_providers:
                continue
            ok, parsed = self._run_provider(provider, user_prompt)
            if ok:
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

    def runtime(self, provider: str = ""):
        """Local-runtime adapter for *provider* (or the first in the chain).

        Returns ``None`` for cloud providers or when nothing is configured;
        building the adapter never makes a network call.
        """
        from lib.local_runtime import runtime_for

        name = str(provider or (self.providers[0] if self.providers else "")).lower()
        if not is_runtime_provider(name):
            return None
        return runtime_for(name, self.base_url_for(name), self.model_for(name), self.timeout)

    def check_runtime(self, provider: str = "") -> dict[str, Any]:
        """Probe the local runtime and return its health/inventory (opt-in)."""
        adapter = self.runtime(provider)
        if adapter is None:
            return {
                "provider": "", "flavor": "", "base_url": "",
                "available": False, "model_count": 0, "models": [],
                "error": "no local/OpenAI-compatible runtime in the provider chain",
            }
        return adapter.probe().to_dict()

    def key_status(self) -> list[dict]:
        """Masked status of all configured keys (for CLI output)."""
        return self.pools.describe_all()

    def status_summary(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "providers": self.providers,
            "providers_with_keys": self.pools.providers_with_keys(),
            "reasoning_effort": self.reasoning_effort or "off",
            "max_retries": self.max_retries,
            "runtime_providers": [p for p in self.providers if is_runtime_provider(p)],
            "stats": dict(self.stats),
        }
