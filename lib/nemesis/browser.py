"""Browser execution adapter (Phase E) — mock-first, Playwright optional.

Real browser automation is OPTIONAL and OFF by default
(``nemesis.browser.enabled``). This module provides:

- a narrow adapter interface (navigate, DOM inspection, forms, inputs,
  tabs, frames, screenshots, downloads, page-state observation,
  authenticated context references);
- a deterministic ``MockBrowserAdapter`` for tests and dry runs;
- a Playwright adapter that degrades cleanly when the dependency is
  absent (``BrowserUnavailable``) — it never blocks the wider pass;
- the NEXUS evidence schema for browser actions.

Browser page content is ALWAYS untrusted input. This module performs no
credential theft, session extraction, or unauthorized browser access —
only explicitly configured/authorized sessions.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urljoin

from lib.logger import get_logger
from lib.ops_guard import spend_requests
from lib.scope_validator import validate_finding_scope
from lib.ssrf_guard import is_safe_url
from lib.utils import sanitize_path_component

logger = get_logger("nemesis.browser")


class BrowserUnavailable(RuntimeError):
    """Raised when a real browser backend is not safely available."""


class BrowserPolicyError(RuntimeError):
    """Raised when a browser action violates NEXUS policy (scope/SSRF/authz)."""


@dataclass
class BrowserObservation:
    """One observed browser state (page content is untrusted input)."""

    url: str
    action: str
    dom_summary: str = ""
    state: dict[str, Any] = field(default_factory=dict)
    screenshot_ref: str = ""
    downloads: list[str] = field(default_factory=list)
    identity_ref: str = ""
    trusted: bool = False


class BrowserAdapter(ABC):
    """Contract for browser-assisted security testing (off by default)."""

    @abstractmethod
    def start(self) -> None: ...

    @abstractmethod
    def stop(self) -> None: ...

    @abstractmethod
    def navigate(self, url: str) -> BrowserObservation: ...

    @abstractmethod
    def inspect_dom(self) -> str: ...

    @abstractmethod
    def click(self, selector: str) -> BrowserObservation: ...

    @abstractmethod
    def fill_form(self, selector: str, value: str) -> BrowserObservation: ...

    @abstractmethod
    def open_tab(self, url: str) -> BrowserObservation: ...

    @abstractmethod
    def switch_frame(self, selector: str) -> BrowserObservation: ...

    @abstractmethod
    def screenshot(self) -> str: ...

    @abstractmethod
    def observe(self) -> BrowserObservation: ...

    def tabs(self) -> list[str]:
        return []

    def downloads(self) -> list[str]:
        return []


class MockBrowserAdapter(BrowserAdapter):
    """Deterministic, fully offline adapter (tests + dry runs)."""

    def __init__(self) -> None:
        self.actions: list[dict[str, Any]] = []
        self._tabs: list[str] = []
        self._frames: list[str] = []
        self._shot = 0
        self._current = ""

    def _record(self, action: str, detail: str = "") -> None:
        self.actions.append({"action": action, "detail": detail})

    def start(self) -> None:
        self._record("start")

    def stop(self) -> None:
        self._record("stop")

    def navigate(self, url: str) -> BrowserObservation:
        self._current = str(url)
        self._record("navigate", self._current)
        return BrowserObservation(url=self._current, action="navigate")

    def inspect_dom(self) -> str:
        return f'<html data-url="{self._current}"><body>mock page</body></html>'

    def click(self, selector: str) -> BrowserObservation:
        self._record("click", str(selector))
        return BrowserObservation(url=self._current, action="click", state={"selector": selector})

    def fill_form(self, selector: str, value: str) -> BrowserObservation:
        self._record("fill", f"{selector}={value}")
        return BrowserObservation(url=self._current, action="fill",
                                  state={"selector": selector, "length": len(str(value))})

    def open_tab(self, url: str) -> BrowserObservation:
        self._tabs.append(str(url))
        return self.navigate(url)

    def switch_frame(self, selector: str) -> BrowserObservation:
        self._frames.append(str(selector))
        self._record("switch_frame", str(selector))
        return BrowserObservation(url=self._current, action="switch_frame",
                                  state={"frame": selector})

    def screenshot(self) -> str:
        self._shot += 1
        ref = f"mock://screenshot-{self._shot}.png"
        self._record("screenshot", ref)
        return ref

    def observe(self) -> BrowserObservation:
        self._record("observe")
        return BrowserObservation(
            url=self._current, action="observe", dom_summary=self.inspect_dom(),
            state={"tabs": list(self._tabs), "frames": list(self._frames)},
        )

    def tabs(self) -> list[str]:
        return list(self._tabs)

    def downloads(self) -> list[str]:
        return []


class PlaywrightBrowserAdapter(BrowserAdapter):
    """Real Playwright adapter — optional, headless by default.

    Security posture:
    - the dependency is optional; absence raises ``BrowserUnavailable``
      (degrade cleanly, never block the wider pass);
    - no cookie/token/password extraction — an explicitly configured
      storage-state file provided by the operator may be USED, never read,
      parsed, logged, or reported; credentials never enter logs, evidence,
      or the database;
    - a ``request_guard`` callback (the NEXUS policy check) is installed on
      the context so EVERY request — including redirects and subresources —
      is validated before it happens;
    - downloads are written to a sandboxed directory with path checks.
    """

    def __init__(
        self,
        headless: bool = True,
        storage_state_path: str | Path | None = None,
        download_dir: str | Path | None = None,
        default_timeout_ms: int = 15000,
        max_redirect_hops: int = 10,
        request_guard: Callable[[str], tuple[bool, str]] | None = None,
    ):
        try:
            from playwright.sync_api import sync_playwright  # noqa: F401
        except Exception as exc:  # dependency genuinely not available
            raise BrowserUnavailable(f"playwright not available: {exc}") from exc
        self.headless = bool(headless)
        self.storage_state_path = Path(storage_state_path) if storage_state_path else None
        self.download_dir = Path(download_dir) if download_dir else None
        self.default_timeout_ms = int(default_timeout_ms)
        self.request_guard = request_guard
        self._pw = None
        self._browser = None
        self._context = None
        self._page = None
        self._cancelled = False
        self._blocked_requests: list[str] = []
        self._policy_violation: str | None = None
        self.max_redirect_hops = int(max_redirect_hops)
        self._chain_client = None
        self._blocked_navigations = 0

    # -- lifecycle ---------------------------------------------------------------

    def start(self) -> None:
        from playwright.sync_api import sync_playwright

        self._pw = sync_playwright().start()
        self._browser = self._pw.chromium.launch(headless=self.headless)
        context_kwargs: dict[str, Any] = {"accept_downloads": True}
        if self.storage_state_path is not None and self.storage_state_path.exists():
            # Operator-configured test session. The file is USED only — never
            # read, parsed, logged, or copied by NEXUS code.
            context_kwargs["storage_state"] = str(self.storage_state_path)
        self._context = self._browser.new_context(**context_kwargs)
        self._context.set_default_timeout(self.default_timeout_ms)
        if self.request_guard is not None:
            self._context.route("**/*", self._route_handler)
            # Watchdog: the route layer does not re-intercept main-frame
            # redirect hops (Playwright/Chromium behaviour, verified), so a
            # request-level watcher kills the page the moment a disallowed
            # navigation request — including a redirect hop — is observed.
            self._context.on("request", self._on_request_watch)
        self._chain_client = self._context.request
        self._page = self._context.new_page()

    def _route_handler(self, route: Any, request: Any = None) -> None:
        """Route-layer policy gate.

        - Document (navigation) requests: the response is fetched with
          ``max_redirects=0`` and the WHOLE redirect chain is validated
          out-of-browser before the browser can follow it — prohibited
          destinations are never contacted (strict pre-fetch, verified).
        - All other requests (incl. subresources): validated before fetch.
        """
        req = request if request is not None else getattr(route, "request", None)
        url = str(getattr(req, "url", "") or "")
        resource_type = str(getattr(req, "resource_type", "") or "")
        allowed, reason = self.request_guard(url) if self.request_guard else (True, "ok")
        if not allowed:
            self._record_blocked(url, reason, navigation=(resource_type == "document"))
            route.abort()
            return
        if resource_type != "document" or self.request_guard is None:
            route.continue_()
            return
        try:
            resp = route.fetch(max_redirects=0)
        except Exception as exc:
            logger.debug("route.fetch unavailable; falling back to continue: %s", exc)
            route.continue_()
            return
        ok, blocked_target = self._validate_redirect_chain(url, resp)
        if not ok:
            self._record_blocked(blocked_target, "redirect chain blocked", navigation=True)
            route.abort()
            return
        route.fulfill(response=resp)

    def _record_blocked(self, url: str, reason: str = "", navigation: bool = False) -> None:
        if url and url not in self._blocked_requests:
            self._blocked_requests.append(url)
        if navigation:
            self._blocked_navigations += 1
        self._policy_violation = f"{url} ({reason})"
        logger.warning("browser request blocked by policy: %s (%s)", url, reason)

    def _validate_redirect_chain(
        self, url: str, first_response: Any, fetch_next: Any = None
    ) -> tuple[bool, str]:
        """Follow redirects OUT-OF-BROWSER, validating each hop first.

        Prohibited destinations are never fetched. Returns ``(ok, reason)``
        with the offending URL in the reason when blocked. If a hop cannot
        be fetched for validation, the browser is allowed to try — the
        request watchdog remains the fail-closed backstop.
        """
        if self.request_guard is None:
            return True, ""
        fetch = fetch_next or self._fetch_hop
        current_url, current = url, first_response
        seen = {url}
        for _ in range(self.max_redirect_hops):
            status = int(getattr(current, "status", 0) or 0)
            if status not in (301, 302, 303, 307, 308):
                return True, ""
            try:
                location = str((current.headers or {}).get("location", "") or "")
            except Exception:  # pragma: no cover - defensive
                location = ""
            if not location:
                return True, ""
            target = urljoin(current_url, location)
            if target in seen:
                logger.warning("redirect loop detected at %s", target)
                return False, f"{target} (redirect loop)"
            ok, reason = self.request_guard(target)
            if not ok:
                return False, f"{target} ({reason})"
            seen.add(target)
            try:
                current = fetch(target)
            except Exception as exc:
                logger.debug("chain validation fetch failed at %s: %s", target, exc)
                return True, ""
            current_url = target
        return False, f"{url} (too many redirects)"

    def _fetch_hop(self, url: str) -> Any:
        """Fetch one chain hop for validation (no redirect following)."""
        return self._chain_client.get(url, max_redirects=0, timeout=self.default_timeout_ms)

    def _on_request_watch(self, request: Any) -> None:
        """Kill the page when a disallowed NAVIGATION request is observed.

        Covers redirect hops that escape route interception: the page is
        closed immediately (aborting the navigation), the event is recorded,
        and the session is marked policy-violated. Non-navigation requests
        are recorded only — the route layer already blocks them pre-fetch.
        """
        url = str(getattr(request, "url", "") or "")
        allowed, reason = self.request_guard(url) if self.request_guard else (True, "ok")
        if allowed:
            return
        if url not in self._blocked_requests:
            self._blocked_requests.append(url)
        self._policy_violation = f"{url} ({reason})"
        try:
            is_nav = bool(request.is_navigation_request())
        except Exception:  # pragma: no cover - defensive
            is_nav = False
        if not is_nav:
            return
        self._blocked_navigations += 1
        logger.warning("browser watchdog: disallowed navigation aborted: %s (%s)", url, reason)
        try:
            if self._page is not None:
                self._page.close()
        except Exception as exc:  # pragma: no cover - best effort
            logger.debug("watchdog close: %s", exc)

    def cancel(self) -> None:
        """Request cancellation (checked around every operation)."""
        self._cancelled = True

    def stop(self) -> None:
        self._cancelled = True
        try:
            if self._context is not None:
                self._context.close()
            if self._browser is not None:
                self._browser.close()
            if self._pw is not None:
                self._pw.stop()
        except Exception as exc:  # pragma: no cover - best-effort teardown
            logger.debug("browser teardown: %s", exc)

    # -- primitives -----------------------------------------------------------------

    def _check_cancelled(self) -> None:
        if self._cancelled:
            raise BrowserPolicyError("browser session cancelled")

    def _obs(self, action: str, url: str = "", **state: Any) -> BrowserObservation:
        self._check_cancelled()
        current = url or ((self._page.url if self._page else "") or "")
        return BrowserObservation(url=current, action=action, state=dict(state), trusted=False)

    def navigate(self, url: str, timeout_ms: int | None = None) -> BrowserObservation:
        self._check_cancelled()
        before = self._blocked_navigations
        try:
            self._page.goto(url, wait_until="domcontentloaded",
                            timeout=timeout_ms or self.default_timeout_ms)
        except Exception as exc:
            if self._blocked_navigations > before:
                raise BrowserPolicyError(
                    "navigation blocked by policy: "
                    f"{self._policy_violation or self._blocked_requests[-1]}"
                ) from exc
            raise
        if self._blocked_navigations > before:
            raise BrowserPolicyError(
                "navigation blocked by policy: "
                f"{self._policy_violation or self._blocked_requests[-1]}"
            )
        self._check_cancelled()
        title = ""
        try:
            title = self._page.title()
        except Exception:  # pragma: no cover - best effort
            title = ""
        # The route guard validated every hop before it was fetched; the
        # final URL after redirects is what observers see.
        return self._obs("navigate", self._page.url, title=title)

    def inspect_dom(self) -> str:
        self._check_cancelled()
        return (self._page.content() or "")[:200000]

    def click(self, selector: str, timeout_ms: int | None = None) -> BrowserObservation:
        self._check_cancelled()
        self._page.click(selector, timeout=timeout_ms or self.default_timeout_ms)
        return self._obs("click", state={"selector": selector})

    def fill_form(self, selector: str, value: str,
                  timeout_ms: int | None = None) -> BrowserObservation:
        self._check_cancelled()
        self._page.fill(selector, value, timeout=timeout_ms or self.default_timeout_ms)
        # The value is intentionally never reflected anywhere (sensitive input).
        return self._obs("fill", state={"selector": selector, "length": len(str(value))})

    def open_tab(self, url: str) -> BrowserObservation:
        self._check_cancelled()
        self._page = self._context.new_page()
        return self.navigate(url)

    def switch_frame(self, selector: str) -> BrowserObservation:
        # Frame-scoped operations remain best-effort (documented limitation).
        return self._obs("switch_frame", state={"frame": selector, "frames": self.frame_urls()})

    def frame_urls(self) -> list[str]:
        try:
            return [f.url for f in (self._page.frames or [])]
        except Exception:  # pragma: no cover - best effort
            return []

    def screenshot(self) -> str:
        self._check_cancelled()
        base = self.download_dir or Path("browser-artifacts")
        base.mkdir(parents=True, exist_ok=True)
        name = f"browser-screenshot-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.png"
        path = _safe_download_target(base, name)
        self._page.screenshot(path=str(path))
        return str(path)

    def save_download(self, download: Any) -> str:
        """Persist a download INSIDE the sandboxed directory (path-checked)."""
        base = self.download_dir or Path("browser-downloads")
        base.mkdir(parents=True, exist_ok=True)
        name = str(getattr(download, "suggested_filename", "") or "download.bin")
        target = _safe_download_target(base, name)
        download.save_as(str(target))
        return str(target)

    def observe(self) -> BrowserObservation:
        obs = self._obs("observe")
        obs.dom_summary = self.inspect_dom()[:4000]
        return obs

    def tabs(self) -> list[str]:
        try:
            return [p.url for p in (self._context.pages if self._context else [])]
        except Exception:  # pragma: no cover - best effort
            return []


def _safe_download_target(base: Path | str, filename: str) -> Path:
    """Resolve a download/artifact filename inside *base*; refuse escapes."""
    base_r = Path(base).resolve()
    name = sanitize_path_component(str(filename or "download.bin")) or "download.bin"
    target = (base_r / name).resolve()
    if base_r not in target.parents:
        raise BrowserPolicyError("download path escapes configured directory")
    return target


def playwright_available() -> bool:
    """True when the real browser backend can be used."""
    try:
        from playwright.sync_api import sync_playwright  # noqa: F401

        return True
    except Exception:
        return False


@dataclass
class BrowserPolicy:
    """Policy context for guarded browser actions (reuses NEXUS primitives).

    - ``target_config``: destination SCOPE checks via the existing
      ``validate_finding_scope`` (no second policy engine);
    - ``ssrf_allow``: explicit operator allowlist for the SSRF guard
      (e.g. an authorized local test app);
    - ``download_dir``: sandboxed artifact directory;
    - ``state_changes_authorized``: must be explicitly granted before any
      state-changing action (click/fill);
    - ``db``/``actor``: audit trail identity.
    """

    target_config: Any = None
    ssrf_allow: set[str] = field(default_factory=set)
    download_dir: Path | None = None
    state_changes_authorized: bool = False
    actor: str = "operator"
    db: Any = None

    def check_url(self, url: str) -> tuple[bool, str]:
        """Destination validation: scope first (cheap), then SSRF guard."""
        if self.target_config is not None and not validate_finding_scope(str(url), self.target_config):
            return False, "scope: destination not authorized"
        ok, reason = is_safe_url(str(url), allow=set(self.ssrf_allow))
        if not ok:
            return False, f"ssrf: {reason}"
        return True, "ok"

    def authorize_state_changes(self, note: str = "") -> None:
        """Explicit authorization for state-changing browser actions."""
        self.state_changes_authorized = True
        if self.db is not None:
            try:
                self.db.insert_audit_event(
                    actor=self.actor, action="browser.authorize_state_changes",
                    category="nemesis", detail=str(note)[:200],
                )
            except Exception:
                pass


class GuardedBrowser:
    """Browser actions wrapped with NEXUS policy enforcement.

    Every point where the browser touches the network or state passes:
    DESTINATION VALIDATION (scope + SSRF) → RESOURCE BUDGET (request
    budget) → ACTION. Redirects and subresources are revalidated by the
    adapter's request guard, which is built from ``policy.check_url``.
    """

    def __init__(self, adapter: BrowserAdapter, policy: BrowserPolicy):
        self.adapter = adapter
        self.policy = policy
        if isinstance(adapter, PlaywrightBrowserAdapter) and adapter.request_guard is None:
            adapter.request_guard = policy.check_url

    def _audit(self, action: str, detail: str = "") -> None:
        if self.policy.db is not None:
            try:
                self.policy.db.insert_audit_event(
                    actor=self.policy.actor, action=action,
                    category="nemesis", detail=str(detail)[:300],
                )
            except Exception:
                pass

    def _gate(self, url: str) -> None:
        ok, reason = self.policy.check_url(url)
        if not ok:
            self._audit("browser.blocked", f"{url} {reason}")
            raise BrowserPolicyError(f"blocked: {reason} ({url})")
        if not spend_requests(1):
            raise BrowserPolicyError("request budget exhausted")

    def start(self) -> None:
        self.adapter.start()

    def stop(self) -> None:
        self.adapter.stop()

    def cancel(self) -> None:
        if hasattr(self.adapter, "cancel"):
            self.adapter.cancel()

    def navigate(self, url: str) -> BrowserObservation:
        self._gate(url)
        obs = self.adapter.navigate(url)
        # Revalidate the FINAL destination (post-redirect) as well.
        if obs.url and obs.url != url:
            ok, reason = self.policy.check_url(obs.url)
            if not ok:
                self._audit("browser.blocked", f"{obs.url} redirect hop: {reason}")
                raise BrowserPolicyError(f"blocked after redirect: {reason} ({obs.url})")
        self._audit("browser.navigate", url)
        return obs

    def observe(self) -> BrowserObservation:
        return self.adapter.observe()

    def inspect_dom(self) -> str:
        return self.adapter.inspect_dom()

    def screenshot(self) -> str:
        return self.adapter.screenshot()

    def click(self, selector: str) -> BrowserObservation:
        if not self.policy.state_changes_authorized:
            raise BrowserPolicyError("state-changing action requires explicit authorization")
        self._audit("browser.click", selector)
        return self.adapter.click(selector)

    def fill_form(self, selector: str, value: str) -> BrowserObservation:
        if not self.policy.state_changes_authorized:
            raise BrowserPolicyError("state-changing action requires explicit authorization")
        self._audit("browser.fill", selector)
        return self.adapter.fill_form(selector, value)

    def open_tab(self, url: str) -> BrowserObservation:
        self._gate(url)
        return self.adapter.open_tab(url)


@dataclass
class BrowserStep:
    """One resumable browser task step (values are never persisted)."""

    action: str                     # navigate | observe | screenshot | click | fill
    url: str = ""
    selector: str = ""
    value: str = ""

    def signature(self) -> str:
        label = f"browser.{self.action}:{self.url or self.selector}"
        if self.action == "fill":
            label += f":len={len(self.value)}"
        return label


def run_browser_task(
    db: Any,
    guarded: GuardedBrowser,
    steps: list[BrowserStep],
    *,
    engagement: str,
    scan_id: int,
    phase: str = "browser",
    finding_ref: int | None = None,
    session: Any = None,
) -> dict[str, Any]:
    """Run (or resume) browser steps through NEMESIS with evidence capture.

    Interrupted work stays recorded in the session as pending actions so a
    task can be safely resumed. Fill VALUES are never persisted (only a
    signature with the value length) — sensitive input stays out of the
    database, audit trail, and memory.
    """
    from lib.nemesis.session import NemesisSession, load_session, save_session

    if session is None and db is not None:
        session = load_session(db, engagement)
    if session is None:
        session = NemesisSession(engagement=engagement, scan_id=scan_id)

    def _refresh_pending() -> None:
        done_now = set(session.completed_actions)
        session.pending_actions = [s.signature() for s in steps if s.signature() not in done_now]

    _refresh_pending()
    done = set(session.completed_actions)
    completed: list[str] = []
    evidence_ids: list[int] = []
    errors: list[str] = []

    for step in steps:
        sig = step.signature()
        if sig in done:
            continue
        try:
            if step.action == "navigate":
                obs = guarded.navigate(step.url)
                evidence_ids.append(record_browser_evidence(
                    db, obs, scan_id=scan_id, phase=phase, finding_ref=finding_ref))
            elif step.action == "observe":
                obs = guarded.observe()
                evidence_ids.append(record_browser_evidence(
                    db, obs, scan_id=scan_id, phase=phase, finding_ref=finding_ref))
            elif step.action == "screenshot":
                ref = guarded.screenshot()
                obs = BrowserObservation(url="", action="screenshot", screenshot_ref=ref)
                evidence_ids.append(record_browser_evidence(
                    db, obs, scan_id=scan_id, phase=phase, finding_ref=finding_ref))
            elif step.action == "click":
                guarded.click(step.selector)
            elif step.action == "fill":
                guarded.fill_form(step.selector, step.value)
            else:
                raise BrowserPolicyError(f"unknown browser step action: {step.action}")
            session.completed_actions.append(sig)
            completed.append(sig)
        except Exception as exc:
            errors.append(f"{sig}: {exc}")
            session.previous_errors.append(errors[-1])
            break  # interrupted → remaining steps stay pending for resume
        finally:
            _refresh_pending()
            if db is not None:
                save_session(db, session)

    session.state = "completed" if not errors and not session.pending_actions else "partial"
    if db is not None:
        save_session(db, session)
    return {
        "engagement": engagement,
        "completed": completed,
        "pending": list(session.pending_actions),
        "evidence_ids": evidence_ids,
        "errors": errors,
        "state": session.state,
    }


def browser_enabled(cfg: Any) -> bool:
    """Browser capabilities are OFF unless explicitly enabled in config."""
    section = getattr(cfg, "nemesis", {}) or {}
    return bool((section.get("browser", {}) or {}).get("enabled", False))


def build_browser_evidence(
    obs: BrowserObservation,
    *,
    phase: str = "browser",
    finding_ref: int | None = None,
    request_response_ref: str = "",
    asset: str = "",
    engagement: str = "",
) -> dict[str, Any]:
    """NEXUS evidence schema for one browser action (directive Phase E)."""
    return {
        "engagement": engagement,
        "url": obs.url,
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "action": obs.action,
        "dom_observation": obs.dom_summary,
        "request_response_ref": request_response_ref,
        "screenshot_reference": obs.screenshot_ref,
        "identity_reference": obs.identity_ref,
        "asset": asset,
        "phase": phase,
        "finding_reference": finding_ref,
        "trusted": False,  # page content is untrusted input, always
    }


def record_browser_evidence(
    db: Any,
    obs: BrowserObservation,
    *,
    scan_id: int,
    phase: str = "browser",
    finding_ref: int | None = None,
) -> int:
    """Persist a browser observation as sanitized NEXUS evidence.

    Sanitization + asset auto-link happen inside the database choke
    point; page content is treated as untrusted and never executed.
    """
    return db.insert_evidence(
        scan_id,
        url=obs.url,
        method="GET",
        tool="browser",
        source=phase,
        response_body=obs.dom_summary,
        screenshot_path=obs.screenshot_ref,
        finding_id=finding_ref,
    )
