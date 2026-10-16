"""AI provider error classification and retry/failover policy.

A dedicated layer that turns an HTTP status (or a transport exception)
into a **category** and a **decision** so the analyzer never retries
permanent failures blindly and never rotates a key to evade a genuine
quota or usage restriction.

Categories (never carry secret values):

    invalid_credentials  — 401/403 credential rejection; retire the key
    rate_limit           — 429 (transient); sideline the key, back off
    quota_exhausted      — 402/quota 429; account-level, skip the provider
    outage               — 5xx / connection errors; transient, back off
    timeout              — read/connect timeout; transient, retry
    unsupported_model    — 400/404 model/param errors; skip the provider
    invalid_request      — 400 malformed request; do not retry the same call
    permission           — 403 without quota hints; skip the provider
    unknown              — anything else; bounded single retry

The policy is data, not control flow: :func:`classify_status` and
:func:`classify_exception` are pure and unit-testable.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

import requests


class AIErrorClass(str, Enum):
    """Stable error categories shared by the key pool and analyzer."""

    INVALID_CREDENTIALS = "invalid_credentials"
    RATE_LIMIT = "rate_limit"
    QUOTA_EXHAUSTED = "quota_exhausted"
    OUTAGE = "outage"
    TIMEOUT = "timeout"
    UNSUPPORTED_MODEL = "unsupported_model"
    INVALID_REQUEST = "invalid_request"
    PERMISSION = "permission"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ErrorDecision:
    """What the caller should do after an error of a given class."""

    error_class: AIErrorClass
    retire_key: bool = False       # mark the key permanently dead
    cool_key: bool = False         # sideline the key with a cooldown
    skip_provider: bool = False    # stop using this provider for the run
    retry: bool = False            # retry within the same provider (backoff)
    fatal: bool = False            # give up entirely (no further providers)
    detail: str = ""


#: Classes worth retrying with exponential backoff before failing over.
TRANSIENT_CLASSES = frozenset(
    {AIErrorClass.RATE_LIMIT, AIErrorClass.OUTAGE, AIErrorClass.TIMEOUT}
)

#: Classes that are permanent for the current run — never blindly retried.
PERMANENT_CLASSES = frozenset(
    {
        AIErrorClass.INVALID_CREDENTIALS,
        AIErrorClass.QUOTA_EXHAUSTED,
        AIErrorClass.UNSUPPORTED_MODEL,
        AIErrorClass.INVALID_REQUEST,
        AIErrorClass.PERMISSION,
    }
)

_POLICY: dict[AIErrorClass, ErrorDecision] = {
    AIErrorClass.INVALID_CREDENTIALS: ErrorDecision(
        AIErrorClass.INVALID_CREDENTIALS, retire_key=True,
        detail="credential rejected",
    ),
    AIErrorClass.RATE_LIMIT: ErrorDecision(
        AIErrorClass.RATE_LIMIT, cool_key=True, retry=True,
        detail="rate limited",
    ),
    AIErrorClass.QUOTA_EXHAUSTED: ErrorDecision(
        AIErrorClass.QUOTA_EXHAUSTED, cool_key=True, skip_provider=True,
        detail="quota exhausted",
    ),
    AIErrorClass.OUTAGE: ErrorDecision(
        AIErrorClass.OUTAGE, retry=True, skip_provider=False,
        detail="provider outage",
    ),
    AIErrorClass.TIMEOUT: ErrorDecision(
        AIErrorClass.TIMEOUT, retry=True, detail="timeout",
    ),
    AIErrorClass.UNSUPPORTED_MODEL: ErrorDecision(
        AIErrorClass.UNSUPPORTED_MODEL, skip_provider=True,
        detail="unsupported model or parameter",
    ),
    AIErrorClass.INVALID_REQUEST: ErrorDecision(
        AIErrorClass.INVALID_REQUEST, skip_provider=True,
        detail="invalid request",
    ),
    AIErrorClass.PERMISSION: ErrorDecision(
        AIErrorClass.PERMISSION, skip_provider=True, detail="permission denied",
    ),
    AIErrorClass.UNKNOWN: ErrorDecision(
        AIErrorClass.UNKNOWN, retry=True, detail="unknown error",
    ),
}

_QUOTA_HINTS = (
    "quota",
    "insufficient_quota",
    "billing",
    "exceeded your current",
    "out of credits",
    "payment required",
    "resource_exhausted",
)

_MODEL_HINTS = ("model", "does not exist", "not found", "unsupported", "invalid model")


def decision_for(error_class: AIErrorClass) -> ErrorDecision:
    """Return the policy decision for *error_class*."""
    return _POLICY.get(error_class, _POLICY[AIErrorClass.UNKNOWN])


def classify_status(status_code: int, body: str = "") -> AIErrorClass:
    """Map an HTTP status (plus optional response body) to a category."""
    text = (body or "").lower()
    if status_code == 401:
        return AIErrorClass.INVALID_CREDENTIALS
    if status_code == 402:
        return AIErrorClass.QUOTA_EXHAUSTED
    if status_code == 408:
        return AIErrorClass.TIMEOUT
    if status_code == 429:
        if any(h in text for h in _QUOTA_HINTS):
            return AIErrorClass.QUOTA_EXHAUSTED
        return AIErrorClass.RATE_LIMIT
    if status_code == 403:
        if any(h in text for h in _QUOTA_HINTS):
            return AIErrorClass.QUOTA_EXHAUSTED
        return AIErrorClass.PERMISSION
    if status_code == 404:
        return AIErrorClass.UNSUPPORTED_MODEL
    if status_code == 400:
        if any(h in text for h in _MODEL_HINTS):
            return AIErrorClass.UNSUPPORTED_MODEL
        return AIErrorClass.INVALID_REQUEST
    if status_code in (413, 422):
        return AIErrorClass.INVALID_REQUEST
    if 500 <= status_code <= 599:
        return AIErrorClass.OUTAGE
    return AIErrorClass.UNKNOWN


def classify_exception(exc: BaseException) -> AIErrorClass:
    """Map a transport exception to a category."""
    if isinstance(exc, requests.exceptions.Timeout):
        return AIErrorClass.TIMEOUT
    if isinstance(exc, requests.exceptions.ConnectionError):
        return AIErrorClass.OUTAGE
    if isinstance(exc, requests.exceptions.RequestException):
        return AIErrorClass.OUTAGE
    return AIErrorClass.UNKNOWN
