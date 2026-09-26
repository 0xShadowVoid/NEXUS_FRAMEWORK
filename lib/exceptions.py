"""Shared exception types for the NEXUS framework."""
from __future__ import annotations


class NexusError(Exception):
    """Base class for all NEXUS errors."""


class ConfigError(NexusError):
    """Raised when configuration files are missing or invalid."""


class ScopeException(NexusError):
    """Raised when a target or finding violates the scope boundary.

    Part of the NEXUS security boundary enforcement: out-of-scope
    targets must not be scanned and out-of-scope findings must not
    be reported.
    """


class PayloadGuardError(NexusError):
    """Raised when a payload violates the security boundary.

    Destructive SQL, reverse shells, download-and-execute payloads
    and similar harmful payloads are blocked before they can reach
    any tool runner.
    """


class ToolRunnerError(NexusError):
    """Raised when an external tool invocation fails."""


class NotificationError(NexusError):
    """Raised when an alert channel fails (best-effort, usually logged)."""
