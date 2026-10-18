"""Secure MCP (Model Context Protocol) client and tool gateway (Task 21).

NEXUS can act as an MCP *client*: connect to explicitly-configured MCP
servers, discover their tools, and invoke them — but only through NEXUS
policy. The module is deliberately layered:

    protocol  — JSON-RPC 2.0 constants, errors, schema validation, value objects
    transport — stdio / Streamable HTTP / fake (injectable) message delivery
    client    — MCP lifecycle over an injected transport (initialize/tools)
    gateway   — policy: allowlists, scope, SSRF, approval, bounds, audit
    mock      — deterministic offline server/client for tests

Supported transports are stdio and Streamable HTTP; the deprecated HTTP+SSE
transport and the 2026-07-28 stateless revision are not implemented (see
``docs/MCP.md``).
"""
from __future__ import annotations

__all__ = ["protocol", "transport", "client", "gateway", "mock"]
