"""MCP transports — the pluggable byte-moving layer.

A transport only *delivers* JSON-RPC messages; it never decides policy. Three
implementations ship:

- :class:`StdioTransport`   — launches a local MCP server as a subprocess and
  speaks newline-delimited JSON over its stdin/stdout. The command is an
  explicit argv **list** (never a shell string) and is re-validated by
  :func:`lib.payload_guard.validate_tool_command` before launch.
- :class:`StreamableHttpTransport` — POSTs each JSON-RPC message to a single
  MCP endpoint over HTTPS/HTTP, guarded by the SSRF allowlist, with redirects
  disabled.
- :class:`FakeTransport` — deterministic in-memory transport driving an
  injected server callable (offline tests / ``nexus mcp --mock``).

SSE is intentionally **not** implemented (it is deprecated in favour of
Streamable HTTP); see ``docs/MCP.md`` for the supported-transport statement.
"""
from __future__ import annotations

import json
import queue
import subprocess
import threading
from abc import ABC, abstractmethod
from typing import Any, Callable, Sequence

from lib.logger import get_logger
from lib.mcp.protocol import (
    McpConnectionError,
    McpPolicyError,
    McpProtocolError,
    McpTimeoutError,
    McpTransportError,
    decode_message,
    rpc_error,
)
from lib.payload_guard import validate_tool_command
from lib.redaction import redact_text
from lib.ssrf_guard import is_safe_url

logger = get_logger("mcp.transport")

#: Hard cap on a single message from a server (protects against a hostile or
#: runaway server); callers may request a smaller bound.
DEFAULT_MAX_MESSAGE_BYTES = 1_048_576
DEFAULT_TIMEOUT = 30.0


class McpTransport(ABC):
    """Base transport contract (synchronous request/response)."""

    kind = "transport"

    @abstractmethod
    def start(self) -> None:
        """Open the transport (spawn process / validate endpoint)."""

    @abstractmethod
    def request(self, message: dict[str, Any], timeout: float = DEFAULT_TIMEOUT) -> dict[str, Any]:
        """Send a JSON-RPC *request* and return the matching response object."""

    @abstractmethod
    def notify(self, message: dict[str, Any]) -> None:
        """Send a JSON-RPC notification (no response expected)."""

    def close(self) -> None:
        """Release resources (default: nothing)."""

    def describe(self) -> dict[str, Any]:
        """Return a secret-free description of the transport."""
        return {"kind": self.kind}


class StdioTransport(McpTransport):
    """Newline-delimited JSON-RPC over a local subprocess' stdio."""

    kind = "stdio"

    def __init__(
        self,
        command: Sequence[str],
        *,
        timeout: float = DEFAULT_TIMEOUT,
        env: dict[str, str] | None = None,
        max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES,
    ):
        self.command = [str(part) for part in (command or ())]
        self.timeout = float(timeout)
        self.env_extra = dict(env or {})
        self.max_message_bytes = int(max_message_bytes)
        self._proc: subprocess.Popen[str] | None = None
        self._lines: "queue.Queue[str | None]" = queue.Queue()
        self._reader: threading.Thread | None = None
        self._stderr_reader: threading.Thread | None = None

    # -- lifecycle ----------------------------------------------------------

    def start(self) -> None:
        if self._proc is not None:
            return
        if not self.command:
            raise McpPolicyError("stdio transport requires a command")
        allowed, reason = validate_tool_command(self.command)
        if not allowed:
            raise McpPolicyError(f"stdio command refused by safety guard: {reason}")
        import os

        env = dict(os.environ)
        env.update(self.env_extra)
        try:
            self._proc = subprocess.Popen(  # noqa: S603 - argv list, shell=False
                self.command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                shell=False,
                env=env,
                encoding="utf-8",
                errors="replace",
            )
        except OSError as exc:
            raise McpConnectionError(
                f"could not start stdio MCP server: {exc.__class__.__name__}"
            ) from exc

        self._reader = threading.Thread(target=self._pump_stdout, daemon=True)
        self._reader.start()
        self._stderr_reader = threading.Thread(target=self._pump_stderr, daemon=True)
        self._stderr_reader.start()

    def _pump_stdout(self) -> None:
        proc = self._proc
        assert proc is not None and proc.stdout is not None
        try:
            for line in proc.stdout:
                self._lines.put(line)
        finally:
            self._lines.put(None)

    def _pump_stderr(self) -> None:
        proc = self._proc
        assert proc is not None and proc.stderr is not None
        for line in proc.stderr:
            stripped = line.rstrip("\n")
            if stripped:
                logger.debug("mcp stdio stderr: %s", redact_text(stripped))

    # -- messaging ----------------------------------------------------------

    def _write(self, message: dict[str, Any]) -> None:
        proc = self._proc
        if proc is None or proc.stdin is None or proc.poll() is not None:
            raise McpConnectionError("stdio MCP server is not running")
        data = json.dumps(message, separators=(",", ":"))
        if len(data.encode("utf-8")) > self.max_message_bytes:
            raise McpProtocolError("outgoing MCP message exceeds size limit")
        try:
            proc.stdin.write(data + "\n")
            proc.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise McpConnectionError("stdio MCP server closed the pipe") from exc

    def notify(self, message: dict[str, Any]) -> None:
        self._write(message)

    def request(self, message: dict[str, Any], timeout: float = DEFAULT_TIMEOUT) -> dict[str, Any]:
        if self._proc is None:
            raise McpConnectionError("stdio transport not started")
        self._write(message)
        deadline = timeout if timeout and timeout > 0 else self.timeout
        import time as _time

        start = _time.monotonic()
        while True:
            remaining = deadline - (_time.monotonic() - start)
            if remaining <= 0:
                raise McpTimeoutError("timed out waiting for MCP server response")
            try:
                line = self._lines.get(timeout=remaining)
            except queue.Empty as exc:
                raise McpTimeoutError("timed out waiting for MCP server response") from exc
            if line is None:
                raise McpConnectionError("MCP server exited before responding")
            text = line.strip()
            if not text:
                continue
            if len(text.encode("utf-8")) > self.max_message_bytes:
                raise McpProtocolError("incoming MCP message exceeds size limit")
            try:
                payload = json.loads(text)
            except ValueError as exc:
                raise McpProtocolError("MCP server sent malformed JSON") from exc
            payload = decode_message(payload)
            if "id" in payload and payload["id"] == message.get("id"):
                if "error" in payload:
                    raise rpc_error(payload)
                return payload
            # A notification or an unrelated response — ignore and keep reading.
            logger.debug("mcp stdio ignoring out-of-band message")

    def close(self) -> None:
        proc = self._proc
        self._proc = None
        if proc is None:
            return
        try:
            if proc.stdin is not None:
                proc.stdin.close()
        except OSError:
            pass
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:  # pragma: no cover - defensive
                    pass
        for stream in (proc.stdout, proc.stderr):
            try:
                if stream is not None:
                    stream.close()
            except OSError:
                pass

    def describe(self) -> dict[str, Any]:
        return {"kind": self.kind, "command": list(self.command)}


class StreamableHttpTransport(McpTransport):
    """JSON-RPC over HTTP POST to a single MCP endpoint (Streamable HTTP).

    Only the client half of the transport is implemented: each request is one
    POST, and a JSON or request-scoped SSE response is accepted. Per spec the
    URL is treated as operator-configured but still passes the SSRF guard, and
    redirects are refused (a redirect could smuggle a request to a blocked
    host).
    """

    kind = "streamable-http"

    def __init__(
        self,
        url: str,
        *,
        token: str = "",
        timeout: float = DEFAULT_TIMEOUT,
        protocol_version: str = "",
        ssrf_allow: set[str] | None = None,
        max_message_bytes: int = DEFAULT_MAX_MESSAGE_BYTES,
    ):
        self.url = (url or "").strip()
        self.token = token or ""
        self.timeout = float(timeout)
        self.protocol_version = protocol_version
        self.ssrf_allow = set(ssrf_allow or set())
        self.max_message_bytes = int(max_message_bytes)

    def start(self) -> None:
        if not self.url:
            raise McpPolicyError("streamable-http transport requires a url")
        safe, reason = is_safe_url(self.url, allow=self.ssrf_allow, local_ok=True)
        if not safe:
            raise McpPolicyError(f"streamable-http endpoint blocked by SSRF guard: {reason}")

    def _headers(self, message: dict[str, Any]) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        version = self.protocol_version or ""
        if version:
            headers["MCP-Protocol-Version"] = version
        method = str(message.get("method") or "")
        if method:
            headers["Mcp-Method"] = method
        params = message.get("params") or {}
        name = params.get("name") if isinstance(params, dict) else None
        if isinstance(name, str) and name:
            headers["Mcp-Name"] = name
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    def _post(self, message: dict[str, Any], timeout: float) -> tuple[int, str, str]:
        import requests

        try:
            resp = requests.post(
                self.url,
                data=json.dumps(message, separators=(",", ":")),
                headers=self._headers(message),
                timeout=(min(self.timeout, 10.0), timeout),
                allow_redirects=False,
            )
        except requests.Timeout as exc:
            raise McpTimeoutError("streamable-http request timed out") from exc
        except requests.RequestException as exc:
            raise McpConnectionError(
                f"streamable-http unreachable: {exc.__class__.__name__}"
            ) from exc
        content_type = str(resp.headers.get("Content-Type", "")).split(";")[0].strip().lower()
        return int(resp.status_code), content_type, resp.text or ""

    @staticmethod
    def _parse_sse(text: str, request_id: Any) -> dict[str, Any] | None:
        for block in text.replace("\r\n", "\n").split("\n\n"):
            data_lines = [
                line[5:].strip()
                for line in block.splitlines()
                if line.startswith("data:")
            ]
            if not data_lines:
                continue
            try:
                payload = json.loads("\n".join(data_lines))
            except ValueError:
                continue
            if isinstance(payload, dict) and payload.get("id") == request_id:
                return payload
        return None

    def request(self, message: dict[str, Any], timeout: float = DEFAULT_TIMEOUT) -> dict[str, Any]:
        deadline = timeout if timeout and timeout > 0 else self.timeout
        status, content_type, text = self._post(message, deadline)
        if status in (401, 403):
            raise McpTransportError(f"streamable-http authentication failed (HTTP {status})")
        if 300 <= status < 400:
            raise McpProtocolError("streamable-http server tried to redirect; refused")
        if status >= 400:
            raise McpProtocolError(f"streamable-http server returned HTTP {status}")
        if len(text.encode("utf-8")) > self.max_message_bytes:
            raise McpProtocolError("streamable-http response exceeds size limit")

        if content_type == "text/event-stream" or text.lstrip().startswith("event:"):
            payload = self._parse_sse(text, message.get("id"))
            if payload is None:
                raise McpProtocolError("streamable-http SSE stream had no matching response")
        else:
            try:
                payload = json.loads(text) if text.strip() else {}
            except ValueError as exc:
                raise McpProtocolError("streamable-http server sent malformed JSON") from exc
        payload = decode_message(payload)
        if "error" in payload:
            raise rpc_error(payload)
        return payload

    def notify(self, message: dict[str, Any]) -> None:
        status, _content_type, _text = self._post(message, min(self.timeout, 10.0))
        if status >= 400 and status not in (202,):
            raise McpProtocolError(f"streamable-http notification rejected (HTTP {status})")

    def describe(self) -> dict[str, Any]:
        from urllib.parse import urlsplit

        try:
            parts = urlsplit(self.url)
            host = parts.hostname or ""
            label = f"{parts.scheme}://{host}"
        except ValueError:
            label = "invalid"
        return {"kind": self.kind, "endpoint": label, "auth": "bearer" if self.token else "none"}


class FakeTransport(McpTransport):
    """In-memory transport backed by an injected server callable.

    ``server(message) -> response | None`` where ``response`` is a JSON-RPC
    object (or ``None`` for a notification). Records every message it saw so
    tests can assert on the wire conversation.
    """

    kind = "fake"

    def __init__(self, server: Callable[[dict[str, Any]], dict[str, Any] | None]):
        self._server = server
        self.sent: list[dict[str, Any]] = []
        self.started = False
        self.closed = False
        self.fail_start: str = ""

    def start(self) -> None:
        if self.fail_start:
            raise McpConnectionError(self.fail_start)
        self.started = True

    def request(self, message: dict[str, Any], timeout: float = DEFAULT_TIMEOUT) -> dict[str, Any]:
        if not self.started:
            raise McpConnectionError("transport not started")
        self.sent.append(dict(message))
        response = self._server(dict(message))
        if response is None:
            raise McpConnectionError("fake server produced no response")
        return decode_message(response)

    def notify(self, message: dict[str, Any]) -> None:
        self.sent.append(dict(message))
        self._server(dict(message))

    def close(self) -> None:
        self.closed = True

    def describe(self) -> dict[str, Any]:
        return {"kind": self.kind}
