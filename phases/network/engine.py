"""Pass 5 — bounded TCP discovery + minimal service identification engine.

Deterministic and non-destructive:

- TCP connect states only (open / closed / filtered);
- passive banner reads (one bounded recv, read-only);
- one-shot TLS metadata (single handshake, read-only);
- one read-only ``GET /`` HTTP probe for web-ish ports.

No payloads, no credentials, no exploitation, no data extraction.
Scope authorization happens in the orchestrator BEFORE any connection;
the engine re-checks an injected authorization callback for every task.
"""
from __future__ import annotations

import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any, Callable

from lib.logger import get_logger
from lib.ops_guard import spend_requests

logger = get_logger("net_engine")

# Conservative default port set (explicitly conservative; never a range sweep).
DEFAULT_PORTS: tuple[int, ...] = (
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 587, 993, 995,
    1433, 1521, 2049, 3306, 3389, 5432, 5601, 5900, 6379, 8000, 8080, 8443, 9200, 11211,
)
WEB_PLAIN_PORTS = frozenset({80, 8000, 8080, 8888})
WEB_TLS_PORTS = frozenset({443, 8443})
BANNER_PORTS = frozenset({21, 22, 23, 25, 110, 143, 587, 993, 995})
MAX_BANNER_BYTES = 256
MAX_HTTP_BYTES = 4096


@dataclass
class NetSettings:
    """Bounded scan settings (clamped by the orchestrator)."""

    ports: tuple[int, ...] = DEFAULT_PORTS
    concurrency: int = 16
    connect_timeout: float = 1.5
    probe_timeout: float = 2.0
    max_ports_per_ip: int = 512
    allow_private: bool = False
    over_cap: int = 0


@dataclass
class PortResult:
    """One IP/port outcome."""

    ip: str
    port: int
    state: str = "untested"          # open | closed | filtered | skipped | untested
    service: str = ""
    banner: str = ""
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip, "port": self.port, "state": self.state,
            "service": self.service, "banner": self.banner, "meta": dict(self.meta),
        }


def parse_ports(spec: Any, max_ports: int = 512) -> tuple[list[int], int]:
    """Expand a port spec (ints, ``"80"``, ``"8000-8100"``) → (ports, over_cap).

    Invalid entries are ignored; ``over_cap`` counts ports dropped by the cap.
    """
    wanted: set[int] = set()
    if spec is None or spec == () or spec == []:
        spec = DEFAULT_PORTS
    if isinstance(spec, (int, str)):
        spec = [spec]
    for item in spec:
        text = str(item).strip()
        if not text:
            continue
        if "-" in text:
            lo_s, _, hi_s = text.partition("-")
            try:
                lo, hi = int(lo_s), int(hi_s)
            except ValueError:
                continue
            for port in range(max(lo, 1), min(hi, 65535) + 1):
                wanted.add(port)
        else:
            try:
                port = int(text)
            except ValueError:
                continue
            if 1 <= port <= 65535:
                wanted.add(port)
    ordered = sorted(wanted)
    over_cap = max(0, len(ordered) - int(max_ports))
    return ordered[: int(max_ports)], over_cap


class NetworkEngine:
    """Bounded connector with injectable hooks (deterministic in tests)."""

    def __init__(
        self,
        settings: NetSettings,
        connect: Callable[[str, int, float], str] | None = None,
        cancel_event: Any | None = None,
        killed: Callable[[], bool] | None = None,
    ):
        self.settings = settings
        self._connect = connect or self._tcp_state
        self.cancel_event = cancel_event
        self._killed = killed or (lambda: False)

    # -- control ---------------------------------------------------------------

    def cancelled(self) -> bool:
        if self.cancel_event is not None and self.cancel_event.is_set():
            return True
        try:
            return bool(self._killed())
        except Exception:  # pragma: no cover - defensive
            return False

    # -- primitives --------------------------------------------------------------

    def _tcp_state(self, ip: str, port: int, timeout: float) -> str:
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((ip, port))
            return "open"
        except (socket.timeout, TimeoutError):
            return "filtered"
        except ConnectionRefusedError:
            return "closed"
        except OSError:
            return "filtered"
        finally:
            try:
                sock.close()
            except OSError:
                pass

    # -- scan ---------------------------------------------------------------------

    def scan(
        self,
        ip: str,
        ports: list[int],
        per_task_check: Callable[[str, int], bool] | None = None,
    ) -> list[PortResult]:
        """Scan one IP; returns results in plan order.

        Budget: one request spend per attempted connect. Cancellation and the
        kill switch leave the remainder ``untested``; per-task authorization
        failures are ``skipped``.
        """
        settings = self.settings
        results: dict[int, PortResult] = {}
        pending: list[int] = []
        for port in ports:
            if self.cancelled():
                results[port] = PortResult(ip, port, "untested")
            else:
                pending.append(port)

        with ThreadPoolExecutor(max_workers=max(1, int(settings.concurrency))) as pool:
            futures = {}
            for port in pending:
                futures[pool.submit(self._scan_one, ip, port, per_task_check)] = port
            for future in as_completed(futures):
                port = futures[future]
                try:
                    results[port] = future.result()
                except Exception as exc:  # pragma: no cover - defensive
                    logger.debug("scan task %s:%s failed: %s", ip, port, exc)
                    results[port] = PortResult(ip, port, "filtered")

        return [results[p] for p in ports if p in results]

    def _scan_one(
        self, ip: str, port: int, per_task_check: Callable[[str, int], bool] | None
    ) -> PortResult:
        if self.cancelled():
            return PortResult(ip, port, "untested")
        if per_task_check is not None:
            try:
                if not per_task_check(ip, port):
                    return PortResult(ip, port, "skipped")
            except Exception:  # scope re-check failure fails closed
                return PortResult(ip, port, "skipped")
        if not spend_requests(1):
            return PortResult(ip, port, "skipped")
        state = self._connect(ip, port, float(self.settings.connect_timeout))
        return PortResult(ip, port, state if state in ("open", "closed", "filtered") else "filtered")

    # -- service identification (post-open only; minimal and read-only) ------------

    def identify(self, result: PortResult) -> PortResult:
        """Enrich an open port with service/banner metadata (never raises)."""
        if result.state != "open":
            return result
        try:
            if result.port in WEB_TLS_PORTS:
                self._identify_https(result)
            elif result.port in WEB_PLAIN_PORTS:
                self._identify_http(result)
            elif result.port in BANNER_PORTS:
                self._identify_banner(result)
            else:
                self._identify_banner(result, optional=True)
        except Exception as exc:  # malformed/unexpected responses never abort
            logger.debug("service id failed for %s:%s: %s", result.ip, result.port, exc)
            if not result.service:
                result.service = "unknown"
        return result

    def _identify_banner(self, result: PortResult, optional: bool = False) -> None:
        banner = self._read_banner(result.ip, result.port)
        if not banner:
            if not optional:
                result.service = "unknown"
            return
        result.banner = banner
        result.service = _guess_service(result.port, banner)

    def _identify_http(self, result: PortResult) -> None:
        info = self._http_probe(result.ip, result.port, tls=False)
        if info:
            result.service = "http"
            result.meta.update(info)
            result.banner = str(info.get("server", ""))[:MAX_BANNER_BYTES]
        else:
            result.service = "unknown"

    def _identify_https(self, result: PortResult) -> None:
        tls = self._tls_meta(result.ip, result.port)
        info = self._http_probe(result.ip, result.port, tls=True)
        result.service = "https"
        if tls:
            result.meta.update(tls)
            if str(tls.get("protocol", "")) in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
                result.meta["legacy_tls"] = True
        if info:
            result.meta.update({f"http_{k}": v for k, v in info.items()})
            result.banner = str(info.get("server", ""))[:MAX_BANNER_BYTES]

    def _read_banner(self, ip: str, port: int) -> str:
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(float(self.settings.probe_timeout))
        try:
            sock.connect((ip, port))
            data = sock.recv(MAX_BANNER_BYTES)
            return data.decode("utf-8", errors="replace").strip()[:MAX_BANNER_BYTES]
        except (socket.timeout, TimeoutError, OSError):
            return ""
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def _tls_meta(self, ip: str, port: int) -> dict[str, Any]:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(float(self.settings.probe_timeout))
        try:
            sock.connect((ip, port))
            with ctx.wrap_socket(sock, server_hostname=None) as tls:
                cert = tls.getpeercert() or {}
                return {
                    "protocol": tls.version() or "",
                    "cipher": (tls.cipher() or ("",))[0],
                    "subject": str(cert.get("subject", "")),
                    "not_after": str(cert.get("notAfter", "")),
                }
        except (socket.timeout, TimeoutError, ssl.SSLError, OSError):
            return {}
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def _http_probe(self, ip: str, port: int, tls: bool = False) -> dict[str, Any]:
        family = socket.AF_INET6 if ":" in ip else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(float(self.settings.probe_timeout))
        try:
            sock.connect((ip, port))
            stream: Any = sock
            if tls:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                stream = ctx.wrap_socket(sock, server_hostname=None)
            request = (
                f"GET / HTTP/1.1\r\nHost: {ip}\r\nUser-Agent: NEXUS-NetProbe/1.0\r\n"
                "Accept: */*\r\nConnection: close\r\n\r\n"
            )
            stream.sendall(request.encode("ascii", errors="ignore"))
            chunks = []
            total = 0
            while total < MAX_HTTP_BYTES:
                data = stream.recv(1024)
                if not data:
                    break
                chunks.append(data)
                total += len(data)
            text = b"".join(chunks).decode("utf-8", errors="replace")
            status_line, _, rest = text.partition("\r\n")
            info: dict[str, Any] = {"status": status_line.strip()[:120]}
            for line in rest.split("\r\n"):
                key, _, value = line.partition(":")
                key_l = key.strip().lower()
                if key_l in ("server", "content-type", "location", "x-powered-by"):
                    info[key_l] = value.strip()[:MAX_BANNER_BYTES]
            return info
        except (socket.timeout, TimeoutError, ssl.SSLError, OSError):
            return {}
        finally:
            try:
                sock.close()
            except OSError:
                pass


def _guess_service(port: int, banner: str) -> str:
    lower = banner.lower()
    if lower.startswith("ssh-"):
        return "ssh"
    if lower.startswith("220") and "ftp" in lower:
        return "ftp"
    if lower.startswith("220"):
        return "smtp"
    if lower.startswith("+ok"):
        return "pop3"
    if lower.startswith("* ok"):
        return "imap"
    if port == 21:
        return "ftp"
    if port == 22:
        return "ssh"
    if port == 25:
        return "smtp"
    if port == 110:
        return "pop3"
    if port == 143:
        return "imap"
    return "unknown"
