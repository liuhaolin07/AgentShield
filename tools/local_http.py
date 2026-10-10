"""Opt-in loopback transport for synthetic security experiments only.

This transport is a separate safety boundary, not an AgentShield decision.
It never resolves DNS, uses proxies, follows redirects, or changes its target.
"""

import hashlib
import socket
from dataclasses import dataclass
from http.client import HTTPConnection, HTTPException
from urllib.parse import urlsplit


MAX_BODY_BYTES = 256 * 1024


@dataclass(frozen=True)
class HTTPReceipt:
    """A response receipt; receiver arrival must still be observed separately."""

    status: int
    body_bytes: int
    body_sha256: str


class LocalTransportError(RuntimeError):
    """A rejection or failure attributed to the local transport, not policy."""

    def __init__(self, reason: str, receipt: HTTPReceipt | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.receipt = receipt


class _PinnedConnection(HTTPConnection):
    def connect(self) -> None:
        # Numeric AF_INET connect avoids getaddrinfo and hostname resolution.
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            connection.settimeout(self.timeout)
            connection.connect(("127.0.0.1", self.port))
        except OSError:
            connection.close()
            raise
        self.sock = connection


@dataclass(frozen=True)
class LocalHTTPTarget:
    """One explicitly configured IPv4 loopback port for a test receiver."""

    port: int

    def __post_init__(self) -> None:
        if type(self.port) is not int or not 1 <= self.port <= 65535:
            raise ValueError("A loopback receiver port from 1 to 65535 is required")

    @property
    def origin(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def send(self, url: str, data: str) -> HTTPReceipt:
        """POST synthetic text to the pinned origin, with a two-second timeout."""
        if not isinstance(url, str) or not isinstance(data, str):
            raise LocalTransportError("invalid_arguments")
        if any(ord(char) <= 32 or ord(char) >= 127 for char in url) or "\\" in url:
            raise LocalTransportError("invalid_url")
        try:
            parsed = urlsplit(url)
        except ValueError as error:
            raise LocalTransportError("invalid_url") from error
        if (
            parsed.scheme != "http"
            or parsed.netloc != f"127.0.0.1:{self.port}"
            or parsed.fragment
        ):
            raise LocalTransportError("target_not_pinned_loopback")
        try:
            body = data.encode("utf-8")
        except UnicodeError as error:
            raise LocalTransportError("invalid_payload_encoding") from error
        if len(body) > MAX_BODY_BYTES:
            raise LocalTransportError("payload_too_large")
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"
        connection = _PinnedConnection("127.0.0.1", self.port, timeout=2.0)
        try:
            connection.request(
                "POST", path, body=body,
                headers={"Content-Type": "text/plain; charset=utf-8"},
            )
            response = connection.getresponse()
            receipt = HTTPReceipt(
                response.status, len(body), hashlib.sha256(body).hexdigest(),
            )
            response.read(4096)
        except (OSError, HTTPException) as error:
            raise LocalTransportError("connection_unavailable") from error
        finally:
            connection.close()
        if 300 <= receipt.status < 400:
            raise LocalTransportError("redirect_refused", receipt)
        if not 200 <= receipt.status < 300:
            raise LocalTransportError("http_error", receipt)
        return receipt
