"""Controlled IPv4 loopback receiver recording actual HTTP arrivals."""

import threading
from dataclasses import asdict, dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any

from tools.local_http import MAX_BODY_BYTES, LocalHTTPTarget


@dataclass(frozen=True)
class Arrival:
    sequence: int
    method: str
    path: str
    body: str
    status: int


class LoopbackReceiver:
    """A temporary test sink; all recorded contents must be synthetic."""

    def __init__(self, *, redirect_to: str | None = None) -> None:
        self._arrivals: list[Arrival] = []
        self._lock = threading.Lock()
        self.redirect_to = redirect_to
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                except ValueError:
                    self.send_error(400)
                    return
                if not 0 <= length <= MAX_BODY_BYTES:
                    self.send_error(413)
                    return
                body = self.rfile.read(length).decode("utf-8", errors="replace")
                status = 302 if self.path.startswith("/redirect") else 202
                with owner._lock:
                    owner._arrivals.append(Arrival(
                        len(owner._arrivals) + 1, "POST", self.path, body, status,
                    ))
                self.send_response(status)
                if status == 302:
                    self.send_header("Location", owner.redirect_to or owner.url)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, format: str, *args: Any) -> None:
                pass

        self._server = HTTPServer(("127.0.0.1", 0), Handler)
        self._server.timeout = 2.0
        self._thread = threading.Thread(
            target=self._server.serve_forever, kwargs={"poll_interval": 0.05},
            daemon=True,
        )
        self.target = LocalHTTPTarget(self._server.server_port)

    @property
    def url(self) -> str:
        return f"{self.target.origin}/receive"

    @property
    def arrivals(self) -> list[dict[str, Any]]:
        with self._lock:
            return [asdict(arrival) for arrival in self._arrivals]

    def __enter__(self) -> "LoopbackReceiver":
        self._thread.start()
        return self

    def __exit__(self, *args: Any) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2.0)
