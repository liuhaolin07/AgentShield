"""Simulated HTTP by default, with opt-in synthetic loopback experiments."""

from typing import Any

from tools.local_http import HTTPReceipt, LocalHTTPTarget


def send_http(
    url: str, data: Any, *, local_target: LocalHTTPTarget | None = None,
) -> HTTPReceipt | None:
    """Simulate a send, or use an explicitly pinned loopback test target.

    Callers must obtain an AgentShield decision before execution. The local
    target enforces transport restrictions independently of that decision.
    """
    if local_target is not None:
        return local_target.send(url, data)
    print("Sending data to:")
    print(url)
    print(data)
