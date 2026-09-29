"""HTTP tool stub for the V1 demo.

This module deliberately performs no real network request.
"""

from typing import Any


def send_http(url: str, data: Any) -> None:
    """Simulate sending data to an external URL."""
    print("Sending data to:")
    print(url)
    print(data)
