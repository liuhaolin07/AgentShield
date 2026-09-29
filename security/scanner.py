"""Rule-based sensitive-data scanner for AgentShield V1."""

import re


PATTERNS = (
    r"sk-[a-zA-Z0-9]+",
    r"-----BEGIN OPENSSH PRIVATE KEY-----",
    r"AWS_SECRET",
    r"PASSWORD",
)


def scan_sensitive(data: str) -> bool:
    """Return True when data matches any configured sensitive pattern."""
    return any(re.search(pattern, data) is not None for pattern in PATTERNS)
