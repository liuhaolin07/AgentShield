"""Rule-based sensitive-data scanner for AgentShield."""

import re


PATTERNS = (
    r"sk-[a-zA-Z0-9]+",
    r"\bak_[a-zA-Z0-9]{16,}\b",
    r"-----BEGIN OPENSSH PRIVATE KEY-----",
    r"AWS_SECRET",
    r"PASSWORD",
)


def scan_sensitive(data: str) -> bool:
    """Return True when data matches any configured sensitive pattern."""
    return any(
        re.search(pattern, data, flags=re.IGNORECASE) is not None
        for pattern in PATTERNS
    )
