"""Rule-based sensitive-data scanner for AgentShield."""

import re


# Word boundaries and minimum lengths keep ordinary words that merely end in
# "sk" (task-42, risk-2026) from matching; the shape mirrors the redaction
# patterns in model.dots_client so scan and redact agree on what a key is.
PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(pattern, flags=re.IGNORECASE)
    for pattern in (
        r"\bsk-[a-zA-Z0-9_-]{8,}\b",
        r"\bak_[a-zA-Z0-9]{16,}\b",
        r"-----BEGIN OPENSSH PRIVATE KEY-----",
        r"AWS_SECRET",
        r"PASSWORD",
    )
)


def scan_sensitive(data: str) -> bool:
    """Return True when data matches any configured sensitive pattern."""
    return any(pattern.search(data) is not None for pattern in PATTERNS)
