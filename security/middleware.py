"""Security middleware that guards every tool call."""

from collections.abc import Mapping
from typing import Any

from security.scanner import scan_sensitive


def secure_tool_call(tool: str, args: Mapping[str, Any]) -> bool:
    """Check whether a requested tool call is allowed to execute.

    V1 scans outbound HTTP payloads. Other tools pass through unchanged.
    """
    print("[AgentShield] Checking...")

    if tool == "http":
        data = args.get("data", "")
        if scan_sensitive(str(data)):
            print("BLOCKED: Sensitive data detected")
            return False

    print("Allowed")
    return True
