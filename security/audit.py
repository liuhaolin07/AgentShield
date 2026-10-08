"""Append-only audit logging for AgentShield decisions."""

import json
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_AUDIT_PATH = PROJECT_ROOT / "logs" / "audit.jsonl"


def write_audit_event(
    *,
    agent: str,
    tool: str,
    decision: str,
    reason: str,
    path: str | Path = DEFAULT_AUDIT_PATH,
    capability: str | None = None,
) -> dict[str, str | None]:
    """Append one decision without recording tool arguments or payload data."""
    event: dict[str, str | None] = {
        "time": datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z"),
        "agent": agent,
        "tool": tool,
        "decision": decision,
        "reason": reason,
    }
    if capability is not None:
        event["capability"] = capability

    audit_path = Path(path)
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    with audit_path.open("a", encoding="utf-8") as audit_file:
        audit_file.write(json.dumps(event, ensure_ascii=False) + "\n")
    return event
