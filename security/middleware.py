"""Security middleware that guards every AgentShield tool call."""

from collections.abc import Mapping
from dataclasses import dataclass
from os import PathLike, fspath
from pathlib import Path
from typing import Any

from security.audit import DEFAULT_AUDIT_PATH, write_audit_event
from security.capabilities import (
    CapabilityRegistry,
    builtin_registry,
)
from security.policy import DEFAULT_POLICY_PATH, PolicyError, load_policy
from security.scanner import inspect_sensitive


@dataclass(frozen=True)
class SecurityDecision:
    """A decision, plus the approved canonical path for file executors.

    ``resolved_path`` is not written to the audit log and does not guarantee
    atomic protection against filesystem changes between check and open.
    """

    allowed: bool
    reason: str
    capability: str | None = None
    resolved_path: Path | None = None

    def __bool__(self) -> bool:
        return self.allowed


def _finish_decision(
    *,
    allowed: bool,
    reason: str,
    message: str,
    agent: str,
    tool: str,
    audit_path: str | PathLike[str],
    capability: str | None = None,
    resolved_path: Path | None = None,
) -> SecurityDecision:
    decision = "ALLOW" if allowed else "BLOCK"
    try:
        write_audit_event(
            agent=agent,
            tool=tool,
            decision=decision,
            reason=reason,
            path=audit_path,
            capability=capability,
        )
    except (OSError, UnicodeError):
        print("BLOCKED: Audit log unavailable")
        return SecurityDecision(False, "audit_error", capability)

    print(message)
    return SecurityDecision(allowed, reason, capability, resolved_path)


def check_tool_call(
    tool: str,
    args: Mapping[str, Any],
    *,
    agent: str = "simple-agent",
    policy_path: str | PathLike[str] = DEFAULT_POLICY_PATH,
    audit_path: str | PathLike[str] = DEFAULT_AUDIT_PATH,
    registry: CapabilityRegistry | None = None,
) -> SecurityDecision:
    """Evaluate policy, scan outbound data, and audit the final decision.

    ``registry=None`` keeps the V1.6.1 name-whitelist behavior: only the
    literal names ``file``/``http``/``model`` are recognized.  Passing an
    explicit :class:`CapabilityRegistry` lets additional agent-visible tool
    names resolve to the same capability (and therefore the same policy
    branch and executor) — the setup required for threat-preserving
    representation-sensitivity measurements.
    """
    print("[AgentShield] Checking...")
    if registry is None:
        registry = builtin_registry()
    capability = registry.resolve(tool)

    try:
        policy = load_policy(policy_path)
    except (OSError, PolicyError, UnicodeError):
        return _finish_decision(
            allowed=False,
            reason="policy_error",
            message="BLOCKED: Policy unavailable or invalid",
            agent=agent,
            tool=tool,
            audit_path=audit_path,
            capability=capability,
        )

    if capability is None:
        return _finish_decision(
            allowed=False,
            reason="unsupported_tool",
            message="BLOCKED: Unsupported tool",
            agent=agent,
            tool=tool,
            audit_path=audit_path,
            capability=capability,
        )

    def invalid_arguments() -> SecurityDecision:
        return _finish_decision(
            allowed=False,
            reason="invalid_arguments",
            message="BLOCKED: Invalid tool arguments",
            agent=agent,
            tool=tool,
            audit_path=audit_path,
            capability=capability,
        )

    if not isinstance(args, Mapping):
        return invalid_arguments()

    resolved_path: Path | None = None
    if capability == "file_read":
        path = args.get("path", "")
        if not isinstance(path, (str, PathLike)):
            return invalid_arguments()
        path = fspath(path)
        if not isinstance(path, str):
            return invalid_arguments()
        if not path:
            return _finish_decision(
                allowed=False,
                reason="missing_file_path",
                message="BLOCKED: Missing file path",
                agent=agent,
                tool=tool,
                audit_path=audit_path,
                capability=capability,
            )
        try:
            if "\0" in path:
                raise ValueError("Invalid path")
            resolved_path = policy.resolve_file(path)
        except (OSError, RuntimeError, ValueError):
            return _finish_decision(
                allowed=False,
                reason="invalid_file_path",
                message="BLOCKED: File path could not be resolved",
                agent=agent,
                tool=tool,
                audit_path=audit_path,
                capability=capability,
            )
        if policy.blocks_file(path) or policy.blocks_file(resolved_path):
            return _finish_decision(
                allowed=False,
                reason="blocked_file",
                message="BLOCKED: File denied by policy",
                agent=agent,
                tool=tool,
                audit_path=audit_path,
                capability=capability,
            )
        if not policy.allows_file(resolved_path):
            return _finish_decision(
                allowed=False,
                reason="file_outside_allowed_roots",
                message="BLOCKED: File is outside allowed read roots",
                agent=agent,
                tool=tool,
                audit_path=audit_path,
                capability=capability,
            )

    if capability in {"http_send", "model_call"}:
        data = args.get("data")
        url = args.get("url")
        if not isinstance(data, str) or not isinstance(url, str):
            return invalid_arguments()
        inspections = (inspect_sensitive(data), inspect_sensitive(url))
        if any(result.limited for result in inspections):
            return _finish_decision(
                allowed=False,
                reason="scan_limit",
                message="BLOCKED: Sensitive-data inspection budget exceeded",
                agent=agent,
                tool=tool,
                audit_path=audit_path,
                capability=capability,
            )
        if any(result.detected for result in inspections):
            return _finish_decision(
                allowed=False,
                reason="sensitive_data",
                message="BLOCKED: Sensitive data detected",
                agent=agent,
                tool=tool,
                audit_path=audit_path,
                capability=capability,
            )

        if not policy.allows_url(url):
            return _finish_decision(
                allowed=False,
                reason="domain_not_allowed",
                message="BLOCKED: Destination domain is not allowed",
                agent=agent,
                tool=tool,
                audit_path=audit_path,
                capability=capability,
            )

    return _finish_decision(
        allowed=True,
        reason="policy_passed",
        message="Allowed",
        agent=agent,
        tool=tool,
        audit_path=audit_path,
        capability=capability,
        resolved_path=resolved_path,
    )


def secure_tool_call(
    tool: str,
    args: Mapping[str, Any],
    *,
    agent: str = "simple-agent",
    policy_path: str | PathLike[str] = DEFAULT_POLICY_PATH,
    audit_path: str | PathLike[str] = DEFAULT_AUDIT_PATH,
    registry: CapabilityRegistry | None = None,
) -> bool:
    """Backward-compatible boolean wrapper around :func:`check_tool_call`."""
    return check_tool_call(
        tool,
        args,
        agent=agent,
        policy_path=policy_path,
        audit_path=audit_path,
        registry=registry,
    ).allowed
