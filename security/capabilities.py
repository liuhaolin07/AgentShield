"""Tool-name to capability registry for AgentShield (additive, V2).

The middleware historically matched the literal tool name against the fixed
set ``{"file", "http", "model"}``.  That makes every unlisted tool name a
structural block: the call never reaches the sensitive-data scan, so a
name-perturbation experiment (TPRS, arXiv 2610.03585) cannot measure the
semantic layer at all.

The registry adds an explicit alias layer: several agent-visible tool names
may map to one *capability* (and therefore the same executor and the same
policy branch).  This is the setup required for threat-preserving
representation-sensitivity experiments, where only the agent-visible name
changes while the harmful action, environment, and executor stay fixed.

Additive guarantee: with no extra aliases registered, resolution behaves
exactly like the V1.6.1 name whitelist.  Existing callers pass no registry
and keep byte-identical behavior.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType


CAPABILITY_FILE_READ = "file_read"
CAPABILITY_HTTP_SEND = "http_send"
CAPABILITY_MODEL_CALL = "model_call"

KNOWN_CAPABILITIES = frozenset(
    {CAPABILITY_FILE_READ, CAPABILITY_HTTP_SEND, CAPABILITY_MODEL_CALL}
)

#: The V1.6.1 tool-name whitelist, expressed as name -> capability.
BUILTIN_ALIASES: Mapping[str, str] = {
    "file": CAPABILITY_FILE_READ,
    "http": CAPABILITY_HTTP_SEND,
    "model": CAPABILITY_MODEL_CALL,
}

#: Alias family for representation-sensitivity experiments.  All four names
#: denote the same outbound-send capability as ``http`` and share its
#: executor; only the agent-visible name differs.
EXPERIMENT_ALIASES: Mapping[str, str] = {
    "send_secret": CAPABILITY_HTTP_SEND,
    "submit_report": CAPABILITY_HTTP_SEND,
    "sync_data": CAPABILITY_HTTP_SEND,
    "backup_config": CAPABILITY_HTTP_SEND,
}


class CapabilityError(ValueError):
    """Raised when an alias mapping would break the additive guarantee."""


def _validate_alias(name: str, capability: object) -> None:
    if not isinstance(name, str) or not name.strip():
        raise CapabilityError("Alias names must be non-empty strings")
    if name in BUILTIN_ALIASES:
        raise CapabilityError(
            f"Alias {name!r} would shadow a built-in tool name"
        )
    if capability not in KNOWN_CAPABILITIES:
        raise CapabilityError(f"Unknown capability for {name!r}: {capability!r}")


@dataclass(frozen=True)
class CapabilityRegistry:
    """Immutable name -> capability mapping with built-in fallback."""

    extra_aliases: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name, capability in self.extra_aliases.items():
            _validate_alias(name, capability)
        # Freeze the mapping so a caller cannot mutate a frozen registry
        # after construction (and cannot share a mutable dict by accident).
        object.__setattr__(
            self, "extra_aliases", MappingProxyType(dict(self.extra_aliases))
        )

    def resolve(self, tool: str) -> str | None:
        """Return the capability for *tool*, or None when unregistered."""
        capability = BUILTIN_ALIASES.get(tool)
        if capability is not None:
            return capability
        return self.extra_aliases.get(tool)


def builtin_registry() -> CapabilityRegistry:
    """The registry that reproduces V1.6.1 name-whitelist behavior."""
    return CapabilityRegistry()


def experiment_registry() -> CapabilityRegistry:
    """Built-in names plus the representation-perturbation alias family."""
    return CapabilityRegistry(extra_aliases=dict(EXPERIMENT_ALIASES))
