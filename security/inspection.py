"""Sanitized separate scanner/taint observations and frozen static baseline."""

import re
from dataclasses import dataclass
from typing import Any

from security.scanner import ScanFinding, ScanResult
from security.taint import TaintDecision


DEFENSE_MODES = ("no_defense", "static_rule", "scanner", "scanner_taint")
STATIC_PATTERNS = tuple(re.compile(pattern, re.IGNORECASE) for pattern in (
    r"sk-[a-zA-Z0-9]+", r"\bak_[a-zA-Z0-9]{16,}\b", r"PASSWORD", r"AWS_SECRET",
    r"-----BEGIN OPENSSH PRIVATE KEY-----",
))


def inspect_static(text: str) -> ScanResult:
    """Frozen V1.7 pre-enhancement raw rules, not layered scanner detection."""
    if len(text) > 65536:
        return ScanResult(None, "input_length", 0, 0, 0)
    finding = ScanFinding("static_rule", ()) if any(p.search(text) for p in STATIC_PATTERNS) else None
    return ScanResult(finding, None, 1, len(text), 0)


@dataclass(frozen=True)
class InspectionEvidence:
    mode: str
    scanner: tuple[ScanResult, ...] = ()
    taint: tuple[TaintDecision, ...] = ()
    enforced: bool = True

    def explain(self) -> dict[str, Any]:
        return {**({"enforced": False} if not self.enforced else {}), "mode": self.mode,
                "scanner": {"active": bool(self.scanner),
                            "detected": any(result.detected for result in self.scanner),
                            "limited": any(result.limited for result in self.scanner),
                            "findings": [{"kind": result.finding.kind,
                                          "transformations": list(result.finding.transformations)}
                                         for result in self.scanner if result.finding]},
                "taint": {"active": bool(self.taint), "decisions": [result.explain() for result in self.taint]}}

    @property
    def blockers(self) -> tuple[str, ...]:
        modules = []
        if any(result.blocked for result in self.scanner):
            modules.append("static_rule" if self.mode == "static_rule" else "scanner")
        if any(not result.allowed for result in self.taint):
            modules.append("taint")
        return tuple(modules)
