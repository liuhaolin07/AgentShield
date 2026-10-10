"""Local-only trusted experiment configurations, never agent-controlled flags."""

import time
from typing import Any

from security.attested_runtime import AttestedRuntime
from security.middleware import SecurityDecision, check_tool_call
from security.taint_integrity import IntegrityError


RESEARCH_ARMS=("no_defense","static_rule","scanner","taint","full","source_only","detect_only")
BASELINES=RESEARCH_ARMS[:5]
ABLATIONS={"A1":"scanner","A2":"source_only","A3":"detect_only","A4":"full"}


class ResearchRuntime(AttestedRuntime):
    def __init__(self, *, arm: str="full", **kwargs: Any) -> None:
        if arm not in RESEARCH_ARMS or kwargs.get('local_target') is None:
            raise IntegrityError('research_requires_local_target')
        if any(k in kwargs for k in ('defense_mode','source_only','verify_integrity')):
            raise IntegrityError('research_configuration_conflict')
        mode=arm if arm in {'no_defense','static_rule','scanner'} else 'scanner_taint'
        self.arm=arm
        super().__init__(defense_mode=mode,source_only=arm=='source_only',
                         verify_integrity=arm not in {'no_defense','static_rule','scanner'},**kwargs)

    def _check(self, capability: str, args: dict[str, Any]) -> SecurityDecision:
        started=time.perf_counter_ns()
        self.observe('policy_check_started',capability=capability)
        decision=check_tool_call(capability,args,agent='v19-research-agent',policy_path=self.policy_path,
                                 audit_path=self.audit_path,defense_mode=self.defense_mode,
                                 taint_policy=self.context.policy,scan_content=self.arm!='taint',
                                 enforce_content=self.arm!='detect_only')
        self.observe('policy_decision',allowed=decision.allowed,reason=decision.reason,
                     checks=decision.checks.explain() if decision.checks else None,
                     duration_ns=time.perf_counter_ns()-started)
        return decision
