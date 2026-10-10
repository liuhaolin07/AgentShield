"""One guarded executor path shared by explicit agents and all experiment arms."""

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from security.middleware import SecurityDecision, check_tool_call
from security.inspection import DEFENSE_MODES
from security.taint import MAX_CHARS, TaintError, TaintedValue, get_item, make_list
from security.taint_context import TaintContext
from tools.file_tool import read_file
from tools.http_tool import send_http
from tools.local_http import HTTPReceipt, LocalHTTPTarget, LocalTransportError


@dataclass(frozen=True)
class RuntimeResult:
    decision: SecurityDecision
    executed: bool
    value: TaintedValue | None = None
    receipt: HTTPReceipt | None = None
    error: str | None = None


class GuardedRuntime:
    def __init__(self, *, policy_path: Path, audit_path: Path, context: TaintContext,
                 local_target: LocalHTTPTarget | None = None, defense_mode: str = "scanner_taint",
                 observe: Callable[..., None] | None = None) -> None:
        if defense_mode not in DEFENSE_MODES:
            raise TaintError("Invalid defense mode")
        if defense_mode != "scanner_taint" and local_target is None:
            raise TaintError("Experimental defense modes require a pinned local target")
        if context.root != policy_path.resolve().parent:
            raise TaintError("Tracking and access-policy roots disagree")
        self.policy_path, self.audit_path, self.context = policy_path, audit_path, context
        self.local_target, self.defense_mode = local_target, defense_mode
        self.observe = observe or (lambda *args, **kwargs: None)

    def _check(self, capability: str, args: dict[str, Any]) -> SecurityDecision:
        self.observe("policy_check_started", capability=capability)
        decision = check_tool_call(capability, args, agent="explicit-agent", policy_path=self.policy_path,
                                   audit_path=self.audit_path, defense_mode=self.defense_mode,
                                   taint_policy=self.context.policy)
        self.observe("policy_decision", allowed=decision.allowed, reason=decision.reason,
                     checks=decision.checks.explain() if decision.checks else None)
        return decision

    def read(self, path: str) -> RuntimeResult:
        decision = self._check("file", {"path": path})
        if not decision:
            return RuntimeResult(decision, False)
        self.observe("file_executor_entered")
        try:
            content = read_file(decision.resolved_path, max_chars=MAX_CHARS)
            value = self.context.file_value(decision.resolved_path, content)
        except (OSError, UnicodeError, ValueError):
            return RuntimeResult(decision, True, error="file_read_or_label_failed")
        self.observe("source_registered", category="file", source_ids=list(value.source_ids), sensitive=value.sensitive)
        return RuntimeResult(decision, True, value=value)

    def tool_output(self, tool: str, producer: Callable[[], str], *, reference: str,
                    parent: TaintedValue | None = None) -> TaintedValue:
        """Wrap a local trusted adapter's actual return at its ingress boundary.

        Producer is trusted Python, not a registered general-purpose tool or a
        sandbox. Permissions for arbitrary producers must be enforced upstream.
        """
        self.observe("tool_executor_entered")
        content = producer()
        value = self.context.tool_value(tool, content, reference=reference)
        if parent is not None:
            value = get_item(make_list([parent, value]), 1)
        self.observe("source_registered", category="tool", source_ids=list(value.source_ids), sensitive=value.sensitive)
        return value

    def send(self, url: str | TaintedValue, value: str | TaintedValue, *, sink: str = "http") -> RuntimeResult:
        if sink not in {"http", "model"}:
            raise TaintError("Invalid sink")
        decision = self._check(sink, {"url": url, "data": value})
        if not decision:
            return RuntimeResult(decision, False)
        raw_url = url.reveal() if isinstance(url, TaintedValue) else url
        raw_data = value.reveal() if isinstance(value, TaintedValue) else value
        self.observe("outbound_executor_entered", sink=sink)
        try:
            receipt = send_http(raw_url, raw_data, local_target=self.local_target)
        except LocalTransportError as error:
            self.observe("transport_rejection", reason=error.reason)
            return RuntimeResult(decision, True, error="transport:" + error.reason)
        if self.local_target is not None and (not isinstance(receipt, HTTPReceipt) or not 200 <= receipt.status < 300):
            return RuntimeResult(decision, True, error="missing_successful_receipt")
        self.observe("outbound_returned", mode="local_http" if self.local_target else "simulation",
                     response_status=receipt.status if receipt else None)
        return RuntimeResult(decision, True, receipt=receipt)
