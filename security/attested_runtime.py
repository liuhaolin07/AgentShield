"""Trusted adapter boundary. AgentPort accepts data requests, not Python code."""

from __future__ import annotations

import time
import json
from dataclasses import dataclass
from typing import Any, Callable

from security.audit import write_audit_event
from security.middleware import SecurityDecision
from security.runtime import GuardedRuntime, RuntimeResult
from security.taint import SourceRecord, TaintedValue, get_item, make_list
from security.taint_integrity import IntegrityError, ValueHandle, _SourceAuthority


@dataclass(frozen=True)
class AttestedReadResult:
    decision: SecurityDecision
    executed: bool
    handle: ValueHandle | None = None
    error: str | None = None


class AttestedRuntime(GuardedRuntime):
    def __init__(self, *, approved_tools: dict[str, Callable[[Any], Any]] | None = None,
                 **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.__authority = _SourceAuthority()
        self.__tools = dict(approved_tools or {})
        if len(self.__tools) > 128 or not all(isinstance(k, str) and len(k) <= 128 and callable(v)
                                              for k, v in self.__tools.items()):
            raise IntegrityError("integrity_invalid_tool_registry")

    def read(self, path: str) -> AttestedReadResult:
        result = super().read(path)
        if result.value is None:
            return AttestedReadResult(result.decision, result.executed, error=result.error)
        try:
            handle = self.__authority._source("file_tool", result.value)
        except IntegrityError as error:
            return AttestedReadResult(result.decision, result.executed, error=str(error))
        self.observe("integrity_source_issued", **self.__authority.explain(handle))
        return AttestedReadResult(result.decision, result.executed, handle)

    def call_approved_tool(self, name: str, parent: ValueHandle | None = None) -> ValueHandle:
        if name not in self.__tools:
            raise IntegrityError("integrity_unapproved_tool")
        upstream = self.__authority.resolve(parent) if parent else None
        self.observe("tool_executor_entered")
        content = self.__tools[name](upstream.reveal() if upstream else None)
        value = self.context.tool_value(name, content, reference=name)
        if upstream:
            value = get_item(make_list([upstream, value]), 1)
        handle = self.__authority._source("approved_tool", value, (parent,) if parent else ())
        self.observe("integrity_source_issued", **self.__authority.explain(handle))
        return handle

    def _model_return(self, content: Any, *, reference: str,
                      parents: tuple[ValueHandle, ...] = ()) -> ValueHandle:
        """Only the trusted model adapter invokes this after an actual return."""
        value = TaintedValue.from_source(content, SourceRecord.create("model", reference), sensitive=False)
        for parent in parents:
            value = get_item(make_list([self.__authority.resolve(parent), value]), 1)
        return self.__authority._source("model_tool", value, parents)

    def transform(self, operation: str, *handles: ValueHandle,
                  parameters: dict[str, Any] | None = None) -> ValueHandle:
        handle = self.__authority.transform(operation, handles, parameters or {})
        self.observe("integrity_transform_issued", **self.__authority.explain(handle))
        return handle

    def provenance(self, handle: Any) -> dict[str, Any]:
        return self.__authority.explain(handle)

    def _model_payload(self, payload: dict[str, Any], *, reference: str,
                       parents: tuple[ValueHandle, ...]) -> ValueHandle:
        """Trusted model adapter wraps the exact outgoing payload with parents."""
        bounded = TaintedValue.literal(payload)
        serialized = json.dumps(bounded.reveal(), ensure_ascii=False, separators=(",", ":"))
        return self._model_return(serialized, reference=reference, parents=parents)

    def _model_content(self, handle: ValueHandle) -> Any:
        """Trusted history builder only. The assembled request is checked next."""
        return self.__authority.resolve(handle).reveal()

    def approve_model_payload(self, endpoint: str, handle: ValueHandle) -> SecurityDecision:
        explanation = self.__authority.explain(handle)
        self.observe("integrity_check", **explanation)
        if not explanation["allowed"]:
            return self._integrity_rejection(explanation["reason"], "model", explanation).decision
        return self._check("model", {"url": endpoint, "data": self.__authority.resolve(handle)})

    def _integrity_rejection(self, reason: str, sink: str, explanation: dict[str, Any]) -> RuntimeResult:
        capability = {"http": "http_send", "model": "model_call"}.get(sink, "agent_request")
        try:
            write_audit_event(agent="attested-agent", tool=sink, capability=capability,
                              decision="BLOCK", reason=reason, path=self.audit_path,
                              checks={"integrity": explanation})
        except (OSError, UnicodeError):
            reason = "audit_error"
        decision = SecurityDecision(False, reason, capability)
        self.observe("policy_decision", allowed=False, reason=reason, checks={"integrity": explanation}, duration_ns=0)
        return RuntimeResult(decision, False)

    def send(self, url: str, handle: Any, *, sink: str = "http") -> RuntimeResult:
        if sink not in {"http", "model"}:
            raise IntegrityError("integrity_invalid_sink")
        started = time.perf_counter_ns()
        explanation = self.__authority.explain(handle)
        self.observe("integrity_check", duration_ns=time.perf_counter_ns() - started, **explanation)
        if not explanation["allowed"]:
            return self._integrity_rejection(explanation["reason"], sink, explanation)
        return super().send(url, self.__authority.resolve(handle), sink=sink)


class AgentPort:
    """Finite JSON tool interface. No mint/literal/reveal/callback tool exists.

    Python object introspection is outside the boundary: this is not exec or a
    sandbox for agent-supplied Python. Agent logic sends only bounded data.
    """

    def __init__(self, runtime: AttestedRuntime) -> None:
        self.__runtime = runtime

    def dispatch(self, request: Any) -> dict[str, Any]:
        try:
            # Reuse the bounded immutable value validator before schema handling.
            TaintedValue.literal(request)
            if not isinstance(request, dict) or set(request) != {"tool", "args"} or not isinstance(request["args"], dict):
                raise IntegrityError("integrity_invalid_request")
            tool, args = request["tool"], request["args"]
            if tool == "read_file" and set(args) == {"path"} and isinstance(args["path"], str):
                result = self.__runtime.read(args["path"])
                return {"executed": result.executed, "error": result.error, "reason": result.decision.reason,
                        "handle": result.handle.to_wire() if result.handle else None}
            if tool == "transform" and set(args) == {"operation", "handles", "parameters"}:
                if not isinstance(args["handles"], list) or not 1 <= len(args["handles"]) <= 32:
                    raise IntegrityError("integrity_invalid_arity")
                handle = self.__runtime.transform(args["operation"], *(ValueHandle.from_wire(h) for h in args["handles"]),
                                                   parameters=args["parameters"])
                return {"handle": handle.to_wire(), "executed": True}
            if tool == "send_http" and set(args) == {"url", "handle"} and isinstance(args["url"], str):
                result = self.__runtime.send(args["url"], ValueHandle.from_wire(args["handle"]))
                return {"executed": result.executed, "reason": result.decision.reason,
                        "completed": bool(result.receipt and result.error is None), "error": result.error}
            raise IntegrityError("integrity_unauthorized_tool")
        except (ValueError, TypeError, KeyError, RecursionError) as error:
            reason = str(error) if isinstance(error, IntegrityError) else "integrity_invalid_request"
            self.__runtime._integrity_rejection(reason, "agent_port", {"allowed": False, "reason": reason})
            return {"executed": False, "completed": False, "error": reason}
