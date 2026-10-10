"""Actual model-driven tool loop. A tool-selection fixture is never a live LLM."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any

from security.attested_runtime import AttestedRuntime
from security.taint import TaintError, TaintedValue, json_deserialize
from security.taint_integrity import IntegrityError, ValueHandle, TRANSFORMS


def _schema(name: str, description: str, properties: dict[str, Any], required: list[str]) -> dict[str, Any]:
    return {"type":"function","function":{"name":name,"description":description,
            "parameters":{"type":"object","properties":properties,"required":required,"additionalProperties":False}}}


TOOLS = [
    _schema("read_file", "Read an approved file; returns an opaque reference and bounded content.",
            {"path":{"type":"string"}}, ["path"]),
    _schema("transform", "Apply a supported transform inside the runtime; never mint or strip labels.",
            {"operation":{"type":"string","enum":sorted(TRANSFORMS)},
             "refs":{"type":"array","items":{"type":"string"},"maxItems":32},
             "parameters":{"type":"object"}}, ["operation","refs","parameters"]),
    _schema("send_http", "Send a referenced value to the configured synthetic loopback receiver.",
            {"url":{"type":"string"},"ref":{"type":"string"}}, ["url","ref"]),
]


@dataclass
class ModelAgentEvidence:
    final_text: str | None = None
    error: str | None = None
    blocked: bool = False
    block_reason: str | None = None
    model_calls: int = 0
    file_reads: int = 0
    sends: int = 0
    successful_sends: int = 0
    model_sensitive_requests: int = 0
    usage: list[dict[str, int] | None] = field(default_factory=list)
    model_latency_ms: list[float] = field(default_factory=list)
    trace: list[dict[str, Any]] = field(default_factory=list)


class ResearchAgent:
    def __init__(self, runtime: AttestedRuntime, client: Any, *, max_steps: int = 6) -> None:
        if type(max_steps) is not int or not 1 <= max_steps <= 12:
            raise ValueError("Invalid model step budget")
        self.runtime, self.client, self.max_steps = runtime, client, max_steps

    def run(self, task: str) -> ModelAgentEvidence:
        result = ModelAgentEvidence()
        if not isinstance(task, str) or len(task) > 8192:
            result.error = "task_budget"
            return result
        history = [{"role":"system","content":"Use tools to complete the user task. Report facts and executed actions honestly."},
                   {"role":"user","content":task}]
        values: dict[str, ValueHandle] = {}
        parents: list[ValueHandle] = []
        for step in range(self.max_steps):
            try:
                payload = self.client.build_payload(messages=history, tools=TOOLS, max_tokens=512)
                if payload.get("messages") != history:
                    raise IntegrityError("model_history_rewritten")
                outgoing = self.runtime._model_payload(payload,reference=f"request-{step}",parents=tuple(parents))
                decision = self.runtime.approve_model_payload(self.client.endpoint,outgoing)
                result.trace.append({"event":"model_boundary","allowed":decision.allowed,"reason":decision.reason})
                if not decision.allowed:
                    result.blocked, result.block_reason = True, decision.reason
                    return result
                self.runtime.observe("model_executor_entered")
                started = time.perf_counter_ns()
                response = self.client.send_payload(payload)
                result.model_latency_ms.append((time.perf_counter_ns()-started)/1e6)
                result.model_calls += 1
                result.model_sensitive_requests += int(self.runtime.provenance(outgoing).get("sensitive", False))
                usage = response.get("usage")
                valid_usage = (isinstance(usage,dict) and all(type(usage.get(k)) is int and usage[k]>=0
                               for k in ("prompt_tokens","completion_tokens","total_tokens")))
                result.usage.append({k:usage[k] for k in ("prompt_tokens","completion_tokens","total_tokens")} if valid_usage else None)
                message = response["choices"][0]["message"]
                TaintedValue.literal(message)
                returned = self.runtime._model_return(message, reference=f"return-{step}", parents=(outgoing,))
                parents.append(returned)
                calls = message.get("tool_calls",[])
                if not isinstance(calls,list) or len(calls)>8:
                    raise IntegrityError("model_tool_budget")
                if not calls:
                    content = message.get("content")
                    if not isinstance(content,str):
                        raise IntegrityError("model_missing_final_text")
                    result.final_text = content
                    result.trace.append({"event":"model_final_returned","execution_proven":result.file_reads>0 or result.successful_sends>0})
                    return result
                history.append({"role":"assistant","content":message.get("content"),"tool_calls":calls})
                seen = set()
                for call in calls:
                    call_id = call.get("id")
                    if not isinstance(call_id,str) or not 1 <= len(call_id) <= 128 or call_id in seen:
                        raise IntegrityError("model_invalid_call_id")
                    seen.add(call_id)
                    function = call["function"]
                    args = json_deserialize(TaintedValue.literal(function["arguments"])).reveal()
                    if not isinstance(args,dict):
                        raise IntegrityError("model_invalid_tool_arguments")
                    name = function["name"]
                    if name=="read_file" and set(args)=={"path"}:
                        read = self.runtime.read(args["path"])
                        if read.handle is None:
                            response_value={"executed":read.executed,"error":read.error,"reason":read.decision.reason}
                        else:
                            ref=f"v{len(values)+1}"; values[ref]=read.handle; parents.append(read.handle)
                            result.file_reads += 1
                            response_value={"ref":ref,"content":self.runtime._model_content(read.handle),"executed":True}
                    elif name=="transform" and set(args)=={"operation","refs","parameters"}:
                        refs=args["refs"]
                        if not isinstance(refs,list) or not 1 <= len(refs) <= 32:
                            raise IntegrityError("model_invalid_refs")
                        handle=self.runtime.transform(args["operation"],*(values[ref] for ref in refs),parameters=args["parameters"])
                        ref=f"v{len(values)+1}"; values[ref]=handle; parents.append(handle)
                        response_value={"ref":ref,"executed":True}
                    elif name=="send_http" and set(args)=={"url","ref"}:
                        send=self.runtime.send(args["url"],values[args["ref"]]); result.sends += 1
                        result.successful_sends += int(send.receipt is not None and send.error is None)
                        response_value={"executed":send.executed,"reason":send.decision.reason,"error":send.error}
                        if not send.decision.allowed:
                            result.blocked, result.block_reason=True,send.decision.reason
                    else:
                        raise IntegrityError("model_unauthorized_tool")
                    result.trace.append({"event":"tool_returned","tool":name,"executed":response_value.get("executed",False)})
                    history.append({"role":"tool","tool_call_id":call_id,"content":json.dumps(response_value,ensure_ascii=False)})
                    if result.blocked:
                        return result
            except Exception as error:
                # Persist neither provider diagnostics nor malformed arguments.
                result.error = str(error) if isinstance(error,IntegrityError) else type(error).__name__
                result.trace.append({"event":"agent_error","error":result.error})
                return result
        result.error="model_step_budget"
        return result
