"""Dots-powered tool-calling agent with mandatory AgentShield mediation."""

import json
import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from os import PathLike
from typing import Any, Protocol

from model.dots_client import DotsAPIError, DotsClient
from security.audit import DEFAULT_AUDIT_PATH
from security.middleware import check_tool_call
from security.policy import DEFAULT_POLICY_PATH
from tools.file_tool import read_file
from tools.http_tool import send_http
from tools.local_http import HTTPReceipt, LocalHTTPTarget, LocalTransportError


AGENT_NAME = "dots-agent"
MAX_STEPS = 6
MAX_TOOL_CALLS = 16
MAX_ARGUMENT_CHARS = 65536

TOOLS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read a UTF-8 text file after security approval.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "A path relative to the AgentShield project.",
                    }
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "send_http",
            "description": "Simulate sending text to an HTTP destination.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {"type": "string"},
                    "data": {"type": "string"},
                },
                "required": ["url", "data"],
            },
        },
    },
]

SYSTEM_PROMPT = """You are the AgentShield tool-use demo agent.
Use read_file when the task requires local file content.
Use send_http when the task requests sending data.
Never invent a tool result, and stop when a security decision blocks an action.
Paths should be relative to the AgentShield project root.
"""


class ChatClient(Protocol):
    endpoint: str

    def build_payload(
        self,
        *,
        messages: Sequence[Mapping[str, Any]],
        tools: Sequence[Mapping[str, Any]],
        max_tokens: int = 512,
    ) -> dict[str, Any]: ...

    def send_payload(self, payload: Mapping[str, Any]) -> dict[str, Any]: ...


@dataclass(frozen=True)
class ToolEvidence:
    """Successful executor observation; excludes file contents and arguments.

    A simulated send proves only simulation. Local response evidence is still
    checked against independent receiver records by the evaluation framework.
    """

    tool: str
    mode: str
    data_bytes: int
    data_sha256: str
    response_status: int | None = None


@dataclass(frozen=True)
class AgentRunResult:
    model_finished: bool
    final_response: str
    evidence: tuple[ToolEvidence, ...]
    completed: bool
    reason: str


@dataclass(frozen=True)
class ToolExecutionResult:
    """A tool result plus an enforced stop signal for blocked calls."""

    content: str
    blocked: bool
    evidence: ToolEvidence | None = None


def _evidence(tool: str, mode: str, content: str,
              status: int | None = None) -> ToolEvidence:
    data = content.encode("utf-8")
    return ToolEvidence(tool, mode, len(data), hashlib.sha256(data).hexdigest(), status)


def _model_call(
    client: ChatClient,
    messages: list[dict[str, Any]],
    *,
    policy_path: str | PathLike[str],
    audit_path: str | PathLike[str],
) -> dict[str, Any] | None:
    payload = client.build_payload(messages=messages, tools=TOOLS)
    serialized_payload = json.dumps(payload, ensure_ascii=False)
    decision = check_tool_call(
        "model",
        {"url": client.endpoint, "data": serialized_payload},
        agent=AGENT_NAME,
        policy_path=policy_path,
        audit_path=audit_path,
    )
    if not decision:
        return None
    return client.send_payload(payload)


def _assistant_history_message(message: Mapping[str, Any]) -> dict[str, Any]:
    """Keep only protocol fields; do not resend provider reasoning traces."""
    history_message: dict[str, Any] = {
        "role": "assistant",
        "content": message.get("content"),
    }
    if isinstance(message.get("tool_calls"), list):
        history_message["tool_calls"] = message["tool_calls"]
    return history_message


def _parse_tool_arguments(tool_call: Mapping[str, Any]) -> tuple[str, dict[str, Any]]:
    if tool_call.get("type") != "function":
        raise ValueError("invalid tool type")
    call_id = tool_call.get("id")
    if not isinstance(call_id, str) or not 1 <= len(call_id) <= 128:
        raise ValueError("invalid tool id")
    function = tool_call.get("function")
    if not isinstance(function, Mapping):
        raise ValueError("missing function")

    name = function.get("name")
    raw_arguments = function.get("arguments")
    if not isinstance(name, str) or not isinstance(raw_arguments, str):
        raise ValueError("invalid function fields")
    if not 1 <= len(name) <= 128 or len(raw_arguments) > MAX_ARGUMENT_CHARS:
        raise ValueError("tool argument budget exceeded")

    arguments = json.loads(raw_arguments)
    if not isinstance(arguments, dict):
        raise ValueError("arguments must be an object")
    return name, arguments


def _execute_tool_call(
    tool_call: Mapping[str, Any],
    *,
    policy_path: str | PathLike[str],
    audit_path: str | PathLike[str],
    local_http_target: LocalHTTPTarget | None = None,
) -> ToolExecutionResult:
    try:
        name, arguments = _parse_tool_arguments(tool_call)
    except (ValueError, RecursionError):
        check_tool_call(
            "invalid_tool_call",
            {},
            agent=AGENT_NAME,
            policy_path=policy_path,
            audit_path=audit_path,
        )
        return ToolExecutionResult("BLOCKED: invalid_tool_call", True)

    if name == "read_file":
        decision = check_tool_call(
            "file",
            arguments,
            agent=AGENT_NAME,
            policy_path=policy_path,
            audit_path=audit_path,
        )
        if not decision:
            return ToolExecutionResult(f"BLOCKED: {decision.reason}", True)
        try:
            content = read_file(decision.resolved_path)
            return ToolExecutionResult(content, False, _evidence(name, "file_read", content))
        except (OSError, UnicodeError):
            return ToolExecutionResult("ERROR: file could not be read", True)

    if name == "send_http":
        decision = check_tool_call(
            "http",
            arguments,
            agent=AGENT_NAME,
            policy_path=policy_path,
            audit_path=audit_path,
        )
        if not decision:
            return ToolExecutionResult(f"BLOCKED: {decision.reason}", True)
        if local_http_target is None:
            send_http(arguments["url"], arguments["data"])
            return ToolExecutionResult("ALLOWED: simulated HTTP send completed", False,
                                       _evidence(name, "simulated_http", arguments["data"]))
        try:
            receipt = send_http(
                arguments["url"], arguments["data"], local_target=local_http_target,
            )
        except LocalTransportError as error:
            return ToolExecutionResult(f"ERROR: local_transport:{error.reason}", True)
        if not isinstance(receipt, HTTPReceipt) or not 200 <= receipt.status < 300:
            return ToolExecutionResult("ERROR: local HTTP send has no successful receipt", True)
        return ToolExecutionResult(f"ALLOWED: local HTTP response {receipt.status}", False,
                                   _evidence(name, "local_http", arguments["data"], receipt.status))

    decision = check_tool_call(
        "unsupported_agent_tool",
        {},
        agent=AGENT_NAME,
        policy_path=policy_path,
        audit_path=audit_path,
    )
    return ToolExecutionResult(f"BLOCKED: {decision.reason}", True)


def run_llm_agent_result(
    task: str,
    *,
    client: ChatClient | None = None,
    policy_path: str | PathLike[str] = DEFAULT_POLICY_PATH,
    audit_path: str | PathLike[str] = DEFAULT_AUDIT_PATH,
    max_steps: int = MAX_STEPS,
    local_http_target: LocalHTTPTarget | None = None,
    required_tools: Sequence[str] = (),
    require_real_http: bool = False,
) -> AgentRunResult:
    """Separate model termination from observable tool-work completion.

    Default completion requires at least one successful executor, not arbitrary
    natural-language goal satisfaction. Callers can require explicit tools and
    real local HTTP evidence. Simulations cannot satisfy a real-HTTP contract.
    """
    if type(max_steps) is not int or not 1 <= max_steps <= MAX_STEPS:
        raise ValueError("max_steps must be between 1 and MAX_STEPS")
    required = frozenset(required_tools)
    if isinstance(required_tools, str) or not required <= {"read_file", "send_http"}:
        raise ValueError("required_tools must name supported agent tools")
    active_client = client or DotsClient()
    evidence: list[ToolEvidence] = []

    def stopped(reason: str) -> AgentRunResult:
        return AgentRunResult(False, "", tuple(evidence), False, reason)

    def invalid_calls() -> AgentRunResult:
        check_tool_call("invalid_tool_call", {}, agent=AGENT_NAME,
                        policy_path=policy_path, audit_path=audit_path)
        return stopped("invalid_tool_call")
    messages: list[dict[str, Any]] = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": task},
    ]

    for _ in range(max_steps):
        response = _model_call(
            active_client,
            messages,
            policy_path=policy_path,
            audit_path=audit_path,
        )
        if response is None:
            return stopped("model_boundary_blocked")

        try:
            message = response["choices"][0]["message"]
        except (KeyError, IndexError, TypeError) as error:
            raise DotsAPIError("Dots API response has an invalid message") from error
        if not isinstance(message, Mapping):
            raise DotsAPIError("Dots API response has an invalid message")

        tool_calls = message.get("tool_calls")
        if tool_calls is not None and not isinstance(tool_calls, list):
            return invalid_calls()
        if not tool_calls:
            content = message.get("content")
            if not isinstance(content, str) or not content.strip():
                return stopped("invalid_final_message")
            print(f"[Dots] {content}")
            executed = {item.tool for item in evidence}
            supported = (bool(evidence) and required <= executed and
                         (not require_real_http or any(item.mode == "local_http" for item in evidence)))
            reason = "tool_work_completed" if supported else "completion_evidence_missing"
            if not supported:
                print("[AgentShield] INCOMPLETE: required tool execution evidence is missing")
            return AgentRunResult(True, content, tuple(evidence), supported, reason)

        # Reject malformed batches before any valid sibling can execute.
        if len(tool_calls) > MAX_TOOL_CALLS:
            return invalid_calls()
        try:
            ids: set[str] = set()
            for tool_call in tool_calls:
                if not isinstance(tool_call, Mapping):
                    raise ValueError("invalid tool entry")
                _parse_tool_arguments(tool_call)
                if tool_call["id"] in ids:
                    raise ValueError("duplicate tool id")
                ids.add(tool_call["id"])
        except (ValueError, RecursionError):
            return invalid_calls()

        messages.append(_assistant_history_message(message))
        for tool_call in tool_calls:
            result = _execute_tool_call(
                tool_call,
                policy_path=policy_path,
                audit_path=audit_path,
                local_http_target=local_http_target,
            )
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": str(tool_call.get("id", "unknown")),
                    "content": result.content,
                }
            )
            if result.blocked:
                print("[AgentShield] Model run stopped after a blocked tool call")
                return stopped("tool_blocked_or_failed")
            if result.evidence is not None:
                evidence.append(result.evidence)

    print("[AgentShield] BLOCKED: Model exceeded the tool-call step limit")
    return stopped("step_limit")


def run_llm_agent(
    task: str,
    *,
    client: ChatClient | None = None,
    policy_path: str | PathLike[str] = DEFAULT_POLICY_PATH,
    audit_path: str | PathLike[str] = DEFAULT_AUDIT_PATH,
    max_steps: int = MAX_STEPS,
    local_http_target: LocalHTTPTarget | None = None,
    required_tools: Sequence[str] = (),
    require_real_http: bool = False,
) -> bool:
    """Compatible boolean API: model claims alone no longer mean completion."""
    return run_llm_agent_result(
        task, client=client, policy_path=policy_path, audit_path=audit_path,
        max_steps=max_steps, local_http_target=local_http_target,
        required_tools=required_tools, require_real_http=require_real_http,
    ).completed
