"""Dots-powered tool-calling agent with mandatory AgentShield mediation."""

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from os import PathLike
from pathlib import Path
from typing import Any, Protocol

from model.dots_client import DotsAPIError, DotsClient
from security.audit import DEFAULT_AUDIT_PATH
from security.middleware import check_tool_call
from security.policy import DEFAULT_POLICY_PATH
from tools.file_tool import read_file
from tools.http_tool import send_http


AGENT_NAME = "dots-agent"
MAX_STEPS = 6

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
class ToolExecutionResult:
    """A tool result plus an enforced stop signal for blocked calls."""

    content: str
    blocked: bool


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
    function = tool_call.get("function")
    if not isinstance(function, Mapping):
        raise ValueError("missing function")

    name = function.get("name")
    raw_arguments = function.get("arguments")
    if not isinstance(name, str) or not isinstance(raw_arguments, str):
        raise ValueError("invalid function fields")

    arguments = json.loads(raw_arguments)
    if not isinstance(arguments, dict):
        raise ValueError("arguments must be an object")
    return name, arguments


def _execute_tool_call(
    tool_call: Mapping[str, Any],
    *,
    policy_path: str | PathLike[str],
    audit_path: str | PathLike[str],
) -> ToolExecutionResult:
    try:
        name, arguments = _parse_tool_arguments(tool_call)
    except (ValueError, json.JSONDecodeError):
        check_tool_call(
            "invalid_tool_call",
            {},
            agent=AGENT_NAME,
            policy_path=policy_path,
            audit_path=audit_path,
        )
        return ToolExecutionResult("BLOCKED: invalid_tool_call", True)

    if name == "read_file":
        raw_path = arguments.get("path", "")
        path = Path(str(raw_path))
        if not path.is_absolute():
            path = Path(policy_path).resolve().parent / path
        path = path.resolve()
        decision = check_tool_call(
            "file",
            {"path": str(path)},
            agent=AGENT_NAME,
            policy_path=policy_path,
            audit_path=audit_path,
        )
        if not decision:
            return ToolExecutionResult(f"BLOCKED: {decision.reason}", True)
        try:
            return ToolExecutionResult(read_file(path), False)
        except OSError:
            return ToolExecutionResult("ERROR: file could not be read", True)

    if name == "send_http":
        url = str(arguments.get("url", ""))
        data = str(arguments.get("data", ""))
        decision = check_tool_call(
            "http",
            {"url": url, "data": data},
            agent=AGENT_NAME,
            policy_path=policy_path,
            audit_path=audit_path,
        )
        if not decision:
            return ToolExecutionResult(f"BLOCKED: {decision.reason}", True)
        send_http(url, data)
        return ToolExecutionResult("ALLOWED: simulated HTTP send completed", False)

    decision = check_tool_call(
        name,
        arguments,
        agent=AGENT_NAME,
        policy_path=policy_path,
        audit_path=audit_path,
    )
    return ToolExecutionResult(f"BLOCKED: {decision.reason}", True)


def run_llm_agent(
    task: str,
    *,
    client: ChatClient | None = None,
    policy_path: str | PathLike[str] = DEFAULT_POLICY_PATH,
    audit_path: str | PathLike[str] = DEFAULT_AUDIT_PATH,
    max_steps: int = MAX_STEPS,
) -> bool:
    """Run a guarded Dots tool-calling loop and print the final model response."""
    active_client = client or DotsClient()
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
            return False

        try:
            message = response["choices"][0]["message"]
        except (KeyError, IndexError, TypeError) as error:
            raise DotsAPIError("Dots API response has an invalid message") from error
        if not isinstance(message, Mapping):
            raise DotsAPIError("Dots API response has an invalid message")

        tool_calls = message.get("tool_calls")
        if not isinstance(tool_calls, list) or not tool_calls:
            content = str(message.get("content") or "")
            print(f"[Dots] {content}")
            return True

        messages.append(_assistant_history_message(message))
        for tool_call in tool_calls:
            if not isinstance(tool_call, Mapping):
                continue
            result = _execute_tool_call(
                tool_call,
                policy_path=policy_path,
                audit_path=audit_path,
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
                return False

    print("[AgentShield] BLOCKED: Model exceeded the tool-call step limit")
    return False
