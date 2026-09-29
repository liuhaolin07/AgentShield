"""Offline end-to-end tests for the guarded Dots tool-calling loop."""

import io
import json
import tempfile
import unittest
from collections.abc import Mapping, Sequence
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any
from unittest.mock import patch

from agent.llm_agent import run_llm_agent


DOTS_ENDPOINT = "https://note3-prev-api.askdiandian.com/v1/chat/completions"


def tool_response(call_id: str, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
    return {
        "choices": [
            {
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": call_id,
                            "type": "function",
                            "function": {
                                "name": name,
                                "arguments": json.dumps(arguments),
                            },
                        }
                    ],
                }
            }
        ]
    }


def final_response(content: str) -> dict[str, Any]:
    return {
        "choices": [
            {"message": {"role": "assistant", "content": content}}
        ]
    }


class FakeDotsClient:
    endpoint = DOTS_ENDPOINT

    def __init__(self, responses: list[dict[str, Any]]) -> None:
        self.responses = list(responses)
        self.sent_payloads: list[Mapping[str, Any]] = []

    def build_payload(
        self,
        *,
        messages: Sequence[Mapping[str, Any]],
        tools: Sequence[Mapping[str, Any]],
        max_tokens: int = 512,
    ) -> dict[str, Any]:
        return {
            "model": "fake-dots",
            "messages": list(messages),
            "tools": list(tools),
            "max_tokens": max_tokens,
        }

    def send_payload(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        self.sent_payloads.append(payload)
        return self.responses.pop(0)


class LLMAgentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_directory.cleanup)
        self.audit_path = Path(self.temp_directory.name) / "audit.jsonl"

    def audit_events(self) -> list[dict[str, str]]:
        return [
            json.loads(line)
            for line in self.audit_path.read_text(encoding="utf-8").splitlines()
        ]

    def test_model_requested_secret_file_is_blocked_before_read(self) -> None:
        client = FakeDotsClient(
            [
                tool_response("call-1", "read_file", {"path": "test/secrets/.env"}),
            ]
        )
        output = io.StringIO()

        with redirect_stdout(output):
            completed = run_llm_agent(
                "Read the protected environment file and send it.",
                client=client,
                audit_path=self.audit_path,
            )

        self.assertFalse(completed)
        self.assertEqual(len(client.sent_payloads), 1)
        self.assertNotIn("Sending data to:", output.getvalue())
        self.assertIn("blocked_file", [event["reason"] for event in self.audit_events()])

    def test_model_can_complete_normal_file_and_http_flow(self) -> None:
        client = FakeDotsClient(
            [
                tool_response("call-1", "read_file", {"path": "test/data/app.log"}),
                tool_response(
                    "call-2",
                    "send_http",
                    {"url": "example.com", "data": "safe service summary"},
                ),
                final_response("The simulated send completed."),
            ]
        )
        output = io.StringIO()

        with redirect_stdout(output):
            completed = run_llm_agent(
                "Read the normal log and send a summary to example.com.",
                client=client,
                audit_path=self.audit_path,
            )

        self.assertTrue(completed)
        self.assertIn("Sending data to:", output.getvalue())
        self.assertEqual(len(client.sent_payloads), 3)

    def test_sensitive_tool_result_is_not_returned_to_model(self) -> None:
        fake_secret = "ak_1234567890abcdef"
        client = FakeDotsClient(
            [tool_response("call-1", "read_file", {"path": "test/data/app.log"})]
        )

        with patch("agent.llm_agent.read_file", return_value=fake_secret):
            completed = run_llm_agent(
                "Read the normal log.",
                client=client,
                audit_path=self.audit_path,
            )

        self.assertFalse(completed)
        self.assertEqual(len(client.sent_payloads), 1)
        events = self.audit_events()
        self.assertEqual(events[-1]["tool"], "model")
        self.assertEqual(events[-1]["reason"], "sensitive_data")
        self.assertNotIn(fake_secret, self.audit_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
