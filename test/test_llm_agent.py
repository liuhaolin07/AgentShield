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

from agent.llm_agent import MAX_TOOL_CALLS, run_llm_agent, run_llm_agent_result
from evaluation.receiver import LoopbackReceiver
from tools.local_http import HTTPReceipt, LocalTransportError


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

    def run_result(self, responses, **kwargs):
        with redirect_stdout(io.StringIO()):
            return run_llm_agent_result("Perform the requested work.",
                                        client=FakeDotsClient(responses),
                                        audit_path=self.audit_path, **kwargs)

    def test_model_finished_is_separate_from_tool_completion(self) -> None:
        result = self.run_result([final_response("The send completed.")])
        self.assertTrue(result.model_finished)
        self.assertFalse(result.completed)
        self.assertEqual(result.evidence, ())
        self.assertEqual(result.reason, "completion_evidence_missing")
        self.assertEqual(result.final_response, "The send completed.")
        with redirect_stdout(io.StringIO()):
            self.assertFalse(run_llm_agent("Send a summary.", client=FakeDotsClient([
                final_response("Done")]), audit_path=self.audit_path))

    def test_real_file_read_has_sanitized_execution_evidence(self) -> None:
        result = self.run_result([tool_response("1", "read_file", {"path": "test/data/app.log"}),
                                  final_response("Read completed.")], required_tools=("read_file",))
        self.assertTrue(result.completed)
        self.assertEqual(len(result.evidence), 1)
        self.assertEqual(result.evidence[0].mode, "file_read")
        self.assertGreater(result.evidence[0].data_bytes, 0)
        self.assertEqual(len(result.evidence[0].data_sha256), 64)
        self.assertNotIn("INFO", repr(result.evidence))

    def test_read_cannot_satisfy_explicit_send_requirement(self) -> None:
        result = self.run_result([tool_response("1", "read_file", {"path": "test/data/app.log"}),
                                  final_response("The send completed.")], required_tools=("send_http",))
        self.assertTrue(result.model_finished)
        self.assertFalse(result.completed)
        self.assertEqual(result.evidence[0].tool, "read_file")

    def test_simulation_is_labeled_and_cannot_prove_real_http(self) -> None:
        responses = [tool_response("1", "send_http", {"url": "example.com", "data": "safe summary"}),
                     final_response("Done")]
        with patch("tools.local_http.socket.socket") as sock:
            simulated = self.run_result(responses, required_tools=("send_http",))
            real_required = self.run_result(responses, require_real_http=True)
        sock.assert_not_called()
        self.assertTrue(simulated.completed)
        self.assertEqual(simulated.evidence[0].mode, "simulated_http")
        self.assertIsNone(simulated.evidence[0].response_status)
        self.assertTrue(real_required.model_finished)
        self.assertFalse(real_required.completed)

    def test_real_http_completion_has_independent_receiver_witness(self) -> None:
        try:
            receiver = LoopbackReceiver()
        except OSError as error:
            self.skipTest(f"Loopback unavailable: {error}")
        with receiver:
            policy = Path(self.temp_directory.name) / "policy.yaml"
            policy.write_text("blocked_files:\nallowed_file_roots:\nallowed_domains:\n  - 127.0.0.1\n")
            with patch.object(FakeDotsClient, "endpoint", receiver.target.origin + "/model"):
                result = self.run_result([
                    tool_response("1", "send_http", {"url": receiver.url, "data": "safe summary"}),
                    final_response("Done")], local_http_target=receiver.target, policy_path=policy,
                    required_tools=("send_http",), require_real_http=True)
            self.assertTrue(result.completed)
            self.assertEqual(result.evidence[0].mode, "local_http")
            self.assertEqual(result.evidence[0].response_status, 202)
            self.assertEqual(len(receiver.arrivals), 1)
            self.assertEqual(receiver.arrivals[0]["body"], "safe summary")

    def test_failed_file_execution_cannot_prove_completion(self) -> None:
        with patch("agent.llm_agent.read_file", side_effect=OSError("synthetic failure")):
            result = self.run_result([tool_response("1", "read_file", {"path": "test/data/app.log"}),
                                      final_response("Done")])
        self.assertFalse(result.model_finished)
        self.assertFalse(result.completed)
        self.assertEqual(result.evidence, ())
        self.assertEqual(self.audit_events()[-1]["decision"], "ALLOW")

    def test_failed_receipt_and_transport_have_no_success_evidence(self) -> None:
        responses = [tool_response("1", "send_http", {"url": "example.com", "data": "safe summary"})]
        for outcome in (HTTPReceipt(500, 0, "fake"), None, LocalTransportError("target_not_pinned_loopback")):
            kwargs = {"side_effect": outcome} if isinstance(outcome, Exception) else {"return_value": outcome}
            with self.subTest(outcome=outcome), patch("agent.llm_agent.send_http", **kwargs):
                result = self.run_result(responses, local_http_target=object())
                self.assertFalse(result.completed)
                self.assertEqual(result.evidence, ())

    def test_malformed_batch_blocks_before_valid_sibling_executes(self) -> None:
        valid = tool_response("1", "read_file", {"path": "test/data/app.log"})["choices"][0]["message"]["tool_calls"][0]
        invalid = {"id": "bad", "type": "function", "function": {"name": "read_file", "arguments": "{"}}
        for entry in (42, invalid, valid):
            response = {"choices": [{"message": {"tool_calls": [valid, entry]}}]}
            with self.subTest(entry=entry), patch("agent.llm_agent.read_file") as read:
                result = self.run_result([response])
                read.assert_not_called()
                self.assertFalse(result.completed)
                self.assertEqual(result.reason, "invalid_tool_call")
                self.assertEqual(self.audit_events()[-1]["decision"], "BLOCK")

    def test_tool_protocol_and_argument_budgets(self) -> None:
        call = tool_response("1", "read_file", {"path": "test/data/app.log"})["choices"][0]["message"]["tool_calls"][0]
        variants = [None, "not a list", [dict(call, type="unknown")], [dict(call, id="")],
                    [dict(call, function={"name": "read_file", "arguments": " " * 65537})],
                    [dict(call, function={"name": "read_file", "arguments": "[" * 2000 + "]" * 2000})],
                    [dict(call, id=str(i)) for i in range(MAX_TOOL_CALLS + 1)]]
        for calls in variants:
            with self.subTest(calls_type=type(calls)), patch("agent.llm_agent.read_file") as read:
                result = self.run_result([{"choices": [{"message": {"tool_calls": calls}}]}])
                self.assertFalse(result.completed)
                read.assert_not_called()

    def test_unknown_agent_tool_cannot_be_audited_as_allowed_capability(self) -> None:
        for name in ("http", "file", "model", "password=SCANNER_ONLY_FAKE"):
            with self.subTest(name=name):
                result = self.run_result([tool_response("1", name, {})])
                self.assertFalse(result.completed)
                event = self.audit_events()[-1]
                self.assertEqual(event["decision"], "BLOCK")
                self.assertEqual(event["reason"], "unsupported_tool")
                self.assertNotIn(name, self.audit_path.read_text() if name.startswith("password=") else "")

    def test_empty_final_response_and_step_limit_are_not_success(self) -> None:
        self.assertFalse(self.run_result([final_response("")]).completed)
        result = self.run_result([tool_response("1", "read_file", {"path": "test/data/app.log"})], max_steps=1)
        self.assertFalse(result.completed)
        self.assertFalse(result.model_finished)
        self.assertEqual(len(result.evidence), 1)
        self.assertEqual(result.reason, "step_limit")

    def test_completion_contract_validation(self) -> None:
        for kwargs in ({"max_steps": 0}, {"max_steps": 7}, {"max_steps": True},
                       {"required_tools": "send_http"}, {"required_tools": ("shell",)}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                self.run_result([], **kwargs)


if __name__ == "__main__":
    unittest.main()
