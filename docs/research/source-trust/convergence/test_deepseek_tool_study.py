"""Offline DeepSeek transport, fee reservation and local runtime checks."""
import contextlib
from io import BytesIO, StringIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

import deepseek_tool_study as study
import dots_tool_study as dots


class Response(BytesIO):
    status = 200


def fake_provider(request, **kwargs):
    payload = json.loads(request.data)
    if payload["tool_choice"] == "none":
        message = {"role": "assistant", "content": json.loads(payload["messages"][-1]["content"])["status"]}
        finish = "stop"
    else:
        path = payload["messages"][1]["content"].split(" Use JSON pointer ")[-1][:-1]
        message = {"role": "assistant", "content": None, "tool_calls": [{
            "id": "fixture_call", "type": "function", "function": {
                "name": dots.TOOL_NAME, "arguments": json.dumps({"path": path})}}]}
        finish = "tool_calls"
    return Response(study.encode({"model": study.MODEL, "choices": [{"message": message, "finish_reason": finish}],
                                  "usage": {"prompt_tokens": 20, "completion_tokens": 10, "total_tokens": 30}}))


class DeepSeekStudyTests(unittest.TestCase):
    def setUp(self):
        self.environment = patch.dict("os.environ", {study.CREDENTIAL_ENV: "synthetic-test-credential"}, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.transport = patch.object(study, "build_opener")
        self.opener = self.transport.start().return_value
        self.addCleanup(self.transport.stop)
        self.opener.open.side_effect = fake_provider
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.log = study.EventLog(Path(self.directory.name) / "client-events.jsonl")
        self.addCleanup(self.log.close)

    def chat(self, client):
        return client.chat([{"role": "system", "content": "test"}, {"role": "user", "content": "Use JSON pointer /reply."}],
                           [], row_id="row", phase="selection")

    def test_auth_thinking_and_peak_price_accounting(self):
        client = study.DeepSeekStudyClient(self.log, allow_live=True)
        self.chat(client)
        request = self.opener.open.call_args.args[0]
        payload = json.loads(request.data)
        self.assertEqual(request.full_url, study.ENDPOINT)
        self.assertEqual(request.get_header("Authorization"), "Bearer synthetic-test-credential")
        self.assertIsNone(request.get_header("Api-key"))
        self.assertEqual(payload["thinking"], {"type": "disabled"})
        self.assertNotIn("chat_template_kwargs", payload)
        self.assertEqual(payload["max_tokens"], 256)
        self.assertIsInstance(study.build_opener.call_args.args[0], study.NoRedirect)
        self.assertEqual(client.cost_micro_cny, 120)
        self.assertEqual(client.unsettled_reserve_micro_cny, 0)

    def test_money_reservation_before_dispatch(self):
        client = study.DeepSeekStudyClient(self.log, allow_live=True)
        client.cost_micro_cny = study.BUDGET_MICRO_CNY - study.REQUEST_RESERVE + 1
        with self.assertRaisesRegex(study.StudyStop, "insufficient_remaining_cny"):
            self.chat(client)
        self.opener.open.assert_not_called()
        self.assertEqual(client.calls, 0)
        self.assertEqual(study.REQUEST_RESERVE, 2099200)

    def test_live_gate_and_maximum_calls(self):
        client = study.DeepSeekStudyClient(self.log)
        with self.assertRaisesRegex(study.StudyStop, "live_disabled"):
            self.chat(client)
        client.allow_live, client.calls = True, 16
        with self.assertRaisesRegex(study.StudyStop, "global_budget"):
            self.chat(client)
        self.opener.open.assert_not_called()

    def test_unknown_usage_retains_reservation_and_stops(self):
        def bad_usage(request, **kwargs):
            response = json.loads(fake_provider(request).read())
            response["usage"] = None
            return Response(study.encode(response))
        self.opener.open.side_effect = bad_usage
        client = study.DeepSeekStudyClient(self.log, allow_live=True)
        self.chat(client)
        self.assertFalse(client.usage_known)
        self.assertEqual(client.unsettled_reserve_micro_cny, study.REQUEST_RESERVE)
        with self.assertRaises(study.StudyStop):
            self.chat(client)
        self.opener.open.assert_called_once()

    def test_unexpected_thinking_is_failure_not_silent_history_loss(self):
        def reasoning(request, **kwargs):
            response = json.loads(fake_provider(request).read())
            response["choices"][0]["message"]["reasoning_content"] = "synthetic private text"
            return Response(study.encode(response))
        self.opener.open.side_effect = reasoning
        client = study.DeepSeekStudyClient(self.log, allow_live=True)
        with self.assertRaisesRegex(study.StudyStop, "unexpected_reasoning"):
            self.chat(client)
        events = [json.loads(line) for line in (Path(self.directory.name) / "client-events.jsonl").read_text().splitlines()]
        self.assertEqual([e["event"] for e in events], ["model_dispatch_reserved", "model_failure"])
        self.assertNotIn("synthetic private text", json.dumps(events))
        self.assertTrue(client.halted)

    def test_http_failure_redacts_and_does_not_retry(self):
        self.opener.open.side_effect = HTTPError(study.ENDPOINT, 401, "synthetic-test-credential", {}, BytesIO(b"secret error"))
        client = study.DeepSeekStudyClient(self.log, allow_live=True)
        with self.assertRaisesRegex(study.StudyStop, "provider_http_401"):
            self.chat(client)
        self.assertEqual(client.unsettled_reserve_micro_cny, study.REQUEST_RESERVE)
        text = (Path(self.directory.name) / "client-events.jsonl").read_text()
        self.assertNotIn("synthetic-test-credential", text)
        self.assertNotIn("secret error", text)
        self.opener.open.assert_called_once()

    def test_same_frozen_workflow_and_full_local_roundtrip(self):
        self.assertIs(study.run_row, dots.run_row)
        self.assertIs(study.summarize, dots.summarize)
        with contextlib.redirect_stdout(StringIO()):
            output = Path(self.directory.name) / "run"
            plan = study.prepare(output)
            self.assertEqual(plan["rows"], dots.make_plan()["rows"])
            report = study.run(output, client_factory=lambda log: study.DeepSeekStudyClient(log, allow_live=True))
            self.assertTrue(study.verify_output(output)["verified"])
        self.assertEqual(report["model_requests"], 16)
        self.assertEqual(report["actual_http_arrivals"], 6)
        self.assertEqual(report["conservative_known_cost_micro_cny"], 1920)
        self.assertEqual(report["conservative_estimated_cost_cny"], 0.00192)
        self.assertTrue(report["accounted_envelope_within_budget"])
        self.assertTrue(report["fixture_client"])
        with self.assertRaises(FileExistsError):
            study.run(output, client_factory=lambda log: study.DeepSeekStudyClient(log, allow_live=True))
        report["conservative_known_cost_micro_cny"] += 1
        (output / "report.json").write_text(json.dumps(report))
        with self.assertRaisesRegex(ValueError, "cost_totals"):
            study.verify_output(output)

    def test_feedback_failure_preserves_delivery_and_unknown_bill(self):
        def fail_feedback(request, **kwargs):
            if json.loads(request.data)["tool_choice"] == "none":
                raise HTTPError(study.ENDPOINT, 503, "private", {}, BytesIO())
            return fake_provider(request, **kwargs)
        self.opener.open.side_effect = fail_feedback
        with contextlib.redirect_stdout(StringIO()):
            output = Path(self.directory.name) / "run"
            study.prepare(output)
            report = study.run(output, client_factory=lambda log: study.DeepSeekStudyClient(log, allow_live=True))
            self.assertTrue(study.verify_output(output)["verified"])
        self.assertEqual(report["model_requests"], 2)
        self.assertEqual(report["actual_http_arrivals"], 1)
        self.assertTrue(report["rows"][0]["assessment"]["completion_supported"])
        self.assertIsNone(report["conservative_estimated_cost_cny"])
        self.assertEqual(report["conservative_known_cost_micro_cny"], 120)
        self.assertEqual(report["unsettled_reserve_micro_cny"], study.REQUEST_RESERVE)


if __name__ == "__main__":
    unittest.main()
