"""Fake-provider checks and actual local runtime integration; no remote models."""
import contextlib
from copy import deepcopy
from io import BytesIO, StringIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError

import dots_tool_study as study


def completion(message, finish="tool_calls", usage=None):
    return {"model": study.MODEL, "choices": [{"message": message, "finish_reason": finish}],
            "usage": usage if usage is not None else {"prompt_tokens": 20, "completion_tokens": 10, "total_tokens": 30}}


def selection(path):
    return {"role": "assistant", "content": None, "tool_calls": [{
        "id": "fixture_call", "type": "function", "function": {
            "name": study.TOOL_NAME, "arguments": json.dumps({"path": path})}}]}


class Response(BytesIO):
    status = 200


def fake_provider(request, **kwargs):
    payload = json.loads(request.data)
    if payload["tool_choice"] == "none":
        status = json.loads(payload["messages"][-1]["content"])["status"]
        value = completion({"role": "assistant", "content": status}, "stop")
    else:
        path = payload["messages"][1]["content"].split(" Use JSON pointer ")[-1][:-1]
        value = completion(selection(path))
    return Response(study.encode(value))


class DotsToolStudyTests(unittest.TestCase):
    def setUp(self):
        self.environment = patch.dict("os.environ", {study.CREDENTIAL_ENV: "synthetic-test-credential"}, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.transport = patch.object(study, "build_opener")
        self.opener = self.transport.start().return_value
        self.addCleanup(self.transport.stop)
        self.opener.open.side_effect = fake_provider

    def test_selection_distinguishes_nonadoption_wrong_target_and_invalid_call(self):
        target = "/reply"
        self.assertEqual(study.select_call(selection(target), "tool_calls", target)[1], "TARGET_OPERATION_REQUESTED")
        self.assertEqual(study.select_call({"content": "no"}, "stop", target)[1], "MODEL_DID_NOT_REQUEST_TOOL")
        self.assertEqual(study.select_call(selection("/other"), "tool_calls", target)[1], "MODEL_REQUEST_OFF_CONTRACT")
        for field, value in (("name", "run_shell"), ("arguments", '{"path":"/reply","path":"/reply"}')):
            message = selection(target)
            message["tool_calls"][0]["function"][field] = value
            self.assertEqual(study.select_call(message, "tool_calls", target)[1], "MODEL_REQUEST_INVALID")
        self.assertEqual(study.select_call(selection(target), "length", target)[1], "MODEL_REQUEST_INVALID")

    def test_live_gate_call_cap_and_unknown_usage_stop_before_next_dispatch(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.closing(study.EventLog(Path(tmp) / "events.jsonl")) as log:
            client = study.DotsStudyClient(log)
            with self.assertRaisesRegex(study.StudyStop, "live_disabled"):
                client.chat([], [], row_id="row", phase="selection")
            client.allow_live = True
            value = completion(selection("/reply"))
            value["usage"] = {"prompt_tokens": True, "completion_tokens": 1, "total_tokens": 2}
            self.opener.open.side_effect = lambda *a, **k: Response(study.encode(value))
            client.chat([], [], row_id="row", phase="selection")
            self.assertFalse(client.usage_known)
            with self.assertRaisesRegex(study.StudyStop, "global_budget_or_failure_stop"):
                client.chat([], [], row_id="row", phase="feedback")
            self.opener.open.assert_called_once()
            client.halted, client.calls = False, study.MAX_CALLS
            with self.assertRaises(study.StudyStop):
                client.chat([], [], row_id="other", phase="selection")
            self.assertEqual(self.opener.open.call_count, 1)

    def test_http_error_records_fixed_code_without_body_or_retry(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.closing(study.EventLog(Path(tmp) / "events.jsonl")) as log:
            path = Path(tmp) / "events.jsonl"
            client = study.DotsStudyClient(log, allow_live=True)
            error = HTTPError(study.ENDPOINT, 429, "synthetic-test-credential", {}, BytesIO(b"private provider text"))
            error.read = Mock(side_effect=AssertionError("must_not_read"))
            self.opener.open.side_effect = error
            with self.assertRaisesRegex(study.StudyStop, "provider_http_429"):
                client.chat([], [], row_id="row", phase="selection")
            self.assertNotIn("synthetic-test-credential", path.read_text())
            self.assertNotIn("private provider text", path.read_text())
            self.assertTrue(client.halted)
            self.opener.open.assert_called_once()
            error.read.assert_not_called()

    def test_request_limit_and_response_model_mismatch_stop(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.closing(study.EventLog(Path(tmp) / "events.jsonl")) as log:
            client = study.DotsStudyClient(log, allow_live=True)
            with self.assertRaisesRegex(study.StudyStop, "request_byte_limit"):
                client.chat([{"role": "user", "content": "x" * study.MAX_REQUEST_BYTES}], [], row_id="row", phase="selection")
            self.opener.open.assert_not_called()
            client.halted = False
            value = completion(selection("/reply"))
            value["model"] = "unexpected-model"
            self.opener.open.side_effect = lambda *a, **k: Response(study.encode(value))
            with self.assertRaisesRegex(study.StudyStop, "response_schema_or_model_mismatch"):
                client.chat([], [], row_id="row", phase="selection")
            self.assertTrue(client.halted)

    def test_full_local_roundtrip_controls_and_runtime_blocks(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(StringIO()):
            output = Path(tmp) / "run"
            study.prepare(output)
            report = study.run(output, client_factory=lambda log: study.DotsStudyClient(log, allow_live=True))
            self.assertTrue(report["fixture_client"])
            self.assertEqual(report["model_requests"], 16)
            self.assertEqual(report["actual_http_arrivals"], 6)
            self.assertEqual(report["reported_tokens"], 480)
            groups = report["summary"]["by_policy"]
            self.assertEqual(groups["no_defense"]["attack_delivered"], 2)
            self.assertEqual(groups["precision"]["attack_runtime_blocks"], 2)
            self.assertEqual(groups["precision"]["benign_completed"], 2)
            self.assertTrue(all(r["model_acknowledged_status"] for r in report["rows"]))
            self.assertTrue(study.verify_output(output)["verified"])
            with self.assertRaises(FileExistsError):
                study.run(output, client_factory=lambda log: study.DotsStudyClient(log, allow_live=True))
            self.assertEqual(self.opener.open.call_count, 16)
            changed = deepcopy(report)
            changed["rows"][0]["assessment"]["block_supported"] = True
            (output / "report.json").write_text(json.dumps(changed))
            with self.assertRaisesRegex(ValueError, "row_event_binding"):
                study.verify_output(output)

    def test_feedback_failure_preserves_actual_delivery_and_marks_remaining_unknown(self):
        original = fake_provider
        def fail_feedback(request, **kwargs):
            if json.loads(request.data)["tool_choice"] == "none":
                raise HTTPError(study.ENDPOINT, 503, "synthetic-test-credential", {}, BytesIO())
            return original(request, **kwargs)
        self.opener.open.side_effect = fail_feedback
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stdout(StringIO()):
            output = Path(tmp) / "run"
            study.prepare(output)
            report = study.run(output, client_factory=lambda log: study.DotsStudyClient(log, allow_live=True))
            self.assertEqual(report["model_requests"], 2)
            self.assertEqual(report["actual_http_arrivals"], 1)
            first = report["rows"][0]
            self.assertTrue(first["assessment"]["completion_supported"])
            self.assertFalse(first["tool_result_returned_to_model"])
            self.assertIsNone(report["reported_tokens"])
            self.assertEqual(report["summary"]["by_policy"]["precision"]["ASR_identified_bounds"], [0, 1])
            self.assertTrue(study.verify_output(output)["verified"])

    def test_model_nonadoption_never_executes_runtime_or_receives_block_credit(self):
        class RefusingClient:
            def chat(self, *args, **kwargs):
                return {"role": "assistant", "content": "I cannot do that."}, "stop"
        log = Mock()
        task = {"instruction": "Test", "output_path": "/reply"}
        row = {"row_id": "test", "policy": "precision", "kind": "attack"}
        with patch.object(study, "probe_identity") as probe:
            result = study.run_row(row, task, {"labels": [{"path": "/reply"}]}, b"{}", RefusingClient(), None, log)
            probe.assert_not_called()
        self.assertEqual(result["model_selection"], "MODEL_DID_NOT_REQUEST_TOOL")
        self.assertIsNone(result["assessment"])
        self.assertEqual(study.summarize([result])["by_policy"]["precision"]["attack_runtime_blocks"], 0)


if __name__ == "__main__":
    unittest.main()
