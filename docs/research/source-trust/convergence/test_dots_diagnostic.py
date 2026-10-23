"""Offline transport substitutions; these are never genuine model responses."""

from copy import deepcopy
from io import BytesIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError, URLError
from urllib.request import Request

import dots_diagnostic as diagnostic


def response():
    return {
        "model": diagnostic.MODEL,
        "choices": [{"index": 0, "finish_reason": "tool_calls", "message": {
            "role": "assistant", "content": None, "tool_calls": [{
                "id": "fixture-call", "type": "function", "function": {
                    "name": diagnostic.TOOL,
                    "arguments": json.dumps({"marker": diagnostic.MARKER})}}]}}],
        "usage": {"prompt_tokens": 20, "completion_tokens": 15, "total_tokens": 35},
    }


class DotsDiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.key = "test-only-synthetic-credential"
        self.environment = patch.dict("os.environ", {diagnostic.CREDENTIAL_ENV: self.key}, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.opener_patch = patch.object(diagnostic, "build_opener")
        self.opener_factory = self.opener_patch.start()
        self.addCleanup(self.opener_patch.stop)
        self.opener = self.opener_factory.return_value
        self.http_response = self.opener.open.return_value.__enter__.return_value
        self.http_response.status = 200
        self.http_response.read.return_value = diagnostic.encode(response())

    def live(self, **kwargs):
        return diagnostic.diagnose(live=True, max_calls=1, **kwargs)

    def test_live_off_and_missing_explicit_budget_never_dispatch(self):
        for args, reason in (({}, "live_disabled"), ({"live": True}, "explicit_one_call_budget_required")):
            report = diagnostic.diagnose(**args)
            self.assertEqual(report["reason"], reason)
            self.assertEqual(report["dispatch_attempts"], 0)
        self.opener_factory.assert_not_called()

    def test_missing_and_invalid_credentials_never_dispatch(self):
        for value, reason in (("", "missing_credential"), ("fake\nheader", "invalid_credential_format"), ("假", "invalid_credential_format")):
            with self.subTest(reason=reason), patch.dict("os.environ", {diagnostic.CREDENTIAL_ENV: value}, clear=True):
                report = self.live()
                self.assertEqual(report["reason"], reason)
        self.opener_factory.assert_not_called()

    def test_invalid_budget_and_environment_name_fail_before_dispatch(self):
        for value in (0, 2, True, 1.0, "1"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                diagnostic.diagnose(live=True, max_calls=value)
        with self.assertRaises(ValueError):
            self.live(credential_env="KEY\n")
        self.opener_factory.assert_not_called()

    def test_fixed_endpoint_auth_and_bounded_public_payload(self):
        report = self.live()
        request = self.opener.open.call_args.args[0]
        sent = json.loads(request.data)
        self.assertEqual(request.full_url, diagnostic.ENDPOINT)
        self.assertEqual(request.get_header("Api-key"), self.key)
        self.assertIsNone(request.get_header("Authorization"))
        self.assertEqual(sent["model"], diagnostic.MODEL)
        self.assertFalse(sent["chat_template_kwargs"]["enable_thinking"])
        self.assertEqual(sent["max_tokens"], 128)
        self.assertLessEqual(len(request.data), diagnostic.MAX_REQUEST_BYTES)
        self.http_response.read.assert_called_once_with(diagnostic.MAX_RESPONSE_BYTES + 1)
        self.assertEqual(report["status"], "OBSERVED")
        self.assertTrue(report["tool_protocol_check_passed"])
        self.assertTrue(report["usage_known"])
        self.assertFalse(report["defense_credit"])
        self.assertEqual(report["tool_executions"], 0)
        self.assertEqual(report["formal_pilot_rows"], 0)
        self.assertEqual(report["research_metrics"], {"ASR": None, "TCR": None, "FPR": None})
        self.assertNotIn(self.key, json.dumps(report))

    def test_redirect_cannot_forward_credentials(self):
        req = Request(diagnostic.ENDPOINT, headers={"api-key": self.key})
        handler = diagnostic.NoRedirect()
        for code in (301, 302, 303, 307, 308):
            with self.subTest(code=code):
                self.assertIsNone(handler.redirect_request(req, None, code, "redirect", {}, "https://elsewhere.invalid/"))
        self.live()
        self.assertIsInstance(self.opener_factory.call_args.args[0], diagnostic.NoRedirect)

    def test_http_error_diagnostics_are_not_read_or_logged_no_retry(self):
        error = HTTPError(diagnostic.ENDPOINT, 401, self.key, {"secret": self.key}, BytesIO(self.key.encode()))
        error.read = Mock(side_effect=AssertionError("must_not_read_provider_error"))
        self.opener.open.side_effect = error
        report = self.live()
        self.assertEqual(report["reason"], "provider_http_error")
        self.assertEqual(report["http_status"], 401)
        self.assertFalse(report["usage_known"])
        self.assertNotIn(self.key, json.dumps(report))
        self.opener.open.assert_called_once()
        error.read.assert_not_called()

    def test_transport_failure_is_incomplete_not_defense_credit(self):
        self.opener.open.side_effect = URLError(self.key)
        report = self.live()
        self.assertEqual(report["status"], "INCOMPLETE")
        self.assertEqual(report["dispatch_attempts"], 1)
        self.assertFalse(report["defense_credit"])
        self.assertNotIn(self.key, json.dumps(report))
        self.opener.open.assert_called_once()

    def test_response_limits_invalid_json_and_schema_are_failed(self):
        for raw in (b"x" * (diagnostic.MAX_RESPONSE_BYTES + 1), b"<html>secret</html>",
                    b'{"choices":[],"choices":[]}', b'{"choices":NaN}', b"[]", b'{"choices":[]}'):
            with self.subTest(raw_length=len(raw)):
                self.http_response.read.return_value = raw
                report = self.live()
                self.assertEqual(report["status"], "FAILED")
                self.assertFalse(report["response_schema_valid"])
                self.assertFalse(report["defense_credit"])

    def test_missing_or_inconsistent_usage_is_unknown(self):
        for usage in (None, {}, {"prompt_tokens": True, "completion_tokens": 1, "total_tokens": 2},
                      {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 3}):
            value = response()
            value["usage"] = usage
            self.http_response.read.return_value = diagnostic.encode(value)
            report = self.live()
            self.assertEqual(report["status"], "OBSERVED")
            self.assertIsNone(report["usage"])
            self.assertFalse(report["usage_known"])

    def test_unexpected_tool_and_model_output_never_executed_or_persisted(self):
        value = response()
        value["model"] = self.key
        value["choices"][0]["message"]["content"] = self.key
        value["choices"][0]["message"]["tool_calls"][0]["function"]["name"] = "run_shell"
        value["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"] = self.key
        self.http_response.read.return_value = diagnostic.encode(value)
        report = self.live()
        self.assertFalse(report["reported_model_matches_requested"])
        self.assertFalse(report["tool_protocol_check_passed"])
        self.assertEqual(report["tool_request"], "UNEXPECTED_OR_INVALID_REQUEST")
        self.assertEqual(report["tool_executions"], 0)
        self.assertNotIn(self.key, json.dumps(report))

    def test_no_tool_or_wrong_arguments_do_not_pass_tool_protocol(self):
        for variant in ("no_tool", "wrong_marker", "extra_argument", "truncated"):
            value = deepcopy(response())
            choice = value["choices"][0]
            if variant == "no_tool":
                choice["message"]["tool_calls"] = []
                choice["message"]["content"] = "done"
                choice["finish_reason"] = "stop"
            elif variant == "truncated":
                choice["finish_reason"] = "length"
            else:
                arguments = {"marker": "wrong"} if variant == "wrong_marker" else {"marker": diagnostic.MARKER, "extra": 1}
                choice["message"]["tool_calls"][0]["function"]["arguments"] = json.dumps(arguments)
            self.http_response.read.return_value = diagnostic.encode(value)
            with self.subTest(variant=variant):
                self.assertFalse(self.live()["tool_protocol_check_passed"])

    def test_report_is_reserved_before_dispatch_and_cannot_be_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "attempt.json"
            original_response = self.opener.open.return_value
            def observe_checkpoint(*args, **kwargs):
                saved = json.loads(path.read_text())
                self.assertEqual(saved["status"], "INCOMPLETE")
                self.assertEqual(saved["dispatch_attempts"], 1)
                return original_response
            self.opener.open.side_effect = observe_checkpoint
            diagnostic.run_to_file(path, live=True, max_calls=1)
            with self.assertRaises(FileExistsError):
                diagnostic.run_to_file(path, live=True, max_calls=1)
            self.opener.open.assert_called_once()

    def test_failed_checkpoint_prevents_dispatch(self):
        with self.assertRaises(OSError):
            self.live(checkpoint=Mock(side_effect=OSError("fixture disk full")))
        self.opener_factory.assert_not_called()


if __name__ == "__main__":
    unittest.main()
