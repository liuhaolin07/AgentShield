"""Offline adversarial capture tests. No real provider, credential or spend."""

from contextlib import contextmanager
from copy import deepcopy
from http.client import IncompleteRead
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError, URLError

from corruption_graph import canonical, digest
from development_execution_v2 import decode, read_raw, save_raw, sha
from model_transport_v3 import (CapturedClient, CaptureStop, FixtureWire, HttpWire,
                                MAX_RESPONSE, WireResponse, policy, replay_capture)
from model_workflow_v3 import (fixture_response, load, payload, prepare, replay_row,
                               run, tool_request, verify)


@contextmanager
def server(callback):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            status, response = callback(body, dict(self.headers))
            self.send_response(status)
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

        def log_message(self, *_):
            pass
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_port}/v1/chat/completions"
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join()


class CaptureTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / "captures"
        self.row = digest("test-row")
        self.config = policy("deepseek", [self.row])
        self.body = {"model": self.config["model"], "stream": False, "max_tokens": 256,
                     "tool_choice": "auto", "messages": [{"role": "system", "content": "fixture"},
                                                           {"role": "user", "content": "JSON pointer /reply."}]}

    def client(self, callback=fixture_response, config=None):
        return CapturedClient(self.root, config or self.config, FixtureWire(callback))

    def replay(self, phase="selection", body=None):
        return replay_capture(self.root, self.config, self.row, phase, expected_payload=body or self.body)

    def test_actual_request_and_noncanonical_response_are_retained(self):
        original = fixture_response(canonical(self.body)).body
        def wire(body):
            self.assertEqual(read_raw(self.root, digest([self.row, "selection"]), "request.bin"), body)
            self.assertTrue((self.root / digest([self.row, "selection"]) / "input.json").is_file())
            return WireResponse(200, original)
        self.client(wire).chat(self.row, "selection", self.body)
        self.assertEqual(read_raw(self.root, digest([self.row, "selection"]), "response.bin"), original)
        self.assertNotEqual(original, canonical(decode(original)))
        self.assertTrue(self.replay()["usable_response"])

    def test_invalid_bodies_are_archived_before_parser_and_stop(self):
        valid = decode(fixture_response(canonical(self.body)).body)
        malformed = [b"not json", b'{"model":"x","model":"y"}', canonical({**valid, "usage": None}),
                     canonical({**valid, "model": "unexpected-model"})]
        for index, raw in enumerate(malformed):
            with self.subTest(index=index):
                self.root = self.root.parent / f"case-{index}"
                client = self.client(lambda _: WireResponse(200, raw))
                with self.assertRaisesRegex(CaptureStop, "PROVIDER_SCHEMA_OR_USAGE_INVALID"):
                    client.chat(self.row, "selection", self.body)
                self.assertEqual(read_raw(self.root, digest([self.row, "selection"]), "response.bin"), raw)
                self.assertTrue(self.replay()["raw_archive_complete"])
                self.assertFalse(self.replay()["usable_response"])
                with self.assertRaisesRegex(CaptureStop, "PRIOR_FAILURE"):
                    client.chat(self.row, "feedback", self.body)
                self.assertEqual(client.calls, 1)

    def test_partial_missing_and_oversize_never_become_complete(self):
        responses = [WireResponse(200, b"partial", False, "PARTIAL_RESPONSE"), WireResponse(None, None, False),
                     WireResponse(200, b"x" * (MAX_RESPONSE + 2))]
        for index, response in enumerate(responses):
            with self.subTest(index=index):
                self.root = self.root.parent / f"partial-{index}"
                client = self.client(lambda _: response)
                with self.assertRaisesRegex(CaptureStop, "MISSING_OR_PARTIAL"):
                    client.chat(self.row, "selection", self.body)
                self.assertEqual(client.calls, 1)
                self.assertFalse(self.replay()["raw_archive_complete"])

    def test_http_error_body_is_complete_evidence_but_unusable(self):
        client = self.client(lambda _: WireResponse(429, b'{"error":"fixture rate limit"}\n'))
        with self.assertRaisesRegex(CaptureStop, "PROVIDER_HTTP_ERROR"):
            client.chat(self.row, "selection", self.body)
        result = self.replay()
        self.assertTrue(result["raw_archive_complete"])
        self.assertFalse(result["usable_response"])
        self.assertEqual(result["http_status"], 429)

    def test_request_archive_failure_prevents_dispatch(self):
        wire = Mock(side_effect=fixture_response)
        client = self.client(wire)
        def failing(path, raw):
            if path.name == "request.bin":
                raise OSError("fixture disk failure")
            save_raw(path, raw)
        with patch("model_transport_v3.save_raw", failing), self.assertRaisesRegex(CaptureStop, "BEFORE_DISPATCH"):
            client.chat(self.row, "selection", self.body)
        self.assertFalse(wire.called)
        self.assertEqual(client.calls, 0)

    def test_response_archive_failure_charges_attempt_and_stops(self):
        wire = Mock(side_effect=fixture_response)
        client = self.client(wire)
        def failing(path, raw):
            if path.name == "response.bin":
                raise OSError("fixture disk failure")
            save_raw(path, raw)
        with patch("model_transport_v3.save_raw", failing), self.assertRaisesRegex(CaptureStop, "AFTER_DISPATCH"):
            client.chat(self.row, "selection", self.body)
        self.assertEqual((wire.call_count, client.calls, client.halted), (1, 1, True))
        self.assertFalse(self.replay()["raw_archive_complete"])

    def test_live_zero_grant_precedes_any_credential_or_wire_access(self):
        wire = SimpleNamespace(kind="LIVE_PROVIDER", send=Mock())
        client = CapturedClient(self.root, self.config, wire)
        with patch("model_transport_v3.os.environ", {}) as environ, self.assertRaisesRegex(CaptureStop, "NO_NEW_LIVE_AUTHORIZATION"):
            client.chat(self.row, "selection", self.body)
        self.assertFalse(wire.send.called)
        self.assertEqual(client.calls, 0)
        self.assertEqual(list(self.root.iterdir()), [self.root / "capture-plan.json"])

    def test_future_cost_reservation_and_unknown_usage_are_conservative(self):
        config = deepcopy(self.config)
        config.update(max_live_requests=1, live_authorization_ref="TEST_ONLY_NO_REAL_GRANT", budget_micro_cny=1)
        wire = SimpleNamespace(kind="LIVE_PROVIDER", send=Mock(return_value=WireResponse(200, b"invalid")))
        client = CapturedClient(self.root, config, wire)
        with self.assertRaisesRegex(CaptureStop, "INSUFFICIENT_LIVE_COST_RESERVE"):
            client.chat(self.row, "selection", self.body)
        self.assertFalse(wire.send.called)
        config["budget_micro_cny"] = 3_000_000
        self.root = self.root.parent / "reserved"
        client = CapturedClient(self.root, config, wire)
        with patch.dict(os.environ, {"DEEPSEEK_API_KEY": "fixture-secret-never-a-credential"}), self.assertRaises(CaptureStop):
            client.chat(self.row, "selection", self.body)
        self.assertEqual(client.reserve_micro_cny, 2_099_200)
        self.assertEqual((client.calls, client.cost_micro_cny), (1, 0))
        self.assertTrue(client.halted)

    def test_plan_mutation_duplicate_exchange_and_restart_cannot_reset_budget(self):
        client = self.client()
        self.config["max_requests"] = 99
        self.assertEqual(client.config["max_requests"], 16)
        client.chat(self.row, "selection", self.body)
        with self.assertRaises(FileExistsError):
            client.chat(self.row, "selection", self.body)
        self.assertEqual(client.calls, 1)
        with self.assertRaises(FileExistsError):
            CapturedClient(self.root, client.config, FixtureWire(fixture_response))

    def test_sixteen_dispatch_cap_and_unknown_pair_rejection(self):
        rows = [digest(i) for i in range(17)]
        config = policy("deepseek", rows)
        client = self.client(config=config)
        with self.assertRaises(ValueError):
            client.chat(digest("unplanned"), "selection", self.body)
        for row in rows[:16]:
            client.chat(row, "selection", self.body)
        with self.assertRaisesRegex(CaptureStop, "CAPTURE_BUDGET"):
            client.chat(rows[-1], "selection", self.body)
        self.assertEqual(client.calls, 16)

    def test_prompt_tamper_missing_raw_and_symlink_are_rejected(self):
        self.client().chat(self.row, "selection", self.body)
        changed = {**self.body, "messages": []}
        self.assertFalse(self.replay(body=changed)["raw_archive_complete"])
        path = self.root / digest([self.row, "selection"]) / "response.bin"
        raw = path.read_bytes()
        path.write_bytes(raw + b" ")
        self.assertFalse(self.replay()["raw_archive_complete"])
        path.unlink()
        target = self.root.parent / "external-response"
        target.write_bytes(raw)
        path.symlink_to(target)
        self.assertFalse(self.replay()["raw_archive_complete"])
        path.unlink()
        self.assertFalse(self.replay()["raw_archive_complete"])

    def test_reasoning_token_overrun_and_truncated_completion_fail(self):
        original = decode(fixture_response(canonical(self.body)).body)
        for index, kind in enumerate(("reasoning", "tokens", "truncated")):
            response = deepcopy(original)
            if kind == "reasoning": response["choices"][0]["message"]["reasoning_content"] = "unexpected"
            if kind == "tokens": response["usage"] = {"prompt_tokens": 20, "completion_tokens": 257, "total_tokens": 277}
            if kind == "truncated": response["choices"][0]["finish_reason"] = "length"
            self.root = self.root.parent / f"schema-{index}"
            client = self.client(lambda _: WireResponse(200, canonical(response)))
            with self.assertRaises(CaptureStop): client.chat(self.row, "selection", self.body)
            self.assertTrue(self.replay()["raw_archive_complete"])
            self.assertFalse(self.replay()["usable_response"])

    def test_loopback_http_transmits_exact_archived_body_without_auth(self):
        def callback(body, headers):
            self.assertEqual(body, read_raw(self.root, digest([self.row, "selection"]), "request.bin"))
            self.assertFalse(any(key.lower() in ("authorization", "api-key") for key in headers))
            return 200, fixture_response(body).body
        with server(callback) as url:
            client = CapturedClient(self.root, self.config, HttpWire("deepseek", fixture_url=url))
            client.chat(self.row, "selection", self.body)
        self.assertTrue(self.replay()["usable_response"])

    def test_http_error_network_failure_partial_and_secret_echo(self):
        wire = HttpWire("deepseek", fixture_url="http://127.0.0.1:1/v1/chat/completions")
        error = HTTPError(wire.endpoint, 503, "fixture", {}, io.BytesIO(b"original error"))
        with patch("model_transport_v3.build_opener", return_value=SimpleNamespace(open=Mock(side_effect=error))):
            result = wire.send(b"{}")
            self.assertEqual((result.status, result.body, result.complete), (503, b"original error", True))
        with patch("model_transport_v3.build_opener", return_value=SimpleNamespace(open=Mock(side_effect=URLError("fixture")))):
            self.assertIsNone(wire.send(b"{}").body)
        response = Mock(status=200, headers={})
        response.read.side_effect = IncompleteRead(b"partial", 42)
        with patch("model_transport_v3.build_opener", return_value=SimpleNamespace(open=Mock(return_value=response))):
            self.assertEqual(wire.send(b"{}").error, "PARTIAL_RESPONSE")
        secret = "fixture-secret-never-a-credential"
        response.read.side_effect = None
        response.read.return_value = secret.encode()
        with patch.dict(os.environ, {"DEEPSEEK_API_KEY": secret}), patch("model_transport_v3.build_opener", return_value=SimpleNamespace(open=Mock(return_value=response))):
            result = HttpWire("deepseek").send(b"{}")
            self.assertEqual((result.body, result.error), (None, "CREDENTIAL_ECHO_WITHHELD"))

    def test_short_content_length_is_partial_even_without_read_exception(self):
        wire = HttpWire("deepseek", fixture_url="http://127.0.0.1:1/v1/chat/completions")
        response = SimpleNamespace(status=200, headers={"Content-Length": "100"}, read=lambda _: b"short", close=lambda: None)
        with patch("model_transport_v3.build_opener", return_value=SimpleNamespace(open=lambda *_args, **_kwargs: response)):
            result = wire.send(b"{}")
        self.assertEqual((result.body, result.complete, result.error), (b"short", False, "PARTIAL_RESPONSE"))

    def test_nonloopback_fixture_endpoint_and_unknown_wire_rejected(self):
        for url in ("https://example.org/v1/chat/completions", "http://localhost:1/v1/chat/completions", "http://127.0.0.1:1/wrong"):
            with self.assertRaises(ValueError): HttpWire("deepseek", fixture_url=url)
        with self.assertRaises(ValueError):
            CapturedClient(self.root, self.config, SimpleNamespace(kind="unknown"))


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name) / "run"
        self.plan = prepare(self.root)

    def test_complete_fixture_links_provider_tool_and_receiver_and_detects_tamper(self):
        report = run(self.root)
        checked = verify(self.root)
        self.assertTrue(checked["integrity_passed"])
        self.assertEqual((len(report["rows"]), report["fixture_transport_requests"], report["fixture_reported_tokens"], report["actual_http_arrivals"]), (8, 16, 480, 6))
        self.assertEqual((report["real_model_calls"], report["new_cost_cny"], report["formal_pilot_rows"]), (0, 0, 0))
        self.assertEqual(len(checked["sample"]), 10)
        self.assertTrue(all(s["passed"] for s in checked["sample"]))
        for key in ("fixture_reported_tokens", "fixture_transport_requests", "actual_http_arrivals", "new_cost_cny"):
            with self.subTest(key=key):
                changed = deepcopy(report)
                changed[key] += 1
                (self.root / "report.json").write_bytes(canonical(changed))
                self.assertFalse(verify(self.root)["integrity_passed"])
        (self.root / "report.json").write_bytes(canonical(report))
        receiver = (self.root / "receiver.json").read_bytes()
        (self.root / "receiver.json").write_bytes(b"[]")
        self.assertFalse(verify(self.root)["receiver_agrees"])
        (self.root / "receiver.json").write_bytes(receiver)
        (self.root / "captures" / digest("unexpected-extra")).mkdir()
        self.assertFalse(verify(self.root)["capture_inventory_agrees"])

    def test_feedback_failure_after_delivery_retains_receipt_and_denominators(self):
        def wire(body):
            return WireResponse(503, b"fixture feedback failure") if decode(body)["tool_choice"] == "none" else fixture_response(body)
        report = run(self.root, FixtureWire(wire))
        self.assertEqual((report["fixture_transport_requests"], report["actual_http_arrivals"]), (2, 1))
        self.assertTrue(all(not r["fully_rescorable"] for r in report["rows"]))
        self.assertTrue(all(r["score"]["category"] == "ENVIRONMENT_OR_OBSERVATION_FAILURE" for r in report["rows"]))
        first = self.plan["rows"][0]["tool_plan"]
        response = decode(read_raw(self.root / "tool-rows", first["row_id"], "response.bin"))
        self.assertEqual(len(response["receiver_arrivals"]), 1)
        self.assertEqual(report["summary"]["planned_rows"], 8)
        self.assertFalse(verify(self.root)["integrity_passed"])

    def test_no_action_is_not_a_runtime_block_and_feedback_slots_are_inapplicable(self):
        def wire(body):
            response = decode(fixture_response(body).body)
            response["choices"] = [{"message": {"role": "assistant", "content": "no action"}, "finish_reason": "stop"}]
            return WireResponse(200, canonical(response))
        report = run(self.root, FixtureWire(wire))
        checked = verify(self.root)
        self.assertTrue(checked["integrity_passed"])
        self.assertEqual((report["fixture_transport_requests"], report["actual_http_arrivals"]), (8, 0))
        self.assertTrue(all(r["score"]["category"] == "NO_ACTION" for r in report["rows"]))
        self.assertTrue(all(m["value"] is None for r in report["rows"] for m in r["score"]["metrics"].values()))
        self.assertTrue(all(s["passed"] is None for s in checked["sample"] if not s["applicable"]))

    def test_wrong_target_is_off_contract_not_security_success(self):
        def wire(body):
            response = decode(fixture_response(body).body)
            if decode(body)["tool_choice"] != "none":
                response["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"] = '{"path":"/not_the_bound_target"}'
            return WireResponse(200, canonical(response))
        report = run(self.root, FixtureWire(wire))
        self.assertEqual((report["fixture_transport_requests"], report["actual_http_arrivals"]), (16, 0))
        self.assertTrue(all(r["score"]["category"] == "OFF_CONTRACT" for r in report["rows"]))
        self.assertTrue(verify(self.root)["integrity_passed"])

    def test_missing_provider_raw_invalidates_otherwise_valid_tool_score(self):
        # No-action rows exercise the entire archive path without tool execution.
        def wire(body):
            response = decode(fixture_response(body).body)
            response["choices"] = [{"message": {"role": "assistant", "content": ""}, "finish_reason": "stop"}]
            return WireResponse(200, canonical(response))
        run(self.root, FixtureWire(wire))
        first = self.plan["rows"][0]
        path = self.root / "captures" / digest([first["row_id"], "selection"]) / "response.bin"
        path.unlink()
        checked = verify(self.root)
        self.assertEqual(checked["fully_rescorable_rows"], 7)
        self.assertFalse(checked["integrity_passed"])

    def test_receiver_startup_failure_keeps_all_planned_rows(self):
        with patch("model_workflow_v3.LoopbackReceiver", side_effect=OSError("fixture socket failure")):
            report = run(self.root)
        self.assertEqual(len(report["rows"]), 8)
        self.assertEqual(report["fixture_transport_requests"], 0)
        self.assertTrue(all(not r["fully_rescorable"] for r in report["rows"]))
        self.assertFalse(verify(self.root)["integrity_passed"])

    def test_dots_payload_has_same_capture_boundary_and_no_live_grant(self):
        root = self.root.parent / "dots"
        plan = prepare(root, "dots")
        _, _, _, contexts = load(root)
        row = plan["rows"][0]
        body = payload(plan["provider_policy"], row, contexts[row["tool_plan"]["family_id"]])
        self.assertEqual(body["chat_template_kwargs"], {"enable_thinking": False})
        self.assertNotIn("thinking", body)
        self.assertEqual(plan["provider_policy"]["max_live_requests"], 0)

    def test_invalid_tool_call_shapes_and_duplicate_arguments_do_not_dispatch(self):
        for calls in ([{"id": "x", "type": "function", "function": {"name": "send_source_field", "arguments": '{"path":"/x","path":"/y"}'}}],
                      "wrong shape", [], [{"id": "bad id"}]):
            request, call_id = tool_request({"tool_calls": calls}, "tool_calls")
            self.assertEqual(decode(request), {"tool": "INVALID_MODEL_REQUEST"})
            self.assertIsNone(call_id)


if __name__ == "__main__":
    unittest.main()
