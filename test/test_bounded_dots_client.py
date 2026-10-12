"""Offline transport controls; the urllib redirect chain runs without sockets."""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from email.message import Message
from pathlib import Path
from unittest.mock import patch
from urllib.error import URLError
from urllib.request import HTTPSHandler, build_opener
from urllib.response import addinfourl

from agent.llm_agent import run_llm_agent_result
from model.bounded_dots_client import BoundedDotsClient, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES
from model.dots_client import DotsAPIError, DotsClient


KEY = "offline-test-key"
VALID = {"choices": [{"message": {"role": "assistant", "content": "done"}}]}


class RecordingBody(io.BytesIO):
    def __init__(self, body):
        super().__init__(body)
        self.read_sizes = []

    def read(self, size=-1):
        self.read_sizes.append(size)
        return super().read(size)


class ScriptedHTTPS(HTTPSHandler):
    """Return scripted HTTP responses below urllib's real redirect processing."""

    def __init__(self, responses):
        super().__init__()
        self.responses = list(responses)
        self.requests = []
        self.bodies = []

    def https_open(self, request):
        self.requests.append(request)
        if not self.responses:
            raise AssertionError("Unexpected outbound request")
        status, extra_headers, raw = self.responses.pop(0)
        headers = Message()
        for key, value in extra_headers.items():
            headers[key] = value
        body = RecordingBody(raw)
        self.bodies.append(body)
        response = addinfourl(body, headers, request.full_url, status)
        response.msg = "scripted"
        return response


def ok(body=VALID):
    return 200, {}, json.dumps(body).encode()


class BoundedDotsTests(unittest.TestCase):
    def setUp(self):
        # Fail the test if any mock omission could make a real outbound call.
        for name in ("socket.socket", "socket.create_connection"):
            guard = patch(name, side_effect=AssertionError("Network forbidden in offline controls"))
            guard.start()
            self.addCleanup(guard.stop)

    def client(self, **kwargs):
        return BoundedDotsClient(api_key=KEY, allow_live=True, **kwargs)

    def scripted(self, responses):
        handler = ScriptedHTTPS(responses)
        supplied = []

        def factory(*handlers):
            supplied.extend(handlers)
            return build_opener(handler, *handlers)

        return handler, supplied, patch("model.bounded_dots_client.build_opener", side_effect=factory)

    def assert_rejected_before_opener(self, payload, reason):
        with patch("model.bounded_dots_client.build_opener") as opener:
            with self.assertRaisesRegex(DotsAPIError, reason):
                self.client().send_payload(payload)
            opener.assert_not_called()

    def test_default_live_disabled_before_payload_or_transport(self):
        with patch("model.bounded_dots_client.build_opener") as opener:
            client = BoundedDotsClient(api_key=KEY)
            self.assertFalse(client.is_live)
            with self.assertRaisesRegex(DotsAPIError, "live_disabled"):
                client.send_payload({"invalid": object()})
            opener.assert_not_called()

    def test_success_preserves_request_body_key_and_bounded_read(self):
        client = self.client(timeout=3)
        payload = client.build_payload(messages=[{"role": "user", "content": "普通任务"}], tools=[])
        handler, supplied, fake = self.scripted([ok()])
        with fake:
            self.assertEqual(client.send_payload(payload), VALID)
        self.assertEqual(len(handler.requests), 1)
        request = handler.requests[0]
        self.assertEqual(request.full_url, client.endpoint)
        self.assertEqual(request.get_method(), "POST")
        self.assertEqual(json.loads(request.data), payload)
        self.assertEqual(request.get_header("Api-key"), KEY)
        self.assertEqual(request.timeout, 3)
        self.assertEqual(handler.bodies[0].read_sizes, [MAX_RESPONSE_BYTES + 1])
        self.assertTrue(any(getattr(h, "proxies", None) == {} for h in supplied))

    def test_old_adapter_control_follows_redirect_with_credential(self):
        handler = ScriptedHTTPS([(302, {"Location": "https://redirect.invalid/next"}, b""), ok()])
        # Negative control only: all destinations are served by the fake handler.
        with patch("model.dots_client.urlopen", side_effect=build_opener(handler).open):
            self.assertEqual(DotsClient(api_key=KEY).send_payload({"messages": []}), VALID)
        self.assertEqual(len(handler.requests), 2)
        self.assertEqual(handler.requests[1].full_url, "https://redirect.invalid/next")
        self.assertEqual(handler.requests[1].get_header("Api-key"), KEY)

    def test_redirect_statuses_never_issue_second_request(self):
        for code in (301, 302, 303, 307, 308):
            for location in ("/same-origin", "https://redirect.invalid/next", "http://redirect.invalid/plain"):
                with self.subTest(code=code, location=location):
                    handler, _, fake = self.scripted([(code, {"Location": location}, b"private error"), ok()])
                    with fake, self.assertRaisesRegex(DotsAPIError, "redirect_refused"):
                        self.client().send_payload({"messages": []})
                    self.assertEqual(len(handler.requests), 1)
                    self.assertEqual(handler.bodies[0].read_sizes, [])

    def test_redirect_without_location_is_rejected_without_body_read(self):
        handler, _, fake = self.scripted([(302, {}, b"private error")])
        with fake, self.assertRaisesRegex(DotsAPIError, "redirect_refused"):
            self.client().send_payload({})
        self.assertEqual(handler.bodies[0].read_sizes, [])

    def test_endpoint_is_frozen_after_initialization(self):
        client = self.client()
        endpoint = client.endpoint
        client.base_url = "https://changed.invalid"
        handler, _, fake = self.scripted([ok()])
        with fake:
            client.send_payload({})
        self.assertEqual(handler.requests[0].full_url, endpoint)

    def test_invalid_endpoint_rejected_at_construction(self):
        for endpoint in ("http://provider.invalid", "https://user:password@provider.invalid", "https://provider.invalid?q=1",
                         "https://provider.invalid#part", "https://provider.invalid\\next", "https://provider.invalid\n",
                         "https://provider.invalid:invalid", "https://provider.invalid:0", "https://", None):
            with self.subTest(endpoint=endpoint), self.assertRaisesRegex(DotsAPIError, "invalid_endpoint"):
                self.client(base_url=endpoint)

    def test_invalid_timeout_rejected_at_construction(self):
        for timeout in (True, 0, -1, 61, float("nan"), float("inf"), "2"):
            with self.subTest(timeout=timeout), self.assertRaisesRegex(DotsAPIError, "invalid_timeout"):
                self.client(timeout=timeout)

    def test_invalid_flags_models_and_header_credentials(self):
        for field, value, reason in (("allow_live", 1, "invalid_live_flag"), ("model", "", "invalid_model"),
                                     ("model", "x" * 129, "invalid_model"), ("api_key", "key\r\nextra", "invalid_credential"),
                                     ("api_key", "x" * 4097, "invalid_credential")):
            params = {"api_key": KEY, "allow_live": True, field: value}
            with self.subTest(field=field), self.assertRaisesRegex(DotsAPIError, reason):
                BoundedDotsClient(**params)

    def test_oversized_ascii_and_multibyte_requests_reject_before_open(self):
        for data in ("x" * MAX_REQUEST_BYTES, "密" * (MAX_REQUEST_BYTES // 3)):
            with self.subTest(multibyte=data.startswith("密")):
                self.assert_rejected_before_opener({"data": data}, "request_budget")

    def test_invalid_requests_reject_before_open(self):
        cyclic = []
        cyclic.append(cyclic)
        for payload in ([], {"data": float("nan")}, {"data": float("inf")}, {"data": object()}, {"data": "\ud800"}, {"data": cyclic}):
            with self.subTest(payload_type=type(payload).__name__):
                self.assert_rejected_before_opener(payload, "invalid_payload")

    def test_request_wire_byte_boundary(self):
        # JSON representation {"x": "..."} contributes nine ASCII bytes.
        handler, _, fake = self.scripted([ok()])
        with fake:
            self.client().send_payload({"x": "a" * (MAX_REQUEST_BYTES - 9)})
        self.assertEqual(len(handler.requests[0].data), MAX_REQUEST_BYTES)
        self.assert_rejected_before_opener({"x": "a" * (MAX_REQUEST_BYTES - 8)}, "request_budget")

    def test_response_wire_byte_boundary_and_one_byte_overflow(self):
        valid = json.dumps(VALID).encode()
        for size, reason in ((MAX_RESPONSE_BYTES, None), (MAX_RESPONSE_BYTES + 1, "response_budget")):
            handler, _, fake = self.scripted([(200, {}, valid + b" " * (size - len(valid)))])
            with self.subTest(size=size), fake:
                if reason:
                    with self.assertRaisesRegex(DotsAPIError, reason):
                        self.client().send_payload({})
                else:
                    self.assertEqual(self.client().send_payload({}), VALID)
            self.assertEqual(handler.bodies[0].read_sizes, [MAX_RESPONSE_BYTES + 1])

    def test_duplicate_nonfinite_and_invalid_response_json(self):
        for raw in (b'{"choices":[],"choices":[]}', b'{"choices":[],"usage":{"total":1,"total":2}}',
                    b'{"choices":[],"usage":NaN}', b'{"choices":[],"usage":1e999}', b"\xff", b"<html>", b"[" * 1500):
            handler, _, fake = self.scripted([(200, {}, raw)])
            with self.subTest(raw_prefix=raw[:24]), fake, self.assertRaisesRegex(DotsAPIError, "invalid_response_json"):
                self.client().send_payload({})

    def test_invalid_response_envelopes_are_rejected(self):
        for body in ([], {}, {"choices": []}, {"choices": [None]}, {"choices": [{}]}, {"choices": [{"message": []}]}):
            _, _, fake = self.scripted([ok(body)])
            with self.subTest(body=body), fake, self.assertRaisesRegex(DotsAPIError, "invalid_response_schema"):
                self.client().send_payload({})

    def test_provider_error_body_not_read_or_exposed(self):
        handler, _, fake = self.scripted([(403, {}, (KEY + " private user payload").encode())])
        with fake, self.assertRaises(DotsAPIError) as raised:
            self.client().send_payload({})
        self.assertEqual(str(raised.exception), "bounded_dots_http_403")
        self.assertEqual(handler.bodies[0].read_sizes, [])

    def test_transport_exception_details_not_exposed(self):
        with patch("model.bounded_dots_client.build_opener") as opener:
            opener.return_value.open.side_effect = URLError(KEY + " private payload")
            with self.assertRaises(DotsAPIError) as raised:
                self.client().send_payload({})
        self.assertEqual(str(raised.exception), "bounded_dots_transport_failed")

    def test_guarded_loop_can_inject_adapter_without_network(self):
        handler, _, fake = self.scripted([ok()])
        with tempfile.TemporaryDirectory() as directory, fake, redirect_stdout(io.StringIO()):
            result = run_llm_agent_result("Return a status", client=self.client(), audit_path=Path(directory) / "audit.jsonl")
        self.assertEqual(result.final_response, "done")
        self.assertTrue(result.model_finished)
        self.assertFalse(result.completed)  # No tool work was performed.
        self.assertEqual(len(handler.requests), 1)

    def test_guarded_loop_denies_endpoint_before_adapter_entry(self):
        client = self.client(base_url="https://unapproved.invalid")
        with tempfile.TemporaryDirectory() as directory, patch("model.bounded_dots_client.build_opener") as opener, redirect_stdout(io.StringIO()):
            result = run_llm_agent_result("Return a status", client=client, audit_path=Path(directory) / "audit.jsonl")
        self.assertFalse(result.model_finished)
        self.assertEqual(result.reason, "model_boundary_blocked")
        opener.assert_not_called()


if __name__ == "__main__":
    unittest.main()
