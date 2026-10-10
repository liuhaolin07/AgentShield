"""Real loopback and pre-execution transport boundary tests."""

import io
import json
import socket
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from evaluation.receiver import LoopbackReceiver
from security.middleware import check_tool_call
from tools.http_tool import send_http
from tools.local_http import LocalHTTPTarget, LocalTransportError


class LocalHTTPTests(unittest.TestCase):
    def receiver(self, **kwargs) -> LoopbackReceiver:
        try:
            receiver = LoopbackReceiver(**kwargs)
        except OSError as error:
            self.skipTest(f"Loopback unavailable: {error}")
        return receiver

    def test_default_tool_remains_a_simulation(self) -> None:
        with patch("tools.local_http.socket.socket") as sock, redirect_stdout(io.StringIO()):
            self.assertIsNone(send_http("example.com", "safe summary"))
        sock.assert_not_called()

    def test_real_arrival_uses_no_dns_resolution(self) -> None:
        with self.receiver() as receiver:
            with patch("socket.getaddrinfo", side_effect=AssertionError("DNS must not run")):
                receipt = send_http(receiver.url, "synthetic summary", local_target=receiver.target)
            self.assertEqual(receipt.status, 202)
            self.assertEqual(len(receiver.arrivals), 1)
            self.assertEqual(receiver.arrivals[0]["body"], "synthetic summary")

    def test_other_origins_are_rejected_before_socket_creation(self) -> None:
        target = LocalHTTPTarget(9999)
        for url in (
            "http://example.com:9999/receive", "http://localhost:9999/receive",
            "http://127.0.0.2:9999/receive", "http://127.0.0.1:9998/receive",
            "http://2130706433:9999/receive", "http://127.1:9999/receive",
            "http://user@127.0.0.1:9999/receive", "https://127.0.0.1:9999/receive",
            "http://127.0.0.1:9999/receive#fragment",
        ):
            with self.subTest(url=url), patch("tools.local_http.socket.socket") as sock:
                with self.assertRaises(LocalTransportError):
                    target.send(url, "synthetic summary")
                sock.assert_not_called()

    def test_redirect_is_not_followed(self) -> None:
        with self.receiver() as destination:
            with self.receiver(redirect_to=destination.url) as source:
                with self.assertRaises(LocalTransportError) as raised:
                    source.target.send(f"{source.target.origin}/redirect", "synthetic summary")
                self.assertEqual(raised.exception.reason, "redirect_refused")
                self.assertEqual(len(source.arrivals), 1)
                self.assertEqual(len(destination.arrivals), 0)

    def test_allowed_and_blocked_policy_requests_have_real_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory, self.receiver() as receiver:
            policy = Path(directory) / "policy.yaml"
            audit = Path(directory) / "audit.jsonl"
            policy.write_text(
                "blocked_files:\nallowed_file_roots:\nallowed_domains:\n  - 127.0.0.1\n",
                encoding="utf-8",
            )
            for data, expected in (("synthetic summary", True), ("PASSWORD=EVAL_ONLY_FAKE", False)):
                with redirect_stdout(io.StringIO()):
                    decision = check_tool_call("http", {"url": receiver.url, "data": data}, policy_path=policy, audit_path=audit)
                self.assertEqual(decision.allowed, expected)
                if decision:
                    send_http(receiver.url, data, local_target=receiver.target)
            self.assertEqual(len(receiver.arrivals), 1)
            self.assertEqual(receiver.arrivals[0]["body"], "synthetic summary")
            events = [json.loads(line) for line in audit.read_text().splitlines()]
            self.assertEqual([event["decision"] for event in events], ["ALLOW", "BLOCK"])

    def test_invalid_port_is_rejected(self) -> None:
        for port in (0, 65536, True, "8080"):
            with self.subTest(port=port), self.assertRaises(ValueError):
                LocalHTTPTarget(port)


if __name__ == "__main__":
    unittest.main()
