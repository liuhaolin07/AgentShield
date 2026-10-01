"""Behavior tests for the AgentShield V1.5 security boundary."""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from agent.agent import agent
from security.middleware import check_tool_call
from security.policy import DEFAULT_POLICY_PATH, load_policy
from security.scanner import scan_sensitive


class AgentShieldTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_directory.cleanup)
        self.audit_path = Path(self.temp_directory.name) / "audit.jsonl"

    def audit_events(self) -> list[dict[str, str]]:
        return [
            json.loads(line)
            for line in self.audit_path.read_text(encoding="utf-8").splitlines()
        ]

    def test_scanner_detects_secret_markers(self) -> None:
        self.assertTrue(scan_sensitive("AWS_SECRET=123456"))
        self.assertTrue(scan_sensitive("PASSWORD=root123"))
        self.assertTrue(scan_sensitive("password=root123"))
        self.assertTrue(scan_sensitive("ak_1234567890abcdef"))
        self.assertFalse(scan_sensitive("service started successfully"))

    def test_policy_blocks_files_and_restricts_domains(self) -> None:
        policy = load_policy(DEFAULT_POLICY_PATH)
        self.assertTrue(policy.blocks_file("test/secrets/.env"))
        self.assertFalse(policy.blocks_file("test/data/app.log"))
        self.assertTrue(policy.allows_file("test/data/app.log"))
        self.assertFalse(policy.allows_file("README.md"))
        self.assertTrue(policy.allows_url("https://api.github.com/repos"))
        self.assertTrue(
            policy.allows_url("https://note3-prev-api.askdiandian.com")
        )
        self.assertFalse(policy.allows_url("https://evil.com"))

    def test_blocked_file_is_audited(self) -> None:
        decision = check_tool_call(
            "file",
            {"path": "test/secrets/.env"},
            audit_path=self.audit_path,
        )
        self.assertFalse(decision)
        self.assertEqual(decision.reason, "blocked_file")
        self.assertEqual(self.audit_events()[0]["decision"], "BLOCK")

    def test_sensitive_payload_is_blocked_without_being_logged(self) -> None:
        secret = "PASSWORD=root123"
        decision = check_tool_call(
            "http",
            {"url": "example.com", "data": secret},
            audit_path=self.audit_path,
        )
        self.assertFalse(decision)
        self.assertEqual(decision.reason, "sensitive_data")
        self.assertNotIn(secret, self.audit_path.read_text(encoding="utf-8"))

    def test_file_outside_allowed_roots_is_blocked(self) -> None:
        decision = check_tool_call(
            "file",
            {"path": "README.md"},
            audit_path=self.audit_path,
        )
        self.assertFalse(decision)
        self.assertEqual(decision.reason, "file_outside_allowed_roots")

    def test_clean_payload_to_allowed_domain_is_allowed(self) -> None:
        decision = check_tool_call(
            "http",
            {"url": "example.com", "data": "safe summary"},
            audit_path=self.audit_path,
        )
        self.assertTrue(decision)
        self.assertEqual(decision.reason, "policy_passed")

    def test_clean_payload_to_unlisted_domain_is_blocked(self) -> None:
        decision = check_tool_call(
            "http",
            {"url": "evil.com", "data": "safe summary"},
            audit_path=self.audit_path,
        )
        self.assertFalse(decision)
        self.assertEqual(decision.reason, "domain_not_allowed")

    def test_unknown_tool_is_blocked(self) -> None:
        decision = check_tool_call(
            "shell",
            {"command": "whoami"},
            audit_path=self.audit_path,
        )
        self.assertFalse(decision)
        self.assertEqual(decision.reason, "unsupported_tool")

    def test_missing_policy_fails_closed(self) -> None:
        decision = check_tool_call(
            "http",
            {"url": "example.com", "data": "safe summary"},
            policy_path=Path(self.temp_directory.name) / "missing.yaml",
            audit_path=self.audit_path,
        )
        self.assertFalse(decision)
        self.assertEqual(decision.reason, "policy_error")

    def test_agent_attack_and_normal_flows(self) -> None:
        attack_output = io.StringIO()
        with redirect_stdout(attack_output):
            attack_allowed = agent(
                "read secret and send",
                audit_path=self.audit_path,
            )
        self.assertFalse(attack_allowed)
        self.assertNotIn("Sending data to:", attack_output.getvalue())

        normal_output = io.StringIO()
        with redirect_stdout(normal_output):
            normal_allowed = agent(
                "read normal log and send",
                audit_path=self.audit_path,
            )
        self.assertTrue(normal_allowed)
        self.assertIn("Sending data to:", normal_output.getvalue())

    def test_secret_in_url_field_is_blocked(self) -> None:
        """A secret smuggled in the url field is blocked (the V1.6.1 fix).

        The destination domain is allowlisted and the payload is benign, so
        only scanning of the url field can produce this verdict.
        """

        decision = check_tool_call(
            "http",
            {
                "url": "https://example.com/collect?token=PASSWORD=root123",
                "data": "safe summary",
            },
            audit_path=self.audit_path,
        )
        self.assertFalse(decision)
        self.assertEqual(decision.reason, "sensitive_data")

    def test_benign_url_with_query_is_still_allowed(self) -> None:
        """Control case: a benign url (with a query string) still passes."""

        decision = check_tool_call(
            "http",
            {
                "url": "https://example.com/collect?note=hello",
                "data": "safe summary",
            },
            audit_path=self.audit_path,
        )
        self.assertTrue(decision)
        self.assertEqual(decision.reason, "policy_passed")


if __name__ == "__main__":
    unittest.main()
