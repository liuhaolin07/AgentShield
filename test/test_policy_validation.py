"""Offline regression tests for policy and tool input validation."""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from agent.llm_agent import run_llm_agent
from security.capabilities import experiment_registry
from security.middleware import check_tool_call
from security.policy import DEFAULT_POLICY_PATH, PolicyError, load_policy
from test_llm_agent import FakeDotsClient, tool_response


class URLPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = load_policy(DEFAULT_POLICY_PATH)

    def test_supported_destinations_remain_allowed(self) -> None:
        for url in (
            "example.com",
            "example.com:443/path?note=hello",
            "//example.com/path",
            "http://example.com/path",
            "https://EXAMPLE.COM./path",
            "https://api.github.com:8443/repos",
        ):
            with self.subTest(url=url):
                self.assertTrue(self.policy.allows_url(url))

    def test_non_http_schemes_are_denied(self) -> None:
        for scheme in ("ftp", "file", "ssh", "javascript"):
            with self.subTest(scheme=scheme):
                self.assertFalse(self.policy.allows_url(f"{scheme}://example.com"))

    def test_invalid_destinations_are_denied_without_raising(self) -> None:
        for url in (
            "https://[example.com",
            "https://[not-an-ip]/",
            "https://example.com:wrong/path",
            "https://example.com:65536",
            "https://example.com:",
            "https://user:pass@example.com",
            "https://example.com\\@evil.com",
            "https://example.com\n.evil.com",
            "https://example.com\t",
            "https://example.com/with space",
            "https://.example.com",
            "https://example.com..",
            "https://-api.example.com",
            "https://example.com.evil.com",
            "https://notexample.com",
            "https:///example.com",
            "",
        ):
            with self.subTest(url=repr(url)):
                self.assertFalse(self.policy.allows_url(url))


class PolicyValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.policy_path = self.root / "policy.yaml"
        self.audit_path = self.root / "audit.jsonl"
        self.write_policy()

    def write_policy(self, domain: str = "example.com") -> None:
        self.policy_path.write_text(
            "blocked_files:\n  - .env\n"
            "allowed_file_roots:\n  - data\n"
            f"allowed_domains:\n  - {domain}\n",
            encoding="utf-8",
        )

    def check(self, tool, args, **kwargs):
        with redirect_stdout(io.StringIO()):
            decision = check_tool_call(
                tool, args, policy_path=self.policy_path,
                audit_path=self.audit_path, **kwargs,
            )
        event = json.loads(self.audit_path.read_text(encoding="utf-8").splitlines()[-1])
        self.assertEqual(event["reason"], decision.reason)
        self.assertEqual(event["decision"], "ALLOW" if decision else "BLOCK")
        return decision

    def test_malformed_url_has_a_block_audit_event(self) -> None:
        for tool in ("http", "model", "submit_report"):
            with self.subTest(tool=tool):
                decision = self.check(
                    tool, {"url": "https://[example.com", "data": "safe summary"},
                    registry=experiment_registry(),
                )
                self.assertFalse(decision)
                self.assertEqual(decision.reason, "domain_not_allowed")

    def test_non_mapping_arguments_are_rejected_and_audited(self) -> None:
        for args in (None, [], "data"):
            with self.subTest(args=args):
                decision = self.check("http", args)
                self.assertFalse(decision)
                self.assertEqual(decision.reason, "invalid_arguments")

    def test_invalid_argument_types_are_not_coerced(self) -> None:
        for tool, args in (
            ("file", {"path": None}),
            ("file", {"path": 42}),
            ("file", {"path": []}),
            ("http", {"url": "example.com", "data": None}),
            ("http", {"url": "example.com", "data": {"message": "hello"}}),
            ("model", {"url": ["example.com"], "data": "hello"}),
            ("http", {"url": "example.com"}),
        ):
            with self.subTest(tool=tool, args=args):
                decision = self.check(tool, args)
                self.assertFalse(decision)
                self.assertEqual(decision.reason, "invalid_arguments")

    def test_empty_payload_remains_allowed(self) -> None:
        self.assertTrue(self.check("http", {"url": "example.com", "data": ""}))

    def test_missing_file_path_retains_its_reason(self) -> None:
        self.assertEqual(self.check("file", {}).reason, "missing_file_path")

    def test_null_byte_file_path_is_rejected_and_audited(self) -> None:
        decision = self.check("file", {"path": "data/file\0.txt"})
        self.assertFalse(decision)
        self.assertEqual(decision.reason, "invalid_file_path")

    def test_relative_path_is_resolved_against_policy_directory(self) -> None:
        (self.root / "data").mkdir()
        source = self.root / "data" / "notes.txt"
        source.write_text("safe notes", encoding="utf-8")
        decision = self.check("file", {"path": Path("data/notes.txt")})
        self.assertTrue(decision)
        self.assertEqual(decision.resolved_path, source.resolve())

    def test_symlink_targets_obey_file_policy(self) -> None:
        data = self.root / "data"
        data.mkdir()
        secret = data / ".env"
        secret.write_text("fake test fixture", encoding="utf-8")
        alias = data / "notes.txt"
        try:
            alias.symlink_to(secret)
        except OSError as error:
            self.skipTest(f"Symlink creation unavailable: {error}")
        decision = self.check("file", {"path": "data/notes.txt"})
        self.assertFalse(decision)
        self.assertEqual(decision.reason, "blocked_file")

    def test_symlink_loop_is_rejected_and_audited(self) -> None:
        data = self.root / "data"
        data.mkdir()
        loop = data / "loop"
        try:
            loop.symlink_to(loop)
        except OSError as error:
            self.skipTest(f"Symlink creation unavailable: {error}")
        decision = self.check("file", {"path": "data/loop"})
        self.assertFalse(decision)
        self.assertEqual(decision.reason, "invalid_file_path")

    def test_invalid_utf8_policy_is_rejected_and_audited(self) -> None:
        self.policy_path.write_bytes(b"\xff\xfe")
        decision = self.check("http", {"url": "example.com", "data": "hello"})
        self.assertFalse(decision)
        self.assertEqual(decision.reason, "policy_error")

    def test_invalid_domain_configuration_is_rejected(self) -> None:
        for domain in ("https://example.com", "*", "..example.com", "example.com:443", "example.com/path"):
            with self.subTest(domain=domain):
                self.write_policy(domain)
                with self.assertRaises(PolicyError):
                    load_policy(self.policy_path)

    def test_wildcard_domain_and_empty_allowlist_are_supported(self) -> None:
        self.write_policy("*.example.com")
        self.assertTrue(load_policy(self.policy_path).allows_url("https://api.example.com"))
        self.policy_path.write_text(
            "blocked_files:\nallowed_file_roots:\nallowed_domains:\n", encoding="utf-8",
        )
        policy = load_policy(self.policy_path)
        self.assertFalse(policy.allows_url("https://example.com"))
        self.assertFalse(policy.allows_file("data/notes.txt"))

    def test_model_tool_arguments_are_validated_before_execution(self) -> None:
        for name, args, executor in (
            ("read_file", {"path": 42}, "read_file"),
            ("read_file", {"path": "data/file\0.txt"}, "read_file"),
            ("send_http", {"url": "example.com", "data": None}, "send_http"),
        ):
            with self.subTest(name=name, args=args):
                client = FakeDotsClient([tool_response("call-1", name, args)])
                with patch(f"agent.llm_agent.{executor}") as tool, redirect_stdout(io.StringIO()):
                    completed = run_llm_agent("Perform the requested task.", client=client, audit_path=self.audit_path)
                self.assertFalse(completed)
                tool.assert_not_called()
                self.assertEqual(len(client.sent_payloads), 1)
                event = json.loads(self.audit_path.read_text(encoding="utf-8").splitlines()[-1])
                self.assertEqual(event["decision"], "BLOCK")
                self.assertIn(event["reason"], {"invalid_arguments", "invalid_file_path"})


if __name__ == "__main__":
    unittest.main()
