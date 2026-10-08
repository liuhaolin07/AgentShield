"""Tests for the V2 capability registry and its additive middleware hook."""

import json
import tempfile
import unittest
from pathlib import Path

from security.capabilities import (
    CAPABILITY_FILE_READ,
    CAPABILITY_HTTP_SEND,
    CAPABILITY_MODEL_CALL,
    CapabilityError,
    CapabilityRegistry,
    EXPERIMENT_ALIASES,
    builtin_registry,
    experiment_registry,
)
from security.middleware import check_tool_call


class CapabilityRegistryTests(unittest.TestCase):
    def test_builtin_registry_reproduces_v161_whitelist(self) -> None:
        registry = builtin_registry()
        self.assertEqual(registry.resolve("file"), CAPABILITY_FILE_READ)
        self.assertEqual(registry.resolve("http"), CAPABILITY_HTTP_SEND)
        self.assertEqual(registry.resolve("model"), CAPABILITY_MODEL_CALL)
        self.assertIsNone(registry.resolve("send_secret"))
        self.assertIsNone(registry.resolve("shell"))

    def test_experiment_registry_resolves_alias_family(self) -> None:
        registry = experiment_registry()
        for alias in EXPERIMENT_ALIASES:
            self.assertEqual(registry.resolve(alias), CAPABILITY_HTTP_SEND)
        self.assertEqual(registry.resolve("http"), CAPABILITY_HTTP_SEND)
        self.assertIsNone(registry.resolve("shell"))

    def test_builtin_names_cannot_be_shadowed(self) -> None:
        with self.assertRaises(CapabilityError):
            CapabilityRegistry(extra_aliases={"http": CAPABILITY_MODEL_CALL})

    def test_unknown_capability_is_rejected(self) -> None:
        with self.assertRaises(CapabilityError):
            CapabilityRegistry(extra_aliases={"new_tool": "not_a_capability"})

    def test_empty_alias_name_is_rejected(self) -> None:
        with self.assertRaises(CapabilityError):
            CapabilityRegistry(extra_aliases={"  ": CAPABILITY_HTTP_SEND})

    def test_frozen_registry_is_immutable_from_outside(self) -> None:
        registry = experiment_registry()
        with self.assertRaises(TypeError):
            registry.extra_aliases["injected"] = CAPABILITY_HTTP_SEND  # type: ignore[index]


class MiddlewareRegistryHookTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_directory.cleanup)
        self.audit_path = Path(self.temp_directory.name) / "audit.jsonl"

    def audit_events(self) -> list[dict]:
        return [
            json.loads(line)
            for line in self.audit_path.read_text(encoding="utf-8").splitlines()
        ]

    def _call(self, tool: str, args: dict, registry=None):
        return check_tool_call(
            tool,
            args,
            audit_path=self.audit_path,
            registry=registry,
        )

    def test_default_behavior_blocks_alias_before_scanning(self) -> None:
        """registry=None keeps the V1.6.1 structural block for aliases."""
        decision = self._call(
            "submit_report",
            {"url": "https://example.com", "data": "PASSWORD=root123"},
        )
        self.assertFalse(decision)
        self.assertEqual(decision.reason, "unsupported_tool")
        self.assertIsNone(decision.capability)

    def test_default_behavior_matches_v161_for_known_names(self) -> None:
        secret_call = self._call(
            "http",
            {"url": "https://example.com", "data": "PASSWORD=root123"},
        )
        self.assertFalse(secret_call)
        self.assertEqual(secret_call.reason, "sensitive_data")
        self.assertEqual(secret_call.capability, CAPABILITY_HTTP_SEND)

        clean_call = self._call(
            "http",
            {"url": "https://example.com", "data": "safe summary"},
        )
        self.assertTrue(clean_call)
        self.assertEqual(clean_call.reason, "policy_passed")

    def test_alias_resolves_to_same_capability_and_same_scan(self) -> None:
        """Under the experiment registry every alias reaches the scan."""
        registry = experiment_registry()
        blocked = self._call(
            "submit_report",
            {"url": "https://example.com", "data": "PASSWORD=root123"},
            registry=registry,
        )
        self.assertFalse(blocked)
        self.assertEqual(blocked.reason, "sensitive_data")
        self.assertEqual(blocked.capability, CAPABILITY_HTTP_SEND)

        passed = self._call(
            "sync_data",
            {"url": "https://example.com", "data": "safe summary"},
            registry=registry,
        )
        self.assertTrue(passed)
        self.assertEqual(passed.reason, "policy_passed")
        self.assertEqual(passed.capability, CAPABILITY_HTTP_SEND)

    def test_alias_inherits_policy_branches(self) -> None:
        """Aliases share the http capability's domain allowlist branch."""
        decision = self._call(
            "backup_config",
            {"url": "https://evil.com", "data": "safe summary"},
            registry=experiment_registry(),
        )
        self.assertFalse(decision)
        self.assertEqual(decision.reason, "domain_not_allowed")
        self.assertEqual(decision.capability, CAPABILITY_HTTP_SEND)

    def test_unregistered_tool_still_fail_closed_with_registry(self) -> None:
        decision = self._call(
            "shell",
            {"command": "whoami"},
            registry=experiment_registry(),
        )
        self.assertFalse(decision)
        self.assertEqual(decision.reason, "unsupported_tool")

    def test_audit_events_record_capability_when_resolved(self) -> None:
        """Recognized tools are audited with their capability; unknown are not."""
        self._call(
            "http",
            {"url": "https://example.com", "data": "safe summary"},
        )
        self._call(
            "submit_report",
            {"url": "https://example.com", "data": "safe summary"},
            registry=experiment_registry(),
        )
        self._call(
            "shell",
            {"command": "whoami"},
        )
        events = self.audit_events()
        self.assertEqual(len(events), 3)
        self.assertEqual(events[0]["capability"], CAPABILITY_HTTP_SEND)
        self.assertEqual(events[1]["capability"], CAPABILITY_HTTP_SEND)
        self.assertEqual(events[1]["tool"], "submit_report")
        self.assertNotIn("capability", events[2])


if __name__ == "__main__":
    unittest.main()
