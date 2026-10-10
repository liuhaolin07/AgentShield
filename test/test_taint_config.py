"""Trusted configuration validation and existing CLI behavior without API work."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from security.taint import TaintError
from security.taint_context import TaintContext


ROOT = Path(__file__).resolve().parents[1]


class TaintConfigTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.config = Path(self.temporary.name) / "taint.json"

    def test_config_classification_does_not_change_file_access_policy(self):
        self.config.write_text(json.dumps({"sensitive_files": ["test/data/*.log"], "sensitive_tools": ["read_file"]}))
        context = TaintContext.load(self.config, root=ROOT)
        self.assertTrue(context.policy.require_tracked)
        self.assertTrue(context.file_value(ROOT / "test/data/app.log", "opaque synthetic data").sensitive)
        self.assertTrue(context.tool_value("read_file", "opaque", reference="call-1").sensitive)

    def test_bad_and_oversized_configuration_is_rejected(self):
        for text in ('{', '[]', '{"unknown":true}', '{"sensitive_files":"data/private.txt"}',
                     '{"require_tracked":"true"}', '{"sensitive_files":["../private"]}', " " * 65537):
            with self.subTest(text=text[:40]):
                self.config.write_text(text)
                with self.assertRaises(ValueError):
                    TaintContext.load(self.config, root=ROOT)

    def test_default_cli_and_simulated_send_stay_compatible(self):
        audit = Path(self.temporary.name) / "audit.jsonl"
        result = subprocess.run([sys.executable, str(ROOT / "main.py"), "read normal log and send", "--audit-log", str(audit)],
                                capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Sending data to:", result.stdout)

    def test_enabled_cli_public_flow_and_sensitive_source_denial(self):
        for sensitive, sent in (([], True), (["test/data/app.log"], False)):
            self.config.write_text(json.dumps({"sensitive_files": sensitive}))
            audit = Path(self.temporary.name) / "audit.jsonl"
            result = subprocess.run([sys.executable, str(ROOT / "main.py"), "read normal log and send",
                                     "--taint-config", str(self.config), "--audit-log", str(audit)],
                                    capture_output=True,text=True,timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual("Sending data to:" in result.stdout, sent)
            if not sent:
                last=json.loads(audit.read_text().splitlines()[-1])
                self.assertEqual(last["reason"], "taint_sensitive_source")

    def test_invalid_cli_config_fails_before_execution(self):
        self.config.write_text('{"unknown":true}')
        audit = Path(self.temporary.name) / "audit.jsonl"
        result = subprocess.run([sys.executable, str(ROOT / "main.py"), "read normal log and send",
                                 "--taint-config", str(self.config), "--audit-log", str(audit)],
                                capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("Sending data to:", result.stdout)
        self.assertFalse(audit.exists())


if __name__ == "__main__":
    unittest.main()
