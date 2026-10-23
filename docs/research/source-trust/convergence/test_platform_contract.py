"""Native Windows and simulated missing-capability refusal; no provider calls."""

import contextlib
import io
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from development_execution_v2 import execute_row, read_raw, rescore, save_raw
from development_intake import HERE, Reader, preflight
from development_queries_v2 import QueryLedger
from model_transport_v3 import CapturedClient, FixtureWire, policy
from platform_contract import PlatformUnsupported, secure_io_supported


class PlatformContractTests(unittest.TestCase):
    def test_missing_flag_refuses_reader_writer_ledger_and_dispatch_before_effects(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(os, "O_NOFOLLOW", 0, create=True):
                operations = [lambda: save_raw(root / "body", b"data"),
                              lambda: read_raw(root, "a" * 64, "request.bin"),
                              lambda: Reader(root).read("body", 10),
                              lambda: QueryLedger(root / "queries", {"task": ["id"]}),
                              lambda: execute_row(root, {}, {}, b"", "family", "task", "precision", Mock()),
                              lambda: CapturedClient(root / "capture", policy("deepseek", ["row"]), FixtureWire(Mock()))]
                for operation in operations:
                    with self.subTest(operation=operation), self.assertRaisesRegex(PlatformUnsupported, "PLATFORM_UNSUPPORTED"):
                        operation()
                report = preflight(root)
                self.assertEqual(report["state"], "PLATFORM_UNSUPPORTED")
                self.assertFalse(report["experiment_authorized"])
                self.assertEqual(rescore(root, {"kind": "attack", "row_id": "a" * 64})["reason"], "PLATFORM_UNSUPPORTED")
            self.assertEqual(list(root.iterdir()), [])

    def test_missing_fcntl_refuses_query_ledger_before_creating_file(self):
        with tempfile.TemporaryDirectory() as temporary, patch("platform_contract.fcntl", None):
            path = Path(temporary) / "queries"
            with self.assertRaises(PlatformUnsupported):
                QueryLedger(path, {"task": ["id"]})
            self.assertFalse(path.exists())

    def test_missing_dir_fd_or_directory_flag_never_silently_falls_back(self):
        for name, value in (("supports_dir_fd", set()), ("O_DIRECTORY", 0), ("O_NONBLOCK", 0)):
            with self.subTest(name=name), patch.object(os, name, value, create=True):
                self.assertFalse(secure_io_supported())
                with self.assertRaises(PlatformUnsupported):
                    Reader(Path("unused")).read("unused", 1)

    def test_cli_missing_flag_returns_defined_state_for_both_execution_entries(self):
        for name in ("run_development_v2.py", "model_workflow_v3.py"):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "never-created"
                original = getattr(os, "O_NOFOLLOW", None)
                had_flag = hasattr(os, "O_NOFOLLOW")
                output = io.StringIO()
                try:
                    if had_flag:
                        del os.O_NOFOLLOW
                    with patch.object(sys, "argv", [name, "prepare", "--root", str(root)]), contextlib.redirect_stdout(output):
                        with self.assertRaises(SystemExit) as raised:
                            runpy.run_path(str(HERE / name), run_name="__main__")
                    self.assertEqual(raised.exception.code, 2)
                    self.assertEqual(json.loads(output.getvalue())["state"], "PLATFORM_UNSUPPORTED")
                    self.assertFalse(root.exists())
                finally:
                    if had_flag:
                        os.O_NOFOLLOW = original

    def test_cli_uses_current_interpreter_with_empty_path(self):
        # PATH cannot accidentally select a different Python. Metadata init is
        # supported everywhere; secure check either reports pending or refuses.
        with tempfile.TemporaryDirectory() as temporary:
            root, output = Path(temporary) / "new", Path(temporary) / "check.json"
            environment = dict(os.environ, PATH="")
            command = [sys.executable, str(HERE / "development_intake.py")]
            initialized = subprocess.run(command + ["init", "--output", str(root)], env=environment, capture_output=True)
            self.assertEqual(initialized.returncode, 2)
            self.assertEqual(subprocess.run(command + ["init", "--output", str(root)], env=environment, capture_output=True).returncode, 1)
            checked = subprocess.run(command + ["check", "--root", str(root), "--output", str(output)], env=environment, capture_output=True)
            self.assertEqual(checked.returncode, 2)
            report = json.loads(output.read_text())
            self.assertEqual(report["state"], "PENDING_FILES_OR_FAMILIES" if secure_io_supported() else "PLATFORM_UNSUPPORTED")
            original = output.read_bytes()
            self.assertEqual(subprocess.run(command + ["check", "--root", str(root), "--output", str(output)], env=environment, capture_output=True).returncode, 1)
            self.assertEqual(original, output.read_bytes())


if __name__ == "__main__":
    unittest.main()
