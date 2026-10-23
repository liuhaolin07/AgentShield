"""Offline regression tests for the frozen 212-test CI contract.

This sibling directory is intentionally outside convergence/ discovery, so
adding gate regression tests cannot silently change the measured suite size.
"""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


CHECKER = Path(__file__).with_name("check_convergence_log.py")


def suite_log(tests: int = 212, skipped: int = 0) -> str:
    status = f"OK (skipped={skipped})" if skipped else "OK"
    return f"test_example ... ok\n\n{'-' * 70}\nRan {tests} tests in 1.234s\n\n{status}\n"


class ConvergenceLogGateTests(unittest.TestCase):
    def run_gate(self, text: str, runner_os: str) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as temp:
            log = Path(temp) / "tests.log"
            log.write_text(text, encoding="utf-8", newline="")
            return subprocess.run(
                [sys.executable, "-I", str(CHECKER), str(log), "--runner-os", runner_os],
                capture_output=True,
                text=True,
                encoding="utf-8",
            )

    def test_frozen_count_and_platform_skip_boundaries(self):
        cases = [
            ("Linux", 212, 0, True),
            ("Windows", 212, 0, True),
            ("Windows", 212, 49, True),
            ("Windows", 212, 50, True),
            ("Linux", 212, 1, False),
            ("Windows", 212, 51, False),
            ("Linux", 211, 0, False),
            ("Linux", 213, 0, False),
            ("Windows", 211, 50, False),
            ("Windows", 213, 50, False),
            ("macOS", 212, 0, False),
        ]
        for runner_os, tests, skipped, accepted in cases:
            with self.subTest(runner_os=runner_os, tests=tests, skipped=skipped):
                result = self.run_gate(suite_log(tests, skipped), runner_os)
                self.assertEqual(
                    result.returncode, 0 if accepted else 1,
                    f"Gate must enforce the frozen contract: {result.stderr}",
                )
                report = json.loads(result.stdout)
                self.assertEqual(report["status"], "PASS" if accepted else "FAIL")
                if accepted:
                    self.assertEqual(report["tests"], tests)
                    self.assertEqual(report["skipped"], skipped)
                    self.assertEqual(report["runner_os"], runner_os)
                    self.assertEqual(report["expected_tests"], 212)
                    self.assertEqual(report["max_skipped"], 0 if runner_os == "Linux" else 50)

    def test_rejects_missing_ambiguous_or_nonfinal_success_summary(self):
        valid = suite_log()
        cases = {
            "empty": "",
            "truncated": valid.rsplit("OK", 1)[0],
            "duplicate_summary": valid + valid,
            "earlier_failed_run": valid.replace("OK", "FAILED (failures=1)") + valid,
            "trailing_failure": valid + "FAILED (failures=1)\n",
            "trailing_traceback": valid + "Traceback (most recent call last):\nRuntimeError: broken\n",
            "unexpected_success": valid.replace("OK", "OK (unexpected successes=1)"),
            "expected_failure": valid.replace("OK", "OK (expected failures=1)"),
            "negative_skips": valid.replace("OK", "OK (skipped=-1)"),
        }
        for name, text in cases.items():
            with self.subTest(case=name):
                result = self.run_gate(text, "Linux")
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertEqual(json.loads(result.stdout)["status"], "FAIL")

    def test_cli_rejects_missing_and_invalid_utf8_logs(self):
        with tempfile.TemporaryDirectory() as temp:
            missing = Path(temp) / "missing.log"
            invalid = Path(temp) / "invalid.log"
            invalid.write_bytes(b"\xff\xfe\x00")
            for log in (missing, invalid):
                with self.subTest(log=log.name):
                    result = subprocess.run(
                        [sys.executable, "-I", str(CHECKER), str(log), "--runner-os", "Linux"],
                        capture_output=True, text=True, encoding="utf-8",
                    )
                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertEqual(json.loads(result.stdout)["status"], "FAIL")

    def test_accepts_crlf_summary(self):
        result = self.run_gate(suite_log(212, 50).replace("\n", "\r\n"), "Windows")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout)["skipped"], 50)

    def test_workflow_checks_actual_log_and_runs_gate_regressions(self):
        repo = CHECKER.parents[4]
        workflow = (repo / ".github/workflows/convergence.yml").read_text(encoding="utf-8")
        command = (
            'python -I docs/research/source-trust/ci/check_convergence_log.py '
            'logs/convergence/tests.log --runner-os "${{ runner.os }}"'
        )
        self.assertIn(command, workflow)
        self.assertIn('tee logs/convergence/test-counts.json', workflow)
        self.assertIn(
            "python -I -m unittest discover -s docs/research/source-trust/ci -p 'test_*.py' -v",
            workflow,
        )
        suite_position = workflow.index("- name: Full convergence suite")
        self.assertGreater(workflow.index(command), suite_position)
        self.assertLess(workflow.index(command), workflow.index("- name: Original design"))


if __name__ == "__main__":
    unittest.main()
