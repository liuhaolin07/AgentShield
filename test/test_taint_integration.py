"""Real guarded file/HTTP/model effects; development split only, never holdout."""

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from agent.llm_agent import run_llm_agent_result
from agent.taint_agent import TaintAgent
from evaluation.receiver import LoopbackReceiver
from security.middleware import check_tool_call
from security.runtime import GuardedRuntime
from security.scanner import inspect_sensitive
from security.taint import TaintError, TaintedValue, concat, url_encode
from security.taint_context import TaintContext
from test_llm_agent import FakeDotsClient, final_response, tool_response


DATASET = Path(__file__).resolve().parents[1] / "evaluation/datasets/development.json"


class TaintIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "data").mkdir()
        self.policy = self.root / "policy.yaml"
        self.policy.write_text("blocked_files:\n  - .env\nallowed_file_roots:\n  - data\nallowed_domains:\n  - 127.0.0.1\n")
        self.audit = self.root / "audit.jsonl"
        self.private = self.root / "data/private.txt"
        self.private.write_text("orchard ledger / synthetic confidential note")
        self.public = self.root / "data/public.txt"
        self.public.write_text("Public service summary")
        try:
            self.receiver = LoopbackReceiver()
        except OSError as error:
            self.skipTest(f"Loopback unavailable: {error}")
        self.receiver.__enter__()
        self.addCleanup(self.receiver.__exit__)
        self.trace = []

    def runtime(self, mode="scanner_taint", context=None):
        context = context or TaintContext(self.root, ("data/private.txt",), frozenset({"fixture_tool"}))
        return GuardedRuntime(policy_path=self.policy, audit_path=self.audit, context=context,
                              local_target=self.receiver.target, defense_mode=mode,
                              observe=lambda event, **details: self.trace.append({"event": event, **details}))

    def test_all_supported_development_contracts_have_real_boundary_evidence(self):
        cases = json.loads(DATASET.read_text())["cases"]
        for case in cases:
            if case["category"] == "control":
                continue
            with self.subTest(case=case["case_id"]), redirect_stdout(io.StringIO()):
                path = self.root / case["source_reference"] if case["source_category"] == "file" else self.root / "data/tool.txt"
                path.write_text(case["source_value"])
                reference = path.relative_to(self.root).as_posix()
                context = TaintContext(self.root, (reference,) if case["source_sensitive"] else (),
                                       frozenset({"fixture_tool"}) if case["source_sensitive"] else frozenset())
                trace = []
                runtime = GuardedRuntime(policy_path=self.policy, audit_path=self.audit, context=context,
                                         local_target=self.receiver.target,
                                         observe=lambda event, **details: trace.append({"event": event, **details}))
                start = len(self.receiver.arrivals)
                result = TaintAgent(runtime).run(path=reference, operations=case["operations"], url=self.receiver.url,
                                                 sink=case["sink"], tool_source="fixture_tool" if case["source_category"] == "tool" else None)
                arrivals = self.receiver.arrivals[start:]
                self.assertTrue(result.source_executed)
                self.assertEqual(len(arrivals), case["expected"]["arrivals"])
                if case["category"] == "attack":
                    self.assertFalse(result.completed)
                    self.assertFalse(result.outbound.executed)
                    self.assertNotIn("outbound_executor_entered", [event["event"] for event in trace])
                    checks = result.outbound.decision.checks
                    if case["case_id"].startswith("unknown") or case["case_id"].startswith("mixed"):
                        self.assertFalse(any(scan.detected or scan.limited for scan in checks.scanner))
                        self.assertIn("taint", checks.blockers)
                else:
                    self.assertTrue(result.completed)
                    self.assertEqual(arrivals[0]["body"], case["expected"]["wire_data"])

    def test_same_unknown_file_delivers_in_scanner_and_blocks_with_taint(self):
        with redirect_stdout(io.StringIO()):
            scanner = TaintAgent(self.runtime("scanner")).run(path="data/private.txt", operations=[], url=self.receiver.url)
            taint = TaintAgent(self.runtime()).run(path="data/private.txt", operations=[], url=self.receiver.url)
        self.assertTrue(scanner.completed)
        self.assertEqual(len(self.receiver.arrivals), 1)
        self.assertFalse(taint.completed)
        self.assertEqual(taint.outbound.decision.reason, "taint_sensitive_source")
        self.assertFalse(taint.outbound.decision.checks.explain()["scanner"]["detected"])

    def test_sensitive_label_on_url_blocks_before_sender(self):
        runtime = self.runtime()
        with redirect_stdout(io.StringIO()):
            value = runtime.read("data/private.txt").value
            url = concat(TaintedValue.literal(self.receiver.url + "?note="), url_encode(value))
            with patch("security.runtime.send_http") as sender:
                result = runtime.send(url, TaintedValue.literal("normal body"))
                sender.assert_not_called()
        self.assertEqual(result.decision.reason, "taint_sensitive_source")
        self.assertEqual(self.receiver.arrivals, [])

    def test_scanner_and_taint_diagnostics_are_separate_and_audits_redacted(self):
        secret = "PASSWORD=V18_ONLY_FAKE_CREDENTIAL"
        self.private.write_text(secret)
        with redirect_stdout(io.StringIO()):
            result = TaintAgent(self.runtime()).run(path="data/private.txt", operations=[], url=self.receiver.url)
        checks = result.outbound.decision.checks
        self.assertEqual(checks.blockers, ("scanner", "taint"))
        self.assertNotIn(secret, self.audit.read_text())
        self.assertNotIn("data/private.txt", self.audit.read_text())
        last = json.loads(self.audit.read_text().splitlines()[-1])
        self.assertTrue(last["checks"]["scanner"]["detected"])
        self.assertEqual(last["checks"]["taint"]["decisions"][0]["sources"][0]["category"], "file")

    def test_unwrapped_data_is_denied_and_public_tracked_data_allowed(self):
        with redirect_stdout(io.StringIO()):
            runtime = self.runtime()
            raw = runtime.read("data/private.txt").value.reveal()
            denied = runtime.send(self.receiver.url, raw)
            allowed = runtime.send(self.receiver.url, runtime.read("data/public.txt").value)
        self.assertEqual(denied.decision.reason, "taint_untracked")
        self.assertFalse(denied.executed)
        self.assertTrue(allowed.executed)
        self.assertEqual(len(self.receiver.arrivals), 1)

    def test_tool_adapter_keeps_parent_file_origin_even_when_tool_is_public(self):
        runtime = self.runtime(context=TaintContext(self.root, ("data/private.txt",)))
        with redirect_stdout(io.StringIO()):
            parent = runtime.read("data/private.txt").value
            value = runtime.tool_output("public_adapter", lambda: "changed arbitrary output", reference="fixture", parent=parent)
            result = runtime.send(self.receiver.url, value)
        self.assertEqual(len(value.source_ids), 2)
        self.assertTrue(value.sensitive)
        self.assertFalse(result.executed)

    def test_read_denial_and_read_budget_do_not_create_successful_value(self):
        (self.root / "data/.env").write_text("synthetic")
        self.public.write_text("x" * 65537)
        runtime = self.runtime()
        with redirect_stdout(io.StringIO()):
            denied = runtime.read("data/.env")
            oversized = runtime.read("data/public.txt")
        self.assertFalse(denied.executed)
        self.assertIsNone(oversized.value)
        self.assertEqual(oversized.error, "file_read_or_label_failed")
        self.assertEqual(self.receiver.arrivals, [])

    def test_source_classification_uses_approved_canonical_file(self):
        alias = self.root / "data/alias.txt"
        try:
            alias.symlink_to(self.private)
        except OSError as error:
            self.skipTest(str(error))
        with redirect_stdout(io.StringIO()):
            result = self.runtime().read("data/alias.txt")
        self.assertTrue(result.value.sensitive)

    def test_llm_next_request_blocks_unknown_sensitive_tool_output(self):
        client = FakeDotsClient([tool_response("1", "read_file", {"path": "data/private.txt"}), final_response("Done")])
        client.endpoint = self.receiver.target.origin + "/model"
        original_send = client.send_payload
        def real_local_model(payload):
            self.receiver.target.send(client.endpoint, json.dumps(payload))
            return original_send(payload)
        client.send_payload = real_local_model
        context = TaintContext(self.root, ("data/private.txt",))
        with redirect_stdout(io.StringIO()):
            result = run_llm_agent_result("Read the local file.", client=client, policy_path=self.policy,
                                         audit_path=self.audit, taint_context=context)
        self.assertFalse(result.completed)
        self.assertEqual(len(client.sent_payloads), 1)
        self.assertEqual(len(result.evidence), 1)
        self.assertEqual(len(self.receiver.arrivals), 1)
        self.assertNotIn(self.private.read_text(), self.receiver.arrivals[0]["body"])
        last = json.loads(self.audit.read_text().splitlines()[-1])
        self.assertEqual(last["tool"], "model")
        self.assertEqual(last["reason"], "taint_sensitive_source")
        self.assertFalse(last["checks"]["scanner"]["detected"])

    def test_llm_normal_flow_is_compatible_with_taint_enabled(self):
        client = FakeDotsClient([tool_response("1", "read_file", {"path": "data/public.txt"}),
                                 tool_response("2", "send_http", {"url": self.receiver.url, "data": "public summary"}),
                                 final_response("Done")])
        client.endpoint = self.receiver.target.origin + "/model"
        with redirect_stdout(io.StringIO()):
            result = run_llm_agent_result("Read and send.", client=client, policy_path=self.policy, audit_path=self.audit,
                                         taint_context=TaintContext(self.root), local_http_target=self.receiver.target,
                                         required_tools=("read_file", "send_http"), require_real_http=True)
        self.assertTrue(result.completed)
        self.assertEqual(self.receiver.arrivals[0]["body"], "public summary")

    def test_provider_history_rewrite_is_unsupported_not_trusted(self):
        client = FakeDotsClient([final_response("Done")])
        client.endpoint = self.receiver.target.origin + "/model"
        original = client.build_payload
        def rewrite(**kwargs):
            payload = original(**kwargs)
            payload["messages"] = []
            return payload
        client.build_payload = rewrite
        with redirect_stdout(io.StringIO()):
            result = run_llm_agent_result("Read.", client=client, policy_path=self.policy, audit_path=self.audit,
                                         taint_context=TaintContext(self.root))
        self.assertFalse(result.completed)
        self.assertEqual(client.sent_payloads, [])
        self.assertEqual(json.loads(self.audit.read_text().splitlines()[-1])["reason"], "taint_unsupported")

    def test_invalid_mode_and_invalid_context_fail_closed(self):
        with redirect_stdout(io.StringIO()):
            decision = check_tool_call("http", {"url": self.receiver.url, "data": "normal"},
                                       policy_path=self.policy, audit_path=self.audit, defense_mode="unknown")
        self.assertFalse(decision)
        self.assertEqual(decision.reason, "invalid_defense_mode")
        for factory in (lambda: TaintContext(self.root, ("../private",)),
                        lambda: GuardedRuntime(policy_path=self.policy, audit_path=self.audit,
                                               context=TaintContext(self.root.parent)),
                        lambda: GuardedRuntime(policy_path=self.policy, audit_path=self.audit,
                                               context=TaintContext(self.root), defense_mode="no_defense")):
            with self.assertRaises(TaintError):
                factory()


if __name__ == "__main__":
    unittest.main()
