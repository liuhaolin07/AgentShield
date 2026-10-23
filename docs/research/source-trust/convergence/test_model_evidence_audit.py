"""Evidence aggregation rejects scope inflation; no runtime or API calls."""
from copy import deepcopy
import json
import unittest

from model_evidence_audit import HERE, BUNDLE, synthesize


class ModelEvidenceAuditTests(unittest.TestCase):
    def setUp(self):
        read = lambda p: json.loads(p.read_text())
        self.inputs = [
            read(HERE / "dots-diagnostic-v1/live-001.json"),
            {p: read(HERE / f"{p}-tool-study-v1/run-001/report.json") for p in ("dots", "deepseek")},
            {p: read(HERE / f"{p}-tool-study-v1/run-001/plan.json") for p in ("dots", "deepseek")},
            read(BUNDLE / "manifest.json"), read(HERE / "intake-manifest.json"),
            read(HERE / "evidence-gates.json"), read(HERE.parent / "protocol-draft.json"),
        ]

    def test_reused_models_do_not_multiply_material_independence(self):
        result = synthesize(*self.inputs)
        self.assertEqual(result["real_model_requests_including_diagnostic"], 33)
        self.assertEqual(result["provider_reported_tokens_including_diagnostic"], 9402)
        self.assertEqual(result["development_trajectories"], 16)
        self.assertEqual(result["unique_reused_families"], 2)
        self.assertEqual(result["unique_declared_template_clusters"], 1)
        self.assertEqual(len(result["pending_evidence_gates"]), 13)
        self.assertFalse(result["independent_clusters_verified"])
        self.assertEqual(result["formal_pilot_rows"], 0)

    def test_cannot_promote_fixture_formal_or_changed_budget(self):
        for mode in ("fixture", "formal", "budget", "intake", "currency"):
            args = deepcopy(self.inputs)
            if mode == "fixture":
                args[1]["deepseek"]["fixture_client"] = True
            elif mode == "formal":
                args[1]["dots"]["summary"]["formal_pilot_rows"] = 8
            elif mode == "budget":
                args[5]["budget_snapshot"]["E0_E1"] *= 2
            elif mode == "intake":
                args[4]["families"] = [{"unexpected": "new_material"}]
            else:
                args[1]["deepseek"]["budget_currency"] = "USD"
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                synthesize(*args)

    def test_different_tasks_or_unknown_usage_cannot_be_same_workflow_check(self):
        for mode in ("tasks", "usage", "calls"):
            args = deepcopy(self.inputs)
            if mode == "tasks":
                args[2]["deepseek"]["rows"][0]["task_id"] = "different"
            elif mode == "usage":
                args[1]["deepseek"]["usage_known"] = False
            else:
                args[1]["deepseek"]["model_requests"] = 17
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                synthesize(*args)


if __name__ == "__main__":
    unittest.main()
