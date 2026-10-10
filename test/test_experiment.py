"""Measurement independence and arithmetic; development split only."""

import copy
import csv
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from evaluation.__main__ import export_report
from evaluation.experiment import calculate_metrics, load_dataset, run_experiment
from evaluation.plot import export_metrics_csv
from tools.local_http import HTTPReceipt
from agent.taint_agent import ExplicitAgentResult


class ExperimentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = run_experiment(split="development", repeat=1)
        cls.results = {(row["arm"], row["case_id"]): row for row in cls.report["results"]}

    def require_loopback(self):
        if self.results["no_defense", "transport_canary"]["status"] == "UNRUN":
            self.skipTest("Loopback unavailable; no experiment defense credit")

    def test_same_frozen_inputs_contracts_and_policies_in_every_arm(self):
        dataset, digest = load_dataset()
        self.assertEqual(self.report["dataset_sha256"], digest)
        for case in dataset["cases"]:
            rows = [row for (arm, name), row in self.results.items() if name == case["case_id"]]
            self.assertEqual(len(rows), 4)
            self.assertTrue(all(row["inputs"] == case and row["expected"] == case["expected"] for row in rows))
            self.assertTrue(all(row["policy"] == rows[0]["policy"] for row in rows))

    def test_source_tracking_improvement_requires_receiver_and_false_scanner_match(self):
        self.require_loopback()
        scanner = self.results["scanner", "unknown_base64"]
        taint = self.results["scanner_taint", "unknown_base64"]
        self.assertEqual(scanner["status"], "FAILED")
        self.assertEqual(scanner["actual"]["arrivals"], 1)
        self.assertEqual(taint["status"], "HELD")
        self.assertEqual(taint["actual"]["arrivals"], 0)
        self.assertEqual(taint["actual"]["executor_calls"], 0)
        self.assertFalse(taint["actual"]["checks"]["scanner"]["detected"])
        self.assertEqual(taint["actual"]["defense_modules"], ["taint"])
        self.assertEqual(taint["block_source"], "agentshield")

    def test_normal_deliveries_and_canary_make_blanket_deny_visible(self):
        self.require_loopback()
        for arm in self.report["metrics"]:
            canary = self.results[arm, "transport_canary"]
            self.assertEqual(canary["actual"]["arrivals"], 1)
            self.assertEqual(canary["actual"]["effective_mode"], "no_defense")
            self.assertFalse(canary["defense_credit"])
            normal = self.results[arm, "benign_file_http"]
            self.assertEqual(normal["actual"]["arrivals"], 1)
            self.assertTrue(normal["actual"]["completion_supported"])

    def test_unsupported_flows_stay_unrun_in_all_arms(self):
        for (arm, name), row in self.results.items():
            if name in {"unsupported_third_party", "implicit_information_flow"}:
                self.assertEqual(row["status"], "UNRUN")
                self.assertEqual(row["block_source"], "unsupported")
                self.assertFalse(row["defense_credit"])

    def test_metrics_expose_numerators_denominators_and_classification(self):
        self.require_loopback()
        metrics = calculate_metrics(self.report["results"])
        for arm, expected in metrics.items():
            rows = [row for row in self.report["results"] if row["arm"] == arm and row["category"] != "control"
                    and row["status"] != "UNRUN" and row["actual"].get("valid_observation")]
            attacks = [row for row in rows if row["category"] == "attack"]
            benign = [row for row in rows if row["category"] == "benign"]
            self.assertEqual(expected["ASR"]["denominator"], len(attacks))
            self.assertEqual(expected["ASR"]["numerator"], sum(row["actual"]["arrivals"] == 1 for row in attacks))
            self.assertEqual(expected["FPR"]["numerator"], sum(row["actual"]["middleware_block"] for row in benign))
            self.assertEqual(expected["TCR"]["denominator"], len(benign))
            self.assertEqual(expected["precision"]["denominator"], expected["confusion"]["TP"] + expected["confusion"]["FP"])
        self.assertIsNone(metrics["no_defense"]["precision"]["value"])
        self.assertGreater(metrics["static_rule"]["FPR"]["numerator"], 0)

    def test_metrics_exclude_unavailable_and_invalid_evidence(self):
        rows = copy.deepcopy(self.report["results"])
        for row in rows:
            if row["category"] != "control":
                row["actual"]["valid_observation"] = False
        for metric in calculate_metrics(rows).values():
            self.assertEqual(metric["ASR"]["denominator"], 0)
            self.assertIsNone(metric["ASR"]["value"])
            self.assertEqual(metric["extra_defense_latency_ms"]["paired_samples"], 0)

    def test_fabricated_receipts_do_not_prove_delivery(self):
        self.require_loopback()
        with patch("security.runtime.send_http", return_value=HTTPReceipt(202, 0, "fabricated")):
            report = run_experiment(repeat=1)
        canary = next(row for row in report["results"] if row["arm"] == "no_defense" and row["case_id"] == "transport_canary")
        self.assertEqual(canary["status"], "FAILED")
        self.assertFalse(canary["actual"]["valid_observation"])
        unknown = next(row for row in report["results"] if row["arm"] == "scanner_taint" and row["case_id"] == "unknown_direct")
        self.assertEqual(unknown["status"], "UNRUN")
        self.assertFalse(unknown["defense_credit"])

    def test_external_sandbox_restriction_is_never_taint_success(self):
        with patch("evaluation.experiment.LoopbackReceiver", side_effect=PermissionError("test restriction")):
            first = run_experiment(seed=23, repeat=2)
            second = run_experiment(seed=23, repeat=2)
        self.assertTrue(all(row["status"] == "UNRUN" and not row["defense_credit"] for row in first["results"]))
        self.assertEqual([(row["run"], row["arm"], row["case_id"]) for row in first["results"]],
                         [(row["run"], row["arm"], row["case_id"]) for row in second["results"]])
        self.assertEqual(len(first["results"]), 184)

    def test_model_completion_claim_without_execution_is_invalid_evidence(self):
        self.require_loopback()
        with patch("evaluation.experiment.TaintAgent.run", return_value=ExplicitAgentResult(True, True, None)):
            report = run_experiment(repeat=1)
        claims = [row for row in report["results"] if "completion_supported" in row["actual"]]
        self.assertTrue(claims)
        self.assertTrue(all(not row["actual"]["completion_supported"] and row["status"] == "FAILED" for row in claims))
        self.assertTrue(all(metric["ASR"]["denominator"] == 0 for metric in report["metrics"].values()))

    def test_paired_latency_is_actual_difference_not_clamped(self):
        rows = copy.deepcopy(self.report["results"])
        for row in rows:
            if row["category"] != "control" and row["status"] != "UNRUN":
                row["actual"]["gate_duration_ns"] = 4000000 if row["arm"] == "no_defense" else 2000000
        metrics = calculate_metrics(rows)
        for arm, metric in metrics.items():
            if metric["extra_defense_latency_ms"]["paired_samples"]:
                self.assertEqual(metric["extra_defense_latency_ms"]["mean"], 0 if arm == "no_defense" else -2)

    def test_trace_sequences_and_source_categories_are_observed(self):
        self.require_loopback()
        for row in self.report["results"]:
            self.assertEqual([event["sequence"] for event in row["trace"]], list(range(1, len(row["trace"]) + 1)))
        tool = self.results["scanner_taint", "unknown_tool_to_model"]
        categories = {source["category"] for decision in tool["actual"]["checks"]["taint"]["decisions"] for source in decision["sources"]}
        self.assertEqual(categories, {"file", "tool"})

    def test_json_cases_csv_and_metrics_csv_retain_full_records(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            export_report(self.report, output)
            export_metrics_csv(self.report, output)
            self.assertEqual(json.loads((output / "report.json").read_text()), self.report)
            with (output / "cases.csv").open(newline="") as source:
                rows = list(csv.DictReader(source))
            self.assertEqual(len(rows), len(self.report["results"]))
            self.assertEqual(json.loads(rows[0]["inputs"]), self.report["results"][0]["inputs"])
            self.assertEqual(rows[0]["arm"], self.report["results"][0]["arm"])
            with (output / "metrics.csv").open(newline="") as source:
                metrics = list(csv.DictReader(source))
            self.assertEqual(len(metrics), 24)

    def test_dataset_integrity_and_repeat_arguments_are_checked(self):
        with patch("evaluation.experiment.hashlib.sha256") as digest:
            digest.return_value.hexdigest.return_value = "changed"
            with self.assertRaises(ValueError):
                load_dataset()
        for repeat in (0, 101, True):
            with self.assertRaises(ValueError):
                run_experiment(repeat=repeat)


if __name__ == "__main__":
    unittest.main()
