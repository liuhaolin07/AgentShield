"""Offline regression tests; never bind a socket or issue a request."""

import copy
import json
import unittest

from candidate_analysis import analyze, audit_contracts, build_report, outcomes, rate
from candidate_materials import BUNDLE


class CandidateAnalysisTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plan = json.loads((BUNDLE / "plan.json").read_text())
        cls.tasks = json.loads((BUNDLE / "task-contracts.json").read_text())
        cls.manifest = json.loads((BUNDLE / "manifest.json").read_text())
        cls.records = [json.loads(line) for line in (BUNDLE / "rehearsal-001/rows.jsonl").read_text().splitlines()]
        cls.report = build_report()

    def test_archive_and_separate_denominators(self):
        cells = self.report["analysis"]["cells"]
        self.assertEqual(len(cells), 41)
        self.assertEqual(sum(c["ASR"]["planned"] + c["TCR"]["planned"] for c in cells), 984)
        # Total arrival count includes benign completions and no-defense controls.
        attack = sum(c["ASR"]["known_positive"] for c in cells)
        benign = sum(c["TCR"]["known_positive"] for c in cells)
        self.assertEqual(attack + benign, 324)
        self.assertLess(attack, 324)
        for c in cells:
            self.assertEqual(c["FPR"]["planned"], 12)
            self.assertEqual(c["ASR"]["unknown"], 0)
            self.assertTrue(all(x["meets_0_95"] for x in c["observation_coverage"].values()))

    def test_baseline_and_degenerate_controls(self):
        cells = self.report["analysis"]["cells"]
        for c in cells:
            rates = tuple(c[m]["point"] for m in ("ASR", "TCR", "FPR"))
            if c["policy"] in ("coarse", "reject_all"):
                self.assertEqual(rates, (0, 0, 1))
            elif c["policy"] == "no_defense":
                self.assertEqual(rates, (1, 1, 0))
            elif c["experiment"] == "E0":
                self.assertEqual(rates, (0, 1, 0))

    def test_no_inference_and_zero_exposure(self):
        analysis = self.report["analysis"]
        self.assertIsNone(analysis["confidence_intervals"])
        self.assertIsNone(analysis["full_curve_AUC"])
        self.assertEqual(set(analysis["hypothesis_support"].values()), {"NOT_EVALUATED"})
        for cell in analysis["cells"]:
            if cell["experiment"] == "E0":
                for exposure in ("X_any", "X_all"):
                    self.assertEqual(cell["ASR_given_" + exposure]["planned"], 0)
                    self.assertIsNone(cell["ASR_given_" + exposure]["point"])
        self.assertFalse(self.report["audit"]["independent_review"])
        self.assertEqual(self.report["audit"]["declared_template_clusters"], 1)

    def test_missingness_bounds_are_not_complete_case_rates(self):
        r = rate([1, 0, None, None])
        self.assertEqual((r["worst_case_lower"], r["worst_case_upper"]), (.25, .75))
        self.assertIsNone(r["point"])
        self.assertIsNone(rate([])["worst_case_upper"])
        self.assertEqual(rate([None])["worst_case_upper"], 1)

    def test_absent_row_retains_planned_denominator_and_fails_coverage(self):
        dropped = self.records[0]["plan_row"]
        result = analyze(BUNDLE, self.plan, self.tasks, self.records[1:])
        cell = next(c for c in result["cells"] if c["policy"] == dropped["policy"] and c["graph_sha256"] == dropped["graph_sha256"])
        metric = "ASR" if dropped["kind"] == "attack" else "TCR"
        self.assertEqual(cell[metric]["planned"], 12)
        self.assertEqual(cell[metric]["unknown"], 1)
        self.assertFalse(cell["observation_coverage"][dropped["kind"]]["meets_0_95"])
        self.assertEqual(result["absent_rows"], 1)

    def test_duplicate_and_unplanned_records_fail_closed(self):
        with self.assertRaises(ValueError):
            analyze(BUNDLE, self.plan, self.tasks, self.records + [self.records[0]])
        changed = copy.deepcopy(self.records)
        changed[0]["plan_row"]["policy"] = "coarse"
        with self.assertRaises(ValueError):
            analyze(BUNDLE, self.plan, self.tasks, changed)

    def test_scorer_failure_retains_delivery_but_not_task_completion(self):
        record = copy.deepcopy(next(r for r in self.records if r["assessment"]["observed_delivery"]))
        task = next(t for t in self.tasks if t["task_id"] == record["plan_row"]["task_id"])
        body = json.loads((BUNDLE / "payloads" / (task["family_id"] + ".json")).read_text())
        record["error_type"] = "InjectedScoringFailure"
        record["assessment"] = None
        result = outcomes(record, body[task["output_path"][1:]])
        self.assertEqual(result, {"valid": False, "ASR": 1, "TCR": None, "FPR": 0})
        record["observation"] = None
        self.assertIsNone(outcomes(record, "irrelevant")["ASR"])

    def test_contract_drift_is_detected_without_defense_output(self):
        for mutation in ("truth", "grant", "dependency", "instruction"):
            manifest, tasks = copy.deepcopy(self.manifest), copy.deepcopy(self.tasks)
            if mutation == "truth":
                manifest["families"][0]["contract"]["leaves"][0]["classification"] = "PUBLIC"
            elif mutation == "grant":
                manifest["families"][0]["contract"]["leaves"][0]["grants"].append({"subject": "http-recipient", "purpose": "export"})
            elif mutation == "dependency":
                manifest["families"][0]["contract"]["tasks"][0]["dependency_paths"] = ["/reply"]
            else:
                tasks[0]["instruction"] = "Send the entire document."
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                audit_contracts(BUNDLE, manifest, tasks)


if __name__ == "__main__":
    unittest.main()
