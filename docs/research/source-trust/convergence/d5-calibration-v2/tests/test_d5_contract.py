"""Engineering fixtures only; never use the reserved calibration seeds."""
from pathlib import Path
import importlib
import sys
import unittest

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent))


class CoverageGateTests(unittest.TestCase):
    def module(self, required=None):
        try:
            module = importlib.import_module("d5_contract")
        except ModuleNotFoundError:
            self.fail("Missing D5 machine acceptance contract")
        if required:
            self.assertTrue(callable(getattr(module, required, None)), f"Missing {required}")
        return module

    def test_simultaneous_mc_interval_must_fit_entire_band(self):
        m = self.module()
        good = m.coverage_decision(3800, 4000)
        self.assertEqual(good["classification"], "PASS")
        self.assertGreaterEqual(good["mc_interval"][0], .93)
        self.assertLessEqual(good["mc_interval"][1], .97)
        for k in (1160, 3600, 3764, 3849, 4000):
            with self.subTest(covered=k):
                self.assertNotEqual(m.coverage_decision(k, 4000)["classification"], "PASS")
        self.assertEqual(m.coverage_decision(1160, 4000)["classification"], "FAIL_UNDERCOVERAGE")
        self.assertEqual(m.coverage_decision(4000, 4000)["classification"], "FAIL_OVERCOVERAGE")
        for k, n in ((29, 100), (950, 1000), (4001, 4000), (-1, 4000), (True, 4000)):
            with self.subTest(covered=k, total=n):
                with self.assertRaises(ValueError):
                    m.coverage_decision(k, n)

    def fixture(self, n=4000, covered=3800):
        from paired_inference import STAT_IDS
        return {"datasets": n, "joint_covered": covered, "joint_available": n,
                "joint_diagnostic_rejections": 0,
                "per_statistic": {s: {"covered": covered, "available": n,
                    "degenerate": 0, "undefined": 0, "below_minimum_clusters": 0,
                    "min_eligible_clusters": 30, "mean_width": .1, "p95_width": .1}
                    for s in STAT_IDS}}

    def test_frozen_contract_rejects_tuning_and_role_changes(self):
        import copy
        import json
        m = self.module("validate_contract")
        config = json.loads((HERE / "config.json").read_text(encoding="utf-8"))
        m.validate_contract(config)
        for field, value in (("datasets_per_primary_scenario", 5000),
                             ("minimum_independent_template_clusters", 29),
                             ("joint_coverage_acceptance_band", [.90, 1.0]),
                             ("simulation_seed", 4), ("method_replacement", True)):
            with self.subTest(field=field):
                changed = copy.deepcopy(config)
                changed[field] = value
                with self.assertRaises(ValueError):
                    m.validate_contract(changed)
        changed = copy.deepcopy(config)
        changed["scenarios"][4]["role"] = "negative_control"
        with self.assertRaises(ValueError):
            m.validate_contract(changed)

    def test_missing_diagnostics_and_conditional_denominator_cannot_pass(self):
        import copy
        m = self.module("finalize_scenario")
        scenario = {"id": "fixture", "role": "primary"}
        good = self.fixture()
        self.assertEqual(m.finalize_scenario(scenario, good)["classification"], "PASS")
        missing = copy.deepcopy(good)
        missing["joint_available"] = 3999
        missing["per_statistic"]["H1.delta_ASR"]["available"] = 3999
        self.assertEqual(m.finalize_scenario(scenario, missing)["classification"], "FAIL_DIAGNOSTICS")
        below = copy.deepcopy(good)
        below["per_statistic"]["H3.delta_ASR"].update(
            min_eligible_clusters=29, below_minimum_clusters=4000)
        below["joint_diagnostic_rejections"] = 4000
        self.assertEqual(m.finalize_scenario(scenario, below)["classification"], "FAIL_DIAGNOSTICS")
        del good["per_statistic"]["H3.delta_ASR"]
        with self.assertRaises(ValueError):
            m.finalize_scenario(scenario, good)

    def test_json_object_order_does_not_change_statistic_identity(self):
        import json
        m = self.module("finalize_scenario")
        record = json.loads(json.dumps(self.fixture(), sort_keys=True))
        try:
            result = m.finalize_scenario({"id": "fixture", "role": "primary"}, record)
        except ValueError as exc:
            self.fail(f"JSON object order is not a statistic identifier: {exc}")
        self.assertEqual(result["classification"], "PASS")

    def test_negative_controls_require_actual_descriptive_refusal(self):
        m = self.module("finalize_scenario")
        scenario = {"id": "fixture", "role": "negative_control",
                    "required_rejection": "H3_below_minimum_clusters"}
        record = self.fixture(100, 95)
        self.assertEqual(m.finalize_scenario(scenario, record)["classification"], "FAIL_NEGATIVE_CONTROL")
        record["per_statistic"]["H3.delta_ASR"].update(
            min_eligible_clusters=29, below_minimum_clusters=100)
        record["joint_diagnostic_rejections"] = 100
        result = m.finalize_scenario(scenario, record)
        self.assertEqual(result["classification"], "DESCRIPTIVE_ONLY")
        self.assertFalse(result["confirmatory_success"])
        self.assertEqual(result["joint_coverage_all_datasets"], .95)


if __name__ == "__main__":
    unittest.main()
