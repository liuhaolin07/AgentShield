"""Deterministic engineering fixtures, never formal calibration or reserved seeds."""
from pathlib import Path
import copy
import importlib
from itertools import chain
import json
import sys
import unittest

HERE = Path(__file__).resolve().parents[1]
sys.path[:] = [p for p in sys.path if p and "hermes" not in p.casefold()]
sys.path[:0] = [str(HERE), str(HERE.parent)]
from paired_inference import STAT_IDS

CONFIG = json.loads((HERE / "config.json").read_text(encoding="utf-8"))


def row(index, covered=True):
    return {
        "dataset_index": index,
        "intervals": [[.4, .6] if name.startswith("H5.TCR_conservative_") else [-.1, .1]
                      for name in STAT_IDS] if covered else [[.7, .8] if name.startswith("H5.TCR_conservative_") else [.2, .3]
                                                            for name in STAT_IDS],
        "truth": [.5 if name.startswith("H5.TCR_conservative_") else 0. for name in STAT_IDS],
        "eligible_clusters": [30] * 17,
        "degenerate": [False] * 17,
        "undefined_draws": [0] * 17,
        "metadata": {"engineering_fixture": True},
    }


def rows(n=4000, covered=3800):
    return (row(i, i < covered) for i in range(n))


class ResultsTests(unittest.TestCase):
    def module(self, required="summarize_rows"):
        try:
            module = importlib.import_module("d5_results")
        except ModuleNotFoundError:
            self.fail("Missing independent archived-row results module")
        self.assertTrue(callable(getattr(module, required, None)), f"Missing {required}")
        return module

    def test_old_29_percent_style_fixture_is_rejected_from_1160_of_4000(self):
        # 1160/4000 is a deliberately constructed regression fixture, NOT real data.
        result = self.module().summarize_rows(CONFIG["scenarios"][0], rows(4000, 1160))
        self.assertEqual(result["classification"], "FAIL_UNDERCOVERAGE")
        self.assertEqual(result["joint_covered"], 1160)
        self.assertEqual(result["joint_available"], 4000)
        self.assertEqual(result["joint_coverage_all_datasets"], .29)
        self.assertEqual(result["joint_diagnostic_rejections"], 0)
        self.assertEqual(tuple(result["per_statistic"]), STAT_IDS)
        for statistic in result["per_statistic"].values():
            self.assertEqual(statistic["covered"], 1160)
            self.assertEqual(statistic["available"], 4000)
            self.assertEqual(statistic["undefined"], 0)
            self.assertEqual(statistic["min_eligible_clusters"], 30)
            self.assertEqual(statistic["mc_marginal_95"], self.module().d5_contract.cp_interval(1160, 4000))
        self.assertFalse(result["confirmatory_success"])

    def test_unavailable_stays_in_primary_denominator_and_refuses_diagnostics(self):
        def archived():
            for item in rows():
                if item["dataset_index"] == 0:
                    item["intervals"][0] = [None, None]
                    item["undefined_draws"][0] = 10000
                yield item
        result = self.module().summarize_rows(CONFIG["scenarios"][0], archived())
        self.assertEqual(result["datasets"], 4000)
        self.assertEqual(result["joint_covered"], 3799)
        self.assertEqual(result["joint_available"], 3999)
        self.assertEqual(result["joint_diagnostic_rejections"], 1)
        self.assertEqual(result["classification"], "FAIL_DIAGNOSTICS")
        component = result["per_statistic"][STAT_IDS[0]]
        self.assertEqual(component["coverage_all_datasets"], 3799 / 4000)
        self.assertEqual(component["coverage_among_available"], 3799 / 3999)
        self.assertEqual(component["undefined"], 1)  # datasets, not 10000 draws
        self.assertEqual(component["mc_marginal_95"], self.module().d5_contract.cp_interval(3799, 4000))

    def test_unavailable_widths_are_none_and_available_widths_use_type7(self):
        def archived():
            for i in range(100):
                item = row(i)
                item["intervals"][0] = [None, None]
                item["eligible_clusters"][0] = 1
                item["undefined_draws"][0] = 10000
                item["intervals"][1] = [None, None] if i else [-.1, .1]
                item["intervals"][2] = [0., (i + 1) / 1000]
                item["eligible_clusters"][3] = 29
                yield item
        result = self.module().summarize_rows(CONFIG["scenarios"][-1], archived())
        self.assertEqual(result["classification"], "DESCRIPTIVE_ONLY")
        first = result["per_statistic"][STAT_IDS[0]]
        self.assertEqual(first["available"], 0)
        self.assertEqual(first["undefined"], 100)
        self.assertEqual(first["below_minimum_clusters"], 100)
        self.assertEqual(first["min_eligible_clusters"], 1)
        self.assertIsNone(first["coverage_among_available"])
        self.assertIsNone(first["mean_width"])
        self.assertIsNone(first["p95_width"])
        second = result["per_statistic"][STAT_IDS[1]]
        self.assertEqual(second["available"], 1)
        self.assertAlmostEqual(second["mean_width"], .2)
        self.assertAlmostEqual(second["p95_width"], .2)
        third = result["per_statistic"][STAT_IDS[2]]
        self.assertAlmostEqual(third["mean_width"], sum((i + 1) / 1000 for i in range(100)) / 100)
        self.assertAlmostEqual(third["p95_width"], .095 * .95 + .096 * .05)
        self.assertEqual(result["joint_available"], 0)
        self.assertEqual(result["joint_covered"], 0)
        self.assertEqual(result["joint_diagnostic_rejections"], 100)

    def test_rows_fail_closed_for_wrong_schema_domains_counts_and_diagnostics(self):
        m = self.module()
        variants = []
        for field in ("intervals", "truth", "eligible_clusters", "degenerate", "undefined_draws"):
            for size in (16, 18):
                item = row(0)
                item[field] = (item[field] * 2)[:size]
                variants.append((f"{field}_length_{size}", item))
            item = row(0)
            item[field] = {str(j): value for j, value in enumerate(item[field])}
            variants.append((f"{field}_not_array", item))
        for field in row(0):
            item = row(0)
            del item[field]
            variants.append((f"missing_{field}", item))
        for field, value in (("covered", [True] * 17), ("joint_covered", 4000), ("extra", 1)):
            item = row(0)
            item[field] = value
            variants.append((f"unexpected_{field}", item))
        for field, value in (("dataset_index", True), ("dataset_index", 1.), ("dataset_index", -1),
                             ("dataset_index", 4000), ("metadata", []), ("metadata", None)):
            item = row(0)
            item[field] = value
            variants.append((f"{field}_{value}", item))
        for field, value in (("truth", float("nan")), ("truth", float("inf")),
                             ("truth", "0"), ("truth", True), ("truth", -1.01), ("truth", 1.01),
                             ("eligible_clusters", True), ("eligible_clusters", 30.),
                             ("eligible_clusters", -1), ("degenerate", 0), ("degenerate", "false"),
                             ("undefined_draws", -1), ("undefined_draws", 10001),
                             ("undefined_draws", True), ("undefined_draws", 1.)):
            item = row(0)
            item[field][0] = value
            variants.append((f"{field}_{value}", item))
        for value in ([None, 0.], [0., None], [0.], [0., 0., 0.], [float("nan"), .1],
                      [-.1, float("inf")], [-1.01, .1], [0., 1.01], [.2, .1], [False, .1],
                      ["0", .1], "bad"):
            item = row(0)
            item["intervals"][0] = value
            variants.append((f"invalid_interval_{value}", item))
        absolute_index = next(j for j, name in enumerate(STAT_IDS) if name.startswith("H5.TCR_conservative_"))
        for field, value in (("truth", -.01), ("intervals", [-.01, .1])):
            item = row(0)
            item[field][absolute_index] = value
            variants.append((f"absolute_{field}_negative", item))
        for field, value in (("eligible_clusters", 1), ("eligible_clusters", 0), ("undefined_draws", 1)):
            item = row(0)
            item[field][0] = value
            variants.append((f"available_with_{field}_{value}", item))
        for name, item in variants:
            with self.subTest(invalid=name):
                with self.assertRaises(ValueError):
                    m.summarize_rows(CONFIG["scenarios"][0], chain([item], (row(i) for i in range(1, 4000))))
        for name, archived in (("empty", []), ("short", rows(3999)), ("excess", rows(4001)),
                               ("duplicate", (row(0) for _ in range(4000))),
                               ("non_dict", iter([None])), ("not_iterable", None)):
            with self.subTest(invalid=name):
                with self.assertRaises(ValueError):
                    m.summarize_rows(CONFIG["scenarios"][0], archived)
        for role in ("control", None, True):
            with self.subTest(invalid_role=role):
                with self.assertRaises(ValueError):
                    m.summarize_rows({"id": "fixture", "role": role}, rows())
        with self.assertRaises(ValueError):
            m.summarize_rows(CONFIG["scenarios"][-1], rows(4000))

    def test_indices_may_be_unordered_but_joint_is_not_component_average(self):
        def archived():
            for i in reversed(range(4000)):
                item = row(i)
                if i < 17:
                    item["intervals"][i] = [.7, .8] if item["truth"][i] else [.2, .3]
                yield item
        result = self.module().summarize_rows(CONFIG["scenarios"][0], archived())
        self.assertEqual(result["joint_covered"], 4000 - 17)
        self.assertTrue(all(s["covered"] == 3999 for s in result["per_statistic"].values()))
        self.assertEqual(result["joint_available"], 4000)
    def report_fixture(self):
        m = self.module()
        summaries = []
        for scenario in CONFIG["scenarios"]:
            if scenario["role"] == "primary":
                source = rows()
            else:
                def controls(s=scenario):
                    for i in range(100):
                        item = row(i)
                        if s["required_rejection"] == "all_statistics_degenerate":
                            item["degenerate"] = [True] * 17
                            item["intervals"] = [[v, v] for v in item["truth"]]
                        elif s["required_rejection"] == "all_statistics_below_minimum_clusters":
                            item["eligible_clusters"] = [1] * 17
                            item["intervals"] = [[None, None] for _ in range(17)]
                        else:
                            item["eligible_clusters"][3] = 29
                        yield item
                source = controls()
            summaries.append(m.summarize_rows(scenario, source))
        return summaries

    def test_full_report_cannot_promote_power_or_hide_a_failed_scenario(self):
        m = self.module("assemble_report")
        summaries = self.report_fixture()
        freeze = {"verified_tree_commit": "engineering-fixture", "contract_sha256": "0" * 64, "freeze_sha256": "1" * 64}
        report = m.assemble_report(CONFIG, summaries, freeze)
        self.assertTrue(report["synthetic_coverage_gate_passed"])
        for field in ("coverage_certified", "power_validated", "precision_validated", "experiment_authorized",
                      "confirmatory_success", "D5_complete", "holdout_accessed"):
            self.assertIs(report[field], False)
        for field in ("formal_pilot_rows", "new_model_requests", "new_http_requests"):
            self.assertEqual(report[field], 0)
        summaries[4] = m.summarize_rows(CONFIG["scenarios"][4], rows(4000, 1160))
        rejected = m.assemble_report(CONFIG, summaries, freeze)
        self.assertFalse(rejected["synthetic_coverage_gate_passed"])
        self.assertEqual(rejected["state"], "D5_METHOD_REJECTED")
        with self.assertRaises(ValueError):
            m.assemble_report(CONFIG, summaries[:-1], freeze)
        modified = copy.deepcopy(summaries)
        modified[0]["classification"] = "PASS"
        modified[0]["per_statistic"][STAT_IDS[0]]["covered"] = 0
        with self.assertRaises(ValueError):
            m.assemble_report(CONFIG, modified, freeze)

    def test_markdown_lists_every_scenario_and_all_seventeen_components(self):
        m = self.module("render_markdown")
        summaries = self.report_fixture()
        report = m.assemble_report(CONFIG, summaries, {"engineering_fixture": True})
        rendered = m.render_markdown(report)
        for scenario in CONFIG["scenarios"]:
            self.assertIn(scenario["id"], rendered)
        for statistic in STAT_IDS:
            self.assertEqual(rendered.count("| " + statistic + " |"), 13)
        self.assertIn("99.706", rendered)
        self.assertIn("不是同时", rendered)
        self.assertIn("D5_complete", rendered)


if __name__ == "__main__":
    unittest.main()
