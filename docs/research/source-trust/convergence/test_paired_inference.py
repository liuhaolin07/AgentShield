"""Statistical invariants, with no models, runtime probes or research material."""

import copy
import unittest

import numpy as np

from paired_inference import (RATES, SEEDS, STAT_IDS, analyze_families, bootstrap_bounds,
    cluster_draw_counts, key, linear_bounds, numeric_criteria, recipes, reduce_families,
    required_keys, trapezoid_weights)


def family(i, template=None):
    return {"family_id": f"family-{i:03d}", "template_cluster_id": template,
            "H3_eligible_by_seed": {str(s): True for s in SEEDS},
            "values": {k: {"value": 0, "observed": True} for k in required_keys()}}


class PairedInferenceTests(unittest.TestCase):
    def test_full_grid_seeds_and_seventeen_statistics(self):
        self.assertEqual(tuple(recipes()), STAT_IDS)
        self.assertEqual(len(STAT_IDS), 17)
        self.assertAlmostEqual(sum(trapezoid_weights()), 1)
        # Integral of f(p)=p on [0,1], including the unequal .25->.5 spacing.
        self.assertAlmostEqual(sum(p * w for p, w in zip(RATES, trapezoid_weights())), .5)
        with self.assertRaises(ValueError):
            trapezoid_weights((0, .1, .25))
        f = family(0)
        del f["values"][next(iter(required_keys()))]
        with self.assertRaises(ValueError):
            reduce_families([f])

    def test_seed_mean_and_e0_once(self):
        f = family(0)
        f["values"][key("SP", .25, 17, "precision", "ASR")]["value"] = 1
        reduced = reduce_families([f])
        self.assertAlmostEqual(reduced["lower"][0, 0], .2)
        f["values"][key("E0", 0, None, "precision", "ASR")]["value"] = 1
        self.assertAlmostEqual(reduce_families([f])["lower"][0, 0], -.8)

    def test_linear_missingness_orientation_and_shared_key_cancellation(self):
        values = {"a": {"value": None, "observed": False}, "b": {"value": 1, "observed": True}}
        self.assertEqual(linear_bounds({"a": 1, "b": -1}, values), (-1, 0))
        self.assertEqual(linear_bounds({"a": -1, "b": 1}, values), (0, 1))
        f = family(0)
        f["values"][key("SP", .25, 17, "conservative", "TCR")] = {"value": None, "observed": False}
        r = reduce_families([f])
        j = STAT_IDS.index("H5.delta_TCR_p=0.25")
        self.assertEqual((r["lower"][0, j], r["upper"][0, j]), (0, .2))
        self.assertFalse(r["all_cells_covered"])

    def test_known_arrival_does_not_hide_observation_failure(self):
        f = family(0)
        name = key("SP", .25, 17, "precision", "ASR")
        f["values"][name] = {"value": 1, "observed": False}
        r = analyze_families([f])
        self.assertAlmostEqual(r["statistics"][STAT_IDS[0]]["point"], .2)
        self.assertFalse(r["all_cells_covered"])
        self.assertEqual(r["complete_family_sensitivity"]["families"], 0)

    def test_h3_eligibility_frozen_and_zero_cohort_retained(self):
        f = family(0)
        f["H3_eligible_by_seed"] = {str(s): s == 17 for s in SEEDS}
        f["values"][key("targeted", .1, 17, "precision", "ASR")]["value"] = 1
        self.assertEqual(reduce_families([f])["lower"][0, 3], 1)
        f["H3_eligible_by_seed"] = {str(s): False for s in SEEDS}
        r = analyze_families([f])
        h3 = r["statistics"][STAT_IDS[3]]
        self.assertEqual(h3["families"], 0)
        self.assertIsNone(h3["worst_case_percentile_interval"])
        self.assertEqual(h3["undefined_draws"], 10000)
        self.assertEqual(r["statistics"][STAT_IDS[0]]["families"], 1)

    def test_unequal_clusters_keep_family_weights_and_resample_together(self):
        values = np.tile(np.array([0., 1., 1.])[:, None], (1, 17))
        r = bootstrap_bounds(values, values, ["A", "B", "B"])
        self.assertAlmostEqual(r["statistics"][STAT_IDS[0]]["point"], 2 / 3)
        draws = cluster_draw_counts(2)
        # Manual ratio of cluster totals, not the unweighted mean of two means.
        manual = (2 * draws[:, 1]) / (draws[:, 0] + 2 * draws[:, 1])
        tail = .05 / 34
        expected = np.quantile(manual, [tail, 1 - tail], method="linear")
        np.testing.assert_allclose(r["statistics"][STAT_IDS[0]]["worst_case_percentile_interval"], expected)
        np.testing.assert_array_equal(draws.sum(axis=1), np.full(10000, 2))

    def test_shared_cluster_cannot_masquerade_as_many_families(self):
        values = np.tile(np.linspace(0, 1, 60)[:, None], (1, 17))
        r = bootstrap_bounds(values, values, ["shared"] * 60)
        for stat in r["statistics"].values():
            self.assertEqual(stat["clusters"], 1)
            self.assertIsNone(stat["worst_case_percentile_interval"])
        self.assertFalse(r["confirmatory_success"])

    def test_unequal_cluster_interval_matches_manual_family_resampling(self):
        sizes = np.tile([1, 2, 3], 10)
        cluster_values = np.linspace(-.3, .4, 30) ** 3
        labels = [f"c{i:02d}" for i, size in enumerate(sizes) for _ in range(size)]
        values = np.tile(np.repeat(cluster_values, sizes)[:, None], (1, 17))
        result = bootstrap_bounds(values, values, labels)
        # Explicitly expand every sampled cluster back to all its family rows.
        rng = np.random.default_rng(1729)
        sampled = rng.integers(0, 30, size=(10000, 30))
        manual = (cluster_values[sampled] * sizes[sampled]).sum(axis=1) / sizes[sampled].sum(axis=1)
        expected = np.quantile(manual, [.05 / 34, 1 - .05 / 34])
        np.testing.assert_allclose(result["statistics"][STAT_IDS[0]]["worst_case_percentile_interval"], expected, rtol=0, atol=1e-12)

    def test_coverage_threshold_and_worst_case_intervals_preserve_completions(self):
        families = [family(i) for i in range(20)]
        name = key("SP", .25, 17, "precision", "ASR")
        families[0]["values"][name] = {"value": None, "observed": False}
        reduced = reduce_families(families)
        self.assertTrue(reduced["all_cells_covered"])
        self.assertEqual(reduced["coverage_cells"][name]["coverage"], .95)
        bounded = bootstrap_bounds(reduced["lower"], reduced["upper"], reduced["clusters"])
        outer = bounded["statistics"][STAT_IDS[0]]["worst_case_percentile_interval"]
        for value in (0, 1):
            completed = copy.deepcopy(families)
            completed[0]["values"][name] = {"value": value, "observed": True}
            inner = analyze_families(completed)["statistics"][STAT_IDS[0]]["worst_case_percentile_interval"]
            self.assertLessEqual(outer[0], inner[0])
            self.assertGreaterEqual(outer[1], inner[1])
        families[1]["values"][name] = {"value": None, "observed": False}
        self.assertFalse(reduce_families(families)["all_cells_covered"])

    def test_degenerate_all_reject_cannot_confirm(self):
        r = analyze_families([family(i) for i in range(30)])
        self.assertFalse(r["all_statistical_diagnostics_pass"])
        self.assertFalse(r["numeric_criteria_only"]["H5_original_numeric_rule_only"])
        self.assertIn("degenerate_resampling", r["statistics"][STAT_IDS[0]]["flags"])
        self.assertFalse(r["confirmatory_success"])

    def test_seed_determinism_and_family_order_invariance(self):
        rng = np.random.default_rng(91)
        values = rng.uniform(-.1, .1, (30, 17))
        labels = [str(i // 2) for i in range(30)]
        first = bootstrap_bounds(values, values, labels)
        second = bootstrap_bounds(values[::-1], values[::-1], labels[::-1])
        self.assertEqual(first, second)
        self.assertEqual(first["bootstrap_seed"], 1729)
        self.assertEqual(first["multiplicity"], 17)
        self.assertAlmostEqual(first["tail_probability"], .05 / 34)

    def test_numeric_rule_strict_boundaries_are_not_authorization(self):
        result = {"statistics": {k: {"worst_case_percentile_interval": [.1, .2]} for k in STAT_IDS}}
        for k in STAT_IDS[11:]:
            result["statistics"][k]["worst_case_percentile_interval"] = [.8, .9]
        result["statistics"][STAT_IDS[4]]["worst_case_percentile_interval"] = [-.2, -.1]
        self.assertTrue(numeric_criteria(result)["H5_original_numeric_rule_only"])
        result["statistics"][STAT_IDS[5]]["worst_case_percentile_interval"] = [-.05, 0]
        self.assertFalse(numeric_criteria(result)["H5_original_numeric_rule_only"])
        result["statistics"][STAT_IDS[0]]["worst_case_percentile_interval"] = [.05, .1]
        self.assertFalse(numeric_criteria(result)["H1"])

    def test_missing_bounds_contain_every_completion(self):
        # Exhaust all completions for two missing paired endpoints.
        f = family(0)
        keys = [key("SP", .25, 17, p, "TCR") for p in ("precision", "conservative")]
        for k in keys:
            f["values"][k] = {"value": None, "observed": False}
        bounded = reduce_families([f])
        for a in (0, 1):
            for b in (0, 1):
                completed = copy.deepcopy(f)
                for k, value in zip(keys, (a, b)):
                    completed["values"][k] = {"value": value, "observed": True}
                point = reduce_families([completed])["lower"]
                self.assertTrue(np.all(point >= bounded["lower"] - 1e-12))
                self.assertTrue(np.all(point <= bounded["upper"] + 1e-12))

    def test_nan_wrong_shape_duplicates_and_unidentified_observed_fail(self):
        with self.assertRaises(ValueError):
            bootstrap_bounds(np.zeros((2, 16)), np.zeros((2, 16)), ["A", "B"])
        values = np.zeros((2, 17)); values[0, 0] = np.nan
        with self.assertRaises(ValueError):
            bootstrap_bounds(values, values, ["A", "B"])
        with self.assertRaises(ValueError):
            reduce_families([family(0), family(0)])
        f = family(0)
        f["values"][next(iter(required_keys()))] = {"value": None, "observed": True}
        with self.assertRaises(ValueError):
            reduce_families([f])


if __name__ == "__main__":
    unittest.main()
