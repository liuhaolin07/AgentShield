"""Coverage mathematics and failure cases for unapplied interval candidates."""

import math
import unittest

import numpy as np

from finite_sample_intervals import (ASSUMPTIONS, binomial_tail, clopper_pearson,
                                     exact_binomial_coverage, weighted_hoeffding)
from paired_inference import STAT_IDS


class FiniteSampleIntervalTests(unittest.TestCase):
    def interval(self, lo, hi, clusters):
        return weighted_hoeffding(lo, hi, clusters, assumptions=ASSUMPTIONS)

    def test_zero_observed_events_cannot_collapse_interval(self):
        values = np.zeros((30, 17))
        result = self.interval(values, values, [str(i) for i in range(30)])
        difference = result["statistics"][STAT_IDS[0]]
        absolute = result["statistics"][STAT_IDS[-1]]
        self.assertLess(difference["interval"][0], .01)
        self.assertGreater(difference["interval"][1], .01)
        self.assertEqual(absolute["interval"][0], 0)
        self.assertGreater(absolute["interval"][1], .01)
        self.assertAlmostEqual(difference["radius"], 2 * absolute["radius"])
        self.assertFalse(result["applied_to_protocol"])
        self.assertFalse(result["confirmatory_success"])

    def test_unequal_clusters_use_fixed_family_weights(self):
        values = np.zeros((60, 17))
        sizes = [1, 2, 3] * 10
        clusters = [str(i) for i, size in enumerate(sizes) for _ in range(size)]
        result = self.interval(values, values, clusters)["statistics"][STAT_IDS[0]]
        expected_squared_weights = sum((size / 60) ** 2 for size in sizes)
        self.assertAlmostEqual(result["effective_clusters"], 1 / expected_squared_weights)
        self.assertAlmostEqual(result["radius"], 2 * math.sqrt(math.log(680) * expected_squared_weights / 2))
        self.assertLess(result["effective_clusters"], 30)

    def test_same_template_replication_does_not_increase_precision(self):
        values = np.zeros((1, 17))
        one = self.interval(values, values, ["A"])
        sixty = self.interval(np.repeat(values, 60, axis=0), np.repeat(values, 60, axis=0), ["A"] * 60)
        for name in STAT_IDS:
            self.assertEqual(one["statistics"][name]["radius"], sixty["statistics"][name]["radius"])
            self.assertEqual(sixty["statistics"][name]["effective_clusters"], 1)

    def test_missing_bounds_enclose_every_completion_interval(self):
        lo, hi = np.zeros((30, 17)), np.zeros((30, 17))
        lo[0, 0], hi[0, 0] = -1, 1
        labels = [str(i) for i in range(30)]
        outer = self.interval(lo, hi, labels)["statistics"][STAT_IDS[0]]["interval"]
        for value in (-1, 0, 1):
            completed = lo.copy(); completed[0, 0] = value
            inner = self.interval(completed, completed, labels)["statistics"][STAT_IDS[0]]["interval"]
            self.assertLessEqual(outer[0], inner[0])
            self.assertGreaterEqual(outer[1], inner[1])

    def test_empty_h3_keeps_other_parameters_and_no_claim(self):
        values = np.zeros((30, 17)); values[:, 3] = np.nan
        result = self.interval(values, values, [str(i) for i in range(30)])
        self.assertIsNone(result["statistics"][STAT_IDS[3]]["interval"])
        self.assertIsNotNone(result["statistics"][STAT_IDS[0]]["interval"])
        self.assertFalse(result["experiment_authorized"])

    def test_declared_assumptions_and_parameter_domains_are_required(self):
        values = np.zeros((2, 17))
        with self.assertRaises(ValueError):
            weighted_hoeffding(values, values, ["A", "B"], assumptions={})
        values[0, -1] = -.1
        with self.assertRaises(ValueError):
            self.interval(values, values, ["A", "B"])
        values[0, -1] = np.nan
        with self.assertRaises(ValueError):
            self.interval(values, values, ["A", "B"])

    def test_sixty_perfect_clusters_cannot_meet_utility_floor_with_this_bound(self):
        values = np.ones((60, 17))
        result = self.interval(values, values, [str(i) for i in range(60)])
        self.assertLess(result["statistics"][STAT_IDS[-1]]["interval"][0], .8)

    def test_hoeffding_union_bound_exactly_allocates_alpha(self):
        values = np.zeros((30, 17))
        result = self.interval(values, values, [str(i) for i in range(30)])
        for name in STAT_IDS:
            s = result["statistics"][name]
            width = s["domain"][1] - s["domain"][0]
            bound = 2 * math.exp(-2 * s["radius"] ** 2 / (width ** 2 / s["effective_clusters"]))
            self.assertAlmostEqual(bound * 17, .05)

    def test_binomial_zero_and_all_success_closed_forms(self):
        tail = .05 / 34
        for n in (10, 30, 60):
            self.assertAlmostEqual(clopper_pearson(0, n)[1], 1 - tail ** (1 / n), places=10)
            self.assertAlmostEqual(clopper_pearson(n, n)[0], tail ** (1 / n), places=10)
            self.assertEqual(clopper_pearson(0, n)[0], 0)
            self.assertEqual(clopper_pearson(n, n)[1], 1)

    def test_inverted_binomial_tails_match_direct_probability_sums(self):
        n, k = 30, 7
        lo, hi = clopper_pearson(k, n)
        direct_sf = math.fsum(math.comb(n, i) * lo ** i * (1 - lo) ** (n - i) for i in range(k, n + 1))
        direct_cdf = math.fsum(math.comb(n, i) * hi ** i * (1 - hi) ** (n - i) for i in range(k + 1))
        self.assertAlmostEqual(direct_sf, .05 / 34, places=9)
        self.assertAlmostEqual(direct_cdf, .05 / 34, places=9)

    def test_binomial_enumeration_covers_at_nominal_on_fixed_grid(self):
        for n in (10, 30):
            for p in (0, .001, .01, .1, .5, .99, 1):
                with self.subTest(n=n, p=p):
                    self.assertGreaterEqual(exact_binomial_coverage(n, p), 1 - .05 / 17 - 1e-12)

    def test_invalid_binomial_counts_fail(self):
        for k, n in ((-1, 30), (31, 30), (0, 0), (True, 30)):
            with self.assertRaises(ValueError):
                clopper_pearson(k, n)
        with self.assertRaises(ValueError):
            binomial_tail(30, 0, float("nan"), upper=False)


if __name__ == "__main__":
    unittest.main()
