"""Validate the simulation accounting independently of favorable results."""

import contextlib
import io
import json
import unittest

import numpy as np

from validate_statistics import DIRECTORY, run_validation, synthetic_components, wilson


class StatisticsValidationTests(unittest.TestCase):
    def test_wilson_limits_and_undefined_denominator(self):
        self.assertIsNone(wilson(0, 0))
        self.assertAlmostEqual(wilson(0, 100)[0], 0)
        self.assertGreater(wilson(0, 100)[1], .03)
        self.assertLess(wilson(100, 100)[0], .97)
        self.assertAlmostEqual(wilson(100, 100)[1], 1)

    def test_known_component_truth_and_unequal_clusters(self):
        scenario = {"clusters": 30, "sizes": "cycle_1_2_3", "generator": "bounded_correlated_components"}
        values, truth, clusters, icc = synthetic_components(scenario, np.random.default_rng(4))
        self.assertEqual(values.shape, (60, 17))
        self.assertEqual(len(set(clusters)), 30)
        self.assertTrue(np.all(np.abs(values - truth) <= .2))
        self.assertAlmostEqual(icc, .25 / .38)

    def test_rare_cluster_events_share_all_family_rows(self):
        scenario = {"clusters": 30, "sizes": "two", "generator": "cluster_bernoulli", "event_probability": .01}
        values, truth, clusters, icc = synthetic_components(scenario, np.random.default_rng(1))
        np.testing.assert_array_equal(values[::2], values[1::2])
        self.assertEqual(truth[0], .01)
        self.assertEqual(truth[-1], .99)
        self.assertEqual(icc, 1)

    def test_unavailable_intervals_and_degenerate_coverage_are_not_success(self):
        config = json.loads((DIRECTORY / "config.json").read_text())
        config["datasets_per_scenario"] = 2
        config["scenarios"] = config["scenarios"][-2:]
        with contextlib.redirect_stdout(io.StringIO()):
            result = run_validation(config)
        single, constant = result["scenarios"]
        self.assertIsNone(single["joint_coverage_among_available"])
        self.assertEqual(single["interval_available_and_cover_fraction_all_datasets"], 0)
        self.assertEqual(constant["joint_coverage_among_available"], 1)
        self.assertEqual(constant["degenerate_datasets"], 2)
        self.assertEqual(constant["diagnostic_pass_datasets"], 0)
        self.assertFalse(result["coverage_target_certified"])
        self.assertFalse(result["confirmatory_success"])


if __name__ == "__main__":
    unittest.main()
