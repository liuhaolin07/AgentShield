"""Engineering-only checks: tiny fixtures, RNG seeds 4/99, no simulation run."""
import importlib
import importlib.util
import unittest
from unittest.mock import patch
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parents[1]
sys.path[:] = [p for p in sys.path if p and "hermes" not in p.casefold()]
sys.path[:0] = [str(HERE), str(HERE.parent)]

import numpy as np
from paired_inference import (ALPHA, BOOTSTRAP_REPLICATES, BOOTSTRAP_SEED, SEEDS, STAT_IDS,
                              bootstrap_bounds, key, recipes, reduce_families, required_keys)
from validate_statistics import synthetic_components


def scenario(kind="binary_endpoint_process", **options):
    return {"id": "engineering-unit", "clusters": 4, "sizes": "cycle_1_2_3",
            "generator": kind, **options}


class ModelTests(unittest.TestCase):
    def models(self):
        self.assertIsNotNone(importlib.util.find_spec("d5_models"),
                             "D5 generator module is not implemented")
        return importlib.import_module("d5_models")

    def test_legacy_generators_match_original_including_rng_consumption(self):
        models = self.models()
        for kind in ("bounded_correlated_components", "cluster_bernoulli", "constant_components"):
            with self.subTest(kind=kind):
                config = scenario(kind, event_probability=.2)
                original_rng, actual_rng = np.random.default_rng(4), np.random.default_rng(4)
                values, truth, clusters, icc = synthetic_components(config, original_rng)
                actual = models.generate_dataset(config, actual_rng)
                np.testing.assert_array_equal(actual["lower"], values)
                np.testing.assert_array_equal(actual["upper"], values)
                np.testing.assert_array_equal(actual["truth"], truth)
                self.assertEqual(actual["clusters"], clusters)
                self.assertEqual(actual_rng.bit_generator.state, original_rng.bit_generator.state)
                self.assertEqual(actual["metadata"]["family_count"], len(clusters))
                self.assertEqual(actual["metadata"]["cluster_count"], 4)
                self.assertEqual(actual["metadata"]["endpoint_count"], 0)
                self.assertEqual(actual["metadata"]["missing_endpoint_count"], 0)
                self.assertIn("analytic_truth_scope", actual["metadata"])
                self.assertNotIn("families", actual)

    def test_zero_components_are_zero_not_legacy_constant_centers(self):
        data = self.models().generate_dataset(scenario("zero_components"), np.random.default_rng(99))
        np.testing.assert_array_equal(data["lower"], np.zeros((7, 17)))
        np.testing.assert_array_equal(data["upper"], data["lower"])
        np.testing.assert_array_equal(data["truth"], np.zeros(17))
        self.assertEqual(data["clusters"], ["c000", "c001", "c001", "c002", "c002", "c002", "c003"])
        self.assertEqual(data["metadata"]["cluster_count"], 4)

    def test_binary_grid_reduction_exclusivity_and_analytic_marginals(self):
        models = self.models()
        try:
            data = models.generate_dataset(scenario(), np.random.default_rng(4), include_families=True)
        except ValueError as exc:
            self.fail(f"binary endpoint process is not implemented: {exc}")
        self.assertEqual(len(required_keys()), 120)
        self.assertEqual(data["lower"].shape, (7, 17))
        reduced = reduce_families(data["families"])
        np.testing.assert_array_equal(data["lower"], reduced["lower"])
        np.testing.assert_array_equal(data["upper"], reduced["upper"])
        self.assertEqual(data["clusters"], reduced["clusters"])
        for family in data["families"]:
            self.assertEqual(list(family["values"]), sorted(required_keys()))
            for name, endpoint in family["values"].items():
                self.assertTrue(endpoint["observed"])
                self.assertIn(endpoint["value"], (0, 1))
                if name.endswith("|FPR"):
                    tcr = family["values"][name[:-3] + "TCR"]["value"]
                    self.assertLessEqual(tcr + endpoint["value"], 1)
            self.assertEqual(family["H3_eligible_by_seed"], {str(s): True for s in SEEDS})
        marginal = {}
        for name in sorted(required_keys()):
            panel, rate, _, policy, metric = name.split("|")
            p = float(rate)
            if metric == "ASR":
                value = (.04 + (.4*p if panel == "SP" else 0) + (.04 if panel == "targeted" else 0)
                         if policy == "precision" else .01 + (.1*p if panel == "SP" else 0))
            else:
                tcr = (.94 - (.2*p if panel == "PS" else .12*p if panel == "SP" else 0)
                       if policy == "precision" else .90 - (.18*p if panel == "SP" else 0))
                value = tcr if metric == "TCR" else .5 * (1-tcr)
            marginal[name] = value
        expected = [sum(c*marginal[name] for name, c in terms.items()) for terms in recipes().values()]
        np.testing.assert_allclose(data["truth"], expected, rtol=0, atol=1e-15)
        self.assertEqual(data["metadata"]["endpoint_count"], 7*120)
        self.assertEqual(data["metadata"]["missing_endpoint_count"], 0)

    def test_shared_uniform_mixture_and_cluster_shock_match_fixed_rng_oracle(self):
        # Fixed small fixtures, not Monte Carlo calibration. The selector's
        # family threshold is wc+wf, never (1-wc)*wf.
        for wc, wf in ((1., 0.), (0., 1.), (.35, .45)):
            with self.subTest(wc=wc, wf=wf):
                config = scenario(shared_cluster_uniform_weight=wc,
                                  shared_family_uniform_weight=wf, error_shock_scale=.04)
                data = self.models().generate_dataset(config, np.random.default_rng(99), True)
                oracle = np.random.default_rng(99)
                q = oracle.binomial(1, .2, 4)
                cluster_u = oracle.random((4, 2))
                family_u = oracle.random((7, 2))
                groups = sorted({(name.rsplit("|", 1)[0], "attack" if name.endswith("|ASR") else "benign")
                                 for name in required_keys()})
                selectors = oracle.random((7, len(groups)))
                independent_u = oracle.random((7, len(groups)))
                for i, family in enumerate(data["families"]):
                    c = int(family["template_cluster_id"][1:])
                    for name, endpoint in family["values"].items():
                        panel, rate, _, policy, metric = name.split("|")
                        p = float(rate)
                        if metric == "ASR":
                            prob = (.04 + (.4*p if panel == "SP" else 0) + (.04 if panel == "targeted" else 0)
                                    if policy == "precision" else .01 + (.1*p if panel == "SP" else 0))
                            prob += .04*p*(q[c]-.2) if panel != "E0" else 0
                        else:
                            tcr = (.94 - (.2*p if panel == "PS" else .12*p if panel == "SP" else 0)
                                   if policy == "precision" else .90 - (.18*p if panel == "SP" else 0))
                            tcr -= .04*p*(q[c]-.2) if panel != "E0" else 0
                            prob = tcr if metric == "TCR" else .5*(1-tcr)
                        kind = "attack" if metric == "ASR" else "benign"
                        j = groups.index((name.rsplit("|", 1)[0], kind))
                        t = int(kind == "benign")
                        u = (cluster_u[c, t] if selectors[i, j] < wc else
                             family_u[i, t] if selectors[i, j] < wc+wf else independent_u[i, j])
                        expected = int(u >= 1-prob) if metric == "FPR" else int(u < prob)
                        self.assertEqual(endpoint["value"], expected, (wc, wf, i, name))
                no_shock = self.models().generate_dataset(scenario(), np.random.default_rng(4))
                np.testing.assert_array_equal(data["truth"], no_shock["truth"])

    def test_outcome_dependent_missingness_keeps_unknown_endpoints_and_families(self):
        models = self.models()
        complete = models.generate_dataset(scenario(), np.random.default_rng(4), True)
        partial = models.generate_dataset(scenario(missingness="outcome_dependent"), np.random.default_rng(4), True)
        self.assertGreater(partial["metadata"]["missing_endpoint_count"], 0)
        self.assertEqual(len(partial["families"]), 7)
        # One observation per task: paired benign TCR/FPR share its mask.
        oracle = np.random.default_rng(4)
        oracle.binomial(1, .2, 4)
        oracle.random((4, 2)); oracle.random((7, 2))
        groups = sorted({(name.rsplit("|", 1)[0], "attack" if name.endswith("|ASR") else "benign")
                         for name in required_keys()})
        oracle.random((7, len(groups))); oracle.random((7, len(groups)))
        missing_u = oracle.random((7, len(groups)))
        missing_count, separate_benign_missing = 0, False
        for i, (full, part) in enumerate(zip(complete["families"], partial["families"])):
            for name in sorted(required_keys()):
                value = full["values"][name]["value"]
                condition, metric = name.rsplit("|", 1)
                kind = "attack" if metric == "ASR" else "benign"
                success = full["values"][condition + ("|ASR" if kind == "attack" else "|TCR")]["value"]
                adverse = success == (1 if kind == "attack" else 0)
                missing = bool(missing_u[i, groups.index((condition, kind))] < (.25 if adverse else .02))
                self.assertEqual(part["values"][name], {"value": None if missing else value, "observed": not missing})
                missing_count += missing
                if metric == "FPR":
                    separate_benign_missing |= (part["values"][name]["observed"] !=
                                                part["values"][name[:-3]+"TCR"]["observed"])
        self.assertEqual(missing_count, partial["metadata"]["missing_endpoint_count"])
        self.assertFalse(separate_benign_missing)
        reduced = reduce_families(partial["families"])
        np.testing.assert_array_equal(partial["lower"], reduced["lower"])
        np.testing.assert_array_equal(partial["upper"], reduced["upper"])
        self.assertTrue(np.all(partial["lower"] <= complete["lower"]))
        self.assertTrue(np.all(partial["upper"] >= complete["upper"]))
        self.assertTrue(np.any(partial["upper"] > partial["lower"]))
        self.assertTrue(np.isfinite(partial["lower"]).all())
        np.testing.assert_array_equal(partial["truth"], complete["truth"])
        lean = models.generate_dataset(scenario(missingness="outcome_dependent"), np.random.default_rng(4))
        self.assertNotIn("families", lean)
        np.testing.assert_array_equal(lean["lower"], partial["lower"])

    def test_h3_cohort_is_first_k_clusters_fixed_before_outcomes_and_all_seeds(self):
        models = self.models()
        for k in (0, 2, 4):
            with self.subTest(k=k):
                previous_masks = None
                for seed in (4, 99):
                    data = models.generate_dataset(scenario(h3_eligible_clusters=k, missingness="outcome_dependent"),
                                                   np.random.default_rng(seed), True)
                    masks = [f["H3_eligible_by_seed"] for f in data["families"]]
                    if previous_masks is not None:
                        self.assertEqual(masks, previous_masks)
                    previous_masks = masks
                    for i, family in enumerate(data["families"]):
                        eligible = int(family["template_cluster_id"][1:]) < k
                        self.assertEqual(masks[i], {str(s): eligible for s in SEEDS})
                        self.assertEqual(bool(np.isfinite(data["lower"][i, 3])), eligible)
                    other = [j for j in range(17) if j != 3]
                    self.assertTrue(np.isfinite(data["lower"][:, other]).all())
                    if k:
                        # targeted=.08 and SP(.1)=.04+.4*.1=.08.
                        self.assertAlmostEqual(data["truth"][3], 0., places=14)
                    else:
                        self.assertTrue(np.isnan(data["truth"][3]))
                    reduced = reduce_families(data["families"])
                    np.testing.assert_array_equal(data["lower"], reduced["lower"])
                    np.testing.assert_array_equal(data["upper"], reduced["upper"])
                    self.assertIn("fixed preexecution H3 cohort", data["metadata"]["analytic_truth_scope"])

    def test_invalid_scenarios_and_out_of_support_probabilities_are_rejected(self):
        bad = [
            {"generator": "unknown"}, {"clusters": 0}, {"clusters": True}, {"clusters": 2.5},
            {"sizes": "random"}, {"id": ""}, {"missingness": "complete_case"},
            {"shared_cluster_uniform_weight": -.01}, {"shared_family_uniform_weight": 1.01},
            {"shared_cluster_uniform_weight": .7, "shared_family_uniform_weight": .4},
            {"shared_cluster_uniform_weight": float("nan")}, {"shared_family_uniform_weight": float("inf")},
            {"shared_family_uniform_weight": True}, {"error_shock_scale": -1},
            {"error_shock_scale": float("nan")}, {"error_shock_scale": 2.},
            {"h3_eligible_clusters": -1}, {"h3_eligible_clusters": 5},
            {"h3_eligible_clusters": 2.5}, {"h3_eligible_clusters": True},
        ]
        for options in bad:
            with self.subTest(options=options):
                with self.assertRaises(ValueError):
                    self.models().generate_dataset(scenario(**options), np.random.default_rng(4))
        for probability in (-.1, 1.1, float("nan")):
            with self.subTest(probability=probability):
                with self.assertRaises(ValueError):
                    self.models().generate_dataset(scenario("cluster_bernoulli", event_probability=probability),
                                                   np.random.default_rng(99))
        # Mathematical components need not admit a binary endpoint realization.
        with self.assertRaisesRegex(ValueError, "families.*binary"):
            self.models().generate_dataset(scenario("constant_components"), np.random.default_rng(4), True)

    def test_fast_binary_path_matches_family_oracle_without_constructing_families(self):
        models = self.models()
        cases = [scenario(), scenario(missingness="outcome_dependent", h3_eligible_clusters=2,
                                      shared_cluster_uniform_weight=.35, shared_family_uniform_weight=.45,
                                      error_shock_scale=.04),
                 scenario(sizes="two", missingness="outcome_dependent", h3_eligible_clusters=0,
                          shared_cluster_uniform_weight=1.)]
        for seed in (4, 99):
            for config in cases:
                with self.subTest(seed=seed, config=config):
                    reference_rng, fast_rng = np.random.default_rng(seed), np.random.default_rng(seed)
                    reference = models.generate_dataset(config, reference_rng, True)
                    # Spy wraps REAL functions, never replaces behavior. This is
                    # an architectural/performance contract, not a timing gate.
                    with patch.object(models, "reduce_families", wraps=reduce_families) as reducer:
                        fast = models.generate_dataset(config, fast_rng)
                    self.assertEqual(reducer.call_count, 0, "lean path must not construct/reduce endpoint dicts")
                    for field in ("lower", "upper", "truth"):
                        np.testing.assert_array_equal(fast[field], reference[field])
                    self.assertEqual(fast["clusters"], reference["clusters"])
                    self.assertEqual(fast["metadata"], reference["metadata"])
                    self.assertEqual(fast_rng.bit_generator.state, reference_rng.bit_generator.state)


class BatchTests(unittest.TestCase):
    models = ModelTests.models

    def assert_batch_matches_legacy(self, datasets):
        models = self.models()
        self.assertTrue(hasattr(models, "evaluate_batch"), "vectorized D5 evaluator is not implemented")
        result = models.evaluate_batch(datasets)
        d = len(datasets)
        self.assertEqual(result["intervals"].shape, (d, 17, 2))
        self.assertEqual(result["identification"].shape, (d, 17, 2))
        self.assertEqual(result["degenerate"].shape, (d, 17))
        self.assertEqual(result["undefined"].shape, (d, 17))
        eligible = np.broadcast_to(result["eligible_clusters"], (d, 17))
        for i, data in enumerate(datasets):
            expected = bootstrap_bounds(data["lower"], data["upper"], data["clusters"])
            self.assertEqual(expected["bootstrap_replicates"], 10000)
            self.assertEqual(expected["bootstrap_seed"], 1729)
            self.assertEqual(expected["tail_probability"], ALPHA/(2*17))
            for j, name in enumerate(STAT_IDS):
                with self.subTest(dataset=i, statistic=name):
                    stat = expected["statistics"][name]
                    interval = stat["worst_case_percentile_interval"]
                    identification = stat["identification_bounds"]
                    np.testing.assert_allclose(result["intervals"][i, j],
                                               [np.nan, np.nan] if interval is None else interval,
                                               rtol=0, atol=1e-10, equal_nan=True)
                    np.testing.assert_allclose(result["identification"][i, j],
                                               [np.nan, np.nan] if identification is None else identification,
                                               rtol=0, atol=1e-10, equal_nan=True)
                    self.assertEqual(int(eligible[i, j]), stat["clusters"])
                    self.assertEqual(int(result["undefined"][i, j]), stat["undefined_draws"])
                    self.assertEqual(bool(result["degenerate"][i, j]), "degenerate_resampling" in stat["flags"])
        return result

    def test_three_fixed_arrays_match_legacy_all_stats_with_unequal_clusters_and_bounds(self):
        a = np.arange(68, dtype=float).reshape(4, 17)/100 - .4
        b = np.arange(85, dtype=float).reshape(5, 17)/100 - .6
        c = np.tile(np.linspace(-.6, .6, 17), (3, 1))
        datasets = [
            {"lower": a, "upper": a.copy(), "clusters": ["z", "a", "a", "b"]},
            {"lower": b, "upper": b+.25, "clusters": ["k", "b", "k", "b", "b"]},
            {"lower": c, "upper": c+.01, "clusters": ["x", "x", "y"]},
        ]
        result = self.assert_batch_matches_legacy(datasets)
        self.assertTrue(result["degenerate"][2].all())
        self.assertFalse(result["degenerate"][:2].any())
        self.assertFalse(result["undefined"].any())
        self.assertTrue(np.isfinite(result["intervals"]).all())

    def test_h3_missing_clusters_keeps_every_undefined_draw_and_fixed_cohort(self):
        lo = np.arange(102, dtype=float).reshape(6, 17)/200-.3
        hi = lo+.15
        lo[[3, 4, 5], 3] = hi[[3, 4, 5], 3] = np.nan
        absent_lo, absent_hi = lo.copy(), hi.copy()
        absent_lo[:, 3] = absent_hi[:, 3] = np.nan
        result = self.assert_batch_matches_legacy([
            {"lower": lo, "upper": hi, "clusters": ["a", "b", "b", "c", "d", "d"]},
            {"lower": absent_lo, "upper": absent_hi, "clusters": ["a", "b", "b", "c", "d", "d"]},
            {"lower": lo[:2, :], "upper": hi[:2, :], "clusters": ["one", "one"]},
        ])
        self.assertEqual(result["eligible_clusters"][0, 3], 2)
        self.assertGreater(result["undefined"][0, 3], 0)
        self.assertTrue(np.isnan(result["intervals"][0, 3]).all())
        self.assertTrue(np.isfinite(result["identification"][0, 3]).all())
        self.assertFalse(result["degenerate"][0, 3])
        self.assertEqual(result["undefined"][1, 3], 10000)
        self.assertTrue(np.isnan(result["identification"][1, 3]).all())
        self.assertTrue(np.isnan(result["intervals"][2]).all())
        self.assertTrue(result["degenerate"][2].all())

    def test_batch_rejects_the_same_invalid_components_as_legacy(self):
        base = {"lower": np.zeros((2, 17)), "upper": np.ones((2, 17))*.1, "clusters": ["a", "b"]}
        invalid = []
        for side, value, column in (("lower", np.inf, 0), ("upper", np.nan, 3),
                                    ("lower", np.nan, 0), ("lower", .5, 2),
                                    ("lower", -1.1, 1), ("upper", 1.1, 1)):
            data = {k: v.copy() for k, v in base.items()}
            data[side][0, column] = value
            invalid.append(data)
        paired_nan = {k: v.copy() for k, v in base.items()}
        paired_nan["lower"][0, 0] = paired_nan["upper"][0, 0] = np.nan
        invalid.extend([paired_nan,
                        {**base, "clusters": ["a", ""]}, {**base, "clusters": ["a", None]},
                        {**base, "lower": np.zeros((2, 16))},
                        {"lower": np.zeros((0, 17)), "upper": np.zeros((0, 17)), "clusters": []}])
        for i, data in enumerate(invalid):
            with self.subTest(fixture=i):
                with self.assertRaises(ValueError):
                    bootstrap_bounds(data["lower"], data["upper"], data["clusters"])
                with self.assertRaises(ValueError):
                    self.models().evaluate_batch([data])


if __name__ == "__main__":
    unittest.main()
