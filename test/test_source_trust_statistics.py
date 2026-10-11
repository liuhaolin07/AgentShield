import copy
import json
import math
from pathlib import Path
import random
import unittest

from evaluation.source_trust_statistics import (auc, bootstrap_means, hoeffding_interval, quantile,
                                               run, toy_matrix, validate_config, wilson, h5_binding, GRID)


class StatisticsTests(unittest.TestCase):
    def config(self):
        config = json.loads(Path("docs/research/source-trust-methods/r3/statistical-calibration-config.json").read_text())
        config.update(trials=20, bootstrap_draws=100, families=[4], graphs=[5])
        return config

    def test_auc_linear_and_constant(self):
        self.assertAlmostEqual(auc([0, .05, .10, .25, .50, 1.]), .5)
        self.assertAlmostEqual(auc([.3]*6), .3)

    def test_quantile_interpolation(self):
        self.assertEqual(quantile([0, 10], .25), 2.5)
        with self.assertRaises(ValueError): quantile([], .5)

    def test_graph_resampling_keeps_global_columns(self):
        matrix = [[-1, 1]] * 10
        family = bootstrap_means(matrix, unit="family", draws=100, rng=random.Random(9))
        graph = bootstrap_means(matrix, unit="graph", draws=100, rng=random.Random(9))
        self.assertEqual(set(family), {0.})
        self.assertGreater(len(set(graph)), 1)

    def test_template_resampling_keeps_pairs(self):
        values = bootstrap_means([[-1]*5, [1]*5, [-2]*5, [2]*5], unit="family", draws=100,
                                 rng=random.Random(2), template_block=True)
        self.assertEqual(set(values), {0.})

    def test_quota_known_expectation_and_bounds(self):
        for scenario in ("uniform_quota", "template_block_quota"):
            matrix, mean, bounds = toy_matrix(scenario, 30, 5, random.Random(5))
            self.assertAlmostEqual(mean, -.25)
            self.assertEqual(bounds, (-.5, 0.))
            self.assertTrue(all(-1 <= v <= 0 for row in matrix for v in row))
            self.assertTrue(all(set(matrix[i]) == {0.} for i in range(1, 30, 2)))

    def test_rare_fault_truth_is_outside_equivalence(self):
        _, mean, bounds = toy_matrix("rare_global_fault", 4, 5, random.Random(3))
        self.assertEqual(mean, .025)
        self.assertEqual(bounds, (0., .5))

    def test_balanced_fault_mean_zero(self):
        self.assertEqual(toy_matrix("balanced_global_fault", 4, 5, random.Random(1))[1], 0.)

    def test_hoeffding_multiplicity_widens_not_degenerates(self):
        a = hoeffding_interval(0., 30, (-1., 1.), .05)
        b = hoeffding_interval(0., 30, (-1., 1.), .05, 17)
        self.assertLess(b[0], a[0]); self.assertGreater(b[1], a[1])
        self.assertLess(hoeffding_interval(0., 5, (0., .5), .05)[0],
                        hoeffding_interval(0., 5, (0., .5), .05)[1])

    def test_hoeffding_invalid_known_range_and_counts(self):
        for args in ((2., 5, (0., 1.), .05), (0., 0, (0., 1.), .05), (0., 5, (0., 0.), .05)):
            with self.assertRaises(ValueError): hoeffding_interval(*args)

    def test_wilson_reports_uncertainty_even_all_trials_pass(self):
        low, high = wilson(20, 20)
        self.assertLess(low, 1); self.assertAlmostEqual(high, 1)
        with self.assertRaises(ValueError): wilson(1, 0)

    def test_limits_and_frozen_thresholds(self):
        for update in ({"trials": 100000}, {"graphs": [True]}, {"families": [3]},
                       {"kind": "DEFENSE"}, {"threshold_status": "JUSTIFIED"}, {"seed": -1}):
            c = self.config(); c.update(update)
            with self.assertRaises(ValueError): validate_config(c)
        c = self.config(); c['thresholds']['equivalence'] = .1
        with self.assertRaises(ValueError): validate_config(c)

    def test_reproducibility_exclusions_and_no_execution(self):
        report, rows = run(self.config())
        other, again = run(self.config())
        self.assertEqual(rows, again)
        self.assertEqual(report['config_sha256'], other['config_sha256'])
        self.assertEqual(len(rows), 240)
        self.assertEqual(report['actual_defense_executions'], 0)
        self.assertEqual(report['full_joint_H5_power']['status'], 'UNRUN')
        for cell in report['summary']:
            self.assertEqual(cell['coverage_denominator'], 20)
            self.assertEqual(cell['component_gate_denominator'] + cell['component_excluded'], 20)
            if cell['method'] != 'graph_hoeffding':
                self.assertEqual(cell['component_status'], 'UNRUN_insufficient_adjusted_tail_resolution')

    def test_grid_bound_to_external_R1_H5_TCR_contract(self):
        protocol=json.loads(Path("docs/research/source-trust/protocol-draft.json").read_text())
        self.assertEqual(list(GRID),protocol['design']['rates'])
        binding=h5_binding()
        self.assertEqual(binding['integration_domain'],[0,1])
        self.assertEqual(binding['normalization_width'],1)
        c=self.config();c['estimand']['grid']=[0,.01,.05,.1,.25,.5]
        with self.assertRaisesRegex(ValueError,'estimand_binding'):validate_config(c)

    def test_auc_scale_against_independent_linear_integral(self):
        # Integral of -.5*p on [0,1] is -.25, from calculus rather than generator assumptions.
        self.assertAlmostEqual(auc([-.5*p for p in GRID]),-.25)
        self.assertEqual(toy_matrix('uniform_quota',30,5,random.Random(5))[1],-.25)
