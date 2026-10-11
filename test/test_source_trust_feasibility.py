"""Structural algebra tests, never power or defense observations."""
import copy
import unittest

from evaluation.source_trust_feasibility import Contract, best_tcr_lower, build_report, minimum_graphs, radius, read_inputs
from evaluation.source_trust_joint import assess
import json
from pathlib import Path


class FeasibilityTests(unittest.TestCase):
    def setUp(self):
        self.contract, _ = read_inputs()

    def test_independent_graph_radius_reproduces_review_values(self):
        self.assertAlmostEqual(radius(5, 1., self.contract), .8075947497458209)
        self.assertAlmostEqual(radius(30, 1., self.contract), .3296991759713227)
        self.assertLess(best_tcr_lower(30, 0., self.contract), .8)

    def test_exact_integer_boundary_81_fails_82_only_component_possible(self):
        self.assertEqual(minimum_graphs(.2, 1., self.contract), 82)
        self.assertLess(best_tcr_lower(81, 0., self.contract), .8)
        self.assertGreaterEqual(best_tcr_lower(82, 0., self.contract), .8)

    def test_missingness_can_only_reduce_maximum_lower_bound(self):
        self.assertEqual(minimum_graphs(.17, 1., self.contract), 113)
        self.assertEqual(minimum_graphs(.15, 1., self.contract), 145)
        for graphs in (5, 30, 82):
            self.assertLessEqual(best_tcr_lower(graphs, .05, self.contract), best_tcr_lower(graphs, 0., self.contract))
        self.assertIsNone(minimum_graphs(0., 1., self.contract))
        self.assertIsNone(minimum_graphs(-.1, 1., self.contract))

    def test_illustrative_toy_center_is_not_joint_power_or_82_budget(self):
        report = build_report()
        self.assertEqual(report['retained_toy_center_diagnostics'][-1]['graphs_for_expected_center_NI_bound_strict'], 2740)
        self.assertEqual(report['new_study_simulation_trials'], 0)
        self.assertFalse(report['approved_new_graph_budget'])
        self.assertEqual(report['power_and_error_control_of_alternative_estimators'], 'UNRUN_NOT_SELECTED')

    def test_existing_estimator_confirms_structural_bound_without_real_sampling(self):
        config = json.loads(Path('docs/research/source-trust-methods/r3/joint-calibration-config.json').read_text())
        n = config['families']
        # Deterministic algebraic witness: maximally favorable bounded vectors.
        # Repeated vectors are not claimed to be independent observed graphs.
        record = {k: [0] * 5 for k in ('attack_c', 'attack_p', 'attack_missing_c', 'attack_missing_p',
                                     'completed_c', 'completed_p', 'normal_missing_c', 'normal_missing_p')}
        record['attack_p'] = [n] * 5; record['completed_c'] = [n] * 5
        e0 = {k: [v[0]] for k, v in record.items()};e0['attack_p'] = [0]
        for graphs in (5, 30, 81, 82):
            result = assess(config, e0, [copy.deepcopy(record) for _ in range(graphs)])
            self.assertEqual(result['joint_confirmation'], graphs == 82)
            self.assertEqual(result['all_six_absolute_TCR'], graphs == 82)

    def test_E0_is_exact_identification_bound_not_graph_radius(self):
        config = json.loads(Path('docs/research/source-trust-methods/r3/joint-calibration-config.json').read_text())
        n = config['families']
        record = {k: [0] * 5 for k in ('attack_c', 'attack_p', 'attack_missing_c', 'attack_missing_p',
                                     'completed_c', 'completed_p', 'normal_missing_c', 'normal_missing_p')}
        record['completed_c'] = [n] * 5
        e0 = {k: [v[0]] for k, v in record.items()}
        e0['completed_c'] = [n - 13];e0['normal_missing_c'] = [13]
        result = assess(config, e0, [copy.deepcopy(record) for _ in range(82)])
        self.assertEqual(result['intervals'][7], [(n - 13) / n, 1.])
        self.assertFalse(result['all_six_absolute_TCR'])
        self.assertFalse(result['coverage_gate'])

    def test_bad_numeric_and_resource_inputs_rejected(self):
        for graphs in (True, 0, 1.5, 10**12 + 1):
            with self.subTest(graphs=graphs), self.assertRaises(ValueError): radius(graphs, 1., self.contract)
        for width in (True, 0., -1., float('nan'), float('inf'), 3.):
            with self.subTest(width=width), self.assertRaises(ValueError): radius(30, width, self.contract)
        for missing in (True, -.1, 1.1, float('nan')):
            with self.subTest(missing=missing), self.assertRaises(ValueError): best_tcr_lower(30, missing, self.contract)
        with self.assertRaisesRegex(ValueError, 'numeric_domain'): minimum_graphs(1e-8, 1., self.contract)

    def test_inclusive_absolute_and_strict_NI_crossings(self):
        gap = radius(30, 1., self.contract)
        self.assertEqual(minimum_graphs(gap, 1., self.contract), 30)
        self.assertEqual(minimum_graphs(gap, 1., self.contract, strict=True), 31)

    def test_threshold_invalid_or_grid_inconsistent_rejected(self):
        with self.assertRaises(ValueError): Contract(.05, True, .8, .05, .05, self.contract.grid).validate()
        with self.assertRaises(ValueError): Contract(.05, 17, .8, .05, .05, (0., .01, .05, .1, .25, .5)).validate()


if __name__ == '__main__':
    unittest.main()
