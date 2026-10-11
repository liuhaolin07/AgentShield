"""Independent feasibility gate cannot convert a necessary bound into power."""
import json
from pathlib import Path
import unittest

from ci.validate_source_trust_feasibility import metadata_check, validate, validate_artifacts


class FeasibilityGateTests(unittest.TestCase):
    def packet(self):
        return json.loads(Path('docs/research/source-trust-methods/r4/analytic/report.json').read_text())

    def test_real_retained_exports_and_all_frozen_R3_paths(self):
        result = validate_artifacts()
        self.assertEqual(result['unchanged_R3_files'], 409)
        self.assertEqual(result['current_GHO1_budgets_impossible'], [5, 30])
        self.assertFalse(result['pilot_eligible'])

    def test_no_threshold_or_multiplicity_relaxation(self):
        for field, value in (('minimum_TCR', .67), ('multiplicity', 1), ('NI_margin', .10)):
            packet = self.packet();packet['contract'][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'R1_thresholds'):
                validate(packet)

    def test_82_cannot_be_relabelled_as_confirmed_joint_power(self):
        packet = self.packet();packet['best_case_budgets'][3]['joint_status'] = 'POWER_SUFFICIENT'
        with self.assertRaisesRegex(ValueError, 'not_joint_power'): validate(packet)
        packet = self.packet();packet['approved_new_graph_budget'] = True
        with self.assertRaisesRegex(ValueError, 'approval_claim'): validate(packet)

    def test_graph_trial_task_counts_cannot_be_substituted(self):
        packet = self.packet();packet['best_case_budgets'][1]['half_width'] = .19
        with self.assertRaisesRegex(ValueError, 'best_case_bounds'): validate(packet)
        packet = self.packet();packet['new_study_simulation_trials'] = 2000
        with self.assertRaisesRegex(ValueError, 'execution_claim'): validate(packet)

    def test_center_diagnostics_do_not_grant_minimum_real_budget(self):
        packet = self.packet();packet['retained_toy_center_diagnostics'][0]['kind'] = 'REQUIRED_REAL_GRAPH_COUNT'
        with self.assertRaisesRegex(ValueError, 'centering_not_power'): validate(packet)
        packet = self.packet();packet['retained_toy_center_diagnostics'][0]['graphs_for_expected_center_NI_bound_strict'] = 82
        with self.assertRaisesRegex(ValueError, 'center_crossing'): validate(packet)

    def test_missing_and_boundary_rows_cannot_be_removed_or_relaxed(self):
        packet = self.packet();packet['missingness_bounds'][2]['minimum_graphs_for_best_case_absolute_TCR'] = 82
        with self.assertRaisesRegex(ValueError, 'missingness_crossing'): validate(packet)
        packet = self.packet();packet['best_case_budgets'].pop(2)
        with self.assertRaisesRegex(ValueError, 'complete_budget_rows'): validate(packet)

    def test_pending_candidate_or_humans_cannot_be_promoted(self):
        for field, value in (('new_estimator_selected', True), ('real_human_truth_records', 2), ('alternative_joint_power', 'VERIFIED')):
            packet = json.loads(Path('docs/research/source-trust-methods/r4/readiness.json').read_text())
            packet[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): metadata_check(readiness=packet)

    def test_zero_sample_variance_does_not_delete_EB_correction(self):
        packet = json.loads(Path('docs/research/source-trust-methods/r4/literature-evidence.json').read_text())
        packet['zero_variance_analytic_diagnostic']['n30_radius'] = 0.
        with self.assertRaisesRegex(ValueError, 'small_sample_term'): metadata_check(literature=packet)


if __name__ == '__main__':
    unittest.main()
