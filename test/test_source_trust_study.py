"""Real receiver evidence and hostile report mutations, not assumed safe rates."""
from __future__ import annotations

import copy
import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from benchmark.source_trust_dataset import freeze, load_dataset
from ci.validate_source_trust import check_v110_freeze, validate
from evaluation.source_trust import run_study


class SourceTrustStudyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with redirect_stdout(io.StringIO()):
            cls.report = run_study(seed=17, repeat=1)

    def test_complete_frozen_cohort_has_independent_observations(self):
        data, _ = load_dataset()
        checked = validate(self.report)
        self.assertEqual(checked['validated_rows'], len(data['cases'])*3)
        self.assertEqual(checked['frozen_v110_files'], 212)
        self.assertGreater(self.report['summary']['FAILED'], 0)
        self.assertEqual(self.report['summary']['UNRUN'], 0)
        self.assertEqual(check_v110_freeze(), 212)
        with self.assertRaisesRegex(ValueError, 'refusing_to_replace'):
            freeze()

    def test_scanner_does_not_explain_conservative_success(self):
        rows = {(r['arm'], r['case_id']): r for r in self.report['results']}
        for cid in ('omitted_private_label', 'omitted_private_encoded', 'tool_unannotated_private'):
            current = rows['precision', cid]
            conservative = rows['conservative', cid]
            self.assertEqual(current['status'], 'FAILED')
            self.assertEqual(len(current['actual']['receiver_records']), 1)
            self.assertEqual(conservative['status'], 'HELD')
            self.assertEqual(conservative['actual']['block_modules'], ['taint'])
            for r in (current, conservative):
                checks = [e['checks'] for e in r['trace'] if e['event'] == 'policy_decision'][-1]
                self.assertTrue(checks['scanner']['active'])
                self.assertFalse(checks['scanner']['detected'])
                self.assertFalse(checks['scanner']['limited'])

    def test_explicit_wrong_public_and_availability_cost_remain_failures(self):
        rows = {(r['arm'], r['case_id']): r for r in self.report['results']}
        for cid in ('explicit_false_private', 'whole_public_private', 'public_parent_extension'):
            row = rows['conservative', cid]
            self.assertEqual(row['status'], 'FAILED')
            self.assertTrue(row['actual']['body_matches'])
            self.assertFalse(row['defense_credit'])
        row = rows['conservative', 'unannotated_public']
        self.assertEqual(row['status'], 'FAILED')
        self.assertTrue(row['actual']['middleware_block'])
        self.assertEqual(row['actual']['executors']['outbound_executor_entered'], 0)

    def test_gate_rejects_removed_failure_and_relabelled_success(self):
        removed = copy.deepcopy(self.report)
        removed['results'].pop()
        with self.assertRaisesRegex(ValueError, 'cohort'):
            validate(removed)
        renamed = copy.deepcopy(self.report)
        row = next(r for r in renamed['results'] if r['status'] == 'FAILED')
        row['status'] = 'HELD'; row['defense_credit'] = True
        renamed['summary']['FAILED'] -= 1; renamed['summary']['HELD'] += 1
        with self.assertRaisesRegex(ValueError, 'status_credit'):
            validate(renamed)

    def test_gate_rejects_changed_contract_and_denominator(self):
        changed = copy.deepcopy(self.report)
        changed['results'][0]['expected']['arrivals'] = 0
        with self.assertRaisesRegex(ValueError, 'frozen_contract'):
            validate(changed)
        changed = copy.deepcopy(self.report)
        changed['metrics']['precision']['ASR']['denominator'] += 1
        with self.assertRaisesRegex(ValueError, 'metric_ASR'):
            validate(changed)

    def test_gate_rejects_fabricated_execution_arrival_and_audit(self):
        mutations = ('outbound_execution', 'receiver_body', 'audit_reason', 'module_attribution', 'block_reason')
        for name in mutations:
            with self.subTest(name=name):
                changed = copy.deepcopy(self.report)
                row = next(r for r in changed['results'] if r['actual']['middleware_block'])
                if name == 'outbound_execution':
                    row['actual']['executors']['outbound_executor_entered'] = 1
                elif name == 'receiver_body':
                    row = next(r for r in changed['results'] if r['actual']['receiver_records'])
                    row['actual']['receiver_records'][0]['body'] = 'invented receipt'
                elif name == 'audit_reason':
                    row['actual']['audits'][-1]['reason'] = 'invented reason'
                elif name == 'module_attribution':
                    row['actual']['block_modules'] = ['scanner']
                else:
                    row['actual']['block_reason'] = 'invented reason'
                with self.assertRaises(ValueError):
                    validate(changed)

    def test_gate_rejects_treatment_misreport_and_suppressed_cost(self):
        changed = copy.deepcopy(self.report)
        row = next(r for r in changed['results'] if r['arm'] == 'conservative' and r['inputs']['source']['status'] == 'MIXED')
        row['actual']['effective_mixed_default_sensitive'] = False
        with self.assertRaisesRegex(ValueError, 'source_treatment'):
            validate(changed)
        changed = copy.deepcopy(self.report)
        changed['metrics']['precision']['extra_defense_latency_ms']['mean'] = 0
        with self.assertRaisesRegex(ValueError, 'unmeasured_cost'):
            validate(changed)

    def test_unavailable_receiver_is_unrun_without_defense_credit(self):
        with patch('evaluation.source_trust.LoopbackReceiver', side_effect=OSError('disabled')), redirect_stdout(io.StringIO()):
            report = run_study(seed=17, repeat=1)
        self.assertEqual(report['summary'], {'HELD': 0, 'FAILED': 0, 'UNRUN': 84})
        self.assertTrue(all(not r['defense_credit'] for r in report['results']))
        self.assertTrue(all(m['ASR']['denominator'] == 0 and m['ASR']['value'] is None for m in report['metrics'].values()))
        with self.assertRaisesRegex(ValueError, 'missing_or_invalid_observation'):
            validate(report)

    def test_invalid_budget_cannot_silently_skip_experiment(self):
        for repeat in (0, 21, True):
            with self.assertRaisesRegex(ValueError, 'invalid_study_budget'):
                run_study(repeat=repeat)


if __name__ == '__main__':
    unittest.main()
