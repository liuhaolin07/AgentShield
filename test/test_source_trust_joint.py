import copy
import json
from pathlib import Path
import random
import unittest
from evaluation.source_trust_joint import run,assess,counts,graph_bounds,integrate,true_vector,validate_config


class JointH5Tests(unittest.TestCase):
    def config(self):
        c=json.loads(Path('docs/research/source-trust-methods/r3/joint-calibration-config.json').read_text())
        c.update(trials=20,families=10,graphs=[5]);return c

    def test_true_H5_feasible_and_reject_all_fails_utility(self):
        c=self.config();truth=true_vector(c,'beneficial_complete')
        self.assertAlmostEqual(truth[0],-.2375)
        self.assertTrue(all(v>.8 for v in truth[7:]))
        self.assertEqual(true_vector(c,'reject_all_complete')[7:],[0.]*6)

    def test_grid_integral_full_domain(self):
        self.assertAlmostEqual(integrate([0,.05,.1,.25,.5,1],[0,.05,.1,.25,.5,1]),.5)
        with self.assertRaises(ValueError):integrate([0]*6,[0,.01,.05,.1,.25,.5])

    def test_missing_uses_full_denominator_and_worst_case_directions(self):
        c=self.config();r=counts(c,'beneficial_complete',random.Random(2))
        for key in r:r[key]=[0]*5
        for key in ('attack_missing_c','attack_missing_p','normal_missing_c','normal_missing_p'):r[key]=[10]*5
        low,high=graph_bounds(r,10)
        self.assertEqual(low[:10],[-1.]*10);self.assertEqual(high[:10],[1.]*10)
        self.assertEqual(low[10:],[0.]*5);self.assertEqual(high[10:],[1.]*5)

    def test_missing_E0_not_repeated_to_increase_observation_count(self):
        c=self.config();zero=counts(c,'beneficial_complete',random.Random(1),True)
        zero['normal_missing_c']=[1]
        zero['completed_c'][0]-=1
        graphs=[counts(c,'beneficial_complete',random.Random(i)) for i in range(5)]
        result=assess(c,zero,graphs)
        self.assertEqual(result['minimum_observation_fraction'],.9)
        self.assertEqual(result['status'],'UNRUN_missing_observation_gate')
        self.assertFalse(result['joint_confirmation'])

    def test_all_deny_cannot_win_complete_joint_gate(self):
        c=self.config();zero=counts(c,'reject_all_complete',random.Random(1),True)
        maps=[counts(c,'reject_all_complete',random.Random(i)) for i in range(5)]
        result=assess(c,zero,maps)
        self.assertFalse(result['all_six_absolute_TCR']);self.assertFalse(result['joint_confirmation'])

    def test_shared_global_fault_zeroes_all_nonzero_TCR_points(self):
        c=self.config()
        class FaultRNG:
            def random(self):return .01
        record=counts(c,'beneficial_complete',FaultRNG())
        self.assertEqual(record['completed_c'],[0]*5)
        self.assertEqual(record['attack_c'],[10]*5)
        self.assertEqual(record['attack_p'],[10]*5)

    def test_limits_estimand_and_fixed_estimator(self):
        for change in ({'graphs':[True]},{'trials':10000},{'estimator':'choose_after_effect'},{'minimum_coverage':.8}):
            c=self.config();c.update(change)
            with self.assertRaises(ValueError):validate_config(c)

    def test_reproducibility_and_all_exclusions_preserved(self):
        report,trials,graphs,zeros=run(self.config())
        other,again,_,_=run(self.config())
        self.assertEqual(trials,again)
        self.assertEqual(len(trials),100);self.assertEqual(len(zeros),100);self.assertEqual(len(graphs),500)
        for summary in report['summary']:
            self.assertEqual(summary['eligible_trials']+summary['UNRUN_missing_gate'],20)
        self.assertEqual(report['actual_defense_executions'],0)
        self.assertEqual(report['joint_power_status'],'MEASURED_SYNTHETIC_RESPONSE_MODELS_ONLY')

    def test_counts_reject_fake_evidence_negative_boolean_and_overfull(self):
        for action in ('negative','bool','overfull'):
            c=self.config();r=counts(c,'beneficial_complete',random.Random(1))
            if action=='negative':r['attack_c'][0]=-1
            if action=='bool':r['attack_c'][0]=True
            if action=='overfull':r['attack_c'][0]=10;r['attack_missing_c'][0]=1
            with self.subTest(action=action),self.assertRaises(ValueError):graph_bounds(r,10)
