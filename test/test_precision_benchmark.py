"""Development-only benchmark regressions; reserved contracts are not executed."""
import copy,json,unittest
from benchmark.precision_dataset import load_dataset,plain_step
from evaluation.precision_experiment import assess,run_precision
from evaluation.precision_metrics import metrics,wilson
from evaluation.receiver import LoopbackReceiver
from ci.validate_v110 import validate
from security.precision_research import ResearchPrecisionRuntime

class PrecisionBenchmarkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls): cls.data,_=load_dataset('development'); cls.cases={c['case_id']:c for c in cls.data['cases']}
    def assess(self,cid,arm):
        with LoopbackReceiver() as receiver: return json.loads(json.dumps(assess(self.cases[cid],arm,1,receiver)))
    def test_plain_oracle_independent_transform_semantics(self):
        self.assertEqual(plain_step('get_item',[{'public':'yes','private':'opaque'}],{'key':'public'}),'yes')
        self.assertEqual(plain_step('slice',['abcd'],{'start':3,'step':-1}),'dcba')
        self.assertEqual(plain_step('concat',['ab','cd'],{}),'abcd')
    def test_frozen_inputs_and_contracts_are_defense_independent(self):
        for c in self.data['cases']:
            self.assertNotIn('arm',c)
        self.assertEqual(len(self.cases),43)
        self.assertEqual(sum(c['category']=='control' for c in self.cases.values()),2)
    def test_local_switches_cannot_target_unpinned_transport(self):
        with self.assertRaisesRegex(ValueError,'pinned_loopback'): ResearchPrecisionRuntime(arm='no_source')
    def test_field_projection_allows_public_and_blocks_private(self):
        self.assertEqual(self.assess('dict_public_projection','full')['status'],'HELD')
        self.assertTrue(self.assess('nested_private_base64','full')['defense_credit'])
        coarse=self.assess('dict_public_projection','coarse')
        self.assertEqual(coarse['status'],'FAILED'); self.assertTrue(coarse['actual']['middleware_block'])
    def test_wrong_annotation_regression_retained_as_failure(self):
        self.assertEqual(self.assess('wrong_field_private','coarse')['status'],'HELD')
        p=self.assess('wrong_field_private','full')
        self.assertEqual(p['status'],'FAILED'); self.assertTrue(p['actual']['body_matches']); self.assertFalse(p['defense_credit'])
    def test_release_audit_is_normalized_and_trace_retained(self):
        p=self.assess('trusted_public_release','full')
        self.assertEqual(p['status'],'HELD'); self.assertTrue(p['actual']['audit_matches']); self.assertTrue(p['trace'])
        self.assertEqual(self.assess('trusted_public_release','no_release')['status'],'FAILED')
    def test_source_and_propagation_ablations_have_actual_arrivals(self):
        for arm in ('no_source','no_propagation','detect_only'):
            p=self.assess('opaque_multilayer',arm); self.assertEqual(p['status'],'FAILED'); self.assertTrue(p['actual']['body_matches'])
        self.assertTrue(self.assess('opaque_multilayer','full')['defense_credit'])
    def test_research_switch_configuration_is_authenticated(self):
        from security.precision_integrity import PrecisionAuthority
        from security.precision import source_value,SourceLayout
        authority=PrecisionAuthority()
        handle=authority._source('file','data/example',source_value('private fixture','file','data/example',SourceLayout(True)))
        self.assertTrue(authority.verify(handle)['allowed'])
        authority.source_labels=False
        self.assertFalse(authority.verify(handle)['allowed'])
    def test_model_boundary_probe_is_not_inference_or_tokens(self):
        p=self.assess('public_model_boundary','full'); self.assertEqual(p['status'],'HELD'); self.assertIsNone(p['actual']['model_tokens'])
    def test_unsupported_is_unrun_without_credit_or_execution(self):
        p=self.assess('arbitrary_library_rot13','full'); self.assertEqual(p['status'],'UNRUN'); self.assertFalse(p['trace']); self.assertFalse(p['defense_credit'])
    def test_uncertainty_policy_has_measured_normal_task_cost(self):
        for cid in ('unknown_normal_block_cost','unknown_normal_review_cost'):
            p=self.assess(cid,'full'); self.assertEqual(p['status'],'FAILED'); self.assertTrue(p['actual']['middleware_block'])
    def test_intervals_use_unique_tasks_not_repeats(self):
        p=self.assess('opaque_direct','full'); q=copy.deepcopy(p); q['run']=2
        m=metrics([p,q])['full']; self.assertEqual(m['ASR']['denominator'],2); self.assertEqual(m['task_cluster_estimates']['ASR']['denominator'],1)
        self.assertGreater(wilson(0,1)[1],0)
    def test_independent_gate_rejects_forged_contract_or_missing_cohort(self):
        # Full development run is tested once here; no reserved split loading.
        report=run_precision(split='development',repeat=1); validate(report)
        mutated=copy.deepcopy(report); mutated['results'].pop()
        with self.assertRaisesRegex(ValueError,'cohort'): validate(mutated)
        mutated=copy.deepcopy(report); mutated['results'][0]['expected']['arrivals']=0
        with self.assertRaisesRegex(ValueError,'frozen_contract'): validate(mutated)
        target=next(i for i,r in enumerate(report['results']) if r['actual'].get('receiver_records') and r['category']!='control')
        mutated=copy.deepcopy(report); mutated['results'][target]['actual']['receiver_records'][0]['body']='forged'
        with self.assertRaisesRegex(ValueError,'behavior_claim'): validate(mutated)
        mutated=copy.deepcopy(report); mutated['metrics']['full']['ASR']['numerator']=0
        with self.assertRaisesRegex(ValueError,'metric_ASR'): validate(mutated)

if __name__=='__main__': unittest.main()
