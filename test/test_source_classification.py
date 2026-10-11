import json,tempfile,unittest
from dataclasses import replace
from pathlib import Path
from evaluation.receiver import LoopbackReceiver
from security.precision import SourceLayout,FieldRule
from security.source_classification import SourcePlan,SourceRegistry,strict_json
from security.precision_runtime import PrecisionRuntime
from security.taint import TaintError
from security.taint_context import TaintContext


class SourceRegistryTests(unittest.TestCase):
    def test_conflicts_remain_explicit(self):
        r=SourceRegistry((('file','data/source.txt',SourcePlan('PUBLIC')),('file','data/source.txt',SourcePlan('SENSITIVE',SourceLayout(True)))))
        self.assertEqual(r.classify('file','data/source.txt').status,'CONFLICT')
        self.assertEqual(r.classify('tool','unregistered').status,'MISSING')
    def test_registry_validation_and_config_duplicate_keys(self):
        for text in ('{"unknown_policy":"PERMIT"}','{"plans":[{"category":"file","reference":"../private","status":"PUBLIC"}]}','{"plans":[],"plans":[]}','{"secret_config":1}'):
            with self.assertRaises(TaintError): SourceRegistry.from_json(text)
        with self.assertRaises(TaintError): SourceRegistry((('file','*',SourcePlan('PUBLIC')),))
        with self.assertRaises(TaintError): SourcePlan('PUBLIC',SourceLayout(True))
    def test_config_roundtrip_and_model_only_wildcard(self):
        r=SourceRegistry.from_json('{"plans":[{"category":"file","reference":"data/record.json","status":"MIXED","layout":{"structured_json":true,"fields":[{"path":["key"],"sensitive":true}]}},{"category":"model","reference":"*","status":"PUBLIC"}],"unknown_policy":"REQUIRE_REVIEW"}')
        self.assertTrue(r.classify('file','data/record.json').layout.structured_json)
        self.assertEqual(r.classify('model','request-2').status,'PUBLIC')
        self.assertEqual(r.unknown_policy,'REQUIRE_REVIEW')
    def test_malformed_structured_source_rejects_duplicates_and_nonfinite(self):
        for text in ('{"key":"first","key":"second"}','{"x":NaN}','['*18+']'*18):
            with self.assertRaises(TaintError): strict_json(text)


class SourceExecutionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.root=Path(self.temp.name); (self.root/'data').mkdir()
        (self.root/'data/source.txt').write_text('fabricated opaque willow canary 719')
        self.policy=self.root/'policy.yaml'; self.policy.write_text('blocked_files:\nallowed_file_roots:\n  - data\nallowed_domains:\n  - 127.0.0.1\n')
        self.receiver=LoopbackReceiver(); self.receiver.__enter__(); self.events=[]
    def tearDown(self): self.receiver.__exit__(); self.temp.cleanup()
    def runtime(self,plans=(),unknown_policy='BLOCK',**kwargs):
        return PrecisionRuntime(policy_path=self.policy,audit_path=self.root/'audit.jsonl',context=TaintContext(self.root),local_target=self.receiver.target,
            registry=SourceRegistry(tuple(plans),unknown_policy),observe=lambda event,**fields:self.events.append({'event':event,**fields}),**kwargs)
    def test_correct_sensitive_and_wrong_public_are_separately_measured(self):
        for status,layout,allowed in (('SENSITIVE',SourceLayout(True),False),('PUBLIC',SourceLayout(),True)):
            r=self.runtime([('file','data/source.txt',SourcePlan(status,layout))]); h=r.read('data/source.txt').handle
            self.assertTrue(r.provenance(h)['allowed'])
            self.assertEqual(r.send(self.receiver.url,h).executed,allowed)
        self.assertEqual(len(self.receiver.arrivals),1) # Valid HMAC cannot discover the wrong label.
    def test_unknown_missing_conflict_and_review_block_before_sender(self):
        plans=[(),(('file','data/source.txt',SourcePlan('UNKNOWN')),),
               (('file','data/source.txt',SourcePlan('PUBLIC')),('file','data/source.txt',SourcePlan('SENSITIVE',SourceLayout(True))))]
        for p in plans:
            for policy in ('BLOCK','REQUIRE_REVIEW'):
                r=self.runtime(p,policy); h=r.read('data/source.txt').handle
                result=r.send(self.receiver.url,h); self.assertFalse(result.executed)
                self.assertEqual(result.decision.reason,'source_review_required' if policy=='REQUIRE_REVIEW' else 'source_classification_blocked')
        self.assertFalse(self.receiver.arrivals)
        self.assertFalse(any(e['event']=='outbound_executor_entered' for e in self.events))
    def test_unknown_allow_tradeoff_is_explicit_actual_delivery(self):
        r=self.runtime(unknown_policy='ALLOW'); h=r.read('data/source.txt').handle
        self.assertTrue(r.send(self.receiver.url,h).executed); self.assertEqual(len(self.receiver.arrivals),1)
        self.assertIn('MISSING',r.provenance(h)['classifications'][0]['status'])
    def test_unknown_normal_data_has_measurable_utility_cost(self):
        (self.root/'data/source.txt').write_text('public technical summary')
        r=self.runtime(); self.assertFalse(r.send(self.receiver.url,r.read('data/source.txt').handle).executed)
        r=self.runtime([('file','data/source.txt',SourcePlan('PUBLIC'))]); self.assertTrue(r.send(self.receiver.url,r.read('data/source.txt').handle).executed)
    def test_wrong_path_configuration_does_not_silently_mark_public(self):
        r=self.runtime([('file','data/misspelled.txt',SourcePlan('PUBLIC'))]); h=r.read('data/source.txt').handle
        self.assertFalse(r.send(self.receiver.url,h).executed)
        self.assertEqual(r.provenance(h)['classifications'][0]['status'],'MISSING')
    def test_unknown_unused_element_does_not_pollute_known_projection(self):
        (self.root/'data/public.txt').write_text('alice')
        r=self.runtime([('file','data/public.txt',SourcePlan('PUBLIC'))]); known=r.read('data/public.txt').handle; unknown=r.read('data/source.txt').handle
        joined=r.transform('dict',known,unknown,parameters={'keys':['public','unknown']})
        selected=r.transform('get_item',joined,parameters={'key':'public'})
        self.assertTrue(r.send(self.receiver.url,selected).executed)
        self.assertFalse(r.send(self.receiver.url,r.transform('get_item',joined,parameters={'key':'unknown'})).executed)
    def test_classification_metadata_tamper_is_rejected(self):
        r=self.runtime(); h=r.read('data/source.txt').handle; entry=r._precision._entries[h.value_id]
        r._precision._entries[h.value_id]=replace(entry,node=replace(entry.node,classifications=()))
        self.assertFalse(r.send(self.receiver.url,h).executed)
    def test_unknown_and_malformed_tool_returns(self):
        r=self.runtime(approved_tools={'lookup':lambda _: 'synthetic tool private phrase','malformed':lambda _:object()})
        self.assertFalse(r.send(self.receiver.url,r.call_approved_tool('lookup')).executed)
        with self.assertRaises(TaintError): r.call_approved_tool('malformed')
    def test_detection_only_records_unknown_without_claiming_block(self):
        r=self.runtime(enforce_content=False); self.assertTrue(r.send(self.receiver.url,r.read('data/source.txt').handle).executed)
        check=next(e for e in self.events if e['event']=='source_classification_check'); self.assertFalse(check['allowed']); self.assertFalse(check['enforced'])

if __name__=='__main__': unittest.main()
