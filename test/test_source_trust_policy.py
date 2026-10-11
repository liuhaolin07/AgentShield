"""Source-policy mechanism tests independent of experimental rate expectations."""
import tempfile
import unittest
from pathlib import Path
from security.precision import SourceLayout, FieldRule
from security.source_classification import SourcePlan, SourceRegistry
from security.source_trust_policy import effective_registry, SourceTrustRuntime
from security.taint_context import TaintContext
from evaluation.receiver import LoopbackReceiver


class SourceTrustPolicyTests(unittest.TestCase):
    def test_only_mixed_default_changes_and_input_is_immutable(self):
        mixed = SourcePlan('MIXED', SourceLayout(fields=(FieldRule(('public',), False),), structured_json=True))
        public = SourcePlan('PUBLIC'); unknown = SourcePlan('UNKNOWN')
        reg = SourceRegistry((('file', 'data/mixed', mixed), ('tool', 'reader', public), ('file', 'data/unknown', unknown)))
        compiled = effective_registry(reg, 'conservative')
        self.assertTrue(compiled.classify('file', 'data/mixed').layout.default_sensitive)
        self.assertFalse(reg.classify('file', 'data/mixed').layout.default_sensitive)
        self.assertEqual(compiled.plans[1:], reg.plans[1:])
        self.assertEqual(compiled.plans[0][2].layout.fields, mixed.layout.fields)
        self.assertIs(effective_registry(reg, 'precision'), reg)
        self.assertIs(effective_registry(reg, 'coarse'), reg)

    def test_no_unpinned_or_conflicting_research_settings(self):
        with self.assertRaises(ValueError):
            SourceTrustRuntime(strategy='conservative', registry=SourceRegistry())
        with self.assertRaises(ValueError):
            effective_registry(SourceRegistry(), 'unknown_strategy')
        with LoopbackReceiver() as receiver:
            with self.assertRaisesRegex(ValueError, 'conflicting'):
                SourceTrustRuntime(strategy='conservative', registry=SourceRegistry(), local_target=receiver.target, scan_content=False)

    def run_wire(self, strategy, content, fields, selector, status='MIXED'):
        with tempfile.TemporaryDirectory() as directory, LoopbackReceiver() as receiver:
            root = Path(directory); (root/'data').mkdir(); (root/'data/source.txt').write_text(content)
            policy = root/'policy.yaml'; policy.write_text('blocked_files:\nallowed_file_roots:\n  - data\nallowed_domains:\n  - 127.0.0.1\n')
            registry = SourceRegistry((('file', 'data/source.txt', SourcePlan(status, SourceLayout(fields=tuple(fields), structured_json=True))),))
            runtime = SourceTrustRuntime(strategy=strategy, registry=registry, policy_path=policy, audit_path=root/'audit', context=TaintContext(root), local_target=receiver.target)
            handle = runtime.read('data/source.txt').handle
            for key in selector:
                handle = runtime.transform('get_item', handle, parameters={'key':key})
            decision = runtime.send(receiver.url, handle)
            return decision, receiver.arrivals, runtime.provenance(handle)

    def test_unlisted_secret_blocked_but_explicit_public_delivered(self):
        text = '{"public":"ok","new_field":"opaque.fixture.private"}'
        fields = [FieldRule(('public',), False)]
        current, arrivals, _ = self.run_wire('precision', text, fields, ['new_field'])
        self.assertTrue(current.executed); self.assertEqual(arrivals[0]['body'], 'opaque.fixture.private')
        conservative, arrivals, lineage = self.run_wire('conservative', text, fields, ['new_field'])
        self.assertFalse(conservative.executed); self.assertFalse(arrivals); self.assertTrue(lineage['sensitive'])
        public, arrivals, _ = self.run_wire('conservative', text, fields, ['public'])
        self.assertTrue(public.executed); self.assertEqual(arrivals[0]['body'], 'ok')

    def test_public_omission_measures_conservative_false_block(self):
        text = '{"known":"ok","new_field":"public glossary"}'
        fields = [FieldRule(('known',), False)]
        current, arrivals, _ = self.run_wire('precision', text, fields, ['new_field'])
        self.assertTrue(current.executed)
        conservative, arrivals, _ = self.run_wire('conservative', text, fields, ['new_field'])
        self.assertFalse(conservative.executed); self.assertFalse(arrivals)

    def test_explicit_false_and_public_parent_remain_real_limitations(self):
        for text, fields, selector in [
            ('{"field":"opaque.private"}', [FieldRule(('field',), False)], ['field']),
            ('{"parent":{"unexpected":"opaque.private"}}', [FieldRule(('parent',), False)], ['parent', 'unexpected'])]:
            result, arrivals, _ = self.run_wire('conservative', text, fields, selector)
            self.assertTrue(result.executed); self.assertEqual(arrivals[0]['body'], 'opaque.private')

    def test_wrong_whole_public_cannot_be_repaired_by_mixed_default(self):
        result, arrivals, _ = self.run_wire('conservative', '{"field":"opaque.private"}', [], ['field'], 'PUBLIC')
        self.assertTrue(result.executed); self.assertEqual(arrivals[0]['body'], 'opaque.private')

if __name__ == '__main__':
    unittest.main()
