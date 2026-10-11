"""Quota, paired-input and adversarial manifest checks; no safety rate assertions."""
from __future__ import annotations
import ast
import copy
from dataclasses import FrozenInstanceError, replace
import hashlib
import json
from pathlib import Path
import unittest

from benchmark.source_trust_corruption import (
    create_graph, digest, exposure, leaf_id, manifest, measurement_cohort,
    target_graph, validate_cohort,
)
from ci.validate_source_trust_corruption import validate


class CorruptionTests(unittest.TestCase):
    def setUp(self):
        self.cohort = measurement_cohort(2)

    def graph(self, rate="0.10", direction="sensitive_to_public", seed=17):
        return create_graph(self.cohort, rate=rate, direction=direction, seed=seed)

    def test_graph_is_immutable_and_has_no_payload(self):
        g = self.graph()
        with self.assertRaises(FrozenInstanceError):
            g.rate = "1"
        record = g.record()
        record['labels'].clear()
        self.assertEqual(len(g.labels), 40)
        self.assertNotIn('value', json.dumps(g.record()))

    def test_exact_fraction_not_floating_rounding(self):
        self.assertEqual(len(self.graph(rate="0.05").changed_sp), 1)
        self.assertEqual(len(self.graph(rate="1").changed_sp), 20)
        self.assertFalse(self.graph(rate="1").changed_ps)

    def test_different_direction_denominators(self):
        c = measurement_cohort(1)
        for n, leaf in enumerate(c['families'][0]['leaves']):
            leaf['sensitive'] = n < 3
        c['families'][0]['leaves'] = c['families'][0]['leaves'][:8]
        c['families'][0]['tasks'][1]['dependencies'] = [c['families'][0]['leaves'][3]['path']]
        g = create_graph(c, rate="0.4", direction="bidirectional", seed=17)
        self.assertEqual((len(g.changed_sp), len(g.changed_ps)), (1, 2))
        self.assertEqual(validate(manifest(c, [g]))['leaves'], 8)

    def test_nesting_and_panel_shared_ranking(self):
        previous = set()
        for rate in ("0.05", "0.1", "0.25", "0.5", "1"):
            g = self.graph(rate=rate)
            self.assertTrue(previous <= set(g.changed_sp))
            self.assertEqual(g.changed_sp, self.graph(rate=rate, direction="bidirectional").changed_sp)
            previous = set(g.changed_sp)

    def test_e0_has_no_error_seed_or_vacuous_all_exposure(self):
        g = self.graph(rate="0", direction="correct", seed=None)
        for task in self.cohort['families'][0]['tasks']:
            result = exposure(self.cohort, self.cohort['families'][0], task, g)
            self.assertFalse(result['X_any']); self.assertFalse(result['X_all'])
            if task['category'] == 'benign':
                self.assertIsNone(result['hit_fraction'])
        with self.assertRaises(ValueError):
            self.graph(rate="0", direction="correct", seed=17)

    def test_partial_and_all_hits_from_frozen_dependencies(self):
        c = measurement_cohort(1)
        t = c['families'][0]['tasks'][0]
        t['dependencies'] = [leaf['path'] for leaf in c['families'][0]['leaves'][:10]]
        g = create_graph(c, rate="0.5", direction="sensitive_to_public", seed=17)
        x = exposure(c, c['families'][0], t, g)
        self.assertEqual(x['private_hits'], 5)
        self.assertTrue(x['X_any']); self.assertFalse(x['X_all'])
        self.assertEqual(x['hit_fraction'], .5)

    def test_family_zero_quota_is_retained(self):
        g = self.graph(rate="0.05")
        counts = [sum(leaf_id(f['family_id'], leaf['path']) in g.changed_sp for leaf in f['leaves']) for f in self.cohort['families']]
        self.assertEqual(sorted(counts), [0, 1])
        self.assertEqual(validate(manifest(self.cohort, [g]))['planned_consumers'], 12)

    def test_pair_and_three_policies_share_one_graph(self):
        g = self.graph(); packet = manifest(self.cohort, [g])
        self.assertEqual({b['graph_id'] for b in packet['planned_consumers']}, {g.graph_id})
        checked = validate(packet, digest(self.cohort))
        self.assertTrue(checked['trusted_cohort_hash_supplied'])
        self.assertFalse(checked['truth_semantics_verified'])
        self.assertFalse(checked['pilot_eligible'])
        self.assertEqual(checked['executions'], 0)

    def test_targeted_keeps_each_family_budget(self):
        g = self.graph(rate="0.25"); targeted = target_graph(self.cohort, g)
        for family in self.cohort['families']:
            keys = {leaf_id(family['family_id'], leaf['path']) for leaf in family['leaves']}
            self.assertEqual(len(keys.intersection(g.changed_sp)), len(keys.intersection(targeted.changed_sp)))
        self.assertEqual(validate(manifest(self.cohort, [g, targeted]))['graphs'], 2)

    def test_targeting_prioritizes_unauthorized_sensitive_dependency(self):
        c = measurement_cohort(1); f = c['families'][0]
        f['leaves'][1]['allowed_readers'] = ['public_receiver']
        f['tasks'][0]['dependencies'].append(f['leaves'][1]['path'])
        g = create_graph(c, rate="0.1", direction="sensitive_to_public", seed=17)
        target = target_graph(c, g)
        self.assertEqual(target.changed_sp, (leaf_id(f['family_id'], f['leaves'][0]['path']),))
        validate(manifest(c, [g, target]))

    def test_input_order_does_not_change_selected_leaf_set(self):
        other = copy.deepcopy(self.cohort)
        other['families'].reverse()
        for f in other['families']: f['leaves'].reverse()
        g = create_graph(other, rate="0.25", direction="sensitive_to_public", seed=17)
        self.assertEqual(g.changed_sp, self.graph(rate="0.25").changed_sp)

    def test_str_zero_and_array_zero_are_distinct(self):
        c = measurement_cohort(1)
        c['families'][0]['leaves'][0]['path'] = ['0']
        c['families'][0]['leaves'][10]['path'] = [0]
        c['families'][0]['tasks'][0]['dependencies'] = [['0']]
        c['families'][0]['tasks'][1]['dependencies'] = [[0]]
        self.assertEqual(len(validate_cohort(c)), 20)
        validate(manifest(c, [create_graph(c, rate="1", direction="bidirectional", seed=17)]))

    def test_duplicate_container_bool_and_unknown_dependencies_rejected(self):
        for mutation in ('duplicate', 'container', 'bool', 'unknown'):
            c = copy.deepcopy(self.cohort); f=c['families'][0]
            if mutation == 'duplicate': f['leaves'].append(copy.deepcopy(f['leaves'][0]))
            if mutation == 'container': f['leaves'][1]['path']=['records']
            if mutation == 'bool': f['leaves'][1]['path']=[True]
            if mutation == 'unknown': f['tasks'][0]['dependencies']=[['missing']]
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): validate_cohort(c)

    def test_invalid_and_resource_consuming_configurations_rejected(self):
        for rate, seed in (("1/0", 17), ("NaN", 17), ("9"*100, 17), ("0.1", True), ("0.1", 2**32), ("-0.1",17)):
            with self.subTest(rate=rate, seed=seed), self.assertRaises(ValueError): self.graph(rate=rate,seed=seed)
        with self.assertRaises(ValueError): measurement_cohort(129)

    def test_holdout_and_false_review_attestation_not_accepted_as_controls(self):
        for key,value in (('split','holdout'),('annotation_status','independently_reviewed')):
            c=copy.deepcopy(self.cohort);c[key]=value
            with self.assertRaises(ValueError): create_graph(c,rate="0.1",direction="sensitive_to_public",seed=17)

    def test_graphs_from_other_cohort_rejected(self):
        other=measurement_cohort(1)
        with self.assertRaises(ValueError): manifest(other,[self.graph()])
        with self.assertRaises(ValueError): exposure(other,other['families'][0],other['families'][0]['tasks'][0],self.graph())

    def test_independent_checker_rejects_false_budgets_even_with_rehashed_ids(self):
        packet=manifest(self.cohort,[self.graph()]);record=packet['graphs'][0]
        record['rate']='0.5'
        old_id=record['graph_id'];record['graph_id']=digest({k:v for k,v in record.items() if k!='graph_id'})
        for b in packet['planned_consumers']: b['graph_id']=record['graph_id']
        self.assertNotEqual(old_id,record['graph_id'])
        with self.assertRaisesRegex(ValueError,'quota'): validate(packet)

    def test_independent_checker_rejects_binding_removal_and_graph_swap(self):
        gs=[self.graph(), self.graph(rate='0.5')]
        for action in ('remove','swap'):
            packet=manifest(self.cohort,gs)
            if action=='remove': packet['planned_consumers'].pop()
            else: packet['planned_consumers'][0]['graph_id']=gs[1].graph_id
            with self.subTest(action=action), self.assertRaises(ValueError): validate(packet)

    def test_independent_checker_rejects_post_execution_exposure_and_fake_execution(self):
        for action in ('exposure','execution','metric'):
            packet=manifest(self.cohort,[self.graph()])
            if action=='exposure': packet['planned_consumers'][0]['exposure']['X_any']=not packet['planned_consumers'][0]['exposure']['X_any']
            if action=='execution': packet['executions']=1
            if action=='metric': packet['ASR']=0
            with self.subTest(action=action), self.assertRaises(ValueError): validate(packet)

    def test_trusted_external_cohort_hash_detects_modified_truth(self):
        changed=copy.deepcopy(self.cohort);changed['families'][0]['template_id']='different'
        g=create_graph(changed,rate='0.1',direction='sensitive_to_public',seed=17)
        with self.assertRaisesRegex(ValueError,'frozen_cohort'): validate(manifest(changed,[g]),digest(self.cohort))

    def test_target_cannot_accept_fabricated_random_graph(self):
        g=self.graph()
        with self.assertRaises(ValueError): target_graph(self.cohort,replace(g,changed_sp=()))

    def test_checker_imports_no_generator_or_defense(self):
        tree=ast.parse(Path('ci/validate_source_trust_corruption.py').read_text())
        imports=[n.module for n in ast.walk(tree) if isinstance(n,ast.ImportFrom)]
        self.assertFalse(any(n and n.startswith(('benchmark','security','evaluation')) for n in imports))


if __name__ == '__main__':
    unittest.main()
