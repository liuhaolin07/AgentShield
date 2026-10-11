import copy
import unittest
from benchmark.source_trust_corruption import measurement_cohort,create_graph,manifest,validate_cohort
from benchmark.source_trust_truth import convert,digest,fixture_ledger,audit_gate
from ci.validate_source_trust_truth import validate
from ci.validate_source_trust_corruption import validate as check_graph


class TruthProjectionTests(unittest.TestCase):
    def ledger(self):return fixture_ledger(measurement_cohort(2))

    def test_actual_fixture_chain_and_graph_consumption(self):
        ledger=self.ledger();result=convert(ledger)
        self.assertEqual(result['projection'],measurement_cohort(2))
        self.assertTrue(validate(ledger,result,digest(ledger))['projection_verified'])
        self.assertFalse(result['human_identity_or_semantics_verified'])
        graph=create_graph(result['projection'],rate='.1',direction='sensitive_to_public',seed=17)
        self.assertFalse(check_graph(manifest(result['projection'],[graph]))['pilot_eligible'])

    def test_uncertain_not_false_and_no_silent_task_drop(self):
        ledger=self.ledger();key=next(iter(ledger['submissions'][0]['answers']))
        ledger['submissions'][0]['answers'][key]['classification']='UNCERTAIN'
        result=convert(ledger)
        self.assertIsNone(result['projection']);self.assertEqual(result['unresolved_units'],[key])

    def test_arbitrated_uncertainty_preserved_in_chain(self):
        ledger=self.ledger();key=next(iter(ledger['submissions'][0]['answers']))
        ledger['submissions'][0]['answers'][key]['classification']='UNCERTAIN'
        ledger['adjudications'][key]={'adjudicator_id':'fixture-arbitrator-not-human','evidence_ids':list(ledger['evidence']),
                                    'rationale':'Explicit fixture ruling','select_submission':1}
        result=convert(ledger);validate(ledger,result,digest(ledger))
        self.assertEqual(result['conflicting_units'],[key])
        self.assertEqual(result['chain']['adjudications_sha256'],digest(ledger['adjudications']))

    def test_D_read_not_substituted_for_output_exposure(self):
        ledger=self.ledger();family=ledger['inventory']['families'][0];task=family['tasks'][1]['task_id']
        for form in ledger['submissions']:form['answers'][task]['D_read'].append(family['leaves'][0]['path'])
        result=convert(ledger);check=validate(ledger,result,digest(ledger))
        self.assertEqual(result['projection']['families'][0]['tasks'][1]['dependencies'],[family['leaves'][10]['path']])
        self.assertEqual(check['tasks'],4)

    def test_raw_change_and_rehashed_false_projection_detected(self):
        ledger=self.ledger();pin=digest(ledger);result=convert(ledger)
        result['projection']['families'][0]['leaves'][0]['sensitive']=False
        result['chain']['projection_sha256']=digest(result['projection']);result['chain_sha256']=digest(result['chain'])
        with self.assertRaisesRegex(ValueError,'raw_truth'):validate(ledger,result,pin)
        ledger['evidence'][next(iter(ledger['evidence']))]='0'*64
        with self.assertRaisesRegex(ValueError,'frozen_raw'):validate(ledger,result,pin)

    def test_critical_findings_force_full_rework(self):
        ledger=self.ledger();key=next(iter(ledger['submissions'][0]['answers']))
        ledger['audit']['findings']=[{'unit_id':key,'family_id':'control-000','kind':'classification'}]
        result=convert(ledger)
        self.assertEqual(result['status'],'AUDIT_FAILED');self.assertIsNone(result['projection'])
        self.assertTrue(result['audit_gate']['full_rework_required'])

    def test_minor_exact_one_percent_requires_repair_not_pilot(self):
        result=audit_gate({'inspected_units':100,'findings':[{'unit_id':'a','family_id':'f','kind':'rationale_typo'}]})
        self.assertFalse(result['full_rework_required']);self.assertFalse(result['pilot_eligible'])
        self.assertEqual(result['action'],'VERSIONED_REPAIR_AND_REAUDIT')
        result=audit_gate({'inspected_units':99,'findings':[{'unit_id':'a','family_id':'f','kind':'rationale_typo'}]})
        self.assertTrue(result['full_rework_required'])

    def test_systemic_minor_error_forces_full_rework(self):
        findings=[{'unit_id':str(i),'family_id':str(i),'kind':'rationale_typo'} for i in range(2)]
        self.assertTrue(audit_gate({'inspected_units':1000,'findings':findings})['full_rework_required'])

    def test_missing_public_audit_coverage_rejected(self):
        ledger=self.ledger();key=list(ledger['submissions'][0]['answers'])[10]
        ledger['audit']['inspected_unit_ids'].remove(key);ledger['audit']['inspected_units']-=1
        with self.assertRaisesRegex(ValueError,'coverage'):convert(ledger)

    def test_non_fixture_projection_remains_unverified_development(self):
        ledger=self.ledger();ledger['synthetic_fixture']=False
        result=convert(ledger);validate_cohort(result['projection']);validate(ledger,result,digest(ledger))
        self.assertEqual(result['projection']['annotation_status'],'adjudicated_development_NOT_human_verified')
        self.assertFalse(result['pilot_eligible'])

    def test_bad_evidence_identity_outcomes_holdout_and_missing_forms(self):
        for action in ('evidence','identity','outcomes','holdout','missing'):
            ledger=self.ledger()
            if action=='evidence':ledger['submissions'][0]['answers'][next(iter(ledger['submissions'][0]['answers']))]['evidence_ids']=['missing']
            if action=='identity':ledger['submissions'][1]['annotator_id']=ledger['submissions'][0]['annotator_id']
            if action=='outcomes':ledger['submissions'][0]['outcomes']={'ASR':0}
            if action=='holdout':ledger['inventory']['split']='holdout'
            if action=='missing':ledger['submissions'][0]['answers'].popitem()
            with self.subTest(action=action),self.assertRaises(ValueError):convert(ledger)
