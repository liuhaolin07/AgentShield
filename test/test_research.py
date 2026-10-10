"""Actual receipts, signed handles, fair cohorts and uncredited missing evidence."""

import json
import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path
from unittest.mock import patch

from benchmark.loader import load_dataset
from evaluation.__main__ import export_report
from evaluation.receiver import LoopbackReceiver
from evaluation.research import ablations, assess, metrics, run_research
from evaluation.research_plot import export_metrics_csv
from security.research_runtime import RESEARCH_ARMS, ResearchRuntime
from tools.local_http import HTTPReceipt


class ResearchExperimentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.receiver=LoopbackReceiver(); cls.receiver.__enter__()
        cls.cases=load_dataset()[0]['cases']

    @classmethod
    def tearDownClass(cls): cls.receiver.__exit__()

    def case(self,category,index=0):
        return [c for c in self.cases if c['category']==category][index]

    def test_unknown_format_real_delivery_vs_taint(self):
        case=self.case('direct_leakage')
        scan=assess(case,'scanner',1,self.receiver)
        full=assess(case,'full',1,self.receiver)
        self.assertEqual(scan.status,'FAILED'); self.assertTrue(scan.actual['body_matches'])
        self.assertEqual(full.status,'HELD'); self.assertEqual(full.actual['executor_calls'],0)
        self.assertIn('taint',full.actual['defense_modules'])
        self.assertFalse(full.actual['checks'][0]['scanner']['detected'])

    def test_transform_tracking_ablation_actual_escape(self):
        case=self.case('multi_step_attack')
        shallow=assess(case,'source_only',1,self.receiver)
        full=assess(case,'full',1,self.receiver)
        self.assertTrue(shallow.actual['body_matches']); self.assertEqual(shallow.status,'FAILED')
        self.assertEqual(full.status,'HELD'); self.assertEqual(full.actual['arrivals'],0)

    def test_detect_only_detects_but_really_sends(self):
        row=assess(self.case('direct_leakage'),'detect_only',1,self.receiver)
        self.assertEqual(row.status,'FAILED'); self.assertTrue(row.actual['body_matches'])
        self.assertIn('taint',row.actual['detector_modules']); self.assertFalse(row.defense_credit)
        self.assertFalse(row.actual['checks'][0]['enforced'])
        self.assertEqual(row.actual['audits'][-1]['decision'],'ALLOW')

    def test_scanner_and_taint_contribution_under_wrong_source_policy(self):
        # Frozen last known-format source has an intentionally inaccurate label.
        case=self.case('direct_leakage',-1)
        self.assertFalse(case['source']['sensitive'])
        taint=assess(case,'taint',1,self.receiver); full=assess(case,'full',1,self.receiver)
        self.assertEqual(taint.status,'FAILED'); self.assertTrue(taint.actual['body_matches'])
        self.assertEqual(full.status,'HELD'); self.assertIn('scanner',full.actual['defense_modules'])
        opaque=assess(self.case('direct_leakage',-2),'full',1,self.receiver)
        self.assertEqual(opaque.status,'FAILED'); self.assertTrue(opaque.actual['body_matches'])

    def test_coarse_taint_false_positive_is_kept_failed(self):
        case=self.case('benign',-1)
        full=assess(case,'full',1,self.receiver); scan=assess(case,'scanner',1,self.receiver)
        self.assertEqual(full.status,'FAILED'); self.assertTrue(full.actual['middleware_block'])
        self.assertTrue(full.actual['valid_observation']); self.assertFalse(full.defense_credit)
        self.assertEqual(scan.status,'HELD'); self.assertTrue(scan.actual['completed'])

    def test_model_then_http_has_two_actual_requests_without_defense(self):
        case=self.case('tool_result_leakage',1)
        open_row=assess(case,'no_defense',1,self.receiver); defended=assess(case,'full',1,self.receiver)
        self.assertEqual(open_row.actual['arrivals'],2)
        self.assertEqual(open_row.actual['executor_calls'],2)
        self.assertTrue(open_row.actual['receiver_records'][0]['path'].startswith('/model/'))
        self.assertTrue(open_row.actual['receiver_records'][1]['path'].startswith('/http/'))
        self.assertEqual(defended.actual['executor_calls'],0)

    def test_unsupported_and_live_prompts_are_never_credited(self):
        before=len(self.receiver.arrivals)
        case=self.case('prompt_injection')
        for arm in RESEARCH_ARMS:
            row=assess(case,arm,1,self.receiver)
            self.assertEqual(row.status,'UNRUN'); self.assertFalse(row.defense_credit)
            self.assertEqual(row.actual['unrun_reason'],'live_llm_required')
        self.assertEqual(len(self.receiver.arrivals),before)

    def test_fabricated_sender_receipt_has_no_independent_credit(self):
        with patch('security.runtime.send_http',return_value=HTTPReceipt(202,7,'0'*64)):
            row=assess(self.case('benign',2),'full',1,self.receiver)
        self.assertEqual(row.status,'FAILED'); self.assertFalse(row.actual['valid_observation'])
        self.assertFalse(row.defense_credit)

    def test_inconsistent_audit_is_invalid_not_success(self):
        with patch('evaluation.research._audits',return_value=[]):
            row=assess(self.case('direct_leakage'),'full',1,self.receiver)
        self.assertEqual(row.status,'FAILED'); self.assertFalse(row.actual['valid_observation'])

    def test_missing_network_is_unrun_with_undefined_metrics(self):
        with patch('evaluation.research.LoopbackReceiver',side_effect=OSError):
            report=run_research(repeat=1)
        self.assertEqual(report['summary'],{'HELD':0,'FAILED':0,'UNRUN':840})
        for stats in report['metrics'].values():
            self.assertIsNone(stats['ASR']['value']); self.assertEqual(stats['ASR']['denominator'],0)
            self.assertIsNone(stats['paired_cost']['latency_ms']['mean'])

    def test_metric_math_exclusions_cost_pairs_and_exports(self):
        cases=[self.case('direct_leakage'),self.case('benign',2),self.case('benign',-1),self.case('prompt_injection'),self.case('measurement_control')]
        rows=[asdict(assess(case,arm,1,self.receiver)) for arm in RESEARCH_ARMS for case in cases]
        measured=metrics(rows); comparisons=ablations(rows)
        full=measured['full']
        self.assertEqual(full['ASR'],{'numerator':0,'denominator':1,'value':0})
        self.assertEqual(full['FPR'],{'numerator':1,'denominator':2,'value':.5})
        self.assertEqual(full['TCR'],{'numerator':1,'denominator':2,'value':.5})
        self.assertEqual(full['excluded'],{'unrun':1,'control':1})
        self.assertEqual(full['paired_cost']['latency_ms']['pairs'],1)
        self.assertEqual(full['paired_cost']['token_overhead']['status'],'UNRUN')
        self.assertEqual(comparisons['A1']['additional_full_attack_blocks'],1)
        self.assertEqual(comparisons['A1']['additional_full_benign_blocks'],1)
        report={'experiment':'v1.9','metrics':measured,'ablations':comparisons,'results':rows}
        with tempfile.TemporaryDirectory() as directory:
            export_report(report,Path(directory)); export_metrics_csv(report,Path(directory))
            self.assertIn('arm,',(Path(directory)/'cases.csv').read_text())
            self.assertIn('token_overhead',(Path(directory)/'metrics.csv').read_text())
            self.assertEqual(len(json.loads((Path(directory)/'report.json').read_text())['results']),35)

    def test_experimental_modes_require_explicit_local_transport(self):
        with self.assertRaises(ValueError): ResearchRuntime(arm='detect_only')
        with self.assertRaises(ValueError): ResearchRuntime(arm='invalid')


if __name__=='__main__': unittest.main()
