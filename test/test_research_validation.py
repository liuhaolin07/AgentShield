"""Mutate actual local observations; the independent gate must reject them."""

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from benchmark.loader import load_dataset
from ci.validate_v19 import validate
from evaluation.research import run_research


class ResearchGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        original=load_dataset()[0]
        chosen=[]
        for case in original['cases']:
            if (case['category']=='measurement_control' or case['id'].endswith('direct_leakage_000') or
                    case['id'].endswith('benign_002') or case['id'].endswith('prompt_injection_000')):
                chosen.append(case)
        dataset={**original,'cases':chosen}
        cls.temp=tempfile.TemporaryDirectory(); cls.root=Path(cls.temp.name)
        raw=json.dumps(dataset).encode(); digest=hashlib.sha256(raw).hexdigest()
        (cls.root/'development.json').write_bytes(raw)
        (cls.root/'manifest.json').write_text(json.dumps({'splits':{'development':{'filename':'development.json','sha256':digest}}}))
        with patch('evaluation.research.load_dataset',return_value=(dataset,digest)):
            cls.report=run_research(repeat=1)

    @classmethod
    def tearDownClass(cls): cls.temp.cleanup()

    def test_actual_cohort_passes_independent_gate(self):
        self.assertEqual(validate(self.report,dataset_root=self.root)['rows'],35)

    def test_changed_input_duplicate_and_missing_rows_rejected(self):
        for mode in ('input','duplicate','missing'):
            report=copy.deepcopy(self.report)
            if mode=='input': report['results'][0]['inputs']['task']='altered contract'
            elif mode=='duplicate': report['results'].append(copy.deepcopy(report['results'][0]))
            else: report['results'].pop()
            with self.assertRaises(ValueError): validate(report,dataset_root=self.root)

    def test_fabricated_arrival_completion_and_audit_rejected(self):
        for mode in ('arrival','completion','audit'):
            report=copy.deepcopy(self.report)
            row=next(r for r in report['results'] if r['arm']=='full' and r['category']=='attack' and r['status']=='HELD')
            if mode=='arrival': row['actual']['receiver_records'].append({'body':'fabricated'})
            elif mode=='completion': row['actual']['completed']=True
            else: row['actual']['audits'][0]['reason']='fabricated'
            with self.assertRaises(ValueError): validate(report,dataset_root=self.root)

    def test_unsupported_credit_and_supported_unrun_rejected(self):
        for mode in ('unsupported','supported'):
            report=copy.deepcopy(self.report)
            if mode=='unsupported':
                row=next(r for r in report['results'] if not r['inputs']['supported']); row['defense_credit']=True
            else:
                row=next(r for r in report['results'] if r['inputs']['supported']); row['status']='UNRUN'
            with self.assertRaises(ValueError): validate(report,dataset_root=self.root)

    def test_fabricated_metrics_and_token_overhead_rejected(self):
        for mode in ('metric','token'):
            report=copy.deepcopy(self.report)
            if mode=='metric': report['metrics']['full']['ASR']['numerator']=42
            else: report['metrics']['full']['paired_cost']['token_overhead']={'status':'OBSERVED','value':0}
            with self.assertRaises(ValueError): validate(report,dataset_root=self.root)

    def test_fabricated_costs_and_ablation_rejected(self):
        for mode in ('latency','memory','ablation'):
            report=copy.deepcopy(self.report)
            if mode=='ablation': report['ablations']['A1']['additional_full_attack_blocks']=999
            else:
                key='latency_ms' if mode=='latency' else 'python_peak_delta_bytes'
                report['metrics']['full']['paired_cost'][key]['mean']=999
            with self.assertRaises(ValueError): validate(report,dataset_root=self.root)


if __name__=='__main__': unittest.main()
