import copy
import csv
import gzip
import io
import json
from pathlib import Path
import unittest
from ci.validate_source_trust_methods import freeze_check, readiness_check, readiness_r3_check, validate_calibration, validate_artifacts

BASE=Path('docs/research/source-trust-methods/statistical-calibration')


class MethodsGateTests(unittest.TestCase):
    def packet(self):
        report=json.loads(gzip.decompress((BASE/'report.json.gz').read_bytes()))
        rows=list(csv.DictReader(io.StringIO(gzip.decompress((BASE/'trials.csv.gz').read_bytes()).decode())))
        return report,rows

    def test_actual_records_and_frozen_git_objects(self):
        self.assertEqual(freeze_check(),266)
        self.assertEqual(validate_artifacts()['validated_simulation_rows'],9600)
        self.assertEqual(readiness_check()['pilot'],'UNRUN')

    def test_changed_summary_count_rejected(self):
        report,rows=self.packet();report['summary'][0]['coverage_numerator']-=1
        with self.assertRaisesRegex(ValueError,'summary_counts'):validate_calibration(report,rows)

    def test_no_silent_duplicate_or_missing_trial(self):
        report,rows=self.packet();rows[-1]=dict(rows[0])
        with self.assertRaisesRegex(ValueError,'unique_trial'):validate_calibration(report,rows)

    def test_unresolved_bootstrap_power_not_success(self):
        report,rows=self.packet();rows[0]['component_gate_pass']='True'
        with self.assertRaisesRegex(ValueError,'excluded'):validate_calibration(report,rows)

    def test_coverage_recomputed_independently(self):
        report,rows=self.packet();rows[0]['covered']='False' if rows[0]['covered']=='True' else 'True'
        with self.assertRaisesRegex(ValueError,'coverage_recomputed'):validate_calibration(report,rows)

    def test_historical_grid_cannot_receive_formal_h5_credit(self):
        report,rows=self.packet()
        verdict=validate_calibration(report,rows)
        self.assertFalse(verdict['R1_H5_grid_eligible'])
        self.assertIn('RETRACTED',verdict['historical_claim_status'])

    def test_formal_name_with_low_rate_grid_rejected(self):
        report,rows=self.packet()
        report['version']='source-trust-statistical-calibration-2'
        report['estimand']={'grid':[0,.01,.05,.1,.25,.5]}
        report['config']['estimand']=report['estimand']
        with self.assertRaisesRegex(ValueError,'R1_H5_estimand_binding'):validate_calibration(report,rows)

    def test_new_artifacts_bind_to_R1_not_legacy_implementation(self):
        result=validate_artifacts(Path('docs/research/source-trust-methods/r3'))
        self.assertTrue(result['R1_H5_grid_eligible'])
        self.assertEqual(result['validated_simulation_rows'],9600)

    def test_joint_toy_power_cannot_authorize_actual_policy_or_pilot(self):
        verdict=readiness_r3_check()
        self.assertEqual(verdict['actual_policy_joint_power'],'UNRUN')
        self.assertEqual(verdict['toy_joint_power'],'MEASURED_INSUFFICIENT')
        packet=json.loads(Path('docs/research/source-trust-methods/r3/readiness.json').read_text())
        packet['gates']['actual_policy_joint_H5_power']='PASSED'
        with self.assertRaisesRegex(ValueError,'R3_no_automatic_authorization'):readiness_r3_check(packet)

    def test_missing_human_receipts_or_unrun_cannot_be_relabelled(self):
        for field in ('actual_human_annotators','pilot'):
            packet=json.loads(Path('docs/research/source-trust-methods/r3/readiness.json').read_text())
            if field=='pilot':packet[field]['executions']=1
            else:packet[field]=2
            with self.subTest(field=field),self.assertRaises(ValueError):readiness_r3_check(packet)
