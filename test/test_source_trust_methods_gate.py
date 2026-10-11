import copy
import csv
import gzip
import io
import json
from pathlib import Path
import unittest
from ci.validate_source_trust_methods import freeze_check, readiness_check, validate_calibration, validate_artifacts

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
