"""Independent raw-count gate mutation tests, not defense attack experiments."""
import copy
import csv
import gzip
import io
import json
from pathlib import Path
import unittest

from ci.validate_source_trust_joint import validate, validate_artifacts

BASE = Path('docs/research/source-trust-methods/r3/joint-calibration')


class JointRawGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = json.loads(gzip.decompress((BASE / 'report.json.gz').read_bytes()))
        cls.rows = [list(csv.DictReader(io.StringIO(gzip.decompress((BASE / (name + '.csv.gz')).read_bytes()).decode())))
                    for name in ('trials', 'graphs', 'e0')]

    def packet(self):
        # Shallow-copy immutable row strings; replace only the mutated row.
        return copy.deepcopy(self.report), [[dict(row) for row in rows] for rows in self.rows]

    def test_retained_generation_objects_and_all_raw_counts(self):
        result = validate_artifacts(BASE)
        self.assertEqual(result['trial_rows'], 2000)
        self.assertEqual(result['graph_rows'], 35000)
        self.assertEqual(result['E0_rows'], 2000)
        self.assertEqual(result['H5_statistics'], 13)
        self.assertFalse(result['pilot_eligible'])

    def test_independent_R1_grid_check_not_implementation_grid(self):
        report, rows = self.packet()
        report['config']['estimand']['grid'] = [0, .01, .05, .10, .25, .50]
        with self.assertRaisesRegex(ValueError, 'H5_estimand'):
            validate(report, *rows)

    def test_duplicate_graph_or_E0_rejected(self):
        for index, reason in ((1, 'duplicate_graph'), (2, 'E0_not_duplicated')):
            report, rows = self.packet()
            rows[index][1] = dict(rows[index][0])
            with self.subTest(table=index), self.assertRaisesRegex(ValueError, reason):
                validate(report, *rows)

    def test_unobserved_trial_cannot_be_reported_as_confirmed(self):
        report, rows = self.packet()
        row = next(row for row in rows[0] if row['coverage_gate'] == 'False')
        row['joint_confirmation'] = 'True'
        with self.assertRaisesRegex(ValueError, 'joint_gate_joint_confirmation'):
            validate(report, *rows)

    def test_truth_and_intervals_not_accepted_on_author_assertion(self):
        for field, reason in (('true_vector', 'declared_model_truth'),
                              ('intervals', 'intervals_from_raw_counts')):
            report, rows = self.packet()
            value = '[]'
            if field == 'true_vector':
                truth = json.loads(rows[0][0][field]);truth[0] += .01
                value = json.dumps(truth)
            rows[0][0][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, reason):
                validate(report, *rows)

    def test_synthetic_missing_and_denominator_cannot_be_erased(self):
        report, rows = self.packet()
        report['summary'][0]['denominator'] -= 1
        with self.assertRaisesRegex(ValueError, 'summary_denominator'):
            validate(report, *rows)


if __name__ == '__main__':
    unittest.main()
