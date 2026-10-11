import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from evaluation.source_trust_external_smoke import run, verify_intake

ROOT = Path('docs/research/source-trust-methods/external-artifacts')


class ExternalSmokeTests(unittest.TestCase):
    def test_actual_pinned_lattice_cases_and_no_benchmark_claim(self):
        report = run(ROOT)
        self.assertEqual(report['fides']['assertions_passed'], 5)
        self.assertEqual(report['actual_network_sink_executions'], 0)
        self.assertEqual(report['holdout_tasks_executed'], 0)
        self.assertIsNone(report['benchmark_scores'])
        self.assertEqual(report['fides']['runtime_adapter_status'], 'UNRUN')

    def test_changed_primitive_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            copy = Path(folder)/'artifacts';shutil.copytree(ROOT, copy)
            (copy/'fides/lattice_cell_21.py').write_text('raise RuntimeError("unverified code")')
            with self.assertRaisesRegex(ValueError, 'changed'): run(copy)

    def test_traversal_manifest_rejected_before_loading(self):
        with tempfile.TemporaryDirectory() as folder:
            copy = Path(folder)/'artifacts';shutil.copytree(ROOT, copy)
            manifest = json.loads((copy/'manifest.json').read_text())
            manifest['files'][0]['local_path'] = '../outside.py'
            (copy/'manifest.json').write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, 'path'): verify_intake(copy)

    def test_no_holdout_in_source_intake(self):
        manifest = verify_intake(ROOT)
        self.assertFalse(manifest['benchmark_task_materials_copied'])
        self.assertFalse(manifest['upstream_benchmark_claims_independently_verified'])

    def test_forged_manifest_cannot_authorize_changed_executable(self):
        with tempfile.TemporaryDirectory() as folder:
            copy = Path(folder)/'artifacts';shutil.copytree(ROOT, copy)
            blob = b'raise RuntimeError("not the reviewed upstream code")'
            (copy/'fides/lattice_cell_21.py').write_bytes(blob)
            manifest = json.loads((copy/'manifest.json').read_text())
            for record in manifest['files']:
                if record['local_path'] == 'fides/lattice_cell_21.py':
                    record['sha256'] = hashlib.sha256(blob).hexdigest()
            (copy/'manifest.json').write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, 'executable_pin'): run(copy)
