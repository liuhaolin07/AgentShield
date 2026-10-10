"""Only development contracts run during development; reserved bytes hash only."""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from benchmark.build_dataset import CATEGORIES, VERSION, build, oracle
from benchmark.loader import DATASET_ROOT, load_dataset


class BenchmarkContractTests(unittest.TestCase):
    def test_scale_and_categories(self):
        dataset,_=load_dataset()
        self.assertEqual(len(dataset['cases']),120)
        self.assertEqual(set(case['category'] for case in dataset['cases']),set(CATEGORIES))
        self.assertEqual(sum(case['risk']=='attack' for case in dataset['cases']),100)
        self.assertEqual(sum(case['risk']=='benign' for case in dataset['cases']),18)
        self.assertEqual(sum(not case['supported'] for case in dataset['cases']),18)

    def test_deterministic_development_authoring_and_unique_sources(self):
        dataset,_=load_dataset()
        self.assertEqual(dataset,build('development'))
        sources=[c['source']['content'] for c in dataset['cases']]
        self.assertEqual(len(set(sources)),len(sources))

    def test_development_oracle_contracts(self):
        dataset,_=load_dataset()
        for case in dataset['cases']:
            self.assertEqual(oracle(case['source']['content'],case['operations']),case['expected']['wire_data'])
            self.assertEqual(case['expected']['allowed'],case['risk']!='attack')

    def test_reserved_is_only_hash_checked(self):
        manifest=json.loads((DATASET_ROOT/'manifest.json').read_text())
        item=manifest['splits']['reserved']
        self.assertEqual(item['tasks'],40)
        self.assertEqual(hashlib.sha256((DATASET_ROOT/item['filename']).read_bytes()).hexdigest(),item['sha256'])
        self.assertEqual(manifest['dataset_version'],VERSION)

    def test_mutation_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for name in ('manifest.json','development.json'):
                (root/name).write_bytes((DATASET_ROOT/name).read_bytes())
            with (root/'development.json').open('a') as file: file.write(' ')
            with self.assertRaisesRegex(ValueError,'integrity mismatch'):
                load_dataset(root=root)

    def test_unknown_split(self):
        with self.assertRaises(ValueError):
            load_dataset('unfrozen')

    def test_negative_controls_and_unsupported_scope_preserved(self):
        dataset,_=load_dataset()
        classes=[c['source']['classification'] for c in dataset['cases']]
        self.assertEqual(classes.count('intentional_source_misclassification'),4)
        self.assertEqual(classes.count('coarse_taint_projection'),2)
        self.assertTrue(any(c['unsupported_reason']=='live_llm_required' for c in dataset['cases']))
        self.assertTrue(any(c['unsupported_reason']=='unsupported_transform' for c in dataset['cases']))


if __name__=='__main__':
    unittest.main()
