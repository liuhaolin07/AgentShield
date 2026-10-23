"""Engineering tests only. These objects are NOT received research materials."""
import importlib.util
from pathlib import Path
import unittest

MODULE_PATH = Path(__file__).resolve().parents[1] / 'design_binding.py'

def load_module():
    if not MODULE_PATH.exists():
        return None
    spec = importlib.util.spec_from_file_location('prospective_design_binding', MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

class DesignBindingTests(unittest.TestCase):
    def test_rejects_actual_historical_post_outcome_declaration(self):
        module = load_module()
        self.assertIsNotNone(module, 'prospective design gate is missing')
        import json
        historical = Path(__file__).resolve().parents[2] / 'ledger-input-validation-v1/run-001/sampling-contract.json'
        result = module.check_packet(json.loads(historical.read_text(encoding='utf-8')))
        self.assertEqual(result['state'], 'REJECTED_POST_OUTCOME_DESIGN')
        self.assertFalse(result['experiment_authorized'])

    def test_selected_finite_frame_draft_stays_blocked_without_real_refs(self):
        module = load_module()
        import json
        proposal = json.loads((MODULE_PATH.parent / 'proposal.json').read_text(encoding='utf-8'))
        result = module.check_packet(proposal)
        self.assertEqual(result['state'], 'PENDING_REAL_DESIGN_INPUTS')
        self.assertEqual(result['target_population'], 'REGISTERED_FINITE_SOURCE_FRAME')
        self.assertIn('sampling_frame_ref', result['missing_inputs'])
        self.assertFalse(result['interval_selection_ready'])
        self.assertFalse(result['experiment_authorized'])

    def test_exact_rejection_sampler_is_replayable_and_order_invariant(self):
        module = load_module()
        self.assertTrue(hasattr(module, 'draw_clusters'), 'replayable SRSWOR sampler is missing')
        frames = {'development': ['c', 'a', 'b'], 'holdout': ['z', 'x', 'y']}
        selected, consumed = module.draw_clusters(frames, bytes(range(64)), 2)
        self.assertEqual(selected, {'development': ['a', 'c'], 'holdout': ['z', 'y']})
        self.assertEqual(consumed, 4)
        shuffled = {k: list(reversed(v)) for k, v in reversed(list(frames.items()))}
        self.assertEqual(module.draw_clusters(shuffled, bytes(range(64)), 2), (selected, consumed))
        with self.assertRaisesRegex(ValueError, 'random_bytes_exhausted'):
            module.draw_clusters(frames, b'\xff', 2)
        with self.assertRaises(ValueError):
            module.draw_clusters(frames, bytes(range(64)), True)

    def test_complete_metadata_replays_selection_and_validates_full_plan(self):
        module = load_module()
        self.assertTrue(hasattr(module, 'verify_complete_design'), 'complete metadata validator is missing')
        from engineering_fixture import make_packet
        packet = make_packet(module)
        result = module.check_packet(packet)
        self.assertEqual(result['state'], 'DESIGN_METADATA_VALID_NOT_AUTHORIZED')
        self.assertEqual(result['selected_clusters_per_split'], {'development':30, 'holdout':30})
        self.assertEqual(result['configurations_per_split'], 81)
        self.assertEqual(result['planned_execution_rows_per_split'], 29160)
        self.assertTrue(result['selection_replayed'])
        self.assertFalse(result['source_frame_authenticity_verified'])
        self.assertFalse(result['pre_outcome_timing_independently_verified'])
        self.assertFalse(result['experiment_authorized'])
        self.assertEqual(result['sampling_probabilities']['development'], {'numerator':30, 'denominator':32})

    def test_frame_rejects_renamed_shared_lineage_and_missing_h3_masks(self):
        module = load_module()
        self.assertTrue(hasattr(module, 'validate_frame'), 'lineage/material frame validator is missing')
        from engineering_fixture import make_packet
        import json
        from copy import deepcopy
        packet = make_packet(module)
        frame = json.loads(packet['documents'][packet['sampling_frame_ref']])
        module.validate_frame(frame, packet['role'])
        mutations = [
            ('lineage', lambda f: f['units'][1].update(lineage_id=f['units'][0]['lineage_id'])),
            ('source_fingerprint', lambda f: f['units'][1]['members'][0].update(source_sha256=f['units'][0]['members'][0]['source_sha256'])),
            ('H3_mask', lambda f: f['units'][0]['members'][0]['H3_eligible_by_seed'].pop('17')),
            ('member_pair', lambda f: f['units'][0]['members'].pop()),
            ('unknown_metadata', lambda f: f['units'][0].update(outcome=1)),
        ]
        for name, mutate in mutations:
            with self.subTest(name=name):
                altered = deepcopy(frame)
                mutate(altered)
                with self.assertRaises(ValueError):
                    module.validate_frame(altered, packet['role'])
        historical = json.loads((MODULE_PATH.parent.parent/'candidate-materials-v1/manifest.json').read_text(encoding='utf-8'))
        altered = deepcopy(frame)
        altered['units'][0]['members'][0]['source_sha256'] = historical['families'][0]['contract']['source_sha256']
        with self.assertRaisesRegex(ValueError, 'known_author_fixture'):
            module.validate_frame(altered, packet['role'])

    def test_each_row_binds_design_source_task_graph_mode_and_executor(self):
        module = load_module()
        self.assertTrue(hasattr(module, 'make_bound_row'), 'row binding gate is missing')
        from engineering_fixture import make_packet
        from copy import deepcopy
        import json
        packet = make_packet(module)
        frame = module.document(packet, 'sampling_frame_ref')
        cid = packet['selected_cluster_ids']['development'][0]
        member = next(u for u in frame['units'] if u['cluster_id'] == cid)['members'][0]
        condition = next(c for c in module.configurations() if c['experiment'] == 'E3')
        row = module.make_bound_row(packet, 'development', member['family_id'], condition, 'precision', 'attack')
        self.assertTrue(module.check_bound_row(packet, row))
        self.assertEqual(row['pre_outcome_design_commitment_sha256'], packet['pre_outcome_design_commitment_sha256'])
        self.assertEqual(row['source_sha256'], member['source_sha256'])
        for field, value in [('defense_mode','conservative'), ('source_sha256','0'*64), ('H3_eligible',False),
                             ('graph_sha256','0'*64), ('executor_sha256','0'*64), ('pre_outcome_design_commitment_sha256','0'*64)]:
            with self.subTest(field=field):
                forged = deepcopy(row)
                forged[field] = value
                forged['row_id'] = module.digest({k:v for k,v in forged.items() if k != 'row_id'})
                with self.assertRaises(ValueError):
                    module.check_bound_row(packet, forged)
        historical = json.loads((MODULE_PATH.parent.parent/'ledger-input-validation-v1/run-001/sampling-contract.json').read_text(encoding='utf-8'))
        with self.assertRaisesRegex(ValueError, 'complete_prospective_design_required'):
            module.make_bound_row(historical, 'development', member['family_id'], condition, 'precision', 'attack')

    def test_git_cli_binds_utf8_metadata_and_refuses_symlink_blobs(self):
        module = load_module()
        self.assertTrue(hasattr(module, 'read_git_packet'), 'commit-bound CLI is missing')
        import json, os, subprocess, sys, tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            def git(*args, input=None):
                return subprocess.check_output(['git','-c','core.autocrlf=false','-c','commit.gpgsign=false',
                    '-c','core.hooksPath='+str(root/'no-hooks'),'-C',str(root),*args], input=input)
            git('init','-q')
            git('config','user.name','Engineering Test')
            git('config','user.email','engineering@example.invalid')
            relative = 'docs/research/source-trust/convergence/prospective-design-v1/proposal.json'
            target = root/relative
            target.parent.mkdir(parents=True)
            raw = (MODULE_PATH.parent/'proposal.json').read_bytes()
            target.write_bytes(raw)
            git('add','--',relative)
            git('commit','-qm','Engineering metadata only')
            revision = git('rev-parse','HEAD').decode().strip()
            command = [sys.executable,'-I','-X','utf8',str(MODULE_PATH),'--repo',str(root),'--commit',revision,'--packet',relative]
            env = dict(os.environ); env.pop('PYTHONPATH',None)
            result = subprocess.run(command, env=env, capture_output=True)
            self.assertEqual(result.returncode,2,result.stderr.decode('utf-8',errors='replace'))
            report = json.loads(result.stdout)
            self.assertEqual(report['packet_git_commit'],revision)
            self.assertEqual(report['packet_file_sha256'],module.sha(raw))
            self.assertFalse(report['pre_outcome_timing_independently_verified'])
            target.write_text('{"outcomes_seen_before_declaration":true}',encoding='utf-8')
            unchanged = subprocess.run(command,env=env,capture_output=True)
            self.assertEqual(json.loads(unchanged.stdout)['packet_file_sha256'],module.sha(raw))
            with self.assertRaisesRegex(ValueError,'metadata_git_path'):
                module.read_git_packet(root,revision,'../outside.json')
            with self.assertRaisesRegex(ValueError,'metadata_git_path'):
                module.read_git_packet(root,revision,'docs/research/source-trust/convergence/candidate-materials-v1/payloads/forbidden.json')
            symlink_path = relative.replace('proposal.json','symlink.json')
            blob = git('hash-object','-w','--stdin',input=b'../../outside-secret.json').decode().strip()
            git('update-index','--add','--cacheinfo','120000,'+blob+','+symlink_path)
            git('commit','-qm','Engineering symlink object only')
            symlink_commit = git('rev-parse','HEAD').decode().strip()
            with self.assertRaisesRegex(ValueError,'regular_git_blob_required'):
                module.read_git_packet(root,symlink_commit,symlink_path)

    def test_complete_bundle_rejects_hidden_outcomes_and_configuration_gaps(self):
        module = load_module()
        from engineering_fixture import make_packet, mutate_document
        packet = make_packet(module)
        for name, mutate in [
            ('hidden_outcomes', lambda d: d.update(outcomes=[1,0])),
            ('missing_configuration', lambda d: d['graphs']['development'].pop()),
            ('invalid_graph_digest', lambda d: d['graphs']['development'][0].update(graph_sha256='not-a-digest')),
            ('inflated_budget', lambda d: d['planned_execution_rows'].update(development=30000)),
        ]:
            with self.subTest(name=name):
                altered = mutate_document(module, packet, 'preexecution_plan_ref', mutate)
                with self.assertRaises(ValueError):
                    module.check_packet(altered)

    def test_dependencies_use_fixed_git_blobs_without_worktree_reads(self):
        module = load_module()
        from engineering_fixture import make_packet
        from unittest.mock import patch
        import hashlib, subprocess
        baseline = 'd2f2f02d8066bcad7902200aebe978015f5266d7'
        paths = ('docs/research/source-trust/protocol-draft.json',
                 'docs/research/source-trust/convergence/candidate-materials-v1/manifest.json',
                 'docs/research/source-trust/convergence/candidate-materials-v1/authoring-spec.json')
        repo = MODULE_PATH.parent.parents[4]
        expected = {p: hashlib.sha256(subprocess.check_output(
            ['git', '--no-replace-objects', '-C', str(repo), 'show', baseline+':'+p])).hexdigest()
                    for p in paths}
        packet = make_packet(module)
        read_bytes, read_text = Path.read_bytes, Path.read_text
        for relative in paths:
            with self.subTest(dependency=relative):
                forbidden = repo / relative
                def guarded_bytes(path, *args, **kwargs):
                    self.assertNotEqual(path, forbidden, 'dependency must not read the worktree')
                    return read_bytes(path, *args, **kwargs)
                def guarded_text(path, *args, **kwargs):
                    self.assertNotEqual(path, forbidden, 'dependency must not read the worktree')
                    return read_text(path, *args, **kwargs)
                with patch.object(Path, 'read_bytes', guarded_bytes), patch.object(Path, 'read_text', guarded_text):
                    self.assertEqual(len(module.configurations()), 81)
                    report = module.check_packet(packet)
                self.assertEqual(report['dependency_git_commit'], baseline)
                self.assertEqual(report['dependency_sha256'], expected)
                with self.assertRaisesRegex(ValueError, 'metadata_git_path'):
                    module.read_git_packet(repo, baseline, relative)

    def test_configuration_digest_list_is_structured_cli_rejection(self):
        module = load_module()
        from engineering_fixture import make_packet, mutate_document
        import json, os, subprocess, sys, tempfile
        packet = make_packet(module)
        altered = mutate_document(module, packet, 'executor_contract_ref',
            lambda doc: doc.update(configuration_sha256=['coarse', 'precision', 'conservative']))
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp)
            def git(*args):
                return subprocess.check_output(['git', '-c', 'core.autocrlf=false',
                    '-c', 'commit.gpgsign=false', '-c', 'core.hooksPath='+str(repo/'no-hooks'),
                    '-C', str(repo), *args], stderr=subprocess.PIPE)
            git('init', '-q')
            git('config', 'user.name', 'Engineering Test')
            git('config', 'user.email', 'engineering@example.invalid')
            prefix = 'docs/research/source-trust/convergence/prospective-design-v1/'
            for name, value in [('valid.json', packet), ('invalid.json', altered)]:
                target = repo/(prefix+name)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(module.canonical(value))
            git('add', '--', prefix)
            git('commit', '-qm', 'Engineering metadata only')
            revision = git('rev-parse', 'HEAD').decode().strip()
            missing = subprocess.run(['git', '-C', str(repo), 'cat-file', '-e',
                'd2f2f02d8066bcad7902200aebe978015f5266d7^{commit}'], capture_output=True)
            self.assertNotEqual(missing.returncode, 0, 'packet repository must not contain trusted baseline')
            env = dict(os.environ); env.pop('PYTHONPATH', None)
            command = [sys.executable, '-I', '-X', 'utf8', str(MODULE_PATH),
                       '--repo', str(repo), '--commit', revision, '--packet']
            valid = subprocess.run(command+[prefix+'valid.json'], env=env, capture_output=True)
            self.assertEqual(valid.returncode, 0, valid.stderr.decode('utf-8', errors='replace'))
            report = json.loads(valid.stdout)
            self.assertEqual(report['state'], 'DESIGN_METADATA_VALID_NOT_AUTHORIZED')
            self.assertEqual(report['dependency_git_commit'], 'd2f2f02d8066bcad7902200aebe978015f5266d7')
            self.assertFalse(report['experiment_authorized'])
            invalid = subprocess.run(command+[prefix+'invalid.json'], env=env, capture_output=True)
            self.assertEqual(invalid.returncode, 1)
            self.assertNotIn(b'Traceback', invalid.stderr)
            self.assertEqual(json.loads(invalid.stdout),
                {'state': 'INVALID_DESIGN_METADATA', 'experiment_authorized': False})
        with self.assertRaisesRegex(ValueError, 'executor_declaration_binding'):
            module.check_packet(altered)

    def test_json_exponent_overflow_is_rejected(self):
        module = load_module()
        for raw in (b'{"x":1e999}', b'{"x":-1e999}'):
            with self.subTest(raw=raw):
                with self.assertRaisesRegex(ValueError, '^nonfinite_metadata_json$'):
                    module.parse_json(raw)

    def test_pending_proposal_exponent_overflow_is_structured_cli_rejection(self):
        module = load_module()
        import json, os, subprocess, sys, tempfile
        proposal = json.loads((MODULE_PATH.parent/'proposal.json').read_text(encoding='utf-8'))
        self.assertEqual(proposal['documents'], {})
        self.assertTrue(all(proposal[ref] is None for ref in module.REFS))
        self.assertEqual(module.check_packet(proposal)['state'], 'PENDING_REAL_DESIGN_INPUTS')
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp)
            def git(*args):
                return subprocess.check_output(['git', '-c', 'core.autocrlf=false',
                    '-c', 'commit.gpgsign=false', '-c', 'core.hooksPath='+str(repo/'no-hooks'),
                    '-C', str(repo), *args], stderr=subprocess.PIPE)
            git('init', '-q')
            git('config', 'user.name', 'Engineering Test')
            git('config', 'user.email', 'engineering@example.invalid')
            prefix = 'docs/research/source-trust/convergence/prospective-design-v1/'
            cases = [('positive.json', '1e999'), ('negative.json', '-1e999')]
            raw = json.dumps(proposal, ensure_ascii=False, allow_nan=False)
            self.assertEqual(raw.count('"documents": {}'), 1)
            for name, token in cases:
                target = repo/(prefix+name)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(raw.replace('"documents": {}',
                    '"documents": {"overflow": '+token+'}'), encoding='utf-8')
            git('add', '--', prefix)
            git('commit', '-qm', 'Engineering exponent overflow metadata only')
            revision = git('rev-parse', 'HEAD').decode().strip()
            env = dict(os.environ); env.pop('PYTHONPATH', None)
            command = [sys.executable, '-I', '-X', 'utf8', str(MODULE_PATH),
                       '--repo', str(repo), '--commit', revision, '--packet']
            for name, token in cases:
                with self.subTest(token=token):
                    result = subprocess.run(command+[prefix+name], env=env, capture_output=True)
                    self.assertEqual(result.returncode, 1, result.stdout.decode('utf-8', errors='replace'))
                    self.assertEqual(result.stderr, b'')
                    self.assertEqual(json.loads(result.stdout),
                        {'state': 'INVALID_DESIGN_METADATA', 'experiment_authorized': False})

    def check_reference_values(self, ref_name, field):
        module = load_module()
        from engineering_fixture import make_packet, mutate_document
        import json, os, subprocess, sys, tempfile
        packet = make_packet(module)
        cases = [('engineering', packet, 0, 'DESIGN_METADATA_VALID_NOT_AUTHORIZED')]
        for name, value in [('plain_text', ' 工程 outcomes {"outcomes":[0,1]} \t'),
                            ('null', None), ('object', {'outcomes': [0, 1]}),
                            ('list', []), ('empty', ''), ('whitespace', ' \t\r\n')]:
            altered = mutate_document(module, packet, ref_name,
                lambda doc, value=value: doc.update({field: value}))
            valid = name == 'plain_text'
            cases.append((name, altered, 0 if valid else 1,
                          'DESIGN_METADATA_VALID_NOT_AUTHORIZED' if valid else 'INVALID_DESIGN_METADATA'))
        proposal = json.loads((MODULE_PATH.parent/'proposal.json').read_text(encoding='utf-8'))
        self.assertTrue(all(proposal[ref] is None for ref in module.REFS))
        cases.append(('pending', proposal, 2, 'PENDING_REAL_DESIGN_INPUTS'))
        blocked = ('experiment_authorized', 'interval_selection_ready', 'coverage_certified',
                   'power_validated', 'pre_outcome_timing_independently_verified',
                   'source_frame_authenticity_verified', 'independence_verified', 'pilot_dispatchable')
        with tempfile.TemporaryDirectory() as temp:
            repo = Path(temp)
            def git(*args):
                return subprocess.check_output(['git', '-c', 'core.autocrlf=false',
                    '-c', 'commit.gpgsign=false', '-c', 'core.hooksPath='+str(repo/'no-hooks'),
                    '-C', str(repo), *args], stderr=subprocess.PIPE)
            git('init', '-q')
            git('config', 'user.name', 'Engineering Test')
            git('config', 'user.email', 'engineering@example.invalid')
            prefix = 'docs/research/source-trust/convergence/prospective-design-v1/'
            for name, value, _, _ in cases:
                target = repo/(prefix+name+'.json')
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(module.canonical(value))
            git('add', '--', prefix)
            git('commit', '-qm', 'Engineering reference syntax metadata only')
            revision = git('rev-parse', 'HEAD').decode().strip()
            env = dict(os.environ); env.pop('PYTHONPATH', None)
            command = [sys.executable, '-I', '-X', 'utf8', str(MODULE_PATH),
                       '--repo', str(repo), '--commit', revision, '--packet']
            for name, value, exitcode, state in cases:
                with self.subTest(case=name, entrypoint='check_packet'):
                    if exitcode == 1:
                        with self.assertRaisesRegex(ValueError, '^'+field+'$'):
                            module.check_packet(value)
                    else:
                        report = module.check_packet(value)
                        self.assertEqual(report['state'], state)
                        for flag in blocked:
                            self.assertIs(report[flag], False, flag)
                        self.assertEqual(report['formal_materials_admitted'], 0)
                with self.subTest(case=name, entrypoint='git_cli'):
                    result = subprocess.run(command+[prefix+name+'.json'], env=env, capture_output=True)
                    self.assertEqual(result.returncode, exitcode, result.stdout.decode('utf-8', errors='replace'))
                    self.assertEqual(result.stderr, b'')
                    report = json.loads(result.stdout)
                    if exitcode == 1:
                        self.assertEqual(report, {'state': 'INVALID_DESIGN_METADATA',
                                                  'experiment_authorized': False})
                    else:
                        self.assertEqual(report['state'], state)
                        self.assertEqual(report['packet_git_commit'], revision)
                        for flag in blocked:
                            self.assertIs(report[flag], False, flag)
                        self.assertEqual(report['formal_materials_admitted'], 0)

    def test_origin_evidence_ref_requires_nonblank_string(self):
        self.check_reference_values('sampling_randomness_ref', 'origin_evidence_ref')

    def test_review_record_ref_requires_nonblank_string(self):
        self.check_reference_values('cluster_independence_evidence_ref', 'review_record_ref')

    def test_json_duplicate_keys_and_nonfinite_values_are_rejected(self):
        module = load_module()
        self.assertTrue(hasattr(module,'parse_json'), 'strict metadata JSON decoder is missing')
        for raw in (b'{"a":1,"a":2}', b'{"x":NaN}', b'{"x":Infinity}'):
            with self.subTest(raw=raw):
                with self.assertRaises(ValueError):
                    module.parse_json(raw)
        self.assertEqual(module.parse_json('{"说明":"工程元数据"}'.encode('utf-8')), {'说明':'工程元数据'})

if __name__ == '__main__':
    unittest.main()
