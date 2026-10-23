"""Prospective design metadata gate. No executor, sockets or admission authority."""
import hashlib
import json
import math
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCHEMA = 'source-trust-prospective-design-v1'
PROTOCOL_SHA256 = '21468cf426f4b6aa0fd0671704fe38ea3442d0be45820a21b07092e0960b7d04'
DEPENDENCY_GIT_COMMIT = 'd2f2f02d8066bcad7902200aebe978015f5266d7'
DEPENDENCY_SHA256 = {
    'docs/research/source-trust/protocol-draft.json': PROTOCOL_SHA256,
    'docs/research/source-trust/convergence/candidate-materials-v1/manifest.json':
        'e22a600d6c0dbc26d7ca640950a4b74d510e0dec8c76ee56a08718b56731245b',
    'docs/research/source-trust/convergence/candidate-materials-v1/authoring-spec.json':
        '4e04bd86e980c3f4a3346becefdcc6f7f6e060a5af2ccfae79c2a1a289a96117'}
REFS = ('sampling_frame_ref', 'sampling_randomness_ref', 'cluster_independence_evidence_ref',
        'preexecution_plan_ref', 'executor_contract_ref')
ESTIMAND = {
    'population': 'REGISTERED_FINITE_SOURCE_FRAME',
    'outcome_target': 'MEAN_POTENTIAL_BINARY_ENDPOINT_UNDER_FROZEN_EXECUTION_REGIME',
    'family_weighting': 'EQUAL_FRAME_FAMILIES',
    'condition_weighting': 'ORIGINAL_FIXED_17_RECIPES',
    'H3_weighting': 'EQUAL_FRAME_ELIGIBLE_FAMILIES_THEN_EQUAL_ELIGIBLE_SEEDS',
    'injection_seeds': 'FIXED_GRID_NOT_RANDOM_SAMPLE_OF_ALL_SEEDS'}
SELECTION = {'design': 'SRSWOR_WITHIN_PRESPECIFIED_SPLIT_FRAMES', 'unit': 'TEMPLATE_LINEAGE_CLUSTER',
             'clusters_per_split': 30, 'families_per_cluster': 2, 'source_kinds': ['file', 'tool'],
             'randomness_assumption': 'EXTERNAL_RANDOM_BYTES_UNIFORM_INDEPENDENT_NOT_MACHINE_PROVEN'}

def require(condition, message):
    if not condition:
        raise ValueError(message)

def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def digest(value):
    return sha(canonical(value))


def parse_json(raw):
    def pairs(items):
        result = {}
        for name, value in items:
            require(name not in result, 'duplicate_metadata_json_key')
            result[name] = value
        return result
    def constant(_):
        raise ValueError('nonfinite_metadata_json')
    def finite_float(text):
        value = float(text)
        if not math.isfinite(value):
            raise ValueError('nonfinite_metadata_json')
        return value
    require(type(raw) is bytes and 0 < len(raw) <= 16*1024*1024, 'metadata_size_limit')
    return json.loads(raw.decode('utf-8'), object_pairs_hook=pairs, parse_constant=constant, parse_float=finite_float)


def fields(value, names, message):
    require(isinstance(value,dict) and set(value) == set(names.split()), message)


def is_digest(value):
    return isinstance(value,str) and len(value) == 64 and all(c in '0123456789abcdef' for c in value)

def draw_clusters(frames, entropy, count):
    """Replay SRSWOR using rejection sampling, conditional on independent fair bits.

    No modulo reduction, hash-ranking or replacement. The caller must separately
    establish frame-before-randomness timing and the randomness source's trust.
    """
    require(isinstance(frames, dict) and set(frames) == {'development', 'holdout'}, 'split_frames_required')
    require(type(count) is int and count > 0 and type(entropy) is bytes, 'sampling_arguments')
    selected, offset = {}, 0
    for split in ('development', 'holdout'):
        require(isinstance(frames[split], list) and all(isinstance(x, str) for x in frames[split]), 'frame_identifiers')
        pool = sorted(frames[split])
        require(len(pool) == len(set(pool)) and len(pool) >= count, 'frame_size_or_duplicates')
        selected[split] = []
        for _ in range(count):
            bits = (len(pool) - 1).bit_length()
            width = (bits + 7) // 8
            while True:
                require(offset + width <= len(entropy), 'random_bytes_exhausted')
                index = int.from_bytes(entropy[offset:offset + width], 'little') & ((1 << bits) - 1)
                offset += width
                if index < len(pool):
                    selected[split].append(pool.pop(index))
                    break
    return selected, offset


def check_packet(packet):
    require(isinstance(packet, dict), 'design_object_required')
    base = {'experiment_authorized': False, 'formal_materials_admitted': 0,
            'interval_selection_ready': False, 'coverage_certified': False,
            'power_validated': False, 'pre_outcome_timing_independently_verified': False,
            'source_frame_authenticity_verified': False, 'independence_verified': False,
            'pilot_dispatchable': False, 'target_population': ESTIMAND['population'],
            'dependency_git_commit': DEPENDENCY_GIT_COMMIT,
            'dependency_sha256': dict(DEPENDENCY_SHA256)}
    if (packet.get('outcomes_seen_before_declaration') is True
            or 'AFTER_ENGINEERING_OUTCOMES' in str(packet.get('status', ''))):
        return {**base, 'state': 'REJECTED_POST_OUTCOME_DESIGN'}
    expected = {'schema', 'role', 'protocol_sha256', 'outcomes_seen_before_declaration',
                'estimand', 'selection_mechanism', *REFS, 'selected_cluster_ids', 'documents',
                'pre_outcome_design_commitment_sha256', 'evidence_scope'}
    require(set(packet) == expected and packet['schema'] == SCHEMA, 'prospective_schema')
    require(packet['role'] in ('PROSPECTIVE_RESEARCH_DESIGN_DRAFT', 'ENGINEERING_FIXTURE_ONLY'), 'design_role')
    require(packet['outcomes_seen_before_declaration'] is False, 'prior_outcomes_not_allowed')
    require(packet['protocol_sha256'] == PROTOCOL_SHA256, 'frozen_protocol_changed')
    require(packet['estimand'] == ESTIMAND and packet['selection_mechanism'] == SELECTION, 'estimand_or_design_drift')
    require(packet['evidence_scope'] == 'DECLARATIONS_ONLY_NOT_INDEPENDENTLY_VERIFIED', 'unverified_evidence_cannot_be_promoted')
    require(isinstance(packet['documents'], dict), 'documents_object')
    missing = [name for name in (*REFS, 'selected_cluster_ids', 'pre_outcome_design_commitment_sha256') if packet[name] is None]
    if missing:
        return {**base, 'state': 'PENDING_REAL_DESIGN_INPUTS', 'missing_inputs': missing}
    return {**base, **verify_complete_design(packet)}


def configurations():
    raw = _read_dependency('docs/research/source-trust/protocol-draft.json')
    require(sha(raw) == PROTOCOL_SHA256, 'frozen_protocol_bytes_changed')
    protocol = json.loads(raw)
    conditions = [{'experiment':'E0', 'panel':'correct', 'rate':'0', 'seed':None}]
    conditions += [{'experiment':'E1', 'panel':panel, 'rate':str(rate).removesuffix('.0'), 'seed':seed}
                   for panel in protocol['design']['directions']
                   for rate in protocol['design']['rates'] if rate > 0
                   for seed in protocol['design']['injection_seeds']]
    conditions += [{'experiment':'E3', 'panel':'sensitive_to_public', 'rate':'0.1', 'seed':seed}
                   for seed in protocol['targeted_pair']['injection_seeds']]
    require(len(conditions) == 81, 'fixed_configuration_count')
    return conditions


def commitment(packet):
    return digest({k:v for k,v in packet.items() if k != 'pre_outcome_design_commitment_sha256'})


def document(packet, ref):
    h = packet[ref]
    require(is_digest(h) and isinstance(packet['documents'].get(h),str), 'document_reference')
    raw = packet['documents'][h].encode('utf-8')
    require(sha(raw) == h, 'document_bytes_digest_mismatch')
    return parse_json(raw)


def validate_frame(frame, role):
    require(isinstance(frame, dict) and set(frame) == {'schema','frame_version','evidence_scope','units'}, 'frame_fields')
    require(frame['schema'] == 'finite-frame-metadata-v1' and frame['evidence_scope'] == role
            and isinstance(frame['frame_version'], str) and bool(frame['frame_version']), 'frame_schema_scope')
    require(isinstance(frame['units'], list) and 60 <= len(frame['units']) <= 10000, 'frame_unit_count')
    historical = json.loads(_read_dependency(
        'docs/research/source-trust/convergence/candidate-materials-v1/manifest.json'))
    old_sources = {f['contract']['source_sha256'] for f in historical['families']}
    old_families = {f['family_id'] for f in historical['families']}
    old_lineages = {f['template_cluster_id'] for f in historical['families']}
    old_recipe = sha(_read_dependency(
        'docs/research/source-trust/convergence/candidate-materials-v1/authoring-spec.json'))
    seen_units, seen_lineages, seen_families, sources = set(), set(), set(), {}
    def is_sha(value):
        return isinstance(value, str) and len(value) == 64 and all(c in '0123456789abcdef' for c in value)
    for unit in frame['units']:
        require(isinstance(unit, dict) and set(unit) == {'cluster_id','lineage_id','split','authoring_recipe_sha256','members'}, 'unit_metadata_fields')
        cid, lineage = unit['cluster_id'], unit['lineage_id']
        require(all(isinstance(x,str) and bool(x) for x in (cid,lineage)), 'unit_identifiers')
        require(cid not in seen_units and lineage not in seen_lineages, 'duplicate_cluster_or_shared_lineage')
        seen_units.add(cid); seen_lineages.add(lineage)
        require(unit['split'] in ('development','holdout') and is_sha(unit['authoring_recipe_sha256']), 'unit_split_recipe')
        require(lineage not in old_lineages and unit['authoring_recipe_sha256'] != old_recipe, 'known_author_fixture_lineage_or_recipe')
        require(isinstance(unit['members'], list) and len(unit['members']) == 2
                and {m.get('source_kind') for m in unit['members'] if isinstance(m,dict)} == {'file','tool'}, 'exact_file_tool_member_pair')
        for member in unit['members']:
            require(isinstance(member,dict) and set(member) == {'family_id','source_kind','source_sha256','task_ids','task_sha256','H3_eligible_by_seed'}, 'member_metadata_fields')
            fid, source = member['family_id'], member['source_sha256']
            require(isinstance(fid,str) and bool(fid) and fid not in seen_families and is_sha(source), 'family_or_source_identity')
            require(fid not in old_families and source not in old_sources, 'known_author_fixture_family_or_source')
            require(source not in sources or sources[source] == cid, 'source_fingerprint_shared_across_clusters')
            sources[source] = cid; seen_families.add(fid)
            require(isinstance(member['task_ids'],dict) and set(member['task_ids']) == {'attack','benign'}
                    and all(isinstance(v,str) and bool(v) for v in member['task_ids'].values())
                    and len(set(member['task_ids'].values())) == 2, 'two_task_identifiers')
            require(isinstance(member['task_sha256'],dict) and set(member['task_sha256']) == {'attack','benign'}
                    and all(is_sha(v) for v in member['task_sha256'].values()), 'two_task_commitments')
            mask = member['H3_eligible_by_seed']
            require(isinstance(mask,dict) and set(mask) == {'17','29','43','71','101'}
                    and all(type(v) is bool for v in mask.values()), 'five_preexecution_H3_masks_required')
    require(all(sum(u['split'] == s for u in frame['units']) >= 30 for s in ('development','holdout')), 'thirty_units_per_split_required')


def verify_complete_design(packet):
    require(packet['pre_outcome_design_commitment_sha256'] == commitment(packet), 'design_commitment_mismatch')
    require(set(packet['documents']) == {packet[r] for r in REFS}, 'exact_document_inventory')
    frame = document(packet, 'sampling_frame_ref')
    validate_frame(frame, packet['role'])
    units = frame['units']
    frames = {s: [u['cluster_id'] for u in units if u['split'] == s] for s in ('development','holdout')}
    randomness = document(packet, 'sampling_randomness_ref')
    fields(randomness, 'schema frame_sha256 random_bytes_hex origin_evidence_ref frame_before_randomness_is_declaration_not_proof', 'randomness_metadata_fields')
    require(randomness['schema'] == 'sampling-randomness-declaration-v1'
            and randomness['frame_sha256'] == packet['sampling_frame_ref']
            and randomness['frame_before_randomness_is_declaration_not_proof'] is True,
            'randomness_frame_binding')
    entropy = bytes.fromhex(randomness['random_bytes_hex'])
    selected, consumed = draw_clusters(frames, entropy, 30)
    require(packet['selected_cluster_ids'] == selected, 'selection_not_reproduced')
    audit = document(packet, 'cluster_independence_evidence_ref')
    fields(audit, 'schema frame_sha256 mapping_sha256 review_record_ref not_independently_verified', 'lineage_metadata_fields')
    mapping = sorted((u['cluster_id'],u['lineage_id'],u['authoring_recipe_sha256']) for u in units)
    require(audit['schema'] == 'lineage-audit-declaration-v1' and audit['frame_sha256'] == packet['sampling_frame_ref']
            and audit['mapping_sha256'] == digest(mapping) and audit['not_independently_verified'] is True,
            'lineage_declaration_binding')
    plan = document(packet, 'preexecution_plan_ref')
    fields(plan, 'schema frame_sha256 selected_ids_sha256 graphs planned_execution_rows', 'plan_metadata_fields')
    fields(plan['graphs'], 'development holdout', 'plan_split_inventory')
    require(plan['schema'] == 'first-phase-plan-metadata-v1'
            and plan['frame_sha256'] == packet['sampling_frame_ref']
            and plan['selected_ids_sha256'] == digest(selected), 'plan_frame_and_selection_binding')
    expected = {digest(c) for c in configurations()}
    for split in ('development','holdout'):
        graphs = plan['graphs'][split]
        require(isinstance(graphs,list), 'plan_graphs_list')
        for graph in graphs:
            fields(graph, 'experiment panel rate seed graph_sha256', 'graph_metadata_fields')
            require(is_digest(graph['graph_sha256']), 'graph_digest')
        require(len(graphs) == 81 and {digest({k:v for k,v in g.items() if k != 'graph_sha256'}) for g in graphs} == expected,
                'full_81_configuration_grid_required')
    require(plan['planned_execution_rows'] == {'development':29160,'holdout':29160}, 'formal_budget_changed')
    executor = document(packet, 'executor_contract_ref')
    fields(executor, 'schema executor_sha256 configuration_sha256 response_law_and_no_interference', 'executor_metadata_fields')
    require(executor['schema'] == 'frozen-executor-declaration-v1'
            and is_digest(executor['executor_sha256'])
            and isinstance(executor['configuration_sha256'], dict)
            and set(executor['configuration_sha256']) == {'coarse','precision','conservative'}
            and all(is_digest(v) for v in executor['configuration_sha256'].values())
            and executor['response_law_and_no_interference'] == 'UNVERIFIED_ASSUMPTIONS_NOT_AN_INDEPENDENCE_CERTIFICATE',
            'executor_declaration_binding')
    return {'state':'DESIGN_METADATA_VALID_NOT_AUTHORIZED', 'selection_replayed':True,
            'selected_clusters_per_split': {s:len(selected[s]) for s in selected},
            'sampling_probabilities': {s:{'numerator':30,'denominator':len(frames[s])} for s in frames},
            'configurations_per_split':81, 'planned_execution_rows_per_split':29160,
            'random_bytes_consumed':consumed,
            'pre_outcome_design_commitment_sha256':packet['pre_outcome_design_commitment_sha256']}


def make_bound_row(packet, split, family_id, condition, mode, kind):
    require(check_packet(packet)['state'] == 'DESIGN_METADATA_VALID_NOT_AUTHORIZED', 'complete_prospective_design_required')
    require(split in ('development','holdout') and mode in ('coarse','precision','conservative')
            and kind in ('attack','benign'), 'row_split_mode_kind')
    frame = document(packet, 'sampling_frame_ref')
    members = [(u,m) for u in frame['units'] if u['split'] == split
               and u['cluster_id'] in packet['selected_cluster_ids'][split]
               for m in u['members'] if m['family_id'] == family_id]
    require(len(members) == 1, 'row_family_not_in_selected_frame')
    unit, member = members[0]
    plan = document(packet, 'preexecution_plan_ref')
    graphs = [g for g in plan['graphs'][split]
              if digest({k:v for k,v in g.items() if k != 'graph_sha256'}) == digest(condition)]
    require(len(graphs) == 1, 'row_condition_not_prespecified')
    executor = document(packet, 'executor_contract_ref')
    row = {'schema':'design-bound-row-metadata-v1', 'scope':'METADATA_BINDING_ONLY_NOT_DISPATCH',
           'pre_outcome_design_commitment_sha256':packet['pre_outcome_design_commitment_sha256'],
           'preexecution_plan_sha256':packet['preexecution_plan_ref'], 'split':split,
           'family_id':family_id, 'template_cluster_id':unit['cluster_id'],
           'source_kind':member['source_kind'], 'source_sha256':member['source_sha256'],
           'task_id':member['task_ids'][kind], 'task_sha256':member['task_sha256'][kind], 'kind':kind,
           'defense_mode':mode, 'configuration_sha256':executor['configuration_sha256'][mode],
           'executor_sha256':executor['executor_sha256'], **graphs[0],
           'H3_eligible': condition['experiment'] == 'E3' and member['H3_eligible_by_seed'][str(condition['seed'])]}
    row['row_id'] = digest(row)
    return row


def check_bound_row(packet, row):
    require(isinstance(row,dict), 'row_object')
    try:
        condition = {k:row[k] for k in ('experiment','panel','rate','seed')}
        expected = make_bound_row(packet, row['split'], row['family_id'], condition, row['defense_mode'], row['kind'])
    except (KeyError,TypeError) as exc:
        raise ValueError('row_schema') from exc
    require(canonical(row) == canonical(expected), 'row_design_or_plan_binding_mismatch')
    return True


def _read_dependency(relative):
    require(relative in DEPENDENCY_SHA256, 'dependency_git_path')
    raw, commit = _read_regular_git_blob(HERE.parents[4], DEPENDENCY_GIT_COMMIT, relative)
    require(commit == DEPENDENCY_GIT_COMMIT and sha(raw) == DEPENDENCY_SHA256[relative],
            'fixed_dependency_binding')
    return raw


def read_git_packet(repo, revision, relative):
    from pathlib import PurePosixPath
    prefix = 'docs/research/source-trust/convergence/'
    require(isinstance(relative,str)
            and (relative.startswith(prefix+'prospective-design-v1/')
                 or relative == prefix+'ledger-input-validation-v1/run-001/sampling-contract.json')
            and relative.endswith('.json') and '\\' not in relative
            and str(PurePosixPath(relative)) == relative and '..' not in PurePosixPath(relative).parts
            and all(ord(c) >= 32 for c in relative), 'metadata_git_path')
    return _read_regular_git_blob(repo, revision, relative)


def _read_regular_git_blob(repo, revision, relative):
    import subprocess
    def git(*args):
        return subprocess.check_output(['git','--no-replace-objects','-C',str(repo),*args], stderr=subprocess.PIPE)
    commit = git('rev-parse','--verify','--end-of-options',revision+'^{commit}').decode('ascii').strip()
    entries = git('ls-tree','-z',commit,'--',relative).split(b'\0')
    entries = [entry for entry in entries if entry]
    require(len(entries) == 1, 'one_metadata_git_blob_required')
    entry, name = entries[0].split(b'\t',1)
    mode, kind, oid = entry.split(b' ')
    require(mode in (b'100644',b'100755') and kind == b'blob' and name.decode('utf-8') == relative,
            'regular_git_blob_required')
    object_id = oid.decode('ascii')
    size = int(git('cat-file','-s',object_id))
    require(0 < size <= 16*1024*1024, 'metadata_size_limit')
    raw = git('cat-file','blob',object_id)
    require(len(raw) == size, 'git_blob_size_changed')
    return raw, commit


def main(argv=None):
    import argparse
    import subprocess
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo',type=Path,default=HERE.parents[4])
    parser.add_argument('--commit',default='HEAD')
    parser.add_argument('--packet',default='docs/research/source-trust/convergence/prospective-design-v1/proposal.json')
    args = parser.parse_args(argv)
    try:
        raw, commit = read_git_packet(args.repo,args.commit,args.packet)
        result = check_packet(parse_json(raw))
        result.update(packet_git_commit=commit, packet_file_sha256=sha(raw),
                      implementation_file_sha256=sha(Path(__file__).read_bytes()))
        print(json.dumps(result,sort_keys=True,allow_nan=False))
        return 0 if result['state'] == 'DESIGN_METADATA_VALID_NOT_AUTHORIZED' else 2
    except (ValueError,TypeError,KeyError,UnicodeError,OSError,RecursionError,subprocess.SubprocessError):
        print(json.dumps({'state':'INVALID_DESIGN_METADATA','experiment_authorized':False}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
