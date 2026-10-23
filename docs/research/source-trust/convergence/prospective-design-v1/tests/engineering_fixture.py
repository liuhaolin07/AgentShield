"""Only synthetic metadata for engineering tests, never pilot material."""
from copy import deepcopy
import json
from pathlib import Path
import random


def make_packet(module):
    packet = json.loads((Path(module.__file__).parent/'proposal.json').read_text(encoding='utf-8'))
    packet['role'] = 'ENGINEERING_FIXTURE_ONLY'
    units = []
    for split in ('development', 'holdout'):
        for number in range(32):
            uid = f'engineering-{split}-{number:02}'
            units.append({'cluster_id': uid, 'lineage_id': uid, 'split': split,
                'authoring_recipe_sha256': module.digest(uid+'-recipe'),
                'members': [{'family_id': uid+'-'+kind, 'source_kind': kind,
                    'source_sha256': module.digest(uid+'-source-'+kind),
                    'task_ids': {task: uid+'-'+kind+'-'+task for task in ('attack', 'benign')},
                    'task_sha256': {task: module.digest(uid+kind+task) for task in ('attack', 'benign')},
                    'H3_eligible_by_seed': {str(seed): True for seed in (17,29,43,71,101)}}
                    for kind in ('file', 'tool')]})
    frame = {'schema': 'finite-frame-metadata-v1', 'frame_version': 'engineering-fixture-v1',
             'evidence_scope': packet['role'], 'units': units}
    def add_document(ref_name, document):
        raw = json.dumps(document, ensure_ascii=False, sort_keys=True, indent=2)+'\n'
        h = module.sha(raw.encode('utf-8'))
        packet['documents'][h] = raw
        packet[ref_name] = h
        return h
    fsha = add_document('sampling_frame_ref', frame)
    entropy = random.Random(8107).randbytes(4096)
    randomness = {'schema': 'sampling-randomness-declaration-v1', 'frame_sha256': fsha,
                  'random_bytes_hex': entropy.hex(), 'origin_evidence_ref': 'ENGINEERING_ONLY_NO_REAL_RANDOMNESS_EVIDENCE',
                  'frame_before_randomness_is_declaration_not_proof': True}
    add_document('sampling_randomness_ref', randomness)
    frames = {s: [u['cluster_id'] for u in units if u['split'] == s] for s in ('development','holdout')}
    packet['selected_cluster_ids'], _ = module.draw_clusters(frames, entropy, 30)
    mapping = sorted((u['cluster_id'],u['lineage_id'],u['authoring_recipe_sha256']) for u in units)
    add_document('cluster_independence_evidence_ref', {
        'schema': 'lineage-audit-declaration-v1', 'frame_sha256': fsha,
        'mapping_sha256': module.digest(mapping), 'review_record_ref': 'ENGINEERING_ONLY_NO_REVIEW',
        'not_independently_verified': True})
    plan = {'schema': 'first-phase-plan-metadata-v1', 'frame_sha256': fsha,
            'selected_ids_sha256': module.digest(packet['selected_cluster_ids']),
            'graphs': {s: [{**c, 'graph_sha256': module.digest([s,c,'ENGINEERING_ONLY'])} for c in module.configurations()]
                       for s in ('development','holdout')},
            'planned_execution_rows': {'development':29160, 'holdout':29160}}
    add_document('preexecution_plan_ref', plan)
    add_document('executor_contract_ref', {
        'schema': 'frozen-executor-declaration-v1', 'executor_sha256': module.digest('ENGINEERING_NO_EXECUTOR'),
        'configuration_sha256': {mode: module.digest('ENGINEERING_'+mode) for mode in ('coarse','precision','conservative')},
        'response_law_and_no_interference': 'UNVERIFIED_ASSUMPTIONS_NOT_AN_INDEPENDENCE_CERTIFICATE'})
    packet['pre_outcome_design_commitment_sha256'] = module.commitment(packet)
    return packet


def mutate_document(module, packet, ref_name, mutation):
    packet = deepcopy(packet)
    old = packet[ref_name]
    document = json.loads(packet['documents'].pop(old))
    mutation(document)
    raw = json.dumps(document, ensure_ascii=False, sort_keys=True, indent=2)+'\n'
    h = module.sha(raw.encode('utf-8'))
    packet['documents'][h] = raw
    packet[ref_name] = h
    packet['pre_outcome_design_commitment_sha256'] = module.commitment(packet)
    return packet
