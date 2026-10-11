"""Independent raw-ledger / projection chain gate. No converter or defense imports."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path


def encode(value: object) -> bytes:
    return json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode()


def sha(value: object) -> str:
    return hashlib.sha256(encode(value)).hexdigest()


def require(ok: bool, reason: str) -> None:
    if not ok:raise ValueError(reason)


def validate(ledger: dict, result: dict, expected_ledger_sha256: str) -> dict:
    require(len(encode(ledger)) <= 8*1024*1024 and len(encode(result)) <= 8*1024*1024, 'input_limit')
    require(sha(ledger)==expected_ledger_sha256, 'externally_frozen_raw_ledger_identity')
    require(ledger['version']==result['version']=='source-trust-truth-projection-1', 'versions')
    require(result['pilot_eligible'] is False and result['human_identity_or_semantics_verified'] is False, 'no_machine_human_truth_claim')
    require(ledger['inventory']['split']=='development' and ledger['submissions'][0]['annotator_id']!=ledger['submissions'][1]['annotator_id'], 'development_independent_claims')
    chain={'inventory_sha256':sha(ledger['inventory']),'evidence_sha256':sha(ledger['evidence']),
           'submission_sha256':[sha(s) for s in ledger['submissions']],
           'adjudications_sha256':sha(ledger['adjudications']),'audit_sha256':sha(ledger['audit']),
           'raw_ledger_sha256':sha(ledger)}
    if result['projection'] is None:
        require(result['chain']==chain and result['status'] in ('UNRESOLVED','AUDIT_FAILED'), 'failed_conversion_chain')
        return {'status':result['status'],'projection_verified':False,'pilot_eligible':False,'human_identity_or_semantics_verified':False}
    projection=result['projection'];chain['projection_sha256']=sha(projection)
    require(result['chain']==chain and result['chain_sha256']==sha(chain), 'complete_hash_chain')
    require(result['status']=='STRUCTURAL_PROJECTION_ONLY' and projection['split']=='development', 'projection_scope')
    require(projection['annotation_status']==('author_only_measurement_control' if ledger['synthetic_fixture'] else 'adjudicated_development_NOT_human_verified'), 'fixture_never_human_claim')
    require(len(projection['families'])==len(ledger['inventory']['families']), 'no_family_drop')
    leaves_checked,tasks_checked=0,0
    forms=[s['answers'] for s in ledger['submissions']]
    def resolve(key: str, fields: tuple) -> dict:
        a,b=forms[0][key],forms[1][key]
        uncertain=any(a.get(v)=='UNCERTAIN' or b.get(v)=='UNCERTAIN' for v in ('classification','category'))
        agree=all(a[k]==b[k] for k in fields)
        if uncertain or not agree:
            record=ledger['adjudications'].get(key)
            require(record is not None and record['adjudicator_id'] not in {s['annotator_id'] for s in ledger['submissions']}, 'third_adjudication_required')
            chosen=record['select_submission']
            require(type(chosen) is int and chosen in (0,1), 'adjudication_selection')
            answer=forms[chosen][key]
        else:answer=a
        require(answer.get('classification')!='UNCERTAIN' and answer.get('category')!='UNCERTAIN', 'uncertain_not_projected')
        require(answer.get('classification') in (None,'SENSITIVE','PUBLIC') and answer.get('category') in (None,'attack','benign'), 'resolved_classification')
        require(bool(answer['evidence_ids']) and all(k in ledger['evidence'] for k in answer['evidence_ids']), 'annotation_evidence')
        return answer
    for authored,projected in zip(ledger['inventory']['families'],projection['families']):
        require(all(authored[k]==projected[k] for k in ('family_id','template_id','source_kind')), 'family_metadata')
        require(len(authored['leaves'])==len(projected['leaves']) and len(authored['tasks'])==len(projected['tasks']), 'no_leaf_or_task_drop')
        fid=authored['family_id']
        for inventory_leaf,leaf in zip(authored['leaves'],projected['leaves']):
            key=encode([fid,inventory_leaf['path']]).decode()
            answer=resolve(key,('classification','allowed_readers','purposes'))
            require(leaf=={'path':inventory_leaf['path'],'sensitive':answer['classification']=='SENSITIVE',
                           'allowed_readers':answer['allowed_readers'],'purposes':answer['purposes']}, 'projection_matches_raw_truth')
            leaves_checked+=1
        for task,contract in zip(authored['tasks'],projected['tasks']):
            answer=resolve(task['task_id'],('category','D_read','D_out'))
            require({encode(p) for p in answer['D_out']} <= {encode(p) for p in answer['D_read']}, 'output_dependencies_subset_read')
            require(contract=={'task_id':task['task_id'],'category':answer['category'],'sink':task['sink'],'purpose':task['purpose'],
                               'dependencies':answer['D_out']}, 'projection_uses_D_out_not_D_read')
            tasks_checked+=1
    raw_audit=ledger['audit']
    inspected=raw_audit['inspected_unit_ids']
    units={}
    for family in ledger['inventory']['families']:
        for leaf in family['leaves']:units[encode([family['family_id'],leaf['path']]).decode()]=('leaf',family['family_id'])
        for task in family['tasks']:units[task['task_id']]=('task',family['family_id'])
    required=set()
    for key,(kind,fid) in units.items():
        fields=('classification','allowed_readers','purposes') if kind=='leaf' else ('category','D_read','D_out')
        answer=resolve(key,fields)
        if kind=='task' or answer.get('classification')=='PUBLIC' or key in ledger['adjudications']:
            required.add(key)
    require(raw_audit['sampling_seed']==314159 and raw_audit['auditor_id'] not in
            {s['annotator_id'] for s in ledger['submissions']} | {r['adjudicator_id'] for r in ledger['adjudications'].values()}, 'audit_role_and_seed')
    for source_kind in ('file','tool'):
        stratum=[f['family_id'] for f in ledger['inventory']['families'] if f['source_kind']==source_kind]
        stratum.sort(key=lambda fid:(hashlib.sha256(encode(['TA-2',314159,source_kind,fid])).digest(),fid))
        chosen=set(stratum[:(len(stratum)+9)//10])
        required.update(key for key,(_,fid) in units.items() if fid in chosen)
    require(len(inspected)==len(set(inspected))==raw_audit['inspected_units'] and set(inspected)<=set(units)
            and required<=set(inspected), 'independent_audit_sample')
    require(not raw_audit['findings'] and result['audit_gate']['structurally_passed'] is True, 'audit_failure_must_block')
    return {'kind':'RAW_TRUTH_CHAIN_CONSISTENCY_NOT_SEMANTIC_CERTIFICATION','leaves':leaves_checked,'tasks':tasks_checked,
            'projection_verified':True,'pilot_eligible':False,'human_identity_or_semantics_verified':False,
            'raw_ledger_sha256':expected_ledger_sha256,'chain_sha256':sha(chain)}


def main() -> None:
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('ledger',type=Path);p.add_argument('projection',type=Path);p.add_argument('--ledger-sha256',required=True)
    a=p.parse_args();require(a.ledger.stat().st_size<=8*1024*1024 and a.projection.stat().st_size<=8*1024*1024,'input_limit')
    print(json.dumps(validate(json.loads(a.ledger.read_text()),json.loads(a.projection.read_text()),a.ledger_sha256)))


if __name__=='__main__':main()
