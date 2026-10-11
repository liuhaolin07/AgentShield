"""Bounded annotation-to-cohort projection; identity/semantics need human review.

Accepts development records only. No payload values, execution outcomes, policy
names or holdout materials. Uncertain/disagreeing labels require adjudication;
no task is dropped. Synthetic fixtures never count as real human annotations.
"""
from __future__ import annotations
import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path
from typing import Any

VERSION = 'source-trust-truth-projection-1'
CRITICAL = {'classification', 'readers', 'purposes', 'dependencies', 'evidence', 'inventory', 'blinding', 'identity'}


def canonical(value: Any) -> bytes:
    return json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode()


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def require(ok: bool, reason: str) -> None:
    if not ok: raise ValueError(reason)


def text(value: Any) -> bool:
    return type(value) is str and 0 < len(value) <= 256


def path(value: Any) -> bool:
    return type(value) is list and 0 < len(value) <= 16 and all(
        type(v) is str and 0 < len(v) <= 64 or type(v) is int and 0 <= v <= 4096 for v in value)


def refs(value: Any, evidence: dict) -> bool:
    return type(value) is list and 0 < len(value) <= 32 and len(set(value)) == len(value) and all(text(v) and v in evidence for v in value)


def audit_gate(audit: dict) -> dict:
    """Any finding blocks; critical/systemic/>1% minor findings require full rework."""
    require(type(audit['inspected_units']) is int and 1 <= audit['inspected_units'] <= 100000, 'audit_denominator')
    findings=audit['findings']
    require(type(findings) is list and len(findings) <= audit['inspected_units'], 'audit_findings')
    require(all(f['kind'] in CRITICAL | {'rationale_typo'} and text(f['unit_id']) and text(f['family_id']) for f in findings), 'audit_error_kind')
    require(len({f['unit_id'] for f in findings}) == len(findings), 'duplicate_audit_finding')
    critical=sum(f['kind'] in CRITICAL for f in findings)
    minor=len(findings)-critical
    systemic=len({f['family_id'] for f in findings if f['kind']=='rationale_typo'}) >= 2
    full=critical > 0 or systemic or minor*100 > audit['inspected_units']
    return {'structurally_passed':not findings,'critical_errors':critical,'minor_errors':minor,
            'inspected_units':audit['inspected_units'],'full_rework_required':full,
            'action':'FULL_COHORT_REWORK' if full else ('VERSIONED_REPAIR_AND_REAUDIT' if findings else 'AWAIT_HUMAN_VERIFICATION'),
            'pilot_eligible':False}


def _convert(ledger: dict) -> dict:
    require(type(ledger) is dict and len(canonical(ledger)) <= 8*1024*1024, 'ledger_limit')
    require(set(ledger) == {'version','synthetic_fixture','inventory','evidence','submissions','adjudications','audit'}, 'ledger_keys_no_outcomes')
    require(ledger['version'] == VERSION and type(ledger['synthetic_fixture']) is bool, 'ledger_version')
    inventory=ledger['inventory'];families=inventory['families']
    require(inventory['split']=='development' and type(families) is list and 1 <= len(families) <= 128, 'development_inventory_only')
    require(inventory.get('outcomes') is None and inventory.get('policy') is None, 'blind_inventory')
    evidence=ledger['evidence']
    require(type(evidence) is dict and 1 <= len(evidence) <= 4096 and all(text(k) and type(v) is str and
            len(v)==64 and all(c in '0123456789abcdef' for c in v) for k,v in evidence.items()), 'evidence_hash_references')
    units, family_ids = {}, set()
    for family in families:
        fid=family['family_id']
        require(text(fid) and fid not in family_ids and text(family['template_id']) and family['source_kind'] in ('file','tool'), 'family_identity')
        family_ids.add(fid)
        leaves=family['leaves'];tasks=family['tasks']
        require(type(leaves) is list and 1 <= len(leaves) <= 256 and type(tasks) is list and len(tasks)==2, 'family_dimensions')
        for leaf in leaves:
            require(set(leaf)=={'path'} and path(leaf['path']), 'blind_leaf_path')
            key=canonical([fid,leaf['path']]).decode()
            require(key not in units, 'duplicate_leaf')
            units[key]=('leaf',fid)
        for task in tasks:
            require(set(task)=={'task_id','sink','purpose','requesting_actor','completion_contract_sha256'}, 'blind_task_contract')
            require(all(text(task[k]) for k in ('task_id','sink','purpose','requesting_actor')) and text(task['completion_contract_sha256']), 'task_contract')
            require(task['task_id'] not in units, 'duplicate_task')
            units[task['task_id']]=('task',fid)
    require(len(units) <= 4352, 'unit_limit')
    submissions=ledger['submissions']
    require(type(submissions) is list and len(submissions)==2, 'two_submissions')
    require(all(set(s)=={'annotator_id','inventory_sha256','blind_attestation','answers'} for s in submissions), 'submission_keys_no_outcomes')
    require(all(text(s['annotator_id']) and s['inventory_sha256']==digest(inventory) and s['blind_attestation'] is True for s in submissions), 'blind_submission_identity')
    require(submissions[0]['annotator_id']!=submissions[1]['annotator_id'], 'distinct_claimed_annotators')
    parsed=[]
    for submission in submissions:
        answers=submission['answers']
        require(type(answers) is dict and set(answers)==set(units), 'complete_submission_no_task_selection')
        for key,answer in answers.items():
            require(text(answer['rationale']) and type(answer['confidence']) in (int,float) and 0 <= answer['confidence'] <= 1
                    and refs(answer['evidence_ids'],evidence), 'annotation_evidence_and_reason')
            if units[key][0]=='leaf':
                require(set(answer)=={'classification','allowed_readers','purposes','rationale','confidence','evidence_ids'}, 'leaf_answer_keys')
                require(answer['classification'] in ('SENSITIVE','PUBLIC','UNCERTAIN'), 'classification')
                for field in ('allowed_readers','purposes'):
                    values=answer[field]
                    require(type(values) is list and 1 <= len(values) <= 16 and len(set(values))==len(values) and all(text(v) for v in values), 'authorization')
            else:
                require(set(answer)=={'category','D_read','D_out','rationale','confidence','evidence_ids'}, 'task_answer_keys')
                require(answer['category'] in ('attack','benign','UNCERTAIN'), 'category')
                for field in ('D_read','D_out'):
                    values=answer[field]
                    require(type(values) is list and 1 <= len(values) <= 64 and all(path(v) and canonical([units[key][1],v]).decode() in units for v in values), 'dependency_paths')
                    require(len({canonical(v) for v in values})==len(values), 'duplicate_dependency')
                require({canonical(v) for v in answer['D_out']} <= {canonical(v) for v in answer['D_read']}, 'output_subset_read')
        parsed.append(answers)
    def semantics(key,answer):
        return {field:answer[field] for field in (('classification','allowed_readers','purposes') if units[key][0]=='leaf' else ('category','D_read','D_out'))}
    conflicts={key for key in units if semantics(key,parsed[0][key])!=semantics(key,parsed[1][key]) or
               'UNCERTAIN' in (parsed[0][key].get('classification'),parsed[0][key].get('category'),parsed[1][key].get('classification'),parsed[1][key].get('category'))}
    adjudications=ledger['adjudications']
    require(type(adjudications) is dict and set(adjudications) <= conflicts, 'adjudication_only_disagreements')
    resolved={key:deepcopy(parsed[0][key]) for key in units if key not in conflicts}
    for key,record in adjudications.items():
        require(set(record)=={'adjudicator_id','evidence_ids','rationale','select_submission'}, 'adjudication_keys')
        require(text(record['adjudicator_id']) and record['adjudicator_id'] not in {s['annotator_id'] for s in submissions}
                and refs(record['evidence_ids'],evidence) and text(record['rationale']), 'third_role_and_evidence')
        # Adjudication supplies a resolved selection from A or B; novel rulings require new raw revisions.
        require(type(record['select_submission']) is int and record['select_submission'] in (0,1), 'adjudication_selection')
        answer=deepcopy(parsed[record['select_submission']][key])
        require(answer.get('classification')!='UNCERTAIN' and answer.get('category')!='UNCERTAIN', 'uncertain_not_boolean')
        resolved[key]=answer
    raw_audit=ledger['audit']
    require(set(raw_audit)=={'auditor_id','sampling_seed','inspected_units','inspected_unit_ids','findings'}, 'audit_keys')
    require(text(raw_audit['auditor_id']) and raw_audit['auditor_id'] not in {s['annotator_id'] for s in submissions}
            | {r['adjudicator_id'] for r in adjudications.values()}, 'separate_claimed_auditor')
    require(type(raw_audit['sampling_seed']) is int and raw_audit['sampling_seed']==314159, 'frozen_audit_seed')
    inspected=raw_audit['inspected_unit_ids']
    require(type(inspected) is list and len(inspected)==len(set(inspected))==raw_audit['inspected_units'] and set(inspected)<=set(units), 'audit_sample_identity')
    required=set(conflicts) | {k for k,a in resolved.items() if units[k][0]=='task' or a.get('classification')=='PUBLIC'}
    for source_kind in ('file','tool'):
        stratum=[f['family_id'] for f in families if f['source_kind']==source_kind]
        stratum.sort(key=lambda fid:(hashlib.sha256(canonical(['TA-2',314159,source_kind,fid])).digest(),fid))
        chosen=set(stratum[:(len(stratum)+9)//10])
        required.update(k for k,(_,fid) in units.items() if fid in chosen)
    require(required <= set(inspected), 'frozen_audit_sample_and_high_risk_coverage')
    require(all(f['unit_id'] in inspected and f['family_id']==units[f['unit_id']][1] for f in raw_audit['findings']), 'audit_finding_identity')
    audit=audit_gate(raw_audit)
    audit['required_units']=len(required)
    audit['sampling_seed']=314159
    chain={'inventory_sha256':digest(inventory),'evidence_sha256':digest(evidence),
           'submission_sha256':[digest(s) for s in submissions],'adjudications_sha256':digest(adjudications),
           'audit_sha256':digest(ledger['audit']),'raw_ledger_sha256':digest(ledger)}
    if conflicts-set(adjudications) or not audit['structurally_passed']:
        return {'version':VERSION,'status':'UNRESOLVED' if conflicts-set(adjudications) else 'AUDIT_FAILED',
                'unresolved_units':sorted(conflicts-set(adjudications)),'projection':None,'chain':chain,'audit_gate':audit,
                'pilot_eligible':False,'human_identity_or_semantics_verified':False}
    projected=[]
    for family in families:
        fid=family['family_id'];leaves=[];tasks=[]
        for leaf in family['leaves']:
            answer=resolved[canonical([fid,leaf['path']]).decode()]
            leaves.append({'path':leaf['path'],'sensitive':answer['classification']=='SENSITIVE',
                           'allowed_readers':answer['allowed_readers'],'purposes':answer['purposes']})
        for task in family['tasks']:
            answer=resolved[task['task_id']]
            tasks.append({'task_id':task['task_id'],'category':answer['category'],'sink':task['sink'],'purpose':task['purpose'],
                          'dependencies':answer['D_out']})
        projected.append({k:family[k] for k in ('family_id','template_id','source_kind')} | {'leaves':leaves,'tasks':tasks})
    cohort={'schema_version':'source-trust-corruption-1','split':'development',
            'annotation_status':'author_only_measurement_control' if ledger['synthetic_fixture'] else 'adjudicated_development_NOT_human_verified',
            'families':deepcopy(projected)}
    from benchmark.source_trust_corruption import validate_cohort
    validate_cohort(cohort)  # Fail the whole projection if the existing graph contract cannot consume it.
    chain['projection_sha256']=digest(cohort)
    # Full inventory/submissions retain D_read/evidence/rulings even though the graph uses D_out only.
    return {'version':VERSION,'status':'STRUCTURAL_PROJECTION_ONLY','projection':cohort,'chain':chain,
            'chain_sha256':digest(chain),'conflicting_units':sorted(conflicts),'audit_gate':audit,
            'pilot_eligible':False,'human_identity_or_semantics_verified':False}


def convert(ledger: dict) -> dict:
    try:
        return _convert(ledger)
    except (KeyError,TypeError,RecursionError) as error:
        raise ValueError('malformed_annotation_ledger') from error


def fixture_ledger(cohort: dict) -> dict:
    """Explicit author fixture; never called an independent two-human annotation."""
    inventory={'split':'development','families':[]};answers={}
    evidence={'synthetic-author-control':hashlib.sha256(b'fake-method-fixture-not-authority-evidence').hexdigest()}
    for family in cohort['families']:
        inventory['families'].append({k:family[k] for k in ('family_id','template_id','source_kind')} | {
            'leaves':[{'path':f['path']} for f in family['leaves']],
            'tasks':[{'task_id':t['task_id'],'sink':t['sink'],'purpose':t['purpose'],'requesting_actor':'fixture-actor',
                      'completion_contract_sha256':digest(t)} for t in family['tasks']]})
        for leaf in family['leaves']:
            answers[canonical([family['family_id'],leaf['path']]).decode()]={
                'classification':'SENSITIVE' if leaf['sensitive'] else 'PUBLIC',
                'allowed_readers':leaf['allowed_readers'],'purposes':leaf['purposes'],
                'rationale':'Synthetic author fixture only','confidence':1,'evidence_ids':list(evidence)}
        for task in family['tasks']:
            answers[task['task_id']]={'category':task['category'],'D_read':deepcopy(task['dependencies']),'D_out':deepcopy(task['dependencies']),
                                     'rationale':'Synthetic explicit dependency fixture only','confidence':1,'evidence_ids':list(evidence)}
    return {'version':VERSION,'synthetic_fixture':True,'inventory':inventory,'evidence':evidence,
            'submissions':[{'annotator_id':f'fixture-not-human-{i}','inventory_sha256':digest(inventory),'blind_attestation':True,
                            'answers':deepcopy(answers)} for i in range(2)],'adjudications':{},
            'audit':{'auditor_id':'fixture-auditor-not-human','sampling_seed':314159,'inspected_units':len(answers),'inspected_unit_ids':list(answers),'findings':[]}}


def main() -> None:
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('ledger',type=Path);p.add_argument('--output',type=Path,required=True)
    args=p.parse_args();require(args.ledger.stat().st_size <= 8*1024*1024,'ledger_limit')
    result=convert(json.loads(args.ledger.read_text()))
    args.output.parent.mkdir(parents=True,exist_ok=True);args.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({'status':result['status'],'pilot_eligible':False,'human_identity_or_semantics_verified':False}))
    if result['projection'] is None:raise SystemExit(2)


if __name__=='__main__':main()
