"""Independent joint H5 audit from raw integer counts; no simulator imports."""
from __future__ import annotations
import argparse
import csv
import gzip
import hashlib
import io
import json
import math
from pathlib import Path
import re
import subprocess

KEYS=('attack_c','attack_p','attack_missing_c','attack_missing_p','completed_c','completed_p','normal_missing_c','normal_missing_p')


def require(ok: bool, reason: str) -> None:
    if not ok:raise ValueError(reason)


def encoded(value: object) -> bytes:
    return json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False).encode()


def boolean(value: str) -> bool:
    require(value in ('True','False'),'boolean');return value=='True'


def raw_counts(row: dict,n: int,width: int) -> dict:
    record={k:json.loads(row[k]) for k in KEYS}
    require(all(type(v) is list and len(v)==width and all(type(x) is int and 0<=x<=n for x in v) for v in record.values()),'integer_counts')
    for actual,missing in (('attack_c','attack_missing_c'),('attack_p','attack_missing_p'),('completed_c','normal_missing_c'),('completed_p','normal_missing_p')):
        require(all(a+b<=n for a,b in zip(record[actual],record[missing])),'bounded_counts')
    return record


def validate(report: dict,trials: list[dict],graphs: list[dict],zeros: list[dict]) -> dict:
    require(report['kind']=='STATISTICAL_JOINT_TOY_NOT_DEFENSE' and all(report[k]==0 for k in ('actual_defense_executions','receiver_observations','model_requests')),'not_defense')
    c=report['config'];protocol_path=Path('docs/research/source-trust/protocol-draft.json');blob=protocol_path.read_bytes()
    frozen=json.loads(Path('docs/research/source-trust-methods/frozen-pr6.json').read_text())['tracked_files_sha256']
    require(hashlib.sha256(blob).hexdigest()==frozen[str(protocol_path)]==c['estimand']['protocol_sha256'],'protocol_identity')
    p=json.loads(blob);grid=p['design']['rates'];h5=next(h for h in p['hypotheses'] if h['id']=='H5')
    require(c['estimand']['grid']==grid and c['estimand']['integration_domain']==[0,1] and c['estimand']['normalization_width']==1,'H5_estimand')
    require(c['estimator']=='whole_graph_Hoeffding_worst_case_missing_17' and c['multiplicity']==p['inference']['first_phase_statistic_count']==17,'estimator')
    require(c['alpha']==p['inference']['familywise_alpha'] and c['minimum_coverage']==p['missingness']['minimum_coverage_each_cell'],'R1_missing_alpha')
    require(c['threshold_status']=='NOT_JUSTIFIED_BY_TASK_OWNER' and len(h5['statistics'])==13,'no_authorization')
    expected={(s,g,i) for s in c['scenarios'] for g in c['graphs'] for i in range(c['trials'])}
    require(len(trials)==len(zeros)==len(expected)==report['trial_rows']==report['e0_rows'],'trial_E0_count')
    require(len(graphs)==sum(c['graphs'])*len(c['scenarios'])*c['trials']==report['raw_graph_rows'],'graph_count')
    n=c['families'];raw_graphs={};raw_zero={};trial_map={}
    def identity(row):
        require(row['kind']==report['kind'] and int(row['families'])==n,'context')
        key=(row['scenario'],int(row['graphs']),int(row['trial']));require(key in expected,'cell_identity');return key
    for row in zeros:
        key=identity(row);require(key not in raw_zero and int(row['e0_observations_per_task_arm'])==1,'E0_not_duplicated')
        raw_zero[key]=raw_counts(row,n,1)
    for row in graphs:
        key=identity(row);index=int(row['graph_index']);require(0<=index<key[1],'graph_index')
        slots=raw_graphs.setdefault(key,{})
        require(index not in slots,'duplicate_graph');slots[index]=raw_counts(row,n,5)
    def auc(values):return sum((grid[i+1]-grid[i])*(values[i]+values[i+1])/2 for i in range(5))
    def analytic_truth(scenario):
        # Independent reconstruction of the declared hypothetical response law.
        # No policy outcomes or generated trial truth are used as an oracle.
        require(scenario in ('beneficial_complete','beneficial_random_missing','beneficial_targeted_missing',
                             'reject_all_complete','no_security_effect_complete'),'response_model')
        fault=c['global_fault_probability']
        ac0=0. if scenario=='reject_all_complete' else sum((i+.5)/n<.98 for i in range(n))/n
        ap0=sum((i+.5)/n<.96 for i in range(n))/n
        attacks=[0.];deltas=[ac0-ap0];completions=[ac0]
        for rate in grid[1:]:
            pa=.6*rate;ca=pa if scenario=='no_security_effect_complete' else .1*rate
            pc=.96-.01*rate;cc=0. if scenario=='reject_all_complete' else .98-.01*rate
            leak_c=0. if scenario=='reject_all_complete' else fault+(1-fault)*ca
            attacks.append(leak_c-(fault+(1-fault)*pa))
            deltas.append((1-fault)*(cc-pc));completions.append((1-fault)*cc)
        return [auc(attacks)]+deltas+completions
    def bounds(record):
        lo,hi=[],[]
        for i in range(len(record['attack_c'])):
            lo.append((record['attack_c'][i]-record['attack_p'][i]-record['attack_missing_p'][i])/n)
            hi.append((record['attack_c'][i]+record['attack_missing_c'][i]-record['attack_p'][i])/n)
        dl=[(a-b-m)/n for a,b,m in zip(record['completed_c'],record['completed_p'],record['normal_missing_p'])]
        du=[(a+m-b)/n for a,b,m in zip(record['completed_c'],record['completed_p'],record['normal_missing_c'])]
        cl=[v/n for v in record['completed_c']];cu=[(a+m)/n for a,m in zip(record['completed_c'],record['normal_missing_c'])]
        return lo,hi,dl,du,cl,cu
    for row in trials:
        key=identity(row);require(key not in trial_map,'duplicate_trial');trial_map[key]=row
        maps=raw_graphs[key];require(set(maps)==set(range(key[1])),'complete_graphs_per_trial')
        e0=raw_zero[key];z=bounds(e0);lower=[];upper=[]
        for record in maps.values():
            b=bounds(record)
            lower.append([auc(z[0]+b[0])]+z[2]+b[2]+z[4]+b[4])
            upper.append([auc(z[1]+b[1])]+z[3]+b[3]+z[5]+b[5])
        intervals=[]
        for index in range(13):
            l=sum(r[index] for r in lower)/key[1];u=sum(r[index] for r in upper)/key[1]
            if index not in (1,7):
                a,b=(-1.,1.) if index<7 else (0.,1.)
                radius=(b-a)*math.sqrt(math.log(2*c['multiplicity']/c['alpha'])/(2*key[1]))
                l=max(a,l-radius);u=min(b,u+radius)
            intervals.append([l,u])
        actual=json.loads(row['intervals'])
        require(len(actual)==13 and all(type(pair) is list and len(pair)==2 and all(type(v) in (int,float) and math.isfinite(v) for v in pair) for pair in actual)
                and all(abs(v-expected_value)<1e-12 for pair,expected_pair in zip(actual,intervals) for v,expected_value in zip(pair,expected_pair)), 'intervals_from_raw_counts')
        observation=1.
        for missing in ('attack_missing_c','attack_missing_p','normal_missing_c','normal_missing_p'):
            observation=min(observation,1-e0[missing][0]/n)
            for j in range(5):observation=min(observation,1-sum(g[missing][j] for g in maps.values())/(n*key[1]))
        eligible=observation>=c['minimum_coverage']-1e-12
        safety=intervals[0][1]<-h5['minimum_ASR_AUC_reduction']
        ni=all(v[0]>-h5['TCR_noninferiority_margin'] for v in intervals[1:7])
        absolute=all(v[0]>=h5['minimum_TCR'] for v in intervals[7:])
        require(abs(float(row['minimum_observation_fraction'])-observation)<1e-12,'missing_observation_fraction')
        for name,expected_value in (('coverage_gate',eligible),('safety_component',safety),('all_six_TCR_noninferiority',ni),('all_six_absolute_TCR',absolute),('joint_confirmation',eligible and safety and ni and absolute)):
            require(boolean(row[name])==expected_value,'joint_gate_'+name)
        truth=json.loads(row['true_vector'])
        require(len(truth)==13 and all(math.isfinite(t) for t in truth),'truth_vector')
        require(all(abs(a-b)<1e-12 for a,b in zip(truth,analytic_truth(key[0]))),'declared_model_truth')
        require(boolean(row['simultaneous_covered'])==all(l-1e-12<=t<=u+1e-12 for t,(l,u) in zip(truth,intervals)),'simultaneous_coverage')
        true_h5=truth[0]<-h5['minimum_ASR_AUC_reduction'] and all(v>-h5['TCR_noninferiority_margin'] for v in truth[1:7]) and all(v>=h5['minimum_TCR'] for v in truth[7:])
        require(boolean(row['true_H5_joint'])==true_h5,'true_joint_criterion')
        expected_status='UNRUN_missing_observation_gate' if not eligible else ('JOINT_GATE_PASS_TOY_ONLY' if eligible and safety and ni and absolute else 'JOINT_GATE_NOT_PASSED_TOY_ONLY')
        require(row['status']==expected_status,'missing_is_not_success')
    require(set(trial_map)==set(raw_zero)==set(raw_graphs)==expected,'complete_cells')
    summary_keys=set()
    for summary in report['summary']:
        key=(summary['scenario'],summary['graphs']);require(key not in summary_keys,'duplicate_summary');summary_keys.add(key)
        cell=[row for identity,row in trial_map.items() if identity[:2]==key]
        require(len(cell)==c['trials']==summary['denominator'],'summary_denominator')
        for field,count in (('simultaneous_coverage_numerator',sum(boolean(r['simultaneous_covered']) for r in cell)),
                            ('joint_confirmation_numerator',sum(boolean(r['joint_confirmation']) for r in cell)),
                            ('eligible_trials',sum(boolean(r['coverage_gate']) for r in cell)),
                            ('UNRUN_missing_gate',sum(not boolean(r['coverage_gate']) for r in cell))):
            require(summary[field]==count,'summary_counts')
    require(summary_keys=={(s,g) for s in c['scenarios'] for g in c['graphs']},'complete_summary')
    return {'kind':'JOINT_RAW_COUNT_CONSISTENCY_NOT_DEFENSE_VALIDATION','trial_rows':len(trials),'graph_rows':len(graphs),'E0_rows':len(zeros),
            'H5_statistics':13,'multiplicity':17,'actual_defense_executions':0,'pilot_eligible':False}


def load(path: Path) -> bytes:
    with gzip.open(path,'rb') as handle:data=handle.read(32*1024*1024+1)
    require(len(data)<=32*1024*1024,'decompression_limit');return data


def validate_artifacts(base: Path) -> dict:
    provenance=json.loads((base/'provenance.json').read_text());report=json.loads(load(base/'report.json.gz'))
    for name in ('report.json','trials.csv','graphs.csv','e0.csv','summary.csv'):
        require(hashlib.sha256(load(base/(name+'.gz'))).hexdigest()==provenance['files'][name],'artifact_hash')
    require(hashlib.sha256(encoded(report['config'])).hexdigest()==report['config_sha256']==provenance['config_sha256'],'config_identity')
    require(json.loads((base.parent/'joint-calibration-config.json').read_text())==report['config'],'config_file_identity')
    commit=provenance['generation_commit'];require(re.fullmatch('[0-9a-f]{40}',commit) is not None,'generation_commit')
    for source,field in (('evaluation/source_trust_joint.py','source_sha256'),('evaluation/source_trust_statistics.py','dependency_sha256')):
        code=subprocess.check_output(['git','show',commit+':'+source])
        require(hashlib.sha256(code).hexdigest()==report[field],'source_git_object')
    rows=[list(csv.DictReader(io.StringIO(load(base/(name+'.csv.gz')).decode()))) for name in ('trials','graphs','e0')]
    return validate(report,*rows)


def main() -> None:
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('directory',type=Path);a=p.parse_args()
    print(json.dumps(validate_artifacts(a.directory)))


if __name__=='__main__':main()
