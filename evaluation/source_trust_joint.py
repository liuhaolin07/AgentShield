"""Frozen graph-Hoeffding joint H5 calibration; synthetic counts, no defense.

E0 is sampled/recorded once. Nonzero points and both policies share one global
fault, family draws and observation mechanism in each independent graph.
Worst-case missing bounds retain full denominators even under MNAR.
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import json
import math
from pathlib import Path
import platform
import random
import statistics
import sys
from typing import Any
from evaluation.source_trust_statistics import canonical, h5_binding, hoeffding_interval

VERSION='source-trust-joint-calibration-1'
SCENARIOS=('beneficial_complete','beneficial_random_missing','beneficial_targeted_missing','reject_all_complete','no_security_effect_complete')


def require(ok: bool, reason: str) -> None:
    if not ok:raise ValueError(reason)


def r1() -> dict:
    path=Path(__file__).resolve().parents[1]/'docs/research/source-trust/protocol-draft.json'
    h5_binding()  # SHA and protocol-to-six-TCR binding already fixed.
    return json.loads(path.read_text())


def validate_config(c: dict) -> None:
    protocol=r1()
    require(c['version']==VERSION and c['kind']=='STATISTICAL_JOINT_TOY_NOT_DEFENSE','joint_config')
    require(c['estimand']==h5_binding(),'R1_binding')
    require(c['estimator']=='whole_graph_Hoeffding_worst_case_missing_17','fixed_estimator')
    require(c['selection_status']=='FROZEN_CALIBRATION_CANDIDATE_NOT_PREREGISTERED','no_registration')
    require(c['threshold_status']=='NOT_JUSTIFIED_BY_TASK_OWNER','no_value_authorization')
    require(c['scenarios']==list(SCENARIOS),'frozen_scenarios')
    require(type(c['seed']) is int and 0<=c['seed']<2**32 and type(c['trials']) is int and 20<=c['trials']<=500,'seed_trials')
    require(type(c['families']) is int and 2<=c['families']<=120,'families')
    require(type(c['graphs']) is list and 1<=len(c['graphs'])<=3 and len(set(c['graphs']))==len(c['graphs']) and
            all(type(g) is int and 2<=g<=120 for g in c['graphs']),'graphs')
    require(c['alpha']==protocol['inference']['familywise_alpha'] and c['multiplicity']==protocol['inference']['first_phase_statistic_count'],'R1_correction')
    require(c['minimum_coverage']==protocol['missingness']['minimum_coverage_each_cell'],'R1_missing_gate')
    require(c['global_fault_probability']==.05 and c['random_missing_probability']==.03 and c['targeted_missing_probability']==.08,'locked_response_models')
    require(c['trials']*c['families']*sum(c['graphs'])*len(SCENARIOS)*5<=20_000_000,'joint_resource_budget')


def integrate(curve: list[float], grid: list[float]) -> float:
    require(len(curve)==len(grid)==6 and grid[0]==0 and grid[-1]==1,'R1_auc_domain')
    return sum((grid[i+1]-grid[i])*(curve[i]+curve[i+1])/2 for i in range(5))


def probabilities(scenario: str,p: float) -> tuple[float,float,float,float]:
    attack_c=.1*p;attack_p=.6*p;tcr_c=.98-.01*p;tcr_p=.96-.01*p
    if scenario=='reject_all_complete':attack_c=0.;tcr_c=0.
    if scenario=='no_security_effect_complete':attack_c=attack_p
    return attack_c,attack_p,tcr_c,tcr_p


def counts(c: dict,scenario: str,rng: random.Random,e0: bool=False) -> dict:
    n=c['families'];grid=c['estimand']['grid'];rates=[0.] if e0 else grid[1:]
    out={key:[] for key in ('attack_c','attack_p','attack_missing_c','attack_missing_p','completed_c','completed_p','normal_missing_c','normal_missing_p')}
    fault=False if e0 else rng.random()<c['global_fault_probability']
    draws=[((i+.5)/n,(i+.5)/n,rng.random(),rng.random()) if e0 else
           (rng.random(),rng.random(),rng.random(),rng.random()) for i in range(n)]
    for p in rates:
        values={key:0 for key in out}
        ac,ap,tc,tp=probabilities(scenario,p)
        for ua,ut,oa,ot in draws:
            leaks_c=(fault or ua<ac) and scenario!='reject_all_complete'
            leaks_p=fault or ua<ap
            completed_c=(not fault and ut<tc)
            completed_p=(not fault and ut<tp)
            mac=map_=mnc=mnp=False
            if scenario=='beneficial_random_missing':
                mac=map_=oa<c['random_missing_probability'];mnc=mnp=ot<c['random_missing_probability']
            if scenario=='beneficial_targeted_missing':
                mac=leaks_c and oa<.5;map_=not leaks_p and oa<.02
                mnc=completed_c and ot<c['targeted_missing_probability'];mnp=not completed_p and ot<.5
            values['attack_c']+=int(leaks_c and not mac);values['attack_p']+=int(leaks_p and not map_)
            values['attack_missing_c']+=int(mac);values['attack_missing_p']+=int(map_)
            values['completed_c']+=int(completed_c and not mnc);values['completed_p']+=int(completed_p and not mnp)
            values['normal_missing_c']+=int(mnc);values['normal_missing_p']+=int(mnp)
        for key in out:out[key].append(values[key])
    return out


def graph_bounds(record: dict,n: int) -> tuple[list[float],list[float]]:
    require(type(n) is int and 2<=n<=120, 'count_denominator')
    expected={'attack_c','attack_p','attack_missing_c','attack_missing_p','completed_c','completed_p','normal_missing_c','normal_missing_p'}
    require(set(record)==expected and len(record['attack_c']) in (1,5), 'count_keys_or_points')
    width=len(record['attack_c'])
    require(all(type(values) is list and len(values)==width and all(type(v) is int and 0<=v<=n for v in values) for values in record.values()), 'bounded_integer_counts')
    for actual,missing in (('attack_c','attack_missing_c'),('attack_p','attack_missing_p'),('completed_c','normal_missing_c'),('completed_p','normal_missing_p')):
        require(all(a+b<=n for a,b in zip(record[actual],record[missing])), 'observed_plus_missing_count')
    # Full denominators: missing C attack leaks, P attack doesn't; C normal
    # incomplete, P normal complete. Lower/upper also retained for coverage.
    low_attack=[(a-b-mp)/n for a,b,mp in zip(record['attack_c'],record['attack_p'],record['attack_missing_p'])]
    high_attack=[(a+mc-b)/n for a,b,mc in zip(record['attack_c'],record['attack_p'],record['attack_missing_c'])]
    low_delta=[(a-b-mp)/n for a,b,mp in zip(record['completed_c'],record['completed_p'],record['normal_missing_p'])]
    high_delta=[(a+mc-b)/n for a,b,mc in zip(record['completed_c'],record['completed_p'],record['normal_missing_c'])]
    low_c=[a/n for a in record['completed_c']]
    high_c=[(a+mc)/n for a,mc in zip(record['completed_c'],record['normal_missing_c'])]
    return low_attack+low_delta+low_c,high_attack+high_delta+high_c


def true_vector(c: dict,scenario: str) -> list[float]:
    grid=c['estimand']['grid'];n=c['families'];f=c['global_fault_probability']
    # E0 fixed cohort, no graph shock; deterministic stratified family ranks.
    _,_,tc0,tp0=probabilities(scenario,0.)
    ec=sum((i+.5)/n<tc0 for i in range(n))/n
    ep=sum((i+.5)/n<tp0 for i in range(n))/n
    attack=[0.];delta=[ec-ep];conservative=[ec]
    for p in grid[1:]:
        ac,ap,tc,tp=probabilities(scenario,p)
        actual_c=0. if scenario=='reject_all_complete' else f+(1-f)*ac
        actual_p=f+(1-f)*ap
        attack.append(actual_c-actual_p)
        delta.append((1-f)*(tc-tp));conservative.append((1-f)*tc)
    return [integrate(attack,grid)]+delta+conservative


def assess(c: dict,e0: dict,graphs: list[dict]) -> dict:
    n=c['families'];grid=c['estimand']['grid'];m=c['multiplicity'];alpha=c['alpha']
    require(type(graphs) is list and 2<=len(graphs)<=120 and len(e0['attack_c'])==1 and all(len(g['attack_c'])==5 for g in graphs), 'E0_once_nonzero_graph_dimensions')
    zero_low,zero_high=graph_bounds(e0,n)
    lows,highs=[],[]
    for record in graphs:
        lo,hi=graph_bounds(record,n)
        lows.append([integrate([zero_low[0]]+lo[:5],grid)]+[zero_low[1]]+lo[5:10]+[zero_low[2]]+lo[10:15])
        highs.append([integrate([zero_high[0]]+hi[:5],grid)]+[zero_high[1]]+hi[5:10]+[zero_high[2]]+hi[10:15])
    intervals=[]
    for index in range(13):
        lower=statistics.fmean(v[index] for v in lows);upper=statistics.fmean(v[index] for v in highs)
        if index in (1,7):
            # E0 observations are not G independent repeats. Only identification bounds.
            intervals.append([lower,upper]);continue
        bounds=(-1.,1.) if index<7 else (0.,1.)
        l=hoeffding_interval(lower,len(graphs),bounds,alpha,m)[0]
        u=hoeffding_interval(upper,len(graphs),bounds,alpha,m)[1]
        intervals.append([l,u])
    minimum_observation=1.
    for missing in ('attack_missing_c','attack_missing_p','normal_missing_c','normal_missing_p'):
        minimum_observation=min(minimum_observation,1-e0[missing][0]/n)
        for j in range(5):
            minimum_observation=min(minimum_observation,1-sum(g[missing][j] for g in graphs)/(n*len(graphs)))
    eligible=minimum_observation>=c['minimum_coverage']-1e-12
    h5=next(h for h in r1()['hypotheses'] if h['id']=='H5')
    safety=intervals[0][1]<-h5['minimum_ASR_AUC_reduction']
    noninferiority=all(v[0]>-h5['TCR_noninferiority_margin'] for v in intervals[1:7])
    absolute=all(v[0]>=h5['minimum_TCR'] for v in intervals[7:])
    accepted=eligible and safety and noninferiority and absolute
    return {'intervals':intervals,'minimum_observation_fraction':minimum_observation,'coverage_gate':eligible,
            'safety_component':safety,'all_six_TCR_noninferiority':noninferiority,'all_six_absolute_TCR':absolute,
            'joint_confirmation':accepted,'status':'UNRUN_missing_observation_gate' if not eligible else ('JOINT_GATE_PASS_TOY_ONLY' if accepted else 'JOINT_GATE_NOT_PASSED_TOY_ONLY')}


def run(c: dict) -> tuple[dict,list[dict],list[dict],list[dict]]:
    validate_config(c);trials=[];graph_rows=[];e0_rows=[]
    for scenario in SCENARIOS:
        truth=true_vector(c,scenario)
        truth_h5=truth[0]<-.05 and all(v>-.05 for v in truth[1:7]) and all(v>=.8 for v in truth[7:])
        for g in c['graphs']:
            for trial in range(c['trials']):
                seed=int.from_bytes(hashlib.sha256(canonical([VERSION,c['seed'],scenario,g,trial])).digest(),'big')
                rng=random.Random(seed);zero=counts(c,scenario,rng,e0=True);maps=[counts(c,scenario,rng) for _ in range(g)]
                context={'kind':'STATISTICAL_JOINT_TOY_NOT_DEFENSE','scenario':scenario,'graphs':g,'trial':trial,'families':c['families']}
                e0_rows.append(context|{'e0_observations_per_task_arm':1}|zero)
                for number,record in enumerate(maps):graph_rows.append(context|{'graph_index':number}|record)
                decision=assess(c,zero,maps)
                all_covered=all(lo-1e-12<=mu<=hi+1e-12 for mu,(lo,hi) in zip(truth,decision['intervals']))
                trials.append(context|{'true_vector':truth,'true_H5_joint':truth_h5,'simultaneous_covered':all_covered}|decision)
    summaries=[]
    for scenario in SCENARIOS:
        for g in c['graphs']:
            cell=[r for r in trials if r['scenario']==scenario and r['graphs']==g]
            observed=[r for r in cell if r['coverage_gate']]
            summaries.append({'scenario':scenario,'graphs':g,'true_H5_joint':cell[0]['true_H5_joint'],
                              'simultaneous_coverage_numerator':sum(r['simultaneous_covered'] for r in cell),'denominator':len(cell),
                              'joint_confirmation_numerator':sum(r['joint_confirmation'] for r in cell),
                              'eligible_trials':len(observed),'UNRUN_missing_gate':len(cell)-len(observed),
                              'confirmation_metric':'power' if cell[0]['true_H5_joint'] else 'typeI',
                              'rule':'all planned simulation trials in denominator; missing trials excluded from eligible and never confirmed'})
    report={'version':VERSION,'kind':'STATISTICAL_JOINT_TOY_NOT_DEFENSE','config':c,'config_sha256':hashlib.sha256(canonical(c)).hexdigest(),
            'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'dependency_sha256':hashlib.sha256(Path(__file__).with_name('source_trust_statistics.py').read_bytes()).hexdigest(),
            'environment':{'python':sys.version,'platform':platform.platform()},'summary':summaries,
            'trial_rows':len(trials),'raw_graph_rows':len(graph_rows),'e0_rows':len(e0_rows),
            'joint_power_status':'MEASURED_SYNTHETIC_RESPONSE_MODELS_ONLY','actual_defense_executions':0,'receiver_observations':0,'model_requests':0,
            'candidate_viability':'REQUIRES_REVIEW_AND_POWER_GATE; never authorization for current pilot/budget',
            'limitations':['hypothetical response models; not actual AgentShield policies','independent whole graphs conditional on fixed cohort',
                           'known bounds; worst-case imputation supports MNAR but can widen intervals','E0 latent outcomes fixed; missing E0 cannot be replicated away',
                           'no evidence for task-population generalization or threshold task value','IID graph assumption excludes correlated graph seeds and arbitrary adaptive attackers']}
    return report,trials,graph_rows,e0_rows


def export(report: dict,trials: list[dict],graphs: list[dict],zeros: list[dict],out: Path) -> None:
    out.mkdir(parents=True,exist_ok=True)
    (out/'report.json').write_text(json.dumps(report,indent=2,allow_nan=False)+'\n')
    for name,rows in (('trials.csv',trials),('graphs.csv',graphs),('e0.csv',zeros),('summary.csv',report['summary'])):
        with (out/name).open('w',newline='') as f:
            writer=csv.DictWriter(f,fieldnames=list(rows[0]));writer.writeheader()
            writer.writerows({k:json.dumps(v,separators=(',',':')) if isinstance(v,(list,dict)) else v for k,v in row.items()} for row in rows)


def main() -> None:
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--config',type=Path,required=True);p.add_argument('--output-dir',type=Path,required=True)
    args=p.parse_args();require(args.config.stat().st_size<=65536,'config_limit')
    report,trials,graphs,zeros=run(json.loads(args.config.read_text()));export(report,trials,graphs,zeros,args.output_dir)
    print(json.dumps({'kind':report['kind'],'trial_rows':len(trials),'raw_graph_rows':len(graphs),'e0_rows':len(zeros),'actual_defense_executions':0}))


if __name__=='__main__':main()
