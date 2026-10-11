"""Observed rates, task-cluster intervals and matched execution cost.

Repeated executions are assessments, not additional independent tasks. Wilson
intervals use unique task outcomes; authored tasks still are not IID sampling.
"""
from __future__ import annotations
import math,statistics
from collections import defaultdict,Counter
from evaluation.experiment import calculate_metrics,_fraction
from security.precision_research import ARMS,ABLATIONS

def wilson(n,d):
    if not d: return None
    z=1.959963984540054; p=n/d; den=1+z*z/d; center=(p+z*z/(2*d))/den
    rad=z*math.sqrt(p*(1-p)/d+z*z/(4*d*d))/den
    return [max(0,center-rad),min(1,center+rad)]

def observed(row): return row['category']!='control' and row['status']!='UNRUN' and row['actual'].get('valid_observation')

def metrics(rows):
    out=calculate_metrics(rows,arms=ARMS)
    base={(r['run'],r['case_id']):r for r in rows if r['arm']=='no_defense'}
    for arm in ARMS:
        included=[r for r in rows if r['arm']==arm and observed(r)]; m=out[arm]
        m['ABR']=m['recall']; m['normal_execution_success_rate']=m['TCR']
        m['false_block_reasons']=dict(Counter(r['actual']['block_reason'] for r in included if r['category']=='benign' and r['actual']['middleware_block']))
        profiles={}
        for profile in sorted({r['actual']['classification_profile'] for r in included}):
            a=[r for r in included if r['category']=='attack' and r['actual']['classification_profile']==profile]
            b=[r for r in included if r['category']=='benign' and r['actual']['classification_profile']==profile]
            profiles[profile]={'ASR':_fraction(sum(r['actual']['body_matches'] for r in a),len(a)), 'FPR':_fraction(sum(r['actual']['middleware_block'] for r in b),len(b))}
        m['source_classification_sensitivity']=profiles
        groups=defaultdict(list)
        for row in included: groups[row['case_id']].append(row)
        attacks=[g for g in groups.values() if g[0]['category']=='attack']; benign=[g for g in groups.values() if g[0]['category']=='benign']
        # Any observed repeat leak / false block, all observed repeats completing.
        cluster={'ASR':(sum(any(r['actual']['body_matches'] for r in g) for g in attacks),len(attacks)),
                 'TCR':(sum(all(r['actual']['completed'] and r['actual']['body_matches'] for r in g) for g in benign),len(benign)),
                 'FPR':(sum(any(r['actual']['middleware_block'] for r in g) for g in benign),len(benign)),
                 'ABR':(sum(all(r['actual']['middleware_block'] for r in g) for g in attacks),len(attacks))}
        m['task_cluster_estimates']={k:{**_fraction(n,d),'wilson_95':wilson(n,d)} for k,(n,d) in cluster.items()}
        m['task_cluster_rule']='ASR/FPR: any observed repeat; TCR/ABR: all observed repeats. Missing repeats reported, no assumed outcomes; authored non-IID contracts.'
        m['cost']={}
        for field in ('end_to_end_ms','gate_ms','propagation_ms','peak_traced_bytes'):
            values=[r['actual'][field] for r in included]; pairs=[]
            for r in included:
                b=base.get((r['run'],r['case_id']))
                # Avoid falsely attributing skipped tool/network execution to efficiency.
                if r['category']=='benign' and b and observed(b) and r['actual']['completed'] and b['actual']['completed'] and r['actual']['executors']==b['actual']['executors']:
                    pairs.append(r['actual'][field]-b['actual'][field])
            m['cost'][field]={'observations':len(values),'mean':statistics.mean(values) if values else None,'paired_completed_benign':len(pairs),'extra_mean':statistics.mean(pairs) if pairs else None,'extra_min':min(pairs) if pairs else None,'extra_max':max(pairs) if pairs else None}
        m['model_token_cost']=None
    return out
