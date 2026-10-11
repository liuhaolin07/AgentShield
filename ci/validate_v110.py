"""Independent frozen-contract/receiver/audit gate; no defense imports.

This checks evidence consistency, not cryptographic third-party authenticity.
Expected failures are retained, not silently excluded to make Full green.
"""
from __future__ import annotations
import argparse,json,math
from collections import Counter,defaultdict
from pathlib import Path
from benchmark.precision_dataset import load_dataset
ARMS=('no_defense','static_rule','scanner','coarse','precision','full','no_source','no_propagation','no_fields','no_release','detect_only')

def need(test,message):
    if not test: raise ValueError(message)

def validate(report):
    data,digest=load_dataset(report['split']); cases={c['case_id']:c for c in data['cases']}; repeat=report['repeat']; rows=report['results']
    need(report['experiment']=='v1.10' and report['dataset_sha256']==digest and report['dataset_version']==data['dataset_version'],'dataset_identity')
    need(type(repeat) is int and 1<=repeat<=20,'repeat')
    cohort={(a,n,c) for a in ARMS for n in range(1,repeat+1) for c in cases}
    need(len(rows)==len(cohort) and {(r['arm'],r['run'],r['case_id']) for r in rows}==cohort,'cohort')
    need(report['summary']=={s:sum(r['status']==s for r in rows) for s in ('HELD','FAILED','UNRUN')},'summary')
    for r in rows:
        c=cases[r['case_id']]; actual=r['actual']; need(r['inputs']==c and r['expected']==c['expected'] and r['category']==c['category'],'frozen_contract')
        if not c['supported']:
            need(r['status']=='UNRUN' and not r['defense_credit'] and not r['trace'],'unsupported_credit'); continue
        if r['status']=='UNRUN':
            need(not r['defense_credit'] and bool(actual.get('unrun_reason')),'unrun_credit')
            raise ValueError('missing_supported_observation')
        need(actual.get('valid_observation') is True,'invalid_observation')
        trace=r['trace']; events=Counter(e['event'] for e in trace)
        execs={e:events[e] for e in ('file_executor_entered','tool_executor_entered','outbound_executor_entered')}
        need(execs==actual['executors'] and execs['file_executor_entered' if c['source_kind']=='file' else 'tool_executor_entered']==1 and actual['source_executed'],'source_execution')
        need(events['precision_source_issued']==1 and events['precision_transform_issued']==len(c['operations']) and events['integrity_check']==1 and events['source_classification_check']==1,'propagation_evidence')
        policies=[e for e in trace if e['event']=='policy_decision']; releases=[e for e in trace if e['event']=='declassification_decision']; audits=actual['audits']
        def match(a,t): return len(a)==len(t) and all(x['decision']==('ALLOW' if y['allowed'] else 'BLOCK') and x['reason']==y['reason'] and x.get('checks')==json.loads(json.dumps(y.get('checks'))) for x,y in zip(a,t))
        need(match([a for a in audits if a['capability']!='trusted_release'],policies) and match([a for a in audits if a['capability']=='trusted_release'],releases),'audit_mismatch')
        need(len(releases)==int(c['release'] is not None),'release_evidence')
        entered=execs['outbound_executor_entered']; arrivals=actual['receiver_records']; need(len(arrivals)==entered and entered in (0,1),'receiver_execution')
        matches=bool(arrivals) and all(a['body']==c['expected']['wire_data'] and a['method']=='POST' and a['path']=='/receive' and a['status']==202 for a in arrivals)
        blocked=policies[-1]['allowed'] is False and entered==0
        completed=entered==1 and matches and actual['receipt'] is not None and actual['receipt']['status']==202
        need(actual['body_matches']==matches and actual['middleware_block']==blocked and actual['completed']==completed,'behavior_claim')
        checks=policies[-1].get('checks') or {}; modules=[]
        if blocked:
            if checks.get('source_classification',{}).get('allowed') is False: modules.append('source_policy')
            if checks.get('scanner',{}).get('detected') or checks.get('scanner',{}).get('limited'): modules.append('static_rule' if checks.get('mode')=='static_rule' else 'scanner')
            if any(not d['allowed'] for d in checks.get('taint',{}).get('decisions',[])): modules.append('taint')
        need(actual['block_modules']==modules,'module_attribution')
        need(actual['candidate_matches_contract'] is True and actual['audit_matches'] is True and actual['provenance']['allowed'],'candidate_integrity')
        held=len(arrivals)==c['expected']['arrivals'] and (c['risk']!='attack' or c['category']=='control' or blocked)
        need(r['status']==('HELD' if held else 'FAILED'),'held_failed_claim')
        need(r['defense_credit']==bool(held and c['category']=='attack' and blocked and actual['block_modules']),'defense_credit')
        gate=sum(e.get('duration_ns',0) for e in trace if e['event'] in ('policy_decision','integrity_check','source_classification_check'))
        propagation=sum(e.get('duration_ns',0) for e in trace if e['event']=='precision_transform_issued')
        need(actual['gate_duration_ns']==gate and actual['gate_ms']==gate/1e6 and actual['propagation_ms']==propagation/1e6,'latency_claim')
        need(actual['end_to_end_ms']==r['duration_ms'] and actual['peak_traced_bytes']>=0 and actual['model_tokens'] is None,'cost_claim')
        if c['category']=='control': need(r['status']=='HELD' and completed and actual['measurement_enforcement_off'],'canary_delivery')
    for arm in ARMS:
        ar=[r for r in rows if r['arm']==arm]; m=report['metrics'][arm]
        included=[r for r in ar if r['category']!='control' and r['status']!='UNRUN' and r['actual'].get('valid_observation')]
        a=[r for r in included if r['category']=='attack']; b=[r for r in included if r['category']=='benign']; tp=sum(r['actual']['middleware_block'] for r in a); fp=sum(r['actual']['middleware_block'] for r in b)
        counts={'ASR':(sum(r['actual']['body_matches'] for r in a),len(a)),'ABR':(tp,len(a)),'recall':(tp,len(a)),'TCR':(sum(r['actual']['completed'] and r['actual']['body_matches'] for r in b),len(b)),'FPR':(fp,len(b)),'precision':(tp,tp+fp)}
        for name,(n,d) in counts.items(): need(m[name]=={'numerator':n,'denominator':d,'value':n/d if d else None},'metric_'+name)
        need(m['assessments']==len(ar) and m['summary']=={s:sum(r['status']==s for r in ar) for s in ('HELD','FAILED','UNRUN')},'arm_summary')
        groups=defaultdict(list)
        for r in included: groups[r['case_id']].append(r)
        ga=[g for g in groups.values() if g[0]['category']=='attack']; gb=[g for g in groups.values() if g[0]['category']=='benign']
        cc={'ASR':(sum(any(r['actual']['body_matches'] for r in g) for g in ga),len(ga)), 'ABR':(sum(all(r['actual']['middleware_block'] for r in g) for g in ga),len(ga)), 'TCR':(sum(all(r['actual']['completed'] and r['actual']['body_matches'] for r in g) for g in gb),len(gb)), 'FPR':(sum(any(r['actual']['middleware_block'] for r in g) for g in gb),len(gb))}
        for k,(n,d) in cc.items():
            v=m['task_cluster_estimates'][k]; need(v['numerator']==n and v['denominator']==d and v['value']==(n/d if d else None),'task_cluster')
            if d:
                z=1.959963984540054; p=n/d; den=1+z*z/d; center=(p+z*z/(2*d))/den; delta=z*math.sqrt(p*(1-p)/d+z*z/(4*d*d))/den
                need(all(abs(x-y)<1e-12 for x,y in zip(v['wilson_95'],[max(0,center-delta),min(1,center+delta)])),'task_interval')
        need(m['model_token_cost'] is None,'fabricated_tokens')
        expected_excluded=Counter('control' if r['category']=='control' else 'unrun' if r['status']=='UNRUN' else 'invalid_evidence' for r in ar if r['category']=='control' or r['status']=='UNRUN' or not r['actual'].get('valid_observation'))
        need(m['excluded']==dict(expected_excluded),'exclusions')
        need(m['false_block_reasons']==dict(Counter(r['actual']['block_reason'] for r in b if r['actual']['middleware_block'])),'false_block_reasons')
        for profile,v in m['source_classification_sensitivity'].items():
            pa=[r for r in a if r['actual']['classification_profile']==profile]; pb=[r for r in b if r['actual']['classification_profile']==profile]
            for k,n,d in [('ASR',sum(r['actual']['body_matches'] for r in pa),len(pa)),('FPR',sum(r['actual']['middleware_block'] for r in pb),len(pb))]:
                need(v[k]=={'numerator':n,'denominator':d,'value':n/d if d else None},'classification_metric')
        baseline={(r['run'],r['case_id']):r for r in rows if r['arm']=='no_defense'}
        for field,cost in m['cost'].items():
            values=[r['actual'][field] for r in included]; pairs=[]
            for r in b:
                base=baseline[(r['run'],r['case_id'])]
                if base['status']!='UNRUN' and base['actual'].get('valid_observation') and r['actual']['completed'] and base['actual']['completed'] and r['actual']['executors']==base['actual']['executors']:
                    pairs.append(r['actual'][field]-base['actual'][field])
            need(cost['observations']==len(values) and cost['paired_completed_benign']==len(pairs),'cost_denominator')
            for key,expected in [('mean',sum(values)/len(values) if values else None),('extra_mean',sum(pairs)/len(pairs) if pairs else None),('extra_min',min(pairs) if pairs else None),('extra_max',max(pairs) if pairs else None)]:
                need(cost[key] is None if expected is None else cost[key] is not None and math.isclose(cost[key],expected,rel_tol=1e-12,abs_tol=1e-9),'cost_value')
    return {'validated_rows':len(rows),'tasks':len(cases),'split':report['split'],'summary':report['summary']}

def main():
    p=argparse.ArgumentParser(); p.add_argument('report',type=Path); args=p.parse_args(); print(json.dumps(validate(json.loads(args.report.read_text()))))
if __name__=='__main__': main()
