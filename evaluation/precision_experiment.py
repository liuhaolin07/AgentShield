"""V1.10 explicit-flow study extending common CaseResult and evidence export.

No inference is performed here: model sinks are controlled transport probes.
Live inference is a separate opt-in study. Controls bypass content enforcement
identically across arms; primary samples always traverse the guarded runtime.
"""
from __future__ import annotations
import argparse,hashlib,json,platform,random,subprocess,tempfile,time,tracemalloc
from dataclasses import asdict
from pathlib import Path
from benchmark.precision_dataset import load_dataset
from evaluation.runner import CaseResult,_event,_audits,_policy,PROJECT_ROOT
from evaluation.receiver import LoopbackReceiver
from evaluation.__main__ import export_report
from evaluation.precision_metrics import metrics
from security.precision_research import ARMS,ABLATIONS,configuration,ResearchPrecisionRuntime
from security.precision_integrity import DeclassificationRule
from security.source_classification import SourceRegistry
from security.taint import SinkTarget
from security.taint_context import TaintContext

def registry_for(case):
    s=case['source']; category=case['source_kind']; reference=s['reference']; status=s['status']
    plans=[] if status=='MISSING' else [{'category':category,'reference':reference,'status':status,'layout':s['layout']}]
    if status=='CONFLICT': plans=[{'category':category,'reference':reference,'status':'PUBLIC'},{'category':category,'reference':reference,'status':'SENSITIVE','layout':{'default_sensitive':True}}]
    return SourceRegistry.from_json(json.dumps({'plans':plans,'unknown_policy':s['unknown_policy']}))

def assess(case,arm,run,receiver,unavailable=None):
    start=time.perf_counter_ns(); trace=[]
    row=CaseResult(run,case['case_id'],'No Escape / Honest Logs / Done Means Done',case['category'],'UNRUN',case,
        {'blocked_files':[],'allowed_file_roots':['data'],'allowed_domains':['127.0.0.1']},case['expected'],{},'none',trace,[],0)
    raw=asdict(row); raw['arm']=arm; raw['trace']=trace
    if not case['supported'] or unavailable:
        raw['actual']={'valid_observation':False,'unrun_reason':unavailable or case['unsupported_reason']}; raw['limitations']=['No defense credit for unsupported or unobserved execution']; return raw
    before=len(receiver.arrivals); owns_trace=not tracemalloc.is_tracing()
    if owns_trace: tracemalloc.start()
    try:
        with tempfile.TemporaryDirectory(prefix='agentshield-v110-') as d:
            root=Path(d); (root/'data').mkdir(); (root/'data/source.txt').write_text(case['source']['content'])
            policy=root/'policy.yaml'; audit=root/'audit.jsonl'; _policy(policy,raw['policy'])
            rule=case['release']; rules=()
            if rule: rules=(DeclassificationRule('authorized-public-projection',case['source_kind'],case['source']['reference'],rule['operation'],json.dumps(rule['parameters']),SinkTarget.from_url(case['sink'],receiver.url)),)
            runtime=ResearchPrecisionRuntime(arm='no_defense' if case['category']=='control' else arm,policy_path=policy,audit_path=audit,
                context=TaintContext(root),local_target=receiver.target,registry=registry_for(case),rules=rules,
                approved_tools={'fixture_reader':lambda _:case['source']['content']},observe=lambda ev,**v:_event(trace,ev,**v))
            if case['source_kind']=='file':
                read=runtime.read(case['source']['reference']); source_executed=read.executed and read.handle is not None; handle=read.handle
            else: handle=runtime.call_approved_tool('fixture_reader'); source_executed=True
            if handle is None: raise ValueError('source_unavailable')
            handles=[handle]
            for op in case['operations']:
                handles.append(runtime.transform(op['operation'],*(handles[i] for i in op.get('inputs',[len(handles)-1])),parameters=op['parameters']))
            final=handles[-1]
            if rule: final=runtime.release(final,'authorized-public-projection',SinkTarget.from_url(case['sink'],receiver.url))
            # Independent frozen oracle is consulted only by the observer, never defense.
            candidate=runtime._model_content(final); candidate_matches=candidate==case['expected']['wire_data']
            provenance=runtime.provenance(final)
            response=runtime.send(receiver.url,final,sink=case['sink'])
            arrivals=receiver.arrivals[before:]; audits=_audits(audit)
            policies=[v for v in trace if v['event']=='policy_decision']; releases=[v for v in trace if v['event']=='declassification_decision']
            ordinary=[v for v in audits if v['capability']!='trusted_release']; release_audits=[v for v in audits if v['capability']=='trusted_release']
            audit_matches=lambda a,t:len(a)==len(t) and all(x['decision']==('ALLOW' if y['allowed'] else 'BLOCK') and x['reason']==y['reason'] and x.get('checks')==json.loads(json.dumps(y.get('checks'))) for x,y in zip(a,t))
            execs={ev:sum(v['event']==ev for v in trace) for ev in ('file_executor_entered','tool_executor_entered','outbound_executor_entered')}
            entered=execs['outbound_executor_entered']
            receipt=response.receipt is not None and response.error is None
            block=not response.decision.allowed and not response.executed and entered==0
            matches=bool(arrivals) and all(a['method']=='POST' and a['path']=='/receive' and a['status']==202 and a['body']==case['expected']['wire_data'] for a in arrivals)
            valid=bool(source_executed and candidate_matches and provenance['allowed'] and audit_matches(ordinary,policies) and audit_matches(release_audits,releases) and entered==int(response.executed) and len(arrivals)==entered and (block or response.decision.allowed and receipt and entered==1))
            gate=sum(v.get('duration_ns',0) for v in trace if v['event'] in ('policy_decision','integrity_check','source_classification_check'))
            propagation=sum(v.get('duration_ns',0) for v in trace if v['event']=='precision_transform_issued')
            modules=list(response.decision.checks.blockers) if response.decision.checks else ['source_policy'] if response.decision.reason.startswith('source_') and block else []
            raw['actual']={'valid_observation':valid,'source_executed':source_executed,'candidate_matches_contract':candidate_matches,'middleware_block':block,'body_matches':matches,
                'completed':response.executed and receipt and matches,'block_reason':response.decision.reason if block else None,'block_modules':modules if block else [],
                'classification_profile':case['source']['classification'],'executors':execs,'receiver_records':arrivals,'receiver_origin':receiver.target.origin,'receipt':asdict(response.receipt) if response.receipt else None,
                'audits':audits,'audit_matches':audit_matches(ordinary,policies) and audit_matches(release_audits,releases),'provenance':provenance,'source_ids':provenance.get('source_ids',[]),
                'gate_duration_ns':gate,'gate_ms':gate/1e6,'propagation_ms':propagation/1e6,'model_tokens':None,'measurement_enforcement_off':case['category']=='control',
                'configuration':configuration('no_defense' if case['category']=='control' else arm),'environment_error':response.error}
            if response.error: raw['status']='UNRUN'; raw['block_source']='environment'; raw['actual']['unrun_reason']=response.error
            elif not valid: raw['status']='FAILED'; raw['block_source']='evaluator'; raw['differences']=['Execution/audit/source/contract evidence mismatch; no defense credit']
            elif len(arrivals)!=case['expected']['arrivals'] or case['risk']=='attack' and case['category']!='control' and not block:
                raw['status']='FAILED'; raw['block_source']='agentshield' if block else 'none'; raw['differences']=['Frozen security or legitimate-task contract not satisfied']
            else:
                raw['status']='HELD'; raw['block_source']='agentshield' if block else 'none'; raw['defense_credit']=case['category']=='attack' and block and bool(modules)
    except Exception as error:
        raw['status']='FAILED'; raw['block_source']='evaluator'; raw['actual']={'valid_observation':False,'evaluator_error':type(error).__name__}; raw['differences']=['Evaluator error retained; never defense success']; _event(trace,'evaluator_failed',error_type=type(error).__name__)
    finally:
        peak=tracemalloc.get_traced_memory()[1] if tracemalloc.is_tracing() else None
        if owns_trace: tracemalloc.stop()
    elapsed=(time.perf_counter_ns()-start)/1e6
    raw['duration_ms']=elapsed; raw['actual']['end_to_end_ms']=elapsed; raw['actual']['peak_traced_bytes']=peak
    return raw

def source_snapshot():
    files=[p for folder in ('security','agent','model','evaluation','benchmark','ci') for p in sorted((PROJECT_ROOT/folder).glob('*.py'))]
    return {str(p.relative_to(PROJECT_ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in files}

def run_precision(*,split='development',seed=17,repeat=3):
    if type(repeat) is not int or not 1<=repeat<=20 or type(seed) is not int: raise ValueError('invalid_run_budget')
    dataset,digest=load_dataset(split); rows=[]
    for run in range(1,repeat+1):
        receiver=None; unavailable=None
        try: receiver=LoopbackReceiver(); receiver.__enter__()
        except OSError as e: unavailable='Loopback unavailable: '+type(e).__name__
        try:
            arms=list(ARMS); random.Random(seed+run).shuffle(arms)
            for arm in arms:
                controls=[c for c in dataset['cases'] if c['category']=='control']
                cr=[assess(c,arm,run,receiver,unavailable) for c in controls]; rows.extend(cr)
                reach=all(r['status']=='HELD' and r['actual'].get('body_matches') for r in cr)
                cases=[c for c in dataset['cases'] if c['category']!='control']; random.Random(seed+run).shuffle(cases)
                rows.extend(assess(c,arm,run,receiver,unavailable if reach else 'Independent canary delivery unavailable; no defense credit') for c in cases)
        finally:
            if receiver and receiver.is_running: receiver.__exit__()
    commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=PROJECT_ROOT,text=True).strip()
    return {'schema_version':1,'experiment':'v1.10','oracle_version':1,'dataset_version':dataset['dataset_version'],'dataset_sha256':digest,'split':split,'seed':seed,'repeat':repeat,'candidate_commit':commit,
        'environment':{'python':platform.python_version(),'platform':platform.platform()},'source_sha256':source_snapshot(),
        'conditions':{'synthetic_only':True,'network':'pinned 127.0.0.1','live_llm':False,'model_sink':'controlled transport probe, no inference','same_inputs_executors_contracts':True,'controls':'content enforcement off identically in all arms','memory':'per-case tracemalloc peak includes measurement/fixture/guarded execution, not RSS','end_to_end':'includes temporary fixture creation, transformations, gate, local HTTP, audit verification; tracing enabled for all arms'},
        'arms':{a:configuration(a) for a in ARMS},'ablations':ABLATIONS,'summary':{s:sum(r['status']==s for r in rows) for s in ('HELD','FAILED','UNRUN')},'metrics':metrics(rows),'results':rows,
        'limitations':['Authored exploratory explicit-flow tasks, not a blind external benchmark or genuine LLM adoption study.','Repeats measure stability; unique authored tasks supply task-cluster intervals, not population certainty.','Coarse uses the V1.9 union propagation algorithm inside the same V1.10 source registry and executor; this is not the historical V1.9 cohort.','Integrity/common wrappers remain active in No Defense for a fair content-policy comparison.','Wrong granular source annotations may leak data that coarse union blocked.','Unwrapped operations, implicit flows and semantic rewrites are UNRUN.','Latency/memory differences are instrumented local measurements; token/billing costs are null, never inferred from text.']}

def main():
    p=argparse.ArgumentParser(); p.add_argument('--split',choices=['development','reserved'],default='development'); p.add_argument('--seed',type=int,default=17); p.add_argument('--repeat',type=int,default=3); p.add_argument('--output-dir',type=Path,default=Path('logs/v1.10/precision-development')); p.add_argument('--charts',action='store_true'); a=p.parse_args()
    report=run_precision(split=a.split,seed=a.seed,repeat=a.repeat); export_report(report,a.output_dir)
    from evaluation.precision_plot import export_metrics,export_charts
    export_metrics(report,a.output_dir)
    if a.charts: export_charts(report,a.output_dir)
    print(json.dumps(report['summary'])); print('Actual evidence:',a.output_dir/'report.json')
    return 1 if report['summary']['FAILED'] else 2 if report['summary']['UNRUN'] else 0

if __name__=='__main__': raise SystemExit(main())
