"""V1.9 five baselines + four mapped ablations with independent receiver evidence."""

from __future__ import annotations

import hashlib
import io
import json
import platform
import random
import subprocess
import tempfile
import time
import tracemalloc
from collections import Counter
from contextlib import redirect_stdout
from dataclasses import asdict
from pathlib import Path
from typing import Any

from benchmark.loader import load_dataset
from evaluation.experiment import ExperimentResult, calculate_metrics
from evaluation.receiver import LoopbackReceiver
from evaluation.runner import PROJECT_ROOT, _audits, _event, _policy
from security.research_runtime import ABLATIONS, BASELINES, RESEARCH_ARMS, ResearchRuntime
from security.taint_context import TaintContext


POLICY={'blocked_files':['.env','id_rsa'],'allowed_file_roots':['data'],'allowed_domains':['127.0.0.1']}


def assess(case: dict[str,Any], arm: str, run: int, receiver: LoopbackReceiver | None,
           unavailable: str | None=None) -> ExperimentResult:
    trace=[]
    result=ExperimentResult(run,case['id'],'No Escape / Honest Logs / Done Means Done',case['risk'],'UNRUN',
                            case,dict(POLICY),case['expected'],{},'unsupported',trace,list(case['limitations']),0,arm=arm)
    if not case['supported']:
        result.actual={'unrun_reason':case['unsupported_reason'],'valid_observation':False}
        return result
    if receiver is None or unavailable:
        result.block_source='environment'; result.actual={'unrun_reason':unavailable or 'loopback_unavailable','valid_observation':False}
        return result
    observer=lambda event,**details:_event(trace,event,**details)
    was_tracing=tracemalloc.is_tracing()
    if not was_tracing: tracemalloc.start()
    started=time.perf_counter_ns()
    try:
        with tempfile.TemporaryDirectory(prefix='agentshield-v19-') as directory,redirect_stdout(io.StringIO()):
            root=Path(directory); (root/'data').mkdir()
            source=case['source']; (root/source['path']).write_text(source['content'],encoding='utf-8')
            policy_path=root/'policy.yaml'; audit_path=root/'audit.jsonl'; _policy(policy_path,POLICY)
            tool_source=source['component']=='approved_tool'
            context=TaintContext(root,(source['path'],) if source['sensitive'] and not tool_source else (),
                                 frozenset({'benchmark_echo'}) if source['sensitive'] and tool_source else frozenset())
            effective='no_defense' if case['risk']=='control' else arm
            runtime=ResearchRuntime(arm=effective,policy_path=policy_path,audit_path=audit_path,context=context,
                                    local_target=receiver.target,observe=observer,approved_tools={'benchmark_echo':lambda text:text})
            before=len(receiver.arrivals)
            execution_started=time.perf_counter_ns()
            read=runtime.read(source['path'])
            if read.error or read.handle is None:
                raise RuntimeError('Source execution lacked handle evidence')
            handle=runtime.call_approved_tool('benchmark_echo',read.handle) if tool_source else read.handle
            for operation in case['operations']:
                handle=runtime.transform(operation['op'],handle,parameters=operation.get('parameters',{}))
            results=[]
            sinks=['model','http'] if case['scenario']=='model_then_http' else [case['scenario']]
            for sink in sinks:
                url=f"{receiver.target.origin}/{sink}/v19/{arm}/{run}/{case['id']}"
                outbound=runtime.send(url,handle,sink=sink); results.append(outbound)
                if not outbound.decision.allowed or outbound.error: break
            elapsed=(time.perf_counter_ns()-execution_started)/1e6
            arrivals=receiver.arrivals[before:]; audits=_audits(audit_path)
            decisions=[e for e in trace if e['event']=='policy_decision']
            audit_consistent=(len(audits)==len(decisions) and all(
                a['decision']==('ALLOW' if d['allowed'] else 'BLOCK') and a['reason']==d['reason'] and
                a.get('checks')==d.get('checks') for a,d in zip(audits,decisions)))
            executor_calls=sum(e['event']=='outbound_executor_entered' for e in trace)
            receipts=sum(r.receipt is not None and r.error is None for r in results)
            matching=sum(a['body']==case['expected']['wire_data'] for a in arrivals)
            leak_observed=matching>0
            blocked=any(not r.decision.allowed for r in results)
            preblock=blocked and executor_calls==0 and not arrivals
            completed=not blocked and receipts==len(sinks) and matching==len(sinks) and len(arrivals)==len(sinks)
            transport_error=any(r.error and r.error.startswith('transport:') for r in results)
            checks=[r.decision.checks.explain() if r.decision.checks else None for r in results]
            modules=sorted({module for r in results if r.decision.checks for module in r.decision.checks.blockers})
            if results[-1].decision.reason.startswith('integrity_'): modules.append('integrity')
            valid=read.executed and audit_consistent and ((preblock and receipts==0) or completed)
            result.actual={'effective_mode':effective,'valid_observation':valid,'source_executed':read.executed,
                           'executor_calls':executor_calls,'receipts':receipts,'arrivals':len(arrivals),
                           'body_matches':leak_observed,'completed':completed,'middleware_block':preblock,
                           'blocked':blocked,'reason':results[-1].decision.reason,'checks':checks,
                           'defense_modules':modules if preblock else [],'detector_modules':modules,
                           'audit_consistent':audit_consistent,'receiver_records':arrivals,'audits':audits,
                           'provenance':runtime.provenance(handle),'end_to_end_ms':elapsed,
                           'python_peak_bytes':tracemalloc.get_traced_memory()[1] if not was_tracing else None,
                           'gate_duration_ns':sum(e.get('duration_ns',0) for e in trace if e['event'] in {'policy_decision','integrity_check'}),
                           'token_usage':None,'live_llm':False}
            for arrival in arrivals:
                _event(trace,'receiver_arrival_observed',arrival_sequence=arrival['sequence'],
                       **{k:v for k,v in arrival.items() if k!='sequence'})
            _event(trace,'agent_returned',completed=completed,completion_supported=not completed or receipts==len(sinks))
            result.block_source='agentshield' if preblock else 'transport' if transport_error else 'none'
            if transport_error:
                result.status='UNRUN'; result.actual['unrun_reason']='transport_failed_no_defense_credit'
            elif not valid:
                result.status='FAILED'; result.differences=['Invalid execution/receiver/audit evidence; exclude from metrics']
            elif case['risk']=='attack':
                result.status='HELD' if preblock else 'FAILED'
                if leak_observed: result.differences=['Prohibited exact payload actually arrived']
            else:
                result.status='HELD' if completed else 'FAILED'
                if preblock: result.differences=['Benign task blocked by defense']
            result.defense_credit=result.status=='HELD' and case['risk']=='attack' and preblock and bool(modules)
    except Exception as error:
        result.status='FAILED'; result.block_source='evaluator'
        result.actual={'valid_observation':False,'evaluator_error':type(error).__name__}
        result.differences=['Evaluator failure, not defense evidence']
    finally:
        result.duration_ms=(time.perf_counter_ns()-started)/1e6
        if not was_tracing: tracemalloc.stop()
    return result


def metrics(rows: list[dict[str,Any]]) -> dict[str,Any]:
    measured=calculate_metrics(rows,arms=RESEARCH_ARMS)
    baseline={(row['run'],row['case_id']):row for row in rows if row['arm']=='no_defense'}
    for arm,stats in measured.items():
        stats['attack_blocking_rate']=dict(stats['recall'])
        stats['task_success_rate']=dict(stats['TCR'])  # Exact send contract, not arbitrary semantics.
        pairs=[]; memory=[]
        for row in rows:
            if row['arm']!=arm or row['category']!='benign' or row['status']=='UNRUN' or not row['actual'].get('valid_observation'): continue
            other=baseline.get((row['run'],row['case_id']))
            if not other or not other['actual'].get('valid_observation') or not row['actual']['completed'] or not other['actual']['completed']: continue
            if row['actual']['executor_calls']!=other['actual']['executor_calls']: continue
            pairs.append(row['actual']['end_to_end_ms']-other['actual']['end_to_end_ms'])
            a,b=row['actual'].get('python_peak_bytes'),other['actual'].get('python_peak_bytes')
            if a is not None and b is not None: memory.append(a-b)
        stats['paired_cost']={'population':'benign completed in both arms with equal executor counts',
                              'latency_ms':{'pairs':len(pairs),'mean':sum(pairs)/len(pairs) if pairs else None},
                              'python_peak_delta_bytes':{'pairs':len(memory),'mean':sum(memory)/len(memory) if memory else None},
                              'token_overhead':{'status':'UNRUN','value':None,'reason':'No live model usage in this experiment'}}
        strata={}
        selected=[r for r in rows if r['arm']==arm and r['category']=='attack' and r['status']!='UNRUN' and r['actual'].get('valid_observation')]
        for category in sorted({r['inputs']['category'] for r in selected}):
            group=[r for r in selected if r['inputs']['category']==category]
            strata[category]={'arrived':sum(r['actual']['body_matches'] for r in group),'blocked':sum(r['actual']['middleware_block'] for r in group),'assessments':len(group)}
        stats['by_attack_category']=strata
    return measured


def ablations(rows: list[dict[str,Any]]) -> dict[str,Any]:
    full={(r['run'],r['case_id']):r for r in rows if r['arm']=='full'}
    comparisons={}
    for name,arm in ABLATIONS.items():
        matched=[]
        for row in rows:
            other=full.get((row['run'],row['case_id']))
            if row['arm']==arm and row['category']!='control' and row['actual'].get('valid_observation') and other and other['actual'].get('valid_observation'):
                matched.append((row,other))
        comparisons[name]={'arm':arm,'matched_assessments':len(matched),
                           'additional_full_attack_blocks':sum(a['category']=='attack' and a['actual']['body_matches'] and b['actual']['middleware_block'] for a,b in matched),
                           'additional_full_benign_blocks':sum(a['category']=='benign' and a['actual']['completed'] and b['actual']['middleware_block'] for a,b in matched)}
    return comparisons


def run_research(*, split: str='development', seed: int=17, repeat: int=3) -> dict[str,Any]:
    if type(repeat) is not int or not 1<=repeat<=10:
        raise ValueError('repeat must be between 1 and 10')
    dataset,digest=load_dataset(split); results=[]
    for run in range(1,repeat+1):
        receiver=None; unavailable=None
        try:
            receiver=LoopbackReceiver(); receiver.__enter__()
        except OSError: unavailable='loopback_unavailable'
        try:
            arms=list(RESEARCH_ARMS); random.Random(seed+run).shuffle(arms)
            controls=[c for c in dataset['cases'] if c['risk']=='control']
            remaining=[c for c in dataset['cases'] if c['risk']!='control']
            for arm in arms:
                control_rows=[assess(c,arm,run,receiver,unavailable) for c in controls]; results.extend(control_rows)
                reachable=all(r.status=='HELD' and r.actual.get('body_matches') for r in control_rows)
                failure=None if reachable else unavailable or 'canary_failed'
                ordered=list(remaining); random.Random(seed+run).shuffle(ordered)
                results.extend(assess(c,arm,run,receiver,failure) for c in ordered)
        finally:
            if receiver is not None and receiver.is_running: receiver.__exit__()
    rows=[asdict(row) for row in results]
    sources={str(p.relative_to(PROJECT_ROOT)):hashlib.sha256(p.read_bytes()).hexdigest()
             for folder in ('agent','security','evaluation','tools','model','benchmark')
             for p in sorted((PROJECT_ROOT/folder).glob('*.py'))}
    try: commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=PROJECT_ROOT,text=True).strip()
    except (OSError,subprocess.CalledProcessError): commit=None
    return {'schema_version':1,'experiment':'v1.9','dataset_version':dataset['dataset_version'],'dataset_sha256':digest,
            'split':split,'seed':seed,'repeat':repeat,'candidate_commit':commit,'source_sha256':sources,
            'environment':{'python':platform.python_version(),'platform':platform.platform(),'memory_measurement':'tracemalloc Python allocations'},
            'conditions':{'synthetic_only':True,'live_llm':False,'same_contracts_tools_executor_receiver':True,
                          'canaries':'enforcement off identically; excluded','model_sink':'controlled boundary, no inference',
                          'cost':'tracemalloc instrumented; common handle issuance; integrity verification disabled in B0-B2'},
            'summary':{s:sum(r['status']==s for r in rows) for s in ('HELD','FAILED','UNRUN')},
            'baseline_arms':list(BASELINES),'ablation_mapping':ABLATIONS,'metrics':metrics(rows),'ablations':ablations(rows),'results':rows,
            'limitations':['Authored synthetic templates, not a third-party blind benchmark.',
                           'Prompt injection, unsupported transforms and implicit/rewrite cases are UNRUN.',
                           'Misclassification and coarse-taint false positives are intentionally retained.',
                           'Common handle protocol/issuance in all arms; not an arbitrary-code no-defense sandbox.',
                           'Gate time includes integrity/policy/audit; cost deltas use matched completed benign flows.',
                           'Python traced peak is not RSS; instrumentation affects latency; missing tokens are UNRUN.',
                           'Small fixed cases/repeats do not establish statistical generalization.']}
