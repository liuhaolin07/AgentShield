"""Explicitly opt-in objective-specific DeepSeek/Qwen study, with finite budgets."""
from __future__ import annotations
import argparse,hashlib,json,os,platform,random,re
from dataclasses import asdict
from pathlib import Path
from evaluation.__main__ import export_report
from evaluation.precision_agent_study import TASKS,assess_agent
from evaluation.receiver import LoopbackReceiver
from model.research_client import ResearchChatClient,ResearchAPIError,PROVIDERS
from model.study_budget import StudyBudget,BudgetedClient
from benchmark.live_protocol import ROOT as LIVE_DATASET_ROOT

ARMS=('no_defense','static_rule','scanner','coarse','precision','full')


def run_study(*,provider='deepseek',model='deepseek-flash',credential_env=None,live=False,budget=StudyBudget(),seed=17,client_factory=None):
    if provider not in PROVIDERS: raise ValueError('unsupported_provider')
    variable=credential_env or PROVIDERS[provider][1]
    if not isinstance(variable,str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,127}',variable): raise ValueError('invalid_credential_variable_name')
    present=bool(os.environ.get(variable,'')); reason=None; client=None
    if client_factory is not None: client=BudgetedClient(client_factory(),budget)
    elif not live: reason='live_disabled' if present else 'missing_credential'
    elif not present: reason='missing_credential'
    elif budget.input_usd_per_million is None or budget.output_usd_per_million is None: reason='study_prices_required'
    else:
        try: client=BudgetedClient(ResearchChatClient(provider=provider,model=model,credential_env=variable,allow_live=True),budget)
        except ResearchAPIError as error: reason=str(error)
    rows=[]; receiver=None
    if client is not None:
        try: receiver=LoopbackReceiver(); receiver.__enter__()
        except OSError: reason='loopback_unavailable'
    try:
        order=list(ARMS); random.Random(seed).shuffle(order)
        for arm in order:
            for task in TASKS:
                if reason or receiver is None:
                    rows.append({'arm':arm,'run':1,'case_id':task['task_id'],'principle':'No Escape / Done Means Done','category':task['risk'],'status':'UNRUN','inputs':task,'policy':{'unknown_policy':'BLOCK'},'expected':{'success_contract':task['success_contract']},'actual':{'unrun_reason':reason,'live_llm':False,'oracle':{'flags':['UNRUN'],'defense_credit':False}},'block_source':'api_unavailable','defense_credit':False,'trace':[],'duration_ms':0,'differences':[],'limitations':['No observed model response; no defense credit.']})
                else: rows.append(assess_agent(task,arm,client,receiver))
    finally:
        if receiver is not None and receiver.is_running: receiver.__exit__()
    return {'schema_version':1,'experiment':'v1.10-live','dataset_version':'v1.10-live-tasks-1',
        'dataset_sha256':hashlib.sha256((LIVE_DATASET_ROOT/'live-tasks.json').read_bytes()).hexdigest(),
        'provider':provider,'model_requested':model,'model_availability':'FIXTURE_ONLY' if client_factory is not None else 'response_observed' if client and any(r['response_received'] for r in client.records) else 'UNVERIFIED',
        'seed':seed,'repeat':1,'environment':{'python':platform.python_version(),'platform':platform.platform()},
        'conditions':{'live_opt_in':live,'credential_present':present,'fixture_client':client_factory is not None,'only_synthetic_sources':True,'http_attack_sink':'pinned localhost'},
        'budget':asdict(budget),'cost':{'request_attempts':client.calls if client else 0,'reported_tokens':client.tokens if client and not client.usage_unknown else None,'estimated_usd':client.estimated_usd if client and not client.usage_unknown else None,'records':client.records if client else [],'actual_billing_verified':False},
        'summary':{s:sum(r['status']==s for r in rows) for s in ('HELD','FAILED','UNRUN')},'results':rows,
        'limitations':['No automatic paid calls. --live plus explicit prices and finite budgets required.',
            'Input token/money caps are post-response estimates and can overshoot by one bounded request; not a provider billing guarantee.',
            'Unknown usage stops further calls, never estimates tokens from strings.',
            'Fixture requests never establish live LLM performance; semantic rewrites remain unjudged.']}


def main():
    p=argparse.ArgumentParser(description=__doc__); p.add_argument('--provider',choices=tuple(PROVIDERS),default='deepseek'); p.add_argument('--model',default='deepseek-flash'); p.add_argument('--credential-env'); p.add_argument('--live',action='store_true'); p.add_argument('--seed',type=int,default=17); p.add_argument('--max-calls',type=int,default=24); p.add_argument('--max-total-tokens',type=int,default=16384); p.add_argument('--max-estimated-usd',type=float,default=0.25); p.add_argument('--input-usd-per-million',type=float); p.add_argument('--output-usd-per-million',type=float); p.add_argument('--output-dir',type=Path,default=Path('logs/v1.10/live'))
    a=p.parse_args(); budget=StudyBudget(max_calls=a.max_calls,max_reported_tokens=a.max_total_tokens,max_estimated_usd=a.max_estimated_usd,input_usd_per_million=a.input_usd_per_million,output_usd_per_million=a.output_usd_per_million)
    report=run_study(provider=a.provider,model=a.model,credential_env=a.credential_env,live=a.live,budget=budget,seed=a.seed); export_report(report,a.output_dir); print(json.dumps(report['summary']))
    return 1 if report['summary']['FAILED'] else 2 if report['summary']['UNRUN'] else 0

if __name__=='__main__': raise SystemExit(main())
