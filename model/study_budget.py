"""Finite opt-in study budgets; usage-based money/token caps are post-response."""
from __future__ import annotations
import json,math
from dataclasses import dataclass
from model.research_client import ResearchAPIError


@dataclass(frozen=True)
class StudyBudget:
    max_calls: int = 24
    max_reported_tokens: int = 16384
    max_request_chars: int = 32768
    max_completion_tokens: int = 512
    max_estimated_usd: float = 0.25
    input_usd_per_million: float | None = None
    output_usd_per_million: float | None = None
    def __post_init__(self):
        for value,limit in ((self.max_calls,216),(self.max_reported_tokens,1000000),(self.max_request_chars,32768),(self.max_completion_tokens,1024)):
            if type(value) is not int or not 1<=value<=limit: raise ResearchAPIError('invalid_study_budget')
        for price in (self.max_estimated_usd,self.input_usd_per_million,self.output_usd_per_million):
            if price is not None and (type(price) not in (int,float) or not math.isfinite(price) or price<=0): raise ResearchAPIError('invalid_study_prices')


class BudgetedClient:
    def __init__(self,client,budget):
        self.client,self.budget=client,budget; self.calls=0; self.tokens=0; self.estimated_usd=0.0; self.records=[]; self.usage_unknown=False
    @property
    def endpoint(self): return self.client.endpoint
    @property
    def is_live(self): return bool(getattr(self.client,'is_live',False))
    def build_payload(self,**kwargs):
        kwargs['max_tokens']=min(kwargs.get('max_tokens',512),self.budget.max_completion_tokens)
        return self.client.build_payload(**kwargs)
    def send_payload(self,payload):
        if self.calls>=self.budget.max_calls: raise ResearchAPIError('study_call_budget_exhausted')
        if self.usage_unknown: raise ResearchAPIError('study_usage_unknown_no_further_calls')
        if self.tokens>=self.budget.max_reported_tokens or self.estimated_usd>=self.budget.max_estimated_usd: raise ResearchAPIError('study_usage_budget_exhausted')
        if self.budget.input_usd_per_million is None or self.budget.output_usd_per_million is None: raise ResearchAPIError('study_prices_required')
        if len(json.dumps(payload,ensure_ascii=False))>self.budget.max_request_chars: raise ResearchAPIError('study_request_budget')
        if type(payload.get('max_tokens')) is not int or not 1<=payload['max_tokens']<=self.budget.max_completion_tokens: raise ResearchAPIError('study_completion_budget')
        self.calls+=1
        try: response=self.client.send_payload(payload)
        except Exception:
            self.usage_unknown=True; self.records.append({'request':self.calls,'tokens':None,'estimated_usd':None,'response_received':False}); raise
        usage=response.get('usage'); valid=isinstance(usage,dict) and all(type(usage.get(k)) is int and usage[k]>=0 for k in ('prompt_tokens','completion_tokens','total_tokens'))
        valid=valid and usage['total_tokens']==usage['prompt_tokens']+usage['completion_tokens']
        cost=None
        if valid:
            self.tokens+=usage['total_tokens']; cost=(usage['prompt_tokens']*self.budget.input_usd_per_million+usage['completion_tokens']*self.budget.output_usd_per_million)/1000000
            self.estimated_usd+=cost
        else: self.usage_unknown=True
        name=response.get('model'); name=name if isinstance(name,str) and len(name)<=128 else None
        self.records.append({'request':self.calls,'tokens':dict(usage) if valid else None,'estimated_usd':cost,'response_received':True,'reported_model':name})
        return response
