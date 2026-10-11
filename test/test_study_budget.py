import json,os,unittest
from unittest.mock import patch
from model.study_budget import StudyBudget,BudgetedClient
from model.research_client import ResearchAPIError
from evaluation.live_precision import run_study


class Stub:
    endpoint='https://api.deepseek.com/chat/completions'; is_live=False
    def __init__(self,usage=None): self.calls=0; self.usage=usage
    def build_payload(self,**kwargs): return kwargs
    def send_payload(self,payload): self.calls+=1; return {'choices':[{'message':{'role':'assistant','content':'{}'}}],'usage':self.usage,'model':'fixture-only'}


class BudgetTests(unittest.TestCase):
    def budget(self,**kwargs): return StudyBudget(input_usd_per_million=1,output_usd_per_million=2,**kwargs)
    def payload(self,client): return client.build_payload(messages=[],tools=[],max_tokens=512)
    def test_no_live_calls_even_with_credentials_without_explicit_opt_in(self):
        with patch.dict(os.environ,{'DEEPSEEK_API_KEY':'synthetic-budget-key'}),patch('evaluation.live_precision.ResearchChatClient') as actual:
            r=run_study(); self.assertEqual(r['summary'],{'HELD':0,'FAILED':0,'UNRUN':36}); actual.assert_not_called(); self.assertEqual(r['cost']['request_attempts'],0)
    def test_missing_key_and_prices_remain_unrun(self):
        with patch.dict(os.environ,{},clear=True):
            r=run_study(); self.assertTrue(all(x['actual']['unrun_reason']=='missing_credential' for x in r['results']))
        with patch.dict(os.environ,{'DEEPSEEK_API_KEY':'synthetic-key'}),patch('evaluation.live_precision.ResearchChatClient') as actual:
            r=run_study(live=True); actual.assert_not_called(); self.assertTrue(all(x['actual']['unrun_reason']=='study_prices_required' for x in r['results']))
    def test_call_cap_checked_before_delegate(self):
        s=Stub({'prompt_tokens':10,'completion_tokens':5,'total_tokens':15}); c=BudgetedClient(s,self.budget(max_calls=1)); c.send_payload(self.payload(c))
        with self.assertRaisesRegex(ResearchAPIError,'call_budget'): c.send_payload(self.payload(c))
        self.assertEqual(s.calls,1); self.assertEqual(c.tokens,15); self.assertAlmostEqual(c.estimated_usd,20/1000000)
    def test_unknown_or_inconsistent_usage_stops_next_call(self):
        for usage in (None,{'prompt_tokens':10,'completion_tokens':5,'total_tokens':99}):
            s=Stub(usage); c=BudgetedClient(s,self.budget()); c.send_payload(self.payload(c))
            with self.assertRaisesRegex(ResearchAPIError,'usage_unknown'): c.send_payload(self.payload(c))
            self.assertEqual(s.calls,1); self.assertIsNone(c.records[0]['tokens'])
    def test_token_and_price_caps_post_response_no_fabricated_usage(self):
        for b in (self.budget(max_reported_tokens=1),self.budget(max_estimated_usd=0.000001)):
            s=Stub({'prompt_tokens':10,'completion_tokens':5,'total_tokens':15}); c=BudgetedClient(s,b); c.send_payload(self.payload(c))
            with self.assertRaisesRegex(ResearchAPIError,'usage_budget'): c.send_payload(self.payload(c))
    def test_request_output_and_invalid_budget_rejected(self):
        s=Stub(); c=BudgetedClient(s,self.budget(max_request_chars=10));
        with self.assertRaises(ResearchAPIError): c.send_payload(self.payload(c))
        for kwargs in ({'max_calls':0},{'max_reported_tokens':-1},{'input_usd_per_million':float('nan')},{'max_estimated_usd':0}):
            with self.assertRaises(ResearchAPIError): StudyBudget(**kwargs)
        self.assertEqual(s.calls,0)

if __name__=='__main__': unittest.main()
