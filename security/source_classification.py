"""Trusted declarations and explicit uncertainty, not a semantic secret oracle."""
from __future__ import annotations
import json
from dataclasses import dataclass
from pathlib import Path
from security.precision import SourceLayout,FieldRule,RangeRule
from security.taint import TaintError,TaintedValue,json_deserialize

STATUSES=frozenset({'PUBLIC','SENSITIVE','MIXED','UNKNOWN','MISSING','CONFLICT'})
UNKNOWN_POLICIES=frozenset({'BLOCK','REQUIRE_REVIEW','ALLOW'})


def strict_json(text):
    bounded=json_deserialize(TaintedValue.literal(text)).reveal()
    def pairs(items):
        result={}
        for key,value in items:
            if key in result: raise TaintError('source_duplicate_json_key')
            result[key]=value
        return result
    json.loads(text,object_pairs_hook=pairs)
    return bounded


@dataclass(frozen=True)
class SourcePlan:
    status: str
    layout: SourceLayout = SourceLayout()
    def __post_init__(self):
        if self.status not in STATUSES or not isinstance(self.layout,SourceLayout): raise TaintError('source_invalid_plan')
        if self.status=='PUBLIC' and (self.layout.default_sensitive or self.layout.structure_sensitive or any(r.sensitive for r in (*self.layout.fields,*self.layout.ranges))): raise TaintError('source_conflicting_plan')
        if self.status=='SENSITIVE' and not self.layout.default_sensitive: raise TaintError('source_conflicting_plan')
        if self.status in {'UNKNOWN','MISSING','CONFLICT'} and self.layout!=SourceLayout(): raise TaintError('source_uncertainty_cannot_declare_fields')


@dataclass(frozen=True)
class SourceRegistry:
    plans: tuple[tuple[str,str,SourcePlan],...] = ()
    unknown_policy: str = 'BLOCK'
    def __post_init__(self):
        if self.unknown_policy not in UNKNOWN_POLICIES or not isinstance(self.plans,tuple) or len(self.plans)>128: raise TaintError('source_invalid_registry')
        for item in self.plans:
            if not isinstance(item,tuple) or len(item)!=3: raise TaintError('source_invalid_registry')
            category,reference,plan=item
            if category not in {'file','tool','model'} or not isinstance(reference,str) or not 1<=len(reference)<=1024 or not isinstance(plan,SourcePlan): raise TaintError('source_invalid_registry')
            if '*' in reference and not(category=='model' and reference=='*'): raise TaintError('source_wildcard_not_allowed')
            if category=='file' and (Path(reference).is_absolute() or '..' in Path(reference).parts): raise TaintError('source_invalid_reference')

    def classify(self,category,reference):
        matches=[p for c,r,p in self.plans if c==category and r==reference]
        if not matches and category=='model': matches=[p for c,r,p in self.plans if c==category and r=='*']
        if not matches: return SourcePlan('MISSING')
        if len(set(matches))>1: return SourcePlan('CONFLICT')
        return matches[0]

    @classmethod
    def from_json(cls,text):
        if not isinstance(text,str) or len(text)>65536: raise TaintError('source_configuration_budget')
        obj=strict_json(text)
        if not isinstance(obj,dict) or set(obj)-{'plans','unknown_policy'} or not isinstance(obj.get('plans',[]),list): raise TaintError('source_invalid_configuration')
        entries=[]
        for item in obj.get('plans',[]):
            if not isinstance(item,dict) or set(item)-{'category','reference','status','layout'}: raise TaintError('source_invalid_configuration')
            spec=item.get('layout',{})
            if not isinstance(spec,dict) or set(spec)-{'default_sensitive','structure_sensitive','structured_json','fields','ranges'}: raise TaintError('source_invalid_configuration')
            try:
                layout=SourceLayout(default_sensitive=spec.get('default_sensitive',False),structure_sensitive=spec.get('structure_sensitive',False),structured_json=spec.get('structured_json',False),
                    fields=tuple(FieldRule(tuple(r['path']),r['sensitive']) for r in spec.get('fields',[])),
                    ranges=tuple(RangeRule(tuple(r['path']),r['start'],r['stop'],r['sensitive']) for r in spec.get('ranges',[])))
                entries.append((item['category'],item['reference'],SourcePlan(item['status'],layout)))
            except (KeyError,TypeError): raise TaintError('source_invalid_configuration') from None
        return cls(tuple(entries),obj.get('unknown_policy','BLOCK'))


def decide_source(stamps,labels,target,releases=()):
    active={l.source.source_id for l in labels}; uncertain=[]
    reviewed=any(s.target==target for s in releases)
    for stamp in stamps:
        if stamp.status in {'UNKNOWN','MISSING','CONFLICT'} and active.intersection(stamp.source_ids) and stamp.unknown_policy!='ALLOW' and not reviewed:
            uncertain.append(stamp)
    review=any(s.unknown_policy=='REQUIRE_REVIEW' for s in uncertain)
    return {'allowed':not uncertain,'reason':'source_review_required' if review else 'source_classification_blocked' if uncertain else 'source_classification_allowed',
        'statuses':sorted({s.status for s in stamps if active.intersection(s.source_ids)}),
        'blocked_reference_ids':sorted({s.reference_id for s in uncertain}),
        'classification_correctness':'not_established_by_integrity','trusted_review_grant':reviewed}
