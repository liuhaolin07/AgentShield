"""Bounded explicit dependencies. Trusted layouts, never content-based untainting.

JSON precision survives verified serialization roundtrips. Decoding unrelated
text conservatively unions dependencies; arbitrary Python/implicit flow excluded.
"""
from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field, replace
from typing import Any
from urllib.parse import quote

from security.taint import (MAX_CHARS, TaintError, TaintedValue, TaintLabel,
    SourceRecord, SinkTarget, ProvenanceRecord, json_deserialize, base64_decode,
    url_decode, slice_value)

MAX_PARTS=128
MAX_SPANS=512


@dataclass(frozen=True)
class FieldRule:
    path: tuple[str | int, ...]
    sensitive: bool


@dataclass(frozen=True)
class RangeRule:
    path: tuple[str | int, ...]
    start: int
    stop: int
    sensitive: bool


@dataclass(frozen=True)
class SourceLayout:
    default_sensitive: bool = False
    fields: tuple[FieldRule,...] = ()
    ranges: tuple[RangeRule,...] = ()
    structure_sensitive: bool = False
    structured_json: bool = False

    def __post_init__(self):
        if any(type(v) is not bool for v in (self.default_sensitive,self.structure_sensitive,self.structured_json)):
            raise TaintError('precision_invalid_layout')
        if not isinstance(self.fields,tuple) or not isinstance(self.ranges,tuple) or len(self.fields)+len(self.ranges)>32:
            raise TaintError('precision_layout_budget')
        for rule in (*self.fields,*self.ranges):
            if not isinstance(rule,(FieldRule,RangeRule)) or not isinstance(rule.path,tuple) or len(rule.path)>12 or type(rule.sensitive) is not bool:
                raise TaintError('precision_invalid_rule')
            if any(type(p) not in (str,int) or isinstance(p,str) and len(p)>128 or isinstance(p,int) and not 0<=p<128 for p in rule.path):
                raise TaintError('precision_invalid_path')
        if len({r.path for r in self.fields})!=len(self.fields): raise TaintError('precision_conflicting_fields')
        for rule in self.ranges:
            if type(rule.start) is not int or type(rule.stop) is not int or not 0<=rule.start<rule.stop<=MAX_CHARS:
                raise TaintError('precision_invalid_range')
        for i,a in enumerate(self.ranges):
            if any(a.path==b.path and max(a.start,b.start)<min(a.stop,b.stop) for b in self.ranges[i+1:]):
                raise TaintError('precision_conflicting_ranges')


@dataclass(frozen=True)
class Span:
    start: int
    stop: int
    labels: tuple[TaintLabel,...]


@dataclass(frozen=True)
class ReleaseStamp:
    rule_id: str
    target: SinkTarget


@dataclass(frozen=True)
class PrecisionValue:
    raw: TaintedValue = field(repr=False)
    ambient: tuple[TaintLabel,...] = ()
    children: tuple[tuple[str | int,PrecisionValue],...] = ()
    spans: tuple[Span,...] = ()
    witness: tuple[str,PrecisionValue] | None = field(default=None,repr=False)
    releases: tuple[ReleaseStamp,...] = ()

    @property
    def labels(self):
        return union(self.ambient,*(s.labels for s in self.spans),*(c.labels for _,c in self.children))

    def to_tainted(self,target: SinkTarget | None=None):
        labels=self.labels
        if target is not None and any(s.target==target for s in self.releases):
            labels=tuple(replace(label,sensitive=False) for label in labels)
        provenance=(ProvenanceRecord.create('source',tuple(l.source.source_id for l in labels)),) if labels else self.raw.provenance
        return TaintedValue(self.raw.value,labels,provenance,self.raw.tracking)


def union(*groups):
    labels=tuple(dict.fromkeys(l for group in groups for l in group))
    if len(labels)>32: raise TaintError('precision_source_budget')
    return labels


def node(data,ambient=(),children=(),spans=(),witness=None,releases=()):
    value=PrecisionValue(TaintedValue.literal(data),tuple(ambient),tuple(children),tuple(spans),witness,tuple(releases))
    value.to_tainted()  # Existing bounds and label validation.
    if len(value.spans)>MAX_SPANS or len(value.children)>MAX_PARTS: raise TaintError('precision_metadata_budget')
    if isinstance(data,str):
        position=0
        for span in value.spans:
            if span.start!=position or span.stop<=span.start or span.stop>len(data): raise TaintError('precision_span_coverage')
            position=span.stop
        if position!=len(data): raise TaintError('precision_span_coverage')
    return value


def compress(pieces):
    spans=[]; position=0
    for text,labels in pieces:
        if not text: continue
        end=position+len(text)
        if spans and spans[-1].labels==labels: spans[-1]=Span(spans[-1].start,end,labels)
        else: spans.append(Span(position,end,labels))
        position=end
        if len(spans)>MAX_SPANS or position>MAX_CHARS: raise TaintError('precision_output_budget')
    return tuple(spans)


def text_node(pieces,ambient=(),witness=None):
    pieces=list(pieces)
    return node(''.join(t for t,_ in pieces),ambient,spans=compress(pieces),witness=witness)


def dependencies(value,index):
    return union(value.ambient,*(s.labels for s in value.spans if s.start<=index<s.stop))


def uniform(data,labels):
    if isinstance(data,dict): return node(data,labels,tuple((k,uniform(v,labels)) for k,v in data.items()))
    if isinstance(data,list): return node(data,labels,tuple((i,uniform(v,labels)) for i,v in enumerate(data)))
    return node(data,labels,spans=(Span(0,len(data),labels),) if isinstance(data,str) and data else ())


def source_value(data,category: str,reference: str,layout: SourceLayout):
    TaintedValue.literal(data)
    visited=[]; count=0
    def label(path,grain,sensitive):
        return TaintLabel(SourceRecord.create(category,reference+':'+json.dumps([path,grain],separators=(',',':'))),sensitive)
    def build(value,path=(),inherited=None):
        nonlocal count
        count+=1
        if count>MAX_PARTS: raise TaintError('precision_node_budget')
        sensitivity=layout.default_sensitive if inherited is None else inherited
        for rule in layout.fields:
            if rule.path==path: sensitivity=rule.sensitive; visited.append(rule)
        if isinstance(value,(dict,list)):
            shape=(label(path,'shape',layout.structure_sensitive),)
            items=value.items() if isinstance(value,dict) else enumerate(value)
            children=tuple((k,build(v,(*path,k),sensitivity)) for k,v in items)
            return node(value,shape,children)
        if isinstance(value,str) and value:
            rules=[r for r in layout.ranges if r.path==path]
            for r in rules:
                if r.stop>len(value): raise TaintError('precision_range_out_of_bounds')
                visited.append(r)
            bounds=sorted({0,len(value),*(r.start for r in rules),*(r.stop for r in rules)})
            spans=[]
            for start,stop in zip(bounds,bounds[1:]):
                flag=next((r.sensitive for r in rules if r.start<=start and stop<=r.stop),sensitivity)
                spans.append(Span(start,stop,(label(path,[start,stop],flag),)))
            return node(value,spans=tuple(spans))
        return node(value,(label(path,'scalar',sensitivity),))
    result=build(data)
    if any(r not in visited for r in (*layout.fields,*layout.ranges)): raise TaintError('precision_layout_missing_selector')
    result.to_tainted()
    return result


def serialize(value):
    pieces=[]
    def emit(text,labels): pieces.append((text,labels))
    def walk(v,upstream=()):
        data=v.raw.reveal(); shape=union(upstream,v.ambient)
        if isinstance(data,dict):
            emit('{',shape)
            for i,(key,child) in enumerate(v.children):
                if i: emit(',',shape)
                emit(json.dumps(key,ensure_ascii=False)+':',shape); walk(child,shape)
            emit('}',shape)
        elif isinstance(data,list):
            emit('[',shape)
            for i,(_,child) in enumerate(v.children):
                if i: emit(',',shape)
                walk(child,shape)
            emit(']',shape)
        elif isinstance(data,str):
            emit('"',shape)
            for i,char in enumerate(data): emit(json.dumps(char,ensure_ascii=False)[1:-1],union(shape,dependencies(v,i)))
            emit('"',shape)
        else: emit(json.dumps(data,ensure_ascii=False,allow_nan=False),union(shape,v.labels))
    walk(value)
    result=text_node(pieces,witness=('json_encode',value))
    if result.raw.reveal()!=json.dumps(value.raw.reveal(),ensure_ascii=False,separators=(',',':')): raise TaintError('precision_serialization_mismatch')
    return result


def transform(operation: str,values: tuple[PrecisionValue,...],params: dict[str,Any]):
    TaintedValue.literal(params)
    if not values or len(values)>32: raise TaintError('precision_arity')
    if operation not in {'concat','dict','list'} and len(values)!=1: raise TaintError('precision_arity')
    allowed={'get_item':{'key'},'slice':{'start','stop','step'},'dict':{'keys'},'mix':{'prefix','suffix'},
             'slice_rejoin':{'cuts'},'segmented_encode':{'cuts'}}.get(operation,set())
    if set(params)-allowed: raise TaintError('precision_parameters')
    first=values[0]; data=first.raw.reveal()
    if operation=='get_item':
        key=params.get('key')
        if isinstance(data,list):
            if type(key) is not int: raise TaintError('precision_index')
            key=key if key>=0 else len(data)+key
        elif not isinstance(data,dict) or not isinstance(key,str): raise TaintError('precision_index')
        try: child=dict(first.children)[key]
        except KeyError: raise TaintError('precision_missing_item') from None
        return replace(child,ambient=union(child.ambient,first.ambient),releases=())
    if operation=='slice':
        for k in ('start','stop','step'):
            v=params.get(k)
            if v is not None and (type(v) is not int or abs(v)>2**63): raise TaintError('precision_slice')
        if params.get('step')==0 or not isinstance(data,(str,list)): raise TaintError('precision_slice')
        selected=list(range(len(data)))[slice(params.get('start'),params.get('stop'),params.get('step'))]
        if isinstance(data,list):
            items=[dict(first.children)[i] for i in selected]
            return node([c.raw.reveal() for c in items],first.ambient,tuple(enumerate(items)))
        if not selected: return node('',first.labels)  # Conservative empty result, no implicit-flow claim.
        return text_node([(data[i],dependencies(first,i)) for i in selected],first.ambient)
    if operation in {'concat','mix'}:
        if any(not isinstance(v.raw.value,str) for v in values): raise TaintError('precision_text_required')
        pieces=[]
        if operation=='mix':
            for key in ('prefix','suffix'):
                if not isinstance(params.get(key,''),str): raise TaintError('precision_parameters')
            pieces.append((params.get('prefix',''),()))
        for v in values: pieces.extend((v.raw.value[i],dependencies(v,i)) for i in range(len(v.raw.value)))
        if operation=='mix': pieces.append((params.get('suffix',''),()))
        return text_node(pieces)
    if operation in {'list','dict'}:
        keys=list(range(len(values))) if operation=='list' else params.get('keys')
        if not isinstance(keys,list) or len(keys)!=len(values) or operation=='dict' and (not all(isinstance(k,str) and len(k)<=128 for k in keys) or len(set(keys))!=len(keys)): raise TaintError('precision_keys')
        pairs=tuple(zip(keys,values)); raw=[v.raw.reveal() for v in values] if operation=='list' else {k:v.raw.reveal() for k,v in pairs}
        return node(raw,children=pairs)
    if operation in {'json_encode','json_escape'}: return serialize(first)
    if operation=='nested_json':
        inner=transform('dict',(first,),{'keys':['value']})
        middle=transform('list',(inner,),{})
        return serialize(transform('dict',(middle,),{'keys':['envelope']}))
    if operation=='json_roundtrip': return transform('json_decode',(serialize(first),),{})
    if operation in {'slice_rejoin','segmented_encode'}:
        cuts=params.get('cuts')
        if not isinstance(data,str) or not isinstance(cuts,list) or len(cuts)>16 or any(type(c) is not int or not 0<c<len(data) for c in cuts) or cuts!=sorted(set(cuts)): raise TaintError('precision_parameters')
        bounds=[0,*cuts,len(data)]; pieces=[]
        for i in range(len(bounds)-1):
            part=transform('slice',(first,),{'start':bounds[i],'stop':bounds[i+1]})
            if operation=='segmented_encode':
                if i: pieces.append(uniform('.',()))
                part=transform('base64_encode',(part,),{})
            pieces.append(part)
        return transform('concat',tuple(pieces),{})
    if operation=='json_decode':
        decoded=json_deserialize(first.to_tainted()).reveal()
        if first.witness and first.witness[0]=='json_encode' and first.witness[1].raw.reveal()==decoded:
            return replace(first.witness[1],ambient=union(first.witness[1].ambient,first.ambient),releases=())
        return uniform(decoded,first.labels)
    if operation in {'base64_encode','url_encode'}:
        if not isinstance(data,str): raise TaintError('precision_text_required')
        if operation=='url_encode': pieces=[(quote(char,safe=''),dependencies(first,i)) for i,char in enumerate(data)]
        else:
            raw=data.encode(); labels=[dependencies(first,i) for i,c in enumerate(data) for _ in c.encode()]
            encoded=base64.b64encode(raw).decode(); pieces=[]
            for i in range(0,len(raw),3): pieces.append((encoded[(i//3)*4:(i//3)*4+4],union(*labels[i:i+3])))
        return text_node(pieces,ambient=first.labels if not data else (),witness=(operation,first))
    if operation in {'base64_decode','url_decode'}:
        decoded=(base64_decode if operation=='base64_decode' else url_decode)(first.to_tainted()).reveal()
        inverse='base64_encode' if operation=='base64_decode' else 'url_encode'
        if first.witness and first.witness[0]==inverse and first.witness[1].raw.reveal()==decoded:
            return replace(first.witness[1],ambient=union(first.witness[1].ambient,first.ambient),releases=())
        return uniform(decoded,first.labels)
    if operation=='checkpoint': return replace(first,releases=())
    raise TaintError('precision_unsupported_transform')
