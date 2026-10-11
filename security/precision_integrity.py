"""Session attestation of precision metadata and replayed narrowing operations."""
from __future__ import annotations
import hashlib
import hmac
import json
import re
import secrets
from dataclasses import dataclass,field,asdict,replace
from typing import Any
from security.precision import PrecisionValue,ReleaseStamp,transform,uniform
from security.taint import SourceRecord,SinkTarget,TaintError
from security.taint_integrity import (ValueHandle,IntegrityError,_SourceAuthority,
    _canonical,MAX_HANDLES,MAX_REGISTRY_BYTES,MAX_CHAIN,MAX_PARENTS)


@dataclass(frozen=True)
class DeclassificationRule:
    rule_id: str
    category: str
    source_reference: str = field(repr=False)
    operation: str
    parameters_json: str
    target: SinkTarget

    def __post_init__(self):
        if not re.fullmatch(r'[a-z0-9_.-]{1,64}',self.rule_id) or self.category not in {'file','tool'} or self.operation not in {'get_item','slice'} or not isinstance(self.target,SinkTarget) or self.target.destination=='*':
            raise IntegrityError('precision_invalid_release_rule')
        SourceRecord.create(self.category,self.source_reference)
        p=json.loads(self.parameters_json)
        allowed={'key'} if self.operation=='get_item' else {'start','stop','step'}
        if not isinstance(p,dict) or set(p)-allowed or self.operation=='get_item' and (set(p)!={'key'} or type(p['key']) not in (str,int)):
            raise IntegrityError('precision_invalid_release_rule')
        if self.operation=='slice' and (not {'start','stop'}<=set(p) or any(type(v) is not int or abs(v)>65536 for v in p.values()) or p.get('step',1)!=1 or not 0<=p['start']<p['stop']):
            raise IntegrityError('precision_invalid_release_rule')
        _canonical(p)


@dataclass(frozen=True)
class _Entry:
    handle: ValueHandle
    node: PrecisionValue = field(repr=False)
    operation: str
    parents: tuple[ValueHandle,...]
    parameters_json: str
    roots: tuple[tuple[str,str],...]


def snapshot(value,depth=0,counter=None):
    counter=[0] if counter is None else counter; counter[0]+=1
    if depth>24 or counter[0]>512: raise IntegrityError('precision_snapshot_budget')
    def label(x):
        return {'source':asdict(x.source),'sensitive':x.sensitive,
                'allowed':sorted((t.kind,t.destination) for t in x.allowed_targets),
                'forbidden':sorted((t.kind,t.destination) for t in x.forbidden_targets)}
    return {'data':value.raw.reveal(),'tracking':value.raw.tracking,
        'ambient':[label(x) for x in value.ambient],
        'spans':[{'start':s.start,'stop':s.stop,'labels':[label(l) for l in s.labels]} for s in value.spans],
        'children':[(k,snapshot(c,depth+1,counter)) for k,c in value.children],
        'witness':[value.witness[0],snapshot(value.witness[1],depth+1,counter)] if value.witness else None,
        'releases':[asdict(s) for s in value.releases]}


class PrecisionAuthority:
    """Trusted implementation detail; opaque handles are the only agent values."""
    def __init__(self,*,rules=(),field_precision=True,propagate=True,release_enabled=True):
        if any(type(v) is not bool for v in (field_precision,propagate,release_enabled)) or not isinstance(rules,tuple) or len(rules)>32 or any(not isinstance(r,DeclassificationRule) for r in rules) or len({r.rule_id for r in rules})!=len(rules):
            raise IntegrityError('precision_invalid_configuration')
        self._crypto=_SourceAuthority(); self.runtime_id=self._crypto.runtime_id
        self._entries={}; self._bytes=0; self._rules={r.rule_id:r for r in rules}
        self.field_precision,self.propagate,self.release_enabled=field_precision,propagate,release_enabled

    def _mac(self,domain,data): return self._crypto._mac('precision_'+domain,data)

    def _body(self,entry):
        return {'runtime':self.runtime_id,'value_id':entry.handle.value_id,'source_hash':entry.handle.source_hash,
            'provenance_id':entry.handle.provenance_id,'node':snapshot(entry.node),'operation':entry.operation,
            'parents':[h.to_wire() for h in entry.parents],'parameters':entry.parameters_json,'roots':entry.roots,
            'configuration':[self.field_precision,self.propagate,self.release_enabled,[asdict(r) for r in self._rules.values()]]}

    def _issue(self,value,operation,parents,parameters,roots):
        encoded=_canonical(parameters).decode(); snap=snapshot(value)
        source_hash=self._mac('sources',[roots,[p.source_hash for p in parents],snap if operation.startswith('source_') else None])
        prov=self._mac('provenance',[operation,[p.provenance_id for p in parents],encoded,source_hash,snap])
        handle=ValueHandle(self.runtime_id,secrets.token_hex(32),prov,source_hash,'')
        entry=_Entry(handle,value,operation,parents,encoded,tuple(roots)); charge=len(_canonical(self._body(entry)))
        if len(self._entries)>=MAX_HANDLES or self._bytes+charge>MAX_REGISTRY_BYTES: raise IntegrityError('precision_registry_budget')
        handle=replace(handle,seal=self._mac('seal',self._body(entry)))
        self._entries[handle.value_id]=replace(entry,handle=handle); self._bytes+=charge
        return handle

    def _source(self,category,reference,value,parents=()):
        if category not in {'file','tool','model'} or type(value) is not PrecisionValue or len(parents)>MAX_PARENTS: raise IntegrityError('precision_untrusted_source')
        upstream=tuple(self.resolve(h) for h in parents)
        if any(l not in value.labels for p in upstream for l in p.labels): raise IntegrityError('precision_source_downgrade')
        root=(category,SourceRecord.create(category,reference).reference_id)
        roots=tuple(dict.fromkeys([root,*(r for h in parents for r in self._entries[h.value_id].roots)]))
        if len(roots)>32: raise IntegrityError('precision_source_budget')
        if not self.field_precision: value=uniform(value.raw.reveal(),value.labels)
        return self._issue(value,'source_'+category,parents,{},roots)

    def _derive(self,operation,values,parameters):
        result=transform(operation,values,parameters)
        if not self.propagate: return uniform(result.raw.reveal(),())
        if not self.field_precision: return uniform(result.raw.reveal(),tuple(dict.fromkeys(l for v in values for l in v.labels)))
        return result

    def transform(self,operation,handles,parameters):
        if not isinstance(handles,tuple) or not 1<=len(handles)<=32 or not isinstance(parameters,dict): raise IntegrityError('precision_invalid_parameters')
        _canonical(parameters)
        values=tuple(self.resolve(h) for h in handles); result=self._derive(operation,values,parameters)
        roots=tuple(dict.fromkeys(r for h in handles for r in self._entries[h.value_id].roots))
        return self._issue(result,operation,handles,parameters,roots)

    def _released(self,parent,rule_id,target):
        rule=self._rules.get(rule_id)
        expected_roots=((rule.category,SourceRecord.create(rule.category,rule.source_reference).reference_id),) if rule else ()
        projection_input=self._entries.get(parent.parents[0].value_id) if len(parent.parents)==1 else None
        if not rule or rule.target!=target or parent.roots!=expected_roots or not projection_input or projection_input.operation!='source_'+rule.category or projection_input.roots!=expected_roots or projection_input.parents or parent.operation!=rule.operation or json.loads(parent.parameters_json)!=json.loads(rule.parameters_json):
            raise IntegrityError('precision_release_scope_denied')
        return replace(parent.node,releases=(ReleaseStamp(rule.rule_id,rule.target),))

    def release(self,handle,rule_id,target):
        self.resolve(handle); parent=self._entries[handle.value_id]
        if not self.release_enabled: return handle
        result=self._released(parent,rule_id,target)
        return self._issue(result,'trusted_release',(handle,),{'rule_id':rule_id,'target':asdict(target)},parent.roots)

    def verify(self,handle):
        visited={}; active=set()
        def walk(h,depth=0):
            if type(h) is not ValueHandle or h.runtime_id!=self.runtime_id: raise IntegrityError('precision_unattested_or_cross_session')
            entry=self._entries.get(h.value_id)
            if entry is None or h!=entry.handle or not hmac.compare_digest(h.seal,self._mac('seal',self._body(entry))): raise IntegrityError('precision_metadata_mismatch')
            if h.value_id in active: raise IntegrityError('precision_cycle')
            if h.value_id in visited: return entry
            if depth>=MAX_CHAIN or len(visited)>=MAX_CHAIN: raise IntegrityError('precision_chain_budget')
            visited[h.value_id]=entry; active.add(h.value_id); parents=tuple(walk(p,depth+1) for p in entry.parents)
            if entry.operation=='trusted_release':
                args=json.loads(entry.parameters_json); expected=self._released(parents[0],args['rule_id'],SinkTarget(**args['target']))
                if expected!=entry.node: raise IntegrityError('precision_release_mismatch')
            elif not entry.operation.startswith('source_'):
                expected=self._derive(entry.operation,tuple(e.node for e in parents),json.loads(entry.parameters_json))
                if expected!=entry.node: raise IntegrityError('precision_transform_mismatch')
            elif any(l not in entry.node.labels for p in parents for l in p.node.labels): raise IntegrityError('precision_source_downgrade')
            active.remove(h.value_id); return entry
        try:
            entry=walk(handle)
            return {'allowed':True,'reason':'precision_integrity_verified','sensitive':any(l.sensitive for l in entry.node.labels),'source_ids':list(entry.node.to_tainted().source_ids),
                'root_reference_ids':[r for _,r in entry.roots],'releases':[{'rule_id_hash':hashlib.sha256(s.rule_id.encode()).hexdigest(),'target':asdict(s.target)} for s in entry.node.releases],
                'chain':[{'provenance_id':e.handle.provenance_id,'operation':e.operation,'parents':[p.provenance_id for p in e.parents]} for e in visited.values()]}
        except (ValueError,TypeError,KeyError,RecursionError,AttributeError):
            return {'allowed':False,'reason':'precision_integrity_rejected'}

    def resolve(self,handle):
        decision=self.verify(handle)
        if not decision['allowed']: raise IntegrityError(decision['reason'])
        return self._entries[handle.value_id].node
