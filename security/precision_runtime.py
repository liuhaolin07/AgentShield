"""Precision-aware trusted adapters using the existing guarded executor path."""
from __future__ import annotations
import json
import time
from typing import Any
from security.attested_runtime import AttestedReadResult,AttestedRuntime
from security.audit import write_audit_event
from security.middleware import check_tool_call
from security.runtime import GuardedRuntime
from security.taint import SourceRecord,TaintLabel,SinkTarget,TaintedValue,json_deserialize
from security.taint_integrity import IntegrityError
from security.precision import SourceLayout,source_value,uniform,union
from security.precision_integrity import PrecisionAuthority


class PrecisionRuntime(GuardedRuntime):
    def __init__(self,*,layouts=None,rules=(),field_precision=True,propagate=True,release_enabled=True,
                 scan_content=True,enforce_content=True,approved_tools=None,**kwargs):
        super().__init__(**kwargs)
        self._precision=PrecisionAuthority(rules=rules,field_precision=field_precision,propagate=propagate,release_enabled=release_enabled)
        self._layouts=dict(layouts or {}); self._tools=dict(approved_tools or {})
        if len(self._layouts)>128 or any(not isinstance(k,tuple) or len(k)!=2 or k[0] not in {'file','tool','model'} or not isinstance(k[1],str) or not isinstance(v,SourceLayout) for k,v in self._layouts.items()): raise IntegrityError('precision_invalid_layout_registry')
        if len(self._tools)>128 or any(not isinstance(k,str) or not callable(v) for k,v in self._tools.items()): raise IntegrityError('precision_invalid_tools')
        if type(scan_content) is not bool or type(enforce_content) is not bool: raise IntegrityError('precision_invalid_configuration')
        self._scan_content,self._enforce_content=scan_content,enforce_content

    def _check(self,capability,args):
        started=time.perf_counter_ns()
        decision=check_tool_call(capability,args,agent='precision-agent',policy_path=self.policy_path,audit_path=self.audit_path,defense_mode=self.defense_mode,
            taint_policy=self.context.policy,scan_content=self._scan_content,enforce_content=self._enforce_content)
        self.observe('policy_decision',allowed=decision.allowed,reason=decision.reason,checks=decision.checks.explain() if decision.checks else None,duration_ns=time.perf_counter_ns()-started)
        return decision

    def _ingress(self,category,reference,content,parents=(),fallback_sensitive=False):
        layout=self._layouts.get((category,reference),SourceLayout(default_sensitive=fallback_sensitive,structure_sensitive=fallback_sensitive))
        if layout.structured_json:
            if not isinstance(content,str): raise IntegrityError('precision_json_source_requires_text')
            content=json_deserialize(TaintedValue.literal(content)).reveal()
        value=source_value(content,category,reference,layout)
        if parents:
            value=uniform(value.raw.reveal(),union(value.labels,*(self._precision.resolve(h).labels for h in parents)))
        handle=self._precision._source(category,reference,value,parents)
        self.observe('precision_source_issued',category=category,**self.provenance(handle))
        return handle

    def read(self,path):
        result=GuardedRuntime.read(self,path)
        if result.value is None: return AttestedReadResult(result.decision,result.executed,error=result.error)
        try:
            reference=result.decision.resolved_path.resolve().relative_to(self.context.root).as_posix()
            handle=self._ingress('file',reference,result.value.reveal(),fallback_sensitive=result.value.sensitive)
            return AttestedReadResult(result.decision,result.executed,handle)
        except (ValueError,TypeError): return AttestedReadResult(result.decision,result.executed,error='precision_source_rejected')

    def call_approved_tool(self,name,parent=None):
        if name not in self._tools: raise IntegrityError('precision_unapproved_tool')
        value=self._precision.resolve(parent).raw.reveal() if parent else None
        self.observe('tool_executor_entered')
        return self._ingress('tool',name,self._tools[name](value),(parent,) if parent else ())

    def transform(self,operation,*handles,parameters=None):
        started=time.perf_counter_ns(); result=self._precision.transform(operation,handles,parameters or {})
        self.observe('precision_transform_issued',duration_ns=time.perf_counter_ns()-started,**self.provenance(result))
        return result

    def release(self,handle,rule_id,target):
        try:
            result=self._precision.release(handle,rule_id,target); explanation=self.provenance(result); allowed=True; reason='precision_release_allowed' if result!=handle else 'precision_release_disabled'
        except (ValueError,TypeError):
            allowed=False; reason='precision_release_denied'; explanation={'allowed':False,'reason':reason}; result=None
        write_audit_event(agent='trusted-precision-runtime',tool='release',capability='trusted_release',decision='ALLOW' if allowed else 'BLOCK',reason=reason,path=self.audit_path,checks={'declassification':explanation})
        self.observe('declassification_decision',allowed=allowed,reason=reason,checks={'declassification':explanation})
        if result is None: raise IntegrityError(reason)
        return result

    def provenance(self,handle): return self._precision.verify(handle)
    def _model_content(self,handle): return self._precision.resolve(handle).raw.reveal()
    def _model_return(self,content,*,reference,parents=()): return self._ingress('model',reference,content,parents)
    def _model_payload(self,payload,*,reference,parents):
        serialized=json.dumps(TaintedValue.literal(payload).reveal(),ensure_ascii=False,separators=(',',':'))
        return self._model_return(serialized,reference=reference,parents=parents)
    def _integrity_rejection(self,reason,sink,explanation): return AttestedRuntime._integrity_rejection(self,reason,sink,explanation)

    def _sink_value(self,handle,sink,url):
        started=time.perf_counter_ns(); explanation=self.provenance(handle)
        value=self._precision.resolve(handle).to_tainted(SinkTarget.from_url(sink,url)) if explanation['allowed'] else None
        self.observe('integrity_check',duration_ns=time.perf_counter_ns()-started,**explanation)
        return value,explanation

    def send(self,url,handle,*,sink='http'):
        if sink not in {'http','model'}: raise IntegrityError('precision_invalid_sink')
        try: value,explanation=self._sink_value(handle,sink,url)
        except (ValueError,TypeError): return self._integrity_rejection('precision_invalid_sink_input',sink,{'allowed':False})
        if value is None: return self._integrity_rejection(explanation['reason'],sink,explanation)
        return GuardedRuntime.send(self,url,value,sink=sink)

    def approve_model_payload(self,endpoint,handle):
        value,explanation=self._sink_value(handle,'model',endpoint)
        if value is None: return self._integrity_rejection(explanation['reason'],'model',explanation).decision
        return self._check('model',{'url':endpoint,'data':value})
