"""Projection safety uses trusted dependency layouts, with actual sink controls."""
import json,tempfile,unittest
from dataclasses import replace
from pathlib import Path
from security.precision import (SourceLayout,FieldRule,RangeRule,source_value,transform,uniform,Span)
from security.precision_integrity import PrecisionAuthority,DeclassificationRule
from security.precision_runtime import PrecisionRuntime
from security.attested_runtime import AgentPort
from security.taint import SinkTarget,TaintedValue,TaintError
from security.taint_context import TaintContext
from security.taint_integrity import IntegrityError
from evaluation.receiver import LoopbackReceiver


class PrecisionOperationTests(unittest.TestCase):
    def setUp(self):
        self.record=source_value({'username':'alice','api_key':'unrecognized synthetic juniper phrase','rows':['public','opaque private birch']},'file','record.json',
            SourceLayout(fields=(FieldRule(('api_key',),True),FieldRule(('rows',1),True))))
    def op(self,operation,value=None,**params): return transform(operation,(self.record if value is None else value,),params)
    def test_field_projection_selects_only_field_dependencies(self):
        self.assertFalse(self.op('get_item',key='username').to_tainted().sensitive)
        self.assertTrue(self.op('get_item',key='api_key').to_tainted().sensitive)
        self.assertTrue(self.record.to_tainted().sensitive)
    def test_nested_list_and_negative_index(self):
        rows=self.op('get_item',key='rows')
        self.assertFalse(self.op('get_item',rows,key=0).to_tainted().sensitive)
        self.assertTrue(self.op('get_item',rows,key=-1).to_tainted().sensitive)
    def test_list_slice_keeps_selected_dependencies(self):
        rows=self.op('get_item',key='rows')
        self.assertFalse(self.op('slice',rows,start=0,stop=1).to_tainted().sensitive)
        self.assertTrue(self.op('slice',rows,start=1,stop=2).to_tainted().sensitive)
    def test_range_slicing_requires_trusted_layout(self):
        text=source_value('public|opaque_private','file','mixed',SourceLayout(default_sensitive=True,ranges=(RangeRule((),0,6,False),)))
        self.assertFalse(self.op('slice',text,start=0,stop=6).to_tainted().sensitive)
        self.assertTrue(self.op('slice',text,start=7).to_tainted().sensitive)
        whole=source_value('public|opaque_private','file','whole',SourceLayout(default_sensitive=True))
        self.assertTrue(self.op('slice',whole,start=0,stop=6).to_tainted().sensitive)
    def test_noncontiguous_reverse_slice(self):
        text=source_value('abcdSECRET','file','mixed',SourceLayout(default_sensitive=True,ranges=(RangeRule((),0,4,False),)))
        public=self.op('slice',text,start=3,stop=None,step=-1)
        self.assertEqual(public.raw.reveal(),'dcba'); self.assertFalse(public.to_tainted().sensitive)
        self.assertTrue(self.op('slice',text,step=2).to_tainted().sensitive)
    def test_json_roundtrip_preserves_fields_and_escapes(self):
        encoded=self.op('json_encode')
        self.assertTrue(encoded.to_tainted().sensitive)
        decoded=self.op('json_decode',encoded)
        self.assertEqual(decoded.raw.reveal(),self.record.raw.reveal())
        self.assertFalse(self.op('get_item',decoded,key='username').to_tainted().sensitive)
        self.assertTrue(self.op('get_item',decoded,key='api_key').to_tainted().sensitive)
    def test_unrelated_json_decode_is_conservative(self):
        value=source_value('{"username":"alice","api_key":"private"}','file','whole',SourceLayout(default_sensitive=True))
        self.assertTrue(self.op('get_item',self.op('json_decode',value),key='username').to_tainted().sensitive)
    def test_encoding_roundtrips_unicode(self):
        v=source_value('公开|秘密','file','unicode',SourceLayout(default_sensitive=True,ranges=(RangeRule((),0,2,False),)))
        for encode,decode in [('base64_encode','base64_decode'),('url_encode','url_decode')]:
            result=self.op(decode,self.op(encode,v)); self.assertFalse(self.op('slice',result,start=0,stop=2).to_tainted().sensitive)
            self.assertTrue(self.op('slice',result,start=3).to_tainted().sensitive)
    def test_encoded_sensitive_projection_stays_sensitive(self):
        secret=self.op('get_item',key='api_key')
        for operation in ('base64_encode','url_encode','json_encode'):
            self.assertTrue(self.op(operation,secret).to_tainted().sensitive)
    def test_combination_and_projection(self):
        public=self.op('get_item',key='username'); secret=self.op('get_item',key='api_key')
        mixed=transform('dict',(public,secret),{'keys':['user','credential']})
        self.assertFalse(self.op('get_item',mixed,key='user').to_tainted().sensitive)
        self.assertTrue(transform('concat',(public,secret),{}).to_tainted().sensitive)
    def test_coarse_structure_sensitive_is_conservative(self):
        v=source_value({'public':'alice'},'file','shape',SourceLayout(structure_sensitive=True))
        self.assertTrue(self.op('get_item',v,key='public').to_tainted().sensitive)
    def test_invalid_layouts_and_missing_selectors(self):
        for layout in (SourceLayout(fields=(FieldRule(('missing',),True),)),SourceLayout(ranges=(RangeRule((),0,100,False),))):
            with self.assertRaises(TaintError): source_value('abc','file','x',layout)
        with self.assertRaises(TaintError): SourceLayout(ranges=(RangeRule((),0,3,True),RangeRule((),2,4,False)))
    def test_bounded_data_metadata_and_unsupported_ops(self):
        with self.assertRaises(TaintError): source_value('x'*65537,'file','x',SourceLayout())
        for operation in ('rot13','untaint','literal','exec'):
            with self.assertRaisesRegex(TaintError,'unsupported'): self.op(operation)
        with self.assertRaises(TaintError): self.op('slice',step=0)
    def test_empty_sensitive_slice_is_conservative(self):
        self.assertTrue(self.op('slice',self.op('get_item',key='api_key'),start=0,stop=0).to_tainted().sensitive)

    def test_roundtrip_witness_keeps_inherited_container_dependency(self):
        secret=self.op('get_item',key='api_key')
        public=self.op('get_item',key='username')
        for encode,decode in [('json_encode','json_decode'),('base64_encode','base64_decode'),('url_encode','url_decode')]:
            encoded=self.op(encode,public)
            container=transform('list',(encoded,),{})
            container=replace(container,ambient=secret.labels)
            extracted=self.op('get_item',container,key=0)
            self.assertTrue(self.op(decode,extracted).to_tainted().sensitive)


class PrecisionRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.root=Path(self.temp.name); (self.root/'data').mkdir()
        (self.root/'data/source.json').write_text(json.dumps({'username':'alice','api_key':'opaque juniper phrase 611'}))
        (self.root/'data/other.json').write_text(json.dumps({'username':'mallory'}))
        self.policy=self.root/'policy.yaml'; self.policy.write_text('blocked_files:\nallowed_file_roots:\n  - data\nallowed_domains:\n  - 127.0.0.1\n')
        self.receiver=LoopbackReceiver(); self.receiver.__enter__()
    def tearDown(self): self.receiver.__exit__(); self.temp.cleanup()
    def runtime(self,*,whole=False,rules=(),**kwargs):
        layout=SourceLayout(default_sensitive=whole,structured_json=True,fields=() if whole else (FieldRule(('api_key',),True),))
        return PrecisionRuntime(policy_path=self.policy,audit_path=self.root/'audit.jsonl',context=TaintContext(self.root),local_target=self.receiver.target,
            layouts={('file','data/source.json'):layout,('file','data/other.json'):SourceLayout(default_sensitive=True,structured_json=True)},rules=rules,**kwargs)
    def test_public_reaches_receiver_secret_and_encoded_secret_do_not(self):
        runtime=self.runtime(); handle=runtime.read('data/source.json').handle
        public=runtime.transform('get_item',handle,parameters={'key':'username'})
        secret=runtime.transform('get_item',handle,parameters={'key':'api_key'})
        self.assertTrue(runtime.send(self.receiver.url,public).executed)
        for op in (None,'base64_encode','url_encode','json_encode'):
            value=secret if op is None else runtime.transform(op,secret)
            self.assertFalse(runtime.send(self.receiver.url,value).executed)
        self.assertEqual([r['body'] for r in self.receiver.arrivals],['alice'])
    def test_forged_labels_plain_wrappers_and_cross_session_rejected(self):
        runtime=self.runtime(); h=runtime.read('data/source.json').handle
        for bad in (replace(h,source_hash='0'*64),TaintedValue.literal('alice'),self.runtime().read('data/source.json').handle):
            self.assertFalse(runtime.send(self.receiver.url,bad).executed)
        self.assertFalse(self.receiver.arrivals)
    def test_metadata_storage_tamper_rejected(self):
        runtime=self.runtime(); h=runtime.read('data/source.json').handle
        entry=runtime._precision._entries[h.value_id]
        runtime._precision._entries[h.value_id]=replace(entry,node=uniform(entry.node.raw.reveal(),()))
        self.assertFalse(runtime.send(self.receiver.url,h).executed)
    def rule(self): return DeclassificationRule('public_username','file','data/source.json','get_item','{"key":"username"}',SinkTarget.from_url('http',self.receiver.url))
    def test_trusted_release_is_source_operation_and_target_scoped(self):
        runtime=self.runtime(whole=True,rules=(self.rule(),)); h=runtime.read('data/source.json').handle
        public=runtime.transform('get_item',h,parameters={'key':'username'})
        self.assertFalse(runtime.send(self.receiver.url,public).executed)
        released=runtime.release(public,'public_username',SinkTarget.from_url('http',self.receiver.url))
        self.assertTrue(runtime.send(self.receiver.url,released).executed)
        self.assertFalse(runtime.send(self.receiver.url,released,sink='model').executed)
        secret=runtime.transform('get_item',h,parameters={'key':'api_key'})
        for value,target in ((secret,SinkTarget.from_url('http',self.receiver.url)),(public,SinkTarget('http','http://127.0.0.1:1'))):
            with self.assertRaises(IntegrityError): runtime.release(value,'public_username',target)
        wrong=runtime.transform('get_item',runtime.read('data/other.json').handle,parameters={'key':'username'})
        with self.assertRaises(IntegrityError): runtime.release(wrong,'public_username',self.rule().target)
    def test_release_is_revoked_after_transformation(self):
        runtime=self.runtime(whole=True,rules=(self.rule(),)); public=runtime.transform('get_item',runtime.read('data/source.json').handle,parameters={'key':'username'})
        released=runtime.release(public,'public_username',self.rule().target)
        self.assertFalse(runtime.send(self.receiver.url,runtime.transform('base64_encode',released)).executed)

    def test_release_rejects_composed_field_substitution_and_wildcard(self):
        runtime=self.runtime(whole=True,rules=(self.rule(),)); h=runtime.read('data/source.json').handle
        secret=runtime.transform('get_item',h,parameters={'key':'api_key'})
        forged=runtime.transform('dict',secret,parameters={'keys':['username']})
        projected=runtime.transform('get_item',forged,parameters={'key':'username'})
        with self.assertRaises(IntegrityError): runtime.release(projected,'public_username',self.rule().target)
        with self.assertRaises(IntegrityError): replace(self.rule(),target=SinkTarget('http'))
    def test_agent_cannot_request_release_or_literal(self):
        port=AgentPort(self.runtime(whole=True,rules=(self.rule(),)))
        for tool in ('release','untaint','literal','source'):
            self.assertFalse(port.dispatch({'tool':tool,'args':{}})['executed'])
    def test_model_boundary_keeps_sensitive_parent(self):
        runtime=self.runtime(); parent=runtime.read('data/source.json').handle
        payload=runtime._model_payload({'messages':[{'content':'synthetic'}]},reference='request',parents=(parent,))
        self.assertFalse(runtime.approve_model_payload(self.receiver.url,payload).allowed)
    def test_audit_is_redacted(self):
        runtime=self.runtime(whole=True,rules=(self.rule(),)); h=runtime.transform('get_item',runtime.read('data/source.json').handle,parameters={'key':'username'})
        runtime.release(h,'public_username',self.rule().target)
        text=(self.root/'audit.jsonl').read_text()
        for raw in ('alice','opaque juniper phrase 611','data/source.json'): self.assertNotIn(raw,text)

if __name__=='__main__': unittest.main()
