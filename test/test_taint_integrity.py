"""Independent handle forgery, source-policy and real pre-send checks."""

import json
import tempfile
import unittest
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from unittest.mock import patch

from evaluation.receiver import LoopbackReceiver
from security.attested_runtime import AgentPort, AttestedRuntime
from security.taint import SourceRecord, TaintedValue
from security.taint_context import TaintContext
from security.taint_integrity import IntegrityError, ValueHandle, _SourceAuthority


class IntegrityBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.receiver = LoopbackReceiver()
        cls.receiver.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls.receiver.__exit__()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'data').mkdir()
        (self.root / 'data/private.txt').write_text('synthetic saffron ledger 9182')
        (self.root / 'data/public.txt').write_text('public rainfall summary')
        self.policy = self.root / 'policy.yaml'
        self.policy.write_text('blocked_files:\nallowed_file_roots:\n  - data\nallowed_domains:\n  - 127.0.0.1\n')
        self.audit = self.root / 'audit.jsonl'
        self.context = TaintContext(self.root, ('data/private.txt',), frozenset({'echo'}))
        self.runtime = AttestedRuntime(policy_path=self.policy, audit_path=self.audit, context=self.context,
                                       local_target=self.receiver.target, approved_tools={'echo':lambda data:data})
        self.port = AgentPort(self.runtime)
        self.before = len(self.receiver.arrivals)

    def private(self):
        result = self.runtime.read('data/private.txt')
        self.assertTrue(result.executed)
        self.assertIsNotNone(result.handle)
        return result.handle

    def assert_blocked(self, value, reason=None):
        with patch('security.runtime.send_http', wraps=self.receiver.target.send) as sender:
            result = self.runtime.send(self.receiver.url, value)
        self.assertFalse(result.executed)
        sender.assert_not_called()
        self.assertEqual(len(self.receiver.arrivals), self.before)
        if reason:
            self.assertEqual(result.decision.reason, reason)
        return result

    def test_taint_strip_attempt(self):
        self.private()
        self.assert_blocked('synthetic saffron ledger 9182', 'integrity_unattested')

    def test_fake_literal_conversion(self):
        self.private()
        self.assert_blocked(TaintedValue.literal('synthetic saffron ledger 9182'), 'integrity_unattested')
        response = self.port.dispatch({'tool':'literal','args':{'value':'synthetic saffron ledger 9182'}})
        self.assertFalse(response['executed'])
        self.assertEqual(response['error'],'integrity_unauthorized_tool')

    def test_manual_wrapper_attack(self):
        forged = TaintedValue.from_source('synthetic saffron ledger 9182',
                                          SourceRecord.create('file','data/public.txt'),sensitive=False)
        self.assert_blocked(forged,'integrity_unattested')
        forged_handle = ValueHandle(*(['0'*64]*5))
        self.assert_blocked(forged_handle,'integrity_wrong_runtime')

    def test_source_mismatch(self):
        handle = self.private()
        for field in ('source_hash','provenance_id','seal'):
            self.assert_blocked(replace(handle,**{field:'0'*64}),'integrity_source_or_seal_mismatch')

    def test_unissued_and_cross_session(self):
        handle = self.private()
        self.assert_blocked(replace(handle,value_id='0'*64),'integrity_unissued')
        other = AttestedRuntime(policy_path=self.policy,audit_path=self.audit,context=self.context,
                                local_target=self.receiver.target)
        with patch('security.runtime.send_http') as sender:
            self.assertEqual(other.send(self.receiver.url,handle).decision.reason,'integrity_wrong_runtime')
        sender.assert_not_called()

    def test_all_supported_transforms_preserve_confidentiality(self):
        root = self.private()
        cases = [('base64_encode',{}),('url_encode',{}),('slice',{'start':2}),
                 ('nested_json',{}),('json_roundtrip',{}),('checkpoint',{}),('json_escape',{}),
                 ('slice_rejoin',{'cuts':[4,9]}),('segmented_encode',{'cuts':[4,9]}),
                 ('mix',{'prefix':'report: ','suffix':' done'})]
        for name, params in cases:
            handle = self.runtime.transform(name,root,parameters=params)
            self.assertTrue(self.runtime.provenance(handle)['allowed'])
            self.assert_blocked(handle,'taint_sensitive_source')
        for encode,decode in [('base64_encode','base64_decode'),('url_encode','url_decode')]:
            self.assert_blocked(self.runtime.transform(decode,self.runtime.transform(encode,root)))

    def test_container_and_branch_chain(self):
        root = self.private()
        sliced = self.runtime.transform('slice',root,parameters={'stop':5})
        tail = self.runtime.transform('slice',root,parameters={'start':5})
        joined = self.runtime.transform('concat',sliced,tail)
        grouped = self.runtime.transform('dict',joined,parameters={'keys':['note']})
        encoded = self.runtime.transform('json_encode',grouped)
        parsed = self.runtime.transform('json_decode',encoded)
        final = self.runtime.transform('get_item',parsed,parameters={'key':'note'})
        self.assert_blocked(final)
        chain = self.runtime.provenance(final)['chain']
        self.assertEqual(chain[0]['operation'],'file_tool')
        self.assertEqual(chain[-1]['operation'],'get_item')
        self.assertEqual(len({item['provenance_id'] for item in chain}),len(chain))

    def test_public_encoded_actual_delivery(self):
        root = self.runtime.read('data/public.txt').handle
        handle = self.runtime.transform('base64_encode',root)
        result = self.runtime.send(self.receiver.url,handle)
        self.assertTrue(result.executed)
        self.assertIsNotNone(result.receipt)
        self.assertEqual(self.receiver.arrivals[-1]['body'],'cHVibGljIHJhaW5mYWxsIHN1bW1hcnk=')

    def test_tool_parent_cannot_scrub_file(self):
        handle = self.runtime.call_approved_tool('echo',self.private())
        self.assert_blocked(handle)
        self.assertEqual(self.runtime.provenance(handle)['chain'][-1]['operation'],'approved_tool')
        with self.assertRaises(IntegrityError):
            self.runtime.call_approved_tool('arbitrary_python',handle)

    def test_model_sink_rejects_before_send(self):
        handle = self.private()
        with patch('security.runtime.send_http') as sender:
            result = self.runtime.send(self.receiver.url,handle,sink='model')
        self.assertFalse(result.executed)
        sender.assert_not_called()
        self.assertEqual(result.decision.reason,'taint_sensitive_source')

    def test_immutable_handles_and_bounded_wire(self):
        handle = self.private()
        with self.assertRaises(FrozenInstanceError):
            handle.source_hash = '0'*64
        self.assertEqual(ValueHandle.from_wire(handle.to_wire()),handle)
        for value in ({},dict(handle.to_wire(),secret='never-log'),dict(handle.to_wire(),seal='x'*65536)):
            with self.assertRaises(IntegrityError):
                ValueHandle.from_wire(value)

    def test_no_public_mint_and_invalid_transform(self):
        self.assertFalse(hasattr(self.runtime,'literal'))
        self.assertFalse(hasattr(self.runtime,'from_source'))
        handle = self.private()
        for operation in ('literal','from_source','reveal','exec','implicit_flow'):
            with self.assertRaises(IntegrityError):
                self.runtime.transform(operation,handle)
        with self.assertRaises(IntegrityError):
            self.runtime.transform('slice',handle,parameters={'sensitive':False})

    def test_agent_port_data_only_and_no_raw_read(self):
        result = self.port.dispatch({'tool':'read_file','args':{'path':'data/private.txt'}})
        self.assertNotIn('content',result)
        self.assertNotIn('synthetic saffron ledger 9182',json.dumps(result))
        sent = self.port.dispatch({'tool':'send_http','args':{'url':self.receiver.url,'handle':result['handle']}})
        self.assertFalse(sent['executed'])
        self.assertFalse(sent['completed'])
        bad = self.port.dispatch({'tool':'send_http','args':{'url':self.receiver.url,'handle':result['handle'],'data':'replacement'}})
        self.assertEqual(bad['error'],'integrity_unauthorized_tool')

    def test_sanitized_audit_and_lineage(self):
        handle = self.private()
        self.assert_blocked(replace(handle,source_hash='0'*64))
        self.assert_blocked(self.runtime.transform('base64_encode',handle))
        output = self.audit.read_text() + json.dumps(self.runtime.provenance(handle))
        for raw in ('synthetic saffron ledger 9182','data/private.txt',str(self.root)):
            self.assertNotIn(raw,output)

    def test_registry_budget_and_plain_source_rejection(self):
        authority = _SourceAuthority()
        value = TaintedValue.from_source('public',SourceRecord.create('file','public'),sensitive=False)
        with patch('security.taint_integrity.MAX_HANDLES',2):
            first = authority._source('file_tool',value)
            authority.transform('checkpoint',(first,),{})
            with self.assertRaisesRegex(IntegrityError,'registry_budget'):
                authority.transform('checkpoint',(first,),{})
        with self.assertRaises(IntegrityError):
            authority._source('file_tool',TaintedValue.literal('fake'))
        with self.assertRaises(IntegrityError):
            authority._source('unknown_component',value)

    def test_chain_replay_detects_corruption(self):
        authority = _SourceAuthority()
        first = authority._source('file_tool',TaintedValue.from_source('private',SourceRecord.create('file','private'),sensitive=True))
        transformed = authority.transform('base64_encode',(first,),{})
        # Simulated trusted-storage corruption; not a claimed adversary power.
        entry = authority._entries[transformed.value_id]
        authority._entries[transformed.value_id] = replace(entry,value=TaintedValue.literal('fake public'))
        self.assertFalse(authority.verify(transformed).allowed)


if __name__ == '__main__':
    unittest.main()
