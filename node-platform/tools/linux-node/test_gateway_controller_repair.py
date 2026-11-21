"""Exact consumed-install controller repair; no runtime, custody or host action."""
import base64
import copy
import ctypes
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from contextlib import ExitStack
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import bootstrap as b
import controller as c
import lifecycle
import canary_rpc_relay as g
import test_controller_startup as fixtures


class GatewayControllerRepairTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=fixtures.IsolatedControllerStartupTests().fixture(self.temp.name)
        self.control=self.root/'tmp/controller';self.path=self.control/'policy.json'
        self.source=Path(c.__file__).read_text()
        old=self.source.replace("    tools=str(c.control/'tools')\n    if tools not in sys.path:sys.path.insert(0,tools)\n",'')
        self.write(self.control/'controller.py',old.encode())
        self.policy=json.loads(self.path.read_bytes())
        self.policy['engine_files']['controller.py']=self.sha(old.encode())
        self.selection=dict(release_id='test-master',manifest_sha256='a'*64,network_id='test-network',chain_id=99999,node_name='rpc-test')
        target=dict(kind='remote',host='127.0.0.1',port=22,root=str(self.root),
            machine_id_sha256=None,host_key='127.0.0.1 ssh-ed25519 '+'A'*68)
        self.inputs={'formation-context.json':c.canonical(dict(network_id='test-network',chain_id_hex=format(99999,'064x'),formation_id='f'*64))}
        self.inputs.update({'commissioning/network/'+name:('public-'+name).encode() for name in
            ('genesis.json','authority.json','authority-root.pub','network-manifest.json','transport-registry.json','transport-root.pub')})
        pins={name:self.sha(self.inputs['commissioning/network/'+name]) for name in ('genesis.json','authority.json','authority-root.pub')}
        original=dict(version=1,operation='gateway_install',parameters=self.selection)
        self.request=c.request_digest(original)
        doc=dict(version=1,profile=b.AUTHORIZATION_PROFILE,target=target,**self.selection,sequence=1,expires_at=1000,
            artifacts={name:self.sha(raw) for name,raw in self.inputs.items()},genesis_pins=pins,
            requests=[dict(operation='gateway_install',request_sha256=self.request)])
        self.auth=json.dumps(doc,separators=(',',':'));self.pin=self.sha(self.auth.encode())
        self.policy.update(engineering_authorization=dict(sha256=self.pin,sequence=1,expires_at=1000),
            engineering_initial_authorization_sha256=self.pin,engineering_target=target,engineering_selection=self.selection,
            validator_identity_network=pins,authorization_files=doc['artifacts'],
            validator_formation_sha256=doc['artifacts']['formation-context.json'])
        self.write(self.path,c.canonical(self.policy))
        self.write(self.control/'gateway-install-request.json',c.canonical(original))
        self.write(self.control/'audit.jsonl',c.canonical(dict(operation='gateway_install',request_sha256=self.request,time=999))+b'\n')
        for name,raw in self.inputs.items():self.write(self.control/'authorization/inputs'/name,raw)
        for name in ('keys','config','network'):(self.root/name).mkdir(mode=0o700)
        self.receipt=dict(self.selection,package_sha256='a'*64,role='rpc_gateway',consensus_started=False)
        self.manifest=dict(release_id='test-master',files={'tools/'+name:pin for name,pin in self.policy['engine_files'].items()})
        self.wire=dict(authorization=self.auth,artifacts={name:base64.b64encode(raw).decode() for name,raw in self.inputs.items()},gateway_controller_source=self.source)

    @staticmethod
    def sha(raw):return hashlib.sha256(raw).hexdigest()

    def write(self,path,raw):
        path.parent.mkdir(parents=True,exist_ok=True)
        for folder in path.parents:
            if folder==self.root:break
            folder.chmod(0o700)
        path.write_bytes(raw);path.chmod(0o600)

    def adapters(self):
        stack=ExitStack();self.addCleanup(stack.close)
        real_stat,real_lstat=Path.stat,Path.lstat
        def owned(method):
            def inspect(path,*args,**kwargs):
                value=list(method(path,*args,**kwargs));value[4]=0;return os.stat_result(value)
            return inspect
        def exchange(_a,left,_b,right,_flags):
            left,right=Path(os.fsdecode(left)),Path(os.fsdecode(right));swap=left.with_name('fixture-exchange')
            left.rename(swap);right.rename(left);swap.rename(right);return 0
        for obj,name,value in ((b,'ROOT',self.root),(b.os,'geteuid',lambda:0),(b.sys,'platform','linux'),
            (b.os,'uname',lambda:SimpleNamespace(machine='x86_64')),(sys,'path',sys.path.copy()),
            (Path,'stat',owned(real_stat)),(Path,'lstat',owned(real_lstat)),
            (ctypes,'CDLL',lambda *a,**kw:SimpleNamespace(renameat2=exchange)),
            (lifecycle,'_sealed_receipt',lambda root:(self.receipt,self.manifest)),
            (g,'_gateway_target_quiescent',lambda controller:None)):
            stack.enter_context(patch.object(obj,name,value))
        stack.enter_context(patch.object(b,'NATIVE_AUTHENTICATED_AUTHORIZATION_SHA256',self.pin,create=True))
        stack.enter_context(patch.object(b,'NATIVE_AUTHENTICATED_GATEWAY_CONTROLLER_SHA256',self.sha(self.source.encode()),create=True))
        return stack

    def call(self):return b.stage_engineering_authorization(io.BytesIO(c.canonical(self.wire)),repair_gateway_controller=True)

    def inventory(self):return {p.relative_to(self.root).as_posix():p.read_bytes() for p in self.root.rglob('*') if p.is_file()}

    def test_exact_expired_original_repairs_only_controller_and_policy_then_reconciles(self):
        with self.adapters():
            before=self.inventory();result=self.call()
            self.assertTrue(result['gateway_controller_repaired']);self.assertFalse(result['grants_recreated'])
            after=self.inventory()
            self.assertEqual({p for p in before if before[p]!=after[p]}, {'tmp/controller/controller.py','tmp/controller/policy.json'})
            changed=json.loads(self.path.read_bytes());marker=changed.pop('gateway_controller_repair')
            changed['engine_files']['controller.py']=self.policy['engine_files']['controller.py']
            self.assertEqual(changed,self.policy);self.assertEqual(marker['request_sha256'],self.request)
            self.assertEqual(self.call()['reconciled'],True)
            self.assertEqual(after,self.inventory())

    def test_postexchange_verifier_failure_reconciles_exact_predecessor_without_grants(self):
        with self.adapters():
            with patch.object(b,'verify_adopted_controller',side_effect=ValueError('interrupted verification')):
                with self.assertRaisesRegex(ValueError,'interrupted'):self.call()
            self.assertTrue((self.root/'tmp/controller-authorization').is_dir())
            self.assertTrue(self.call()['gateway_controller_repaired'])
            self.assertFalse((self.root/'tmp/controller-authorization').exists())
            self.assertFalse(any((self.control/'grants').iterdir()))

    def test_wrong_source_authorization_audit_receipt_and_custody_refuse_without_writes(self):
        for defect in ('source','authorization','audit','grant','receipt','commissioned','custody','engine','target','unknown_grant'):
            with self.subTest(defect=defect):
                case=GatewayControllerRepairTests();case.setUp()
                try:
                    if defect=='source':case.wire['gateway_controller_source']+='\n# changed'
                    elif defect=='authorization':case.wire['authorization']+=' '
                    elif defect=='audit':case.write(case.control/'audit.jsonl',b'')
                    elif defect=='grant':case.write(case.control/'grants'/(case.request+'.json'),b'{}')
                    elif defect=='receipt':case.receipt['role']='validator'
                    elif defect=='commissioned':case.receipt['gateway_commissioned']=True
                    elif defect=='custody':case.write(case.root/'keys/unknown',b'not read')
                    elif defect=='target':
                        changed=copy.deepcopy(case.policy);changed['engineering_target']['host']='foreign.example'
                        case.write(case.path,c.canonical(changed))
                    elif defect=='unknown_grant':case.write(case.control/'grants'/('0'*64+'.json'),b'{}')
                    else:case.write(case.control/'tools/lifecycle.py',b'changed engine')
                    with case.adapters():
                        before=case.inventory()
                        with self.assertRaises((ValueError,c.Refused)):case.call()
                        self.assertEqual(before,case.inventory())
                finally:case.doCleanups()

    def test_reconciled_foreign_predecessor_is_preserved(self):
        with self.adapters():
            with patch.object(b,'verify_adopted_controller',side_effect=ValueError('interrupt')):
                with self.assertRaises(ValueError):self.call()
            self.write(self.root/'tmp/controller-authorization/controller.py',b'foreign predecessor')
            before=self.inventory()
            with self.assertRaisesRegex(ValueError,'predecessor differs'):self.call()
            self.assertEqual(before,self.inventory())

    def test_repair_source_is_not_accepted_by_ordinary_authorization_wire(self):
        with self.assertRaisesRegex(ValueError,'Invalid authorization transfer'):
            with self.adapters():b.stage_engineering_authorization(io.BytesIO(c.canonical(self.wire)))


if __name__=='__main__':unittest.main()
