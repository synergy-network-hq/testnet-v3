"""Pure native-embedded continuation absence proof; no hosts, grants or key material."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
import bootstrap as b
from unittest.mock import patch
from types import SimpleNamespace

class ContinuationReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name).resolve();self.control=self.root/'tmp/controller'
        (self.control/'tools').mkdir(parents=True);(self.control/'grants').mkdir()
        selection=dict(release_id='old-sealed',manifest_sha256='a'*64,network_id='synergy-posy-canary-20261117',chain_id=99999,node_name='validator-04')
        target=dict(kind='remote',host='host.example',port=22,root=str(self.root),host_key='host.example ssh-ed25519 '+'A'*68,machine_id_sha256=None)
        self.policy=dict(engineering_authorization=dict(sequence=9,sha256='c'*64),engineering_initial_authorization_sha256='b'*64,
            engineering_target=target,validator_formation_sha256='d'*64,validator_identity_network=None,engineering_selection=selection)
        self.pending=dict(version=1,profile=b.AUTHORIZATION_PROFILE,target=target,**selection,sequence=10,expires_at=1000,
            artifacts={},requests=[dict(operation='genesis_stage',request_sha256='e'*64)],genesis_pins={k:'f'*64 for k in ('genesis.json','authority.json','authority-root.pub')})
        self.context=dict(initial_sha256='b'*64,authorization=self.policy['engineering_authorization'],formation_sha256='d'*64,target=target,
            selection=selection,genesis_pins=None,pending_sha256='f'*64,expires_at=int(time.time())+120)
        controller="""import json,stat,os
class Controller:
 def __init__(self,root):self.root=root
 def policy(self):return json.loads((self.root/'tmp/controller/policy.json').read_bytes())
 def direct(self,path,private=False,limit=1048576):
  m=path.lstat();assert path.resolve()==path and stat.S_ISREG(m.st_mode) and m.st_nlink==1 and m.st_uid==os.geteuid() and stat.S_IMODE(m.st_mode)==0o600 and m.st_size<=limit;return path
GENESIS_STAGE='tmp/identity-network'
MUTATIONS={'genesis_stage','commission'}
def control_inventory(root):pass
def engineering_effective_selection(root,policy):return policy['engineering_selection']
"""
        lifecycle="""from contextlib import nullcontext
import json
def _lifecycle_lock(root):return nullcontext()
def _unit_state(name):return {'MainPID':'0','ActiveState':'inactive'}
def _assert_no_application_processes(root,**kw):
 assert not (root/'active-process').exists()
def _commission_fresh_keys(root):
 assert (root/'keys').is_dir() and not any((root/'keys').iterdir())
def _sealed_receipt(root):return ({'package_sha256':json.loads((root/'tmp/controller/policy.json').read_bytes())['engineering_selection']['manifest_sha256']},None)
"""
        pins={}
        for name in b.ENGINE:
            path=self.control/name if name=='controller.py' else self.control/'tools'/name
            raw=(controller if name=='controller.py' else lifecycle if name=='lifecycle.py' else 'FORMATION_PUBLIC_INPUTS='+repr({n[14:] for n in b.AUTHORIZATION_FILES if n.startswith('commissioning/')})+'\n' if name=='apqe_layout.py' else '# sealed fixture module\n').encode()
            path.write_bytes(raw);path.chmod(0o600);pins[name]=hashlib.sha256(raw).hexdigest()
        self.policy['engine_files']=pins
        self.save_policy()
    def save_policy(self):
        path=self.control/'policy.json';path.write_text(json.dumps(self.policy));path.chmod(0o600)
    def run_proof(self,pending=None,context=None,transport=False,readiness=False):
        raw=json.dumps(pending or self.pending);ctx=copy.deepcopy(context or self.context);ctx['pending_sha256']=hashlib.sha256(raw.encode()).hexdigest()
        wire=dict(context=ctx,challenge='1'*64)
        if not transport:wire['pending_json']=raw
        code="import json,pathlib;ns={'__name__':'embedded_proof'};exec(compile(pathlib.Path(%r).read_bytes(),'bootstrap.py','exec'),ns);exec(\"class FixturePath(type(pathlib.Path())):\\n @property\\n def parents(self):return tuple(p for p in super().parents if p.is_relative_to(fixture))\",{'pathlib':pathlib,'fixture':pathlib.Path(%r)},ns);ns['ROOT']=ns['FixturePath'](%r);ns['NATIVE_AUTHENTICATED_AUTHORIZATION_INITIAL_SHA256']='%s';print(json.dumps(ns['continuation_not_applied_proof'](json.loads(%r),%r,%r)))"%(str(Path(b.__file__).resolve()),str(self.root),str(self.root),'b'*64,json.dumps(wire),transport,readiness)
        return subprocess.run([sys.executable,'-I','-B','-c',code],capture_output=True,text=True,timeout=5)
    def snapshot(self):return {str(p.relative_to(self.root)):p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
    def test_isolated_hash_verified_engine_proves_expired_unapplied_document_without_writes(self):
        before=self.snapshot();result=self.run_proof();self.assertEqual(result.returncode,0,result.stderr)
        value=json.loads(result.stdout);self.assertTrue(value['not_applied']);self.assertFalse(value['mutation_performed']);self.assertEqual(value['request_sha256'],'e'*64)
        self.assertEqual(self.snapshot(),before)
    def test_exact_grant_even_expired_consumed_audit_and_partial_refuse_without_writes(self):
        for kind in ('expired-grant','consumed-audit','malformed-audit','partial','pending-partial','grant-link'):
            with self.subTest(kind=kind):
                path=None
                if kind=='expired-grant':path=self.control/'grants'/('e'*64+'.json');path.write_text('{"expires_at":1}')
                elif kind=='grant-link':path=self.control/'grants'/('e'*64+'.json');path.symlink_to(self.control/'policy.json')
                elif kind.endswith('audit'):path=self.control/'audit.jsonl';path.write_text(json.dumps(dict(operation='genesis_stage',request_sha256='e'*64,time=1))+'\n' if kind=='consumed-audit' else '{}\n')
                else:path=self.root/'tmp'/('controller-authorization.pending' if kind=='pending-partial' else 'controller-authorization');path.mkdir()
                before=self.snapshot();result=self.run_proof();self.assertNotEqual(result.returncode,0);self.assertEqual(self.snapshot(),before)
                path.rmdir() if path.is_dir() else path.unlink()
    def test_scope_predecessor_master_and_unknown_operation_refuse(self):
        for field,value in [('initial_sha256','f'*64),('authorization',dict(sequence=8,sha256='c'*64)),('formation_sha256','f'*64),('target',{}),('selection',{}),('genesis_pins',{}),('expires_at',1)]:
            context=copy.deepcopy(self.context);context[field]=value
            with self.subTest(field=field):self.assertNotEqual(self.run_proof(context=context).returncode,0)
        for field,value in [('sequence',11),('artifacts',{'vpn-ca.pem':'f'*64}),('target',{}),('release_id','other')]:
            pending=copy.deepcopy(self.pending);pending[field]=value
            with self.subTest(field=field):self.assertNotEqual(self.run_proof(pending=pending).returncode,0)
        pending=copy.deepcopy(self.pending);pending['requests'][0]['operation']='unknown';self.assertNotEqual(self.run_proof(pending=pending).returncode,0)
    def transport_context(self):
        ctx=copy.deepcopy(self.context)
        pins={}
        for name in b.AUTHORIZATION_FILES:
            if name.startswith('commissioning/'):pins[name[14:]]=hashlib.sha256(name.encode()).hexdigest()
        genesis={n:hashlib.sha256(n.encode()).hexdigest() for n in ('genesis.json','authority.json','authority-root.pub')}
        stage=self.root/'tmp/identity-network';stage.mkdir()
        for name,pin in genesis.items():
            path=stage/name;path.write_bytes(name.encode());path.chmod(0o600);pins['network/'+name]=pin
        for name in ('config','network'):(self.root/name).mkdir(mode=0o700)
        self.policy['validator_identity_network']=genesis;self.save_policy()
        ctx.update(genesis_pins=genesis,artifact_sha256=pins,dispatch_sha256='2'*64)
        return ctx
    def test_transport_proof_preserves_prior_genesis_and_never_claims_success(self):
        ctx=self.transport_context()
        for staged in (False,True):
            if staged:
                for name,pin in ctx['genesis_pins'].items():
                    label='commissioning/network/'+name;path=self.control/'authorization/inputs'/label
                    path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(name.encode());path.chmod(0o600)
                    self.policy.setdefault('authorization_files',{})[label]=pin
                self.save_policy()
            before=self.snapshot();result=self.run_proof(context=ctx,transport=True)
            self.assertEqual(result.returncode,0,result.stderr);value=json.loads(result.stdout)
            self.assertEqual(set(value),{'schema','challenge','pending_sha256','dispatch_sha256','parent_sha256','not_applied','mutation_performed'})
            self.assertEqual(value['schema'],'nodenetwork-transport-not-applied-v1');self.assertFalse(value['mutation_performed'])
            self.assertEqual(self.snapshot(),before)
    def test_transport_refuses_new_drafts_grants_audit_partials_or_published_state(self):
        ctx=self.transport_context()
        key=hashlib.sha256(json.dumps({'version':1,'operation':'commission','parameters':{}},sort_keys=True,separators=(',',':')).encode()).hexdigest()
        for name in ('authorization/inputs/commissioning/config/node.json','grants/'+key+'.json','audit.jsonl'):
            path=self.control/name;path.parent.mkdir(parents=True,exist_ok=True)
            path.write_text(json.dumps(dict(operation='commission',request_sha256=key,time=1))+'\n' if name=='audit.jsonl' else '{}');path.chmod(0o600)
            before=self.snapshot();self.assertNotEqual(self.run_proof(context=ctx,transport=True).returncode,0);self.assertEqual(self.snapshot(),before);path.unlink()
        for name in ('tmp/controller-authorization','tmp/controller-authorization.pending','tmp/commissioning','data','active-process','config/node.json'):
            path=self.root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('unchanged')
            before=self.snapshot();self.assertNotEqual(self.run_proof(context=ctx,transport=True).returncode,0);self.assertEqual(self.snapshot(),before);path.unlink()
        path=self.root/'tmp/identity-network/genesis.json';path.write_bytes(b'changed')
        self.assertNotEqual(self.run_proof(context=ctx,transport=True).returncode,0)
    def test_transport_prior_genesis_rejects_links_modes_and_unapproved_copies(self):
        ctx=self.transport_context();path=self.root/'tmp/identity-network/genesis.json'
        path.chmod(0o644);self.assertNotEqual(self.run_proof(context=ctx,transport=True).returncode,0);path.chmod(0o600)
        raw=path.read_bytes();path.unlink();path.symlink_to(self.root/'tmp/identity-network/authority.json')
        self.assertNotEqual(self.run_proof(context=ctx,transport=True).returncode,0);path.unlink();path.write_bytes(raw);path.chmod(0o600)
        copy=self.control/'authorization/inputs/commissioning/network/genesis.json';copy.parent.mkdir(parents=True);copy.write_bytes(raw);copy.chmod(0o600)
        before=self.snapshot();self.assertNotEqual(self.run_proof(context=ctx,transport=True).returncode,0);self.assertEqual(self.snapshot(),before)

    def test_transport_scope_or_public_inventory_mismatch_refuses(self):
        ctx=self.transport_context()
        for field,value in [('target',{}),('authorization',dict(sequence=8,sha256='c'*64)),('genesis_pins',{}),('artifact_sha256',{}),('dispatch_sha256','wrong'),('expires_at',1)]:
            bad=copy.deepcopy(ctx);bad[field]=value
            with self.subTest(field=field):self.assertNotEqual(self.run_proof(context=bad,transport=True).returncode,0)
        for value in ({},ctx['artifact_sha256']):
            self.policy['validator_commissioning_files']=value;self.save_policy()
            self.assertNotEqual(self.run_proof(context=ctx,transport=True).returncode,0)
    def test_transport_guest_exception_is_exact_public_commission_only(self):
        ctx=self.transport_context();pins={'commissioning/'+n:v for n,v in ctx['artifact_sha256'].items()}
        key=hashlib.sha256(json.dumps({'version':1,'operation':'commission','parameters':{}},sort_keys=True,separators=(',',':')).encode()).hexdigest()
        doc=dict(artifacts=pins,genesis_pins=ctx['genesis_pins'],requests=[dict(operation='commission',request_sha256=key)])
        self.assertTrue(b.transport_authorization(True,pins,doc,self.policy))
        for field,value in [('requests',[dict(operation='start',request_sha256=key)]),('genesis_pins',{}),('artifacts',{**pins,'vpn-ca.pem':'a'*64})]:
            wrong={**doc,field:value};self.assertFalse(b.transport_authorization(True,pins,wrong,self.policy))
        self.assertFalse(b.transport_authorization(False,pins,doc,self.policy))
        self.assertFalse(b.transport_authorization(True,{},doc,self.policy))

    def readiness_context(self):
        ctx=self.transport_context()
        (self.root/'keys').mkdir(mode=0o700)
        pins=ctx.pop('artifact_sha256')
        self.policy['validator_commissioning_files']=pins
        for name,pin in pins.items():
            # Use actual fixed public bytes with matching independent pins.
            raw=name.encode()
            if name.startswith('network/') and name[8:] in ctx['genesis_pins']:raw=name[8:].encode()
            path=self.control/'authorization/inputs/commissioning'/name
            path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw);path.chmod(0o600)
            pins[name]=hashlib.sha256(raw).hexdigest()
        self.save_policy()
        pin='9'*64
        key=hashlib.sha256(json.dumps({'version':1,'operation':'commission','parameters':{}},sort_keys=True,separators=(',',':')).encode()).hexdigest()
        pending=copy.deepcopy(self.pending);pending.update(artifacts={'commissioning-readiness.json':pin},
            requests=[{'operation':'commission','request_sha256':key}],genesis_pins=ctx['genesis_pins'])
        dispatch={'operation':'commission','request_sha256':key,'artifact_sha256':pin}
        ctx.update(artifact_sha256=pin,dispatch_sha256=hashlib.sha256(json.dumps(dispatch,sort_keys=True,separators=(',',':')).encode()).hexdigest())
        return ctx,pending,key
    def test_readiness_exact_historical_pending_proof_is_readonly_and_not_success(self):
        ctx,pending,_=self.readiness_context();before=self.snapshot()
        result=self.run_proof(pending=pending,context=ctx,readiness=True)
        self.assertEqual(result.returncode,0,result.stderr)
        value=json.loads(result.stdout)
        self.assertEqual(set(value),{'schema','challenge','pending_sha256','dispatch_sha256','parent_sha256','not_applied','mutation_performed'})
        self.assertEqual(value['schema'],'nodenetwork-readiness-not-applied-v1');self.assertTrue(value['not_applied']);self.assertFalse(value['mutation_performed'])
        self.assertEqual(self.snapshot(),before)
    def test_readiness_grant_audit_artifact_pin_partials_and_changed_inputs_refuse(self):
        ctx,pending,key=self.readiness_context()
        for relative in ('tmp/controller/grants/'+key+'.json','tmp/controller/audit.jsonl',
                         'tmp/controller/authorization/inputs/commissioning-readiness.json',
                         'tmp/controller-authorization.pending','tmp/commissioning','data','active-process',
                         'config/node.json','keys/foreign'):
            path=self.root/relative;path.parent.mkdir(parents=True,exist_ok=True)
            path.write_text(json.dumps({'operation':'commission','request_sha256':key,'time':1})+'\n' if relative.endswith('audit.jsonl') else '{}');path.chmod(0o600)
            before=self.snapshot();self.assertNotEqual(self.run_proof(pending=pending,context=ctx,readiness=True).returncode,0);self.assertEqual(self.snapshot(),before);path.unlink()
        self.policy.setdefault('authorization_files',{})['commissioning-readiness.json']='9'*64;self.save_policy()
        self.assertNotEqual(self.run_proof(pending=pending,context=ctx,readiness=True).returncode,0)
        del self.policy['authorization_files']['commissioning-readiness.json'];self.save_policy()
        path=self.control/'authorization/inputs/commissioning/config/node.json';path.write_bytes(b'changed')
        self.assertNotEqual(self.run_proof(pending=pending,context=ctx,readiness=True).returncode,0)
    def test_readiness_exact_original_document_and_dispatch_scope_required(self):
        ctx,pending,_=self.readiness_context()
        for field,value in [('dispatch_sha256','0'*64),('artifact_sha256','0'*64),('authorization',{'sha256':'0'*64,'sequence':9}),('selection',{}),('target',{}),('expires_at',1)]:
            bad=copy.deepcopy(ctx);bad[field]=value
            with self.subTest(field=field):self.assertNotEqual(self.run_proof(pending=pending,context=bad,readiness=True).returncode,0)
        for field,value in [('artifacts',{}),('sequence',11),('genesis_pins',None),('requests',[{'operation':'start','request_sha256':'0'*64}])]:
            bad=copy.deepcopy(pending);bad[field]=value
            with self.subTest(field=field):self.assertNotEqual(self.run_proof(pending=bad,context=ctx,readiness=True).returncode,0)

    def test_engine_tamper_refuses_before_any_unverified_import(self):
        path=self.control/'controller.py';path.write_text("raise RuntimeError('UNVERIFIED_ENGINE_EXECUTED')\n")
        before=self.snapshot();result=self.run_proof();self.assertNotEqual(result.returncode,0);self.assertNotIn('UNVERIFIED_ENGINE_EXECUTED',result.stderr);self.assertIn('Enrolled proof engine drift',result.stderr);self.assertEqual(self.snapshot(),before)

if __name__=='__main__':unittest.main()
