"""Exact engineering authorization boundaries. No privileged or remote operations."""
import base64
import copy
import hashlib
import io
import json
import os
import ctypes
from contextlib import ExitStack
from types import SimpleNamespace
import lifecycle
import apqe_layout
import sys
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import bootstrap as b
import controller as c

class OperatorAuthorizationTests(unittest.TestCase):
    def document(self):
        formation=json.dumps({'network_id':'nodenetwork-formation-disposable-test','chain_id_hex':format(99999,'064x'),'formation_id':'a'*64}).encode()
        return {'version':1,'profile':b.AUTHORIZATION_PROFILE,
            'target':{'kind':'remote','host':'127.0.0.1','port':22281,'root':str(b.ROOT),'machine_id_sha256':None,'host_key':'[127.0.0.1]:22281 ssh-ed25519 '+'A'*68},
            'release_id':'independent-master','manifest_sha256':'b'*64,
            'network_id':'nodenetwork-formation-disposable-test','chain_id':99999,'node_name':'validator-test',
            'sequence':1,'expires_at':1060,'artifacts':{'formation-context.json':hashlib.sha256(formation).hexdigest()},
            'requests':[{'operation':'formation_prepare','request_sha256':c.request_digest({'version':1,'operation':'formation_prepare','parameters':{'formation_sha256':hashlib.sha256(formation).hexdigest()}})}],
            'genesis_pins':None},formation
    def encode(self,doc):
        raw=json.dumps(doc,separators=(',',':'));return raw,hashlib.sha256(raw.encode()).hexdigest()
    def test_exact_native_pin_and_target_precede_payload_processing(self):
        doc,_=self.document();raw,pin=self.encode(doc)
        self.assertEqual(b.authorization_document(raw,pin,1000),doc)
        for bad in [raw+' ',raw.replace('99999','99998'),raw.replace('22281','22282')]:
            with self.assertRaisesRegex(ValueError,'independent native approval'):b.authorization_document(bad,pin,1000)
        with self.assertRaisesRegex(ValueError,'independent native approval'):b.authorization_document(raw,'0'*64,1000)
    def test_vpn_stop_is_parameterless_exact_supported_mutation(self):
        doc,_=self.document()
        request={'version':1,'operation':'vpn_stop','parameters':{}}
        self.assertEqual(c.parse_request(c.canonical(request)),request)
        with self.assertRaises(ValueError):c.parse_request(c.canonical(dict(request,parameters={'unit':'foreign.service'})))
        doc['requests']=[{'operation':'vpn_stop','request_sha256':c.request_digest(request)}]
        raw,pin=self.encode(doc)
        self.assertEqual(b.authorization_document(raw,pin,1000),doc)

    def test_vpn_resume_is_parameterless_exact_supported_mutation(self):
        doc,_=self.document()
        request={'version':1,'operation':'vpn_resume','parameters':{}}
        self.assertEqual(c.parse_request(c.canonical(request)),request)
        with self.assertRaises(ValueError):c.parse_request(c.canonical(dict(request,parameters={'unit':'foreign.service'})))
        doc['requests']=[{'operation':'vpn_resume','request_sha256':c.request_digest(request)}]
        raw,pin=self.encode(doc)
        self.assertEqual(b.authorization_document(raw,pin,1000),doc)

    def test_schema_paths_expiry_and_scope_are_bounded(self):
        doc,_=self.document()
        for key,value in [('expires_at',1000),('expires_at',4601),('sequence',0),('chain_id',True),
                ('artifacts',{'../../keys/unlock':'a'*64}),('genesis_pins',{'genesis.json':'a'*64}),('requests',[])]:
            bad=copy.deepcopy(doc);bad[key]=value;raw,pin=self.encode(bad)
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):b.authorization_document(raw,pin,1000)
        for key,value in [('root','/opt/Synergy'),('host_key','[127.0.0.1]:22282 ssh-ed25519 '+'A'*68)]:
            bad=copy.deepcopy(doc);bad['target'][key]=value;raw,pin=self.encode(bad)
            with self.assertRaises(ValueError):b.authorization_document(raw,pin,1000)
        raw,pin=self.encode(doc);raw=raw[:-1]+',"sequence":2}'
        with self.assertRaisesRegex(ValueError,'Duplicate'):b.authorization_document(raw,hashlib.sha256(raw.encode()).hexdigest(),1000)
    def test_exact_input_bytes_and_fixed_inventory_before_writes(self):
        doc,data=self.document();encoded={'formation-context.json':base64.b64encode(data).decode()}
        self.assertEqual(b.authorization_inputs(doc,encoded),{'formation-context.json':data})
        for bad in [{},{**encoded,'keys/apqe/unlock':'AA=='},{'formation-context.json':base64.b64encode(data+b' ').decode()}, {'formation-context.json':'!'}]:
            with self.assertRaises(ValueError):b.authorization_inputs(doc,bad)
    def test_enrolled_inventory_tracks_authorized_inputs_and_denies_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve()/'synergy';control=root/'tmp/controller'
            (control/'tools').mkdir(parents=True,mode=0o700);(control/'grants').mkdir(mode=0o700)
            for p in (root,root/'tmp',control):p.chmod(0o700)
            pins={}
            for name in c.ENGINE_MODULES:
                path=control/name if name=='controller.py' else control/'tools'/name
                path.write_bytes(('engine-'+name).encode());path.chmod(0o600);pins[name]=hashlib.sha256(path.read_bytes()).hexdigest()
            inputs=control/'authorization/inputs';inputs.mkdir(parents=True,mode=0o700)
            path=inputs/'formation-context.json';path.write_bytes(b'public-formation');path.chmod(0o600)
            policy={'format':'synergy-nodenetwork-host-policy-v1','root':str(root),'community_enrollment':False,
                'qualified_operations':[],'engine_files':pins,'releases':{},'authorization_files':{'formation-context.json':hashlib.sha256(path.read_bytes()).hexdigest()}}
            (control/'policy.json').write_bytes(c.canonical(policy));(control/'policy.json').chmod(0o600)
            files,dirs=c.control_inventory(root)
            self.assertIn('tmp/controller/authorization/inputs/formation-context.json',files)
            self.assertIn('tmp/controller/authorization/inputs',dirs)
            self.assertEqual(c.Controller(root).formation_context_path(),path)
            path.write_bytes(b'altered')
            with self.assertRaisesRegex(c.Refused,'drift'):c.control_inventory(root)
    def test_atomic_owner_publication_consumption_replay_and_active_refusal(self):
        # Simulate only privilege/OS integration. Real controller files, one-use
        # grant consumption, fsync and receipt parsing run in disposable scratch.
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve()/'synergy';control=root/'tmp/controller'
            (control/'tools').mkdir(parents=True,mode=0o700);(control/'grants').mkdir(mode=0o700)
            for p in (root,root/'tmp',control):p.chmod(0o700)
            pins={}
            for name in c.ENGINE_MODULES:
                path=control/name if name=='controller.py' else control/'tools'/name
                path.write_bytes(('engine-'+name).encode());path.chmod(0o600);pins[name]=hashlib.sha256(path.read_bytes()).hexdigest()
            policy={'format':'synergy-nodenetwork-host-policy-v1','root':str(root),'community_enrollment':False,
                'qualified_operations':[],'engine_files':pins,'releases':{'independent-master':{'manifest_sha256':'b'*64,
                    'inventory_authenticated':True,'networks':{'nodenetwork-formation-disposable-test':99999}}}}
            policy_path=control/'policy.json';policy_path.write_bytes(c.canonical(policy));policy_path.chmod(0o600)
            real_stat,real_lstat=Path.stat,Path.lstat
            def owned(method):
                def inspect(path,*args,**kwargs):
                    result=list(method(path,*args,**kwargs));result[4]=0;return os.stat_result(result)
                return inspect
            def exchange(_a,left,_b,right,_flags):
                left,right=Path(os.fsdecode(left)),Path(os.fsdecode(right));swap=left.with_name('test-exchange')
                left.rename(swap);right.rename(left);swap.rename(right);return 0
            doc,data=self.document();doc['target']['root']=str(root);raw,pin=self.encode(doc)
            wire=json.dumps({'authorization':raw,'artifacts':{'formation-context.json':base64.b64encode(data).decode()}}).encode()
            with ExitStack() as stack:
                stack.enter_context(patch.object(sys,'path',sys.path.copy()))
                stack.enter_context(patch.object(b,'ROOT',root));stack.enter_context(patch.object(b.os,'geteuid',return_value=0))
                stack.enter_context(patch.object(b.sys,'platform','linux'));stack.enter_context(patch.object(b.os,'uname',return_value=SimpleNamespace(machine='x86_64')))
                stack.enter_context(patch.object(Path,'stat',owned(real_stat)));stack.enter_context(patch.object(Path,'lstat',owned(real_lstat)))
                stack.enter_context(patch.object(ctypes,'CDLL',return_value=SimpleNamespace(renameat2=exchange)))
                state=stack.enter_context(patch.object(lifecycle,'_unit_state',return_value={'MainPID':'0','ActiveState':'inactive'}))
                stack.enter_context(patch.object(lifecycle,'_assert_no_application_processes'))
                stack.enter_context(patch.object(b,'NATIVE_AUTHENTICATED_AUTHORIZATION_SHA256',pin,create=True))
                stack.enter_context(patch.object(b.time if hasattr(b,'time') else __import__('time'),'time',return_value=1000))
                previous_umask=os.umask(0o022)
                try:result=b.stage_engineering_authorization(io.BytesIO(wire))
                finally:os.umask(previous_umask)
                self.assertEqual((control/'authorization').stat().st_mode&0o777,0o700)
                self.assertTrue(result['applied']);self.assertFalse(result['reconciled'])
                key=doc['requests'][0]['request_sha256'];grant=control/'grants'/(key+'.json')
                self.assertTrue(grant.is_file());c.Controller(root).authorize({'version':1,'operation':'formation_prepare','parameters':{'formation_sha256':hashlib.sha256(data).hexdigest()}});self.assertFalse(grant.exists())
                replay=b.stage_engineering_authorization(io.BytesIO(wire))
                self.assertTrue(replay['reconciled']);self.assertFalse(replay['grants_recreated']);self.assertFalse(grant.exists())
                before=policy_path.read_bytes();doc['sequence']=2;raw2,pin2=self.encode(doc)
                nextwire=json.dumps({'authorization':raw2,'artifacts':{'formation-context.json':base64.b64encode(data).decode()}}).encode()
                state.return_value={'MainPID':'123','ActiveState':'active'}
                with patch.object(b,'NATIVE_AUTHENTICATED_AUTHORIZATION_SHA256',pin2),patch.object(b,'NATIVE_AUTHENTICATED_AUTHORIZATION_INITIAL_SHA256',pin,create=True),patch.object(b,'NATIVE_AUTHENTICATED_AUTHORIZATION_PARENT_SHA256',pin,create=True),patch.object(b,'NATIVE_AUTHENTICATED_AUTHORIZATION_FORMATION_SHA256',hashlib.sha256(data).hexdigest(),create=True):
                    with self.assertRaisesRegex(ValueError,'Stop validator'):b.stage_engineering_authorization(io.BytesIO(nextwire))
                self.assertEqual(policy_path.read_bytes(),before)
                self.assertFalse((root/'tmp/controller-authorization').exists())
                # Pure lifecycle grant publication may run while the node is
                # active; no artifact, configuration or node state is changed.
                restart={'version':1,'operation':'restart','parameters':{}}
                doc['artifacts']={};doc['requests']=[{'operation':'restart','request_sha256':c.request_digest(restart)}]
                raw2,pin2=self.encode(doc);nextwire=json.dumps({'authorization':raw2,'artifacts':{}}).encode()
                with patch.object(b,'NATIVE_AUTHENTICATED_AUTHORIZATION_SHA256',pin2),patch.object(b,'NATIVE_AUTHENTICATED_AUTHORIZATION_INITIAL_SHA256',pin,create=True),patch.object(b,'NATIVE_AUTHENTICATED_AUTHORIZATION_PARENT_SHA256',pin,create=True),patch.object(b,'NATIVE_AUTHENTICATED_AUTHORIZATION_FORMATION_SHA256',hashlib.sha256(data).hexdigest(),create=True):
                    result=b.stage_engineering_authorization(io.BytesIO(nextwire));self.assertEqual(result['sequence'],2)
                    c.Controller(root).authorize(restart)
                    self.assertTrue(b.stage_engineering_authorization(io.BytesIO(nextwire))['reconciled'])
                    self.assertFalse((control/'grants'/(c.request_digest(restart)+'.json')).exists())
                    stale=dict(doc,sequence=3);raw3,pin3=self.encode(stale)
                    with patch.object(b,'NATIVE_AUTHENTICATED_AUTHORIZATION_SHA256',pin3):
                        with self.assertRaisesRegex(ValueError,'current receipt'):b.stage_engineering_authorization(io.BytesIO(json.dumps({'authorization':raw3,'artifacts':{}}).encode()))
                # Repeated lifecycle action is a new, explicitly reviewed sequence,
                # unlike replaying the already consumed authorization document.
                doc['sequence']=3;raw3,pin3=self.encode(doc);wire3=json.dumps({'authorization':raw3,'artifacts':{}}).encode()
                real_remove=b.shutil.rmtree
                with patch.object(b,'NATIVE_AUTHENTICATED_AUTHORIZATION_SHA256',pin3),patch.object(b,'NATIVE_AUTHENTICATED_AUTHORIZATION_INITIAL_SHA256',pin,create=True),patch.object(b,'NATIVE_AUTHENTICATED_AUTHORIZATION_PARENT_SHA256',pin2,create=True),patch.object(b,'NATIVE_AUTHENTICATED_AUTHORIZATION_FORMATION_SHA256',hashlib.sha256(data).hexdigest(),create=True):
                    with patch.object(b.shutil,'rmtree',side_effect=OSError('interrupted predecessor cleanup')):
                        with self.assertRaises(OSError):b.stage_engineering_authorization(io.BytesIO(wire3))
                    self.assertTrue((root/'tmp/controller-authorization').exists())
                    self.assertTrue(b.stage_engineering_authorization(io.BytesIO(wire3))['reconciled'])
                    self.assertFalse((root/'tmp/controller-authorization').exists())
                    c.Controller(root).authorize(restart)
                # An expired unconsumed grant has never authorized dispatch. It
                # can be retired only in the atomic next policy exchange.
                doc['sequence']=4;doc['expires_at']=1001;raw4,pin4=self.encode(doc)
                with patch.object(b,'NATIVE_AUTHENTICATED_AUTHORIZATION_SHA256',pin4),patch.object(b,'NATIVE_AUTHENTICATED_AUTHORIZATION_INITIAL_SHA256',pin,create=True),patch.object(b,'NATIVE_AUTHENTICATED_AUTHORIZATION_PARENT_SHA256',pin3,create=True),patch.object(b,'NATIVE_AUTHENTICATED_AUTHORIZATION_FORMATION_SHA256',hashlib.sha256(data).hexdigest(),create=True):
                    b.stage_engineering_authorization(io.BytesIO(json.dumps({'authorization':raw4,'artifacts':{}}).encode()))
                doc['sequence']=5;doc['expires_at']=1100;raw5,pin5=self.encode(doc)
                with patch.object(b,'NATIVE_AUTHENTICATED_AUTHORIZATION_SHA256',pin5),patch.object(b,'NATIVE_AUTHENTICATED_AUTHORIZATION_INITIAL_SHA256',pin,create=True),patch.object(b,'NATIVE_AUTHENTICATED_AUTHORIZATION_PARENT_SHA256',pin4,create=True),patch.object(b,'NATIVE_AUTHENTICATED_AUTHORIZATION_FORMATION_SHA256',hashlib.sha256(data).hexdigest(),create=True),patch('time.time',return_value=1002):
                    self.assertEqual(b.stage_engineering_authorization(io.BytesIO(json.dumps({'authorization':raw5,'artifacts':{}}).encode()))['sequence'],5)
                    c.Controller(root).authorize(restart)

    def test_transport_continuation_routes_only_exact_public_inventory_to_guest_attribution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve()/'synergy';control=root/'tmp/controller'
            (control/'tools').mkdir(parents=True);(control/'grants').mkdir()
            for path in (root,root/'tmp',control):path.chmod(0o700)
            pins={}
            for name in c.ENGINE_MODULES:
                path=control/name if name=='controller.py' else control/'tools'/name
                path.write_bytes(('engine-'+name).encode());path.chmod(0o600);pins[name]=hashlib.sha256(path.read_bytes()).hexdigest()
            doc,data=self.document();doc['target']['root']=str(root);first_raw,first_pin=self.encode(doc)
            policy={'format':'synergy-nodenetwork-host-policy-v1','root':str(root),'community_enrollment':False,'qualified_operations':[],
                'engine_files':pins,'releases':{'independent-master':{'manifest_sha256':'b'*64,'inventory_authenticated':True,'networks':{doc['network_id']:doc['chain_id']}}}}
            policy_path=control/'policy.json';policy_path.write_bytes(c.canonical(policy));policy_path.chmod(0o600)
            real_stat,real_lstat=Path.stat,Path.lstat
            def owned(method):
                def inspect(path,*args,**kwargs):
                    result=list(method(path,*args,**kwargs));result[4]=0;return os.stat_result(result)
                return inspect
            def exchange(_a,left,_b,right,_flags):
                left,right=Path(os.fsdecode(left)),Path(os.fsdecode(right));swap=left.with_name('test-exchange')
                left.rename(swap);right.rename(left);swap.rename(right);return 0
            with ExitStack() as stack:
                for owner,name,value in [(b,'ROOT',root),(b.os,'geteuid',lambda:0),(b.sys,'platform','linux'),(b.os,'uname',lambda:SimpleNamespace(machine='x86_64')),(Path,'stat',owned(real_stat)),(Path,'lstat',owned(real_lstat)),(ctypes,'CDLL',lambda *a,**k:SimpleNamespace(renameat2=exchange)),(lifecycle,'_unit_state',lambda _:dict(MainPID='0',ActiveState='inactive'))]:stack.enter_context(patch.object(owner,name,value))
                stack.enter_context(patch.object(sys,'path',sys.path.copy()));stack.enter_context(patch('time.time',return_value=1000))
                guard=stack.enter_context(patch.object(lifecycle,'_assert_no_application_processes'))
                stack.enter_context(patch.object(b,'NATIVE_AUTHENTICATED_AUTHORIZATION_SHA256',first_pin,create=True))
                b.stage_engineering_authorization(io.BytesIO(json.dumps(dict(authorization=first_raw,artifacts={'formation-context.json':base64.b64encode(data).decode()})).encode()))
                c.Controller(root).authorize(dict(version=1,operation='formation_prepare',parameters={'formation_sha256':hashlib.sha256(data).hexdigest()}))
                contents={n:b'{}' for n in b.AUTHORIZATION_FILES if n.startswith('commissioning/')}
                genesis={n:hashlib.sha256(b'{}').hexdigest() for n in ('genesis.json','authority.json','authority-root.pub')}
                policy=json.loads(policy_path.read_bytes());policy['validator_identity_network']=genesis;policy_path.write_bytes(c.canonical(policy))
                doc.update(sequence=2,artifacts={n:hashlib.sha256(v).hexdigest() for n,v in contents.items()},genesis_pins=genesis,
                    requests=[dict(operation='commission',request_sha256=c.request_digest(dict(version=1,operation='commission',parameters={})))])
                guard.side_effect=ValueError('unattributed QEMU')
                attributed=stack.enter_context(patch.object(b,'guest_management_quiescence'))
                raw,pin=self.encode(doc)
                for name,value in [('NATIVE_AUTHENTICATED_AUTHORIZATION_SHA256',pin),('NATIVE_AUTHENTICATED_AUTHORIZATION_INITIAL_SHA256',first_pin),('NATIVE_AUTHENTICATED_AUTHORIZATION_PARENT_SHA256',first_pin),('NATIVE_AUTHENTICATED_AUTHORIZATION_FORMATION_SHA256',hashlib.sha256(data).hexdigest())]:stack.enter_context(patch.object(b,name,value,create=True))
                encoded={n:base64.b64encode(v).decode() for n,v in contents.items()}
                before=policy_path.read_bytes();bad=copy.deepcopy(doc);bad['requests'][0]['operation']='start';bad_raw,bad_pin=self.encode(bad)
                with patch.object(b,'NATIVE_AUTHENTICATED_AUTHORIZATION_SHA256',bad_pin):
                    with self.assertRaisesRegex(ValueError,'unattributed QEMU'):b.stage_engineering_authorization(io.BytesIO(json.dumps(dict(authorization=bad_raw,artifacts=encoded)).encode()))
                self.assertEqual(policy_path.read_bytes(),before);self.assertFalse(attributed.called)
                result=b.stage_engineering_authorization(io.BytesIO(json.dumps(dict(authorization=raw,artifacts=encoded)).encode()))
                self.assertTrue(result['applied']);attributed.assert_called_once()
                for name,content in contents.items():self.assertEqual((control/'authorization/inputs'/name).read_bytes(),content)

    def test_no_native_approval_never_creates_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)/'not-created'
            with patch.object(b,'ROOT',root),patch.object(b.os,'geteuid',return_value=0),patch.object(b.sys,'platform','linux'),patch.object(b.os,'uname') as uname:
                uname.return_value.machine='x86_64'
                with self.assertRaisesRegex(ValueError,'No independent native authorization'):
                    b.stage_engineering_authorization(io.BytesIO(b'{"authorization":"{}","artifacts":{}}'))
            self.assertFalse(root.exists())

if __name__=='__main__':unittest.main()
