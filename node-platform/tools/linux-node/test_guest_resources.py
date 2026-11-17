"""Pinned resource and bounded-stream boundaries; no guest runtime claim."""
import copy
import base64
import ctypes
import os
import sys
from contextlib import ExitStack
from types import SimpleNamespace
import hashlib
import io
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch
import bootstrap as b
import build_package as build
import controller as c
import guest_lifecycle as g
import lifecycle
import test_guest_lifecycle as fixtures


def elf(needed=(),rpath=False):
    strings=b'\0'+b''.join(name.encode()+b'\0' for name in needed)
    entries=[(5,0x1000+512),(10,len(strings))]
    offset=1
    for name in needed:entries.append((1,offset));offset+=len(name)+1
    if rpath:entries.append((29,0))
    entries.append((0,0))
    data=bytearray(512+len(strings));data[:7]=b'\x7fELF\x02\x01\x01'
    struct.pack_into('<H',data,18,62);struct.pack_into('<Q',data,32,64);struct.pack_into('<HH',data,54,56,2)
    struct.pack_into('<IIQQQQQQ',data,64,1,4,0,0x1000,0,len(data),len(data),4096)
    struct.pack_into('<IIQQQQQQ',data,120,2,4,256,0x1100,0,len(entries)*16,len(entries)*16,8)
    for index,item in enumerate(entries):struct.pack_into('<qQ',data,256+index*16,*item)
    data[512:]=strings
    return bytes(data)


class GuestResourcesTests(unittest.TestCase):
    def source(self,root):
        files={}
        for name in g.RESOURCE_REQUIRED|{'lib/guest-tools/lib/libc.so.6'}:
            path=root/name;path.parent.mkdir(parents=True,exist_ok=True)
            path.write_bytes(elf(('libc.so.6',)) if '/bin/' in name else elf() if '/lib/' in name else b'pinned public data')
            files[name]=build.file_digest(path)
        value={'format':g.RESOURCE_FORMAT,'architecture':'x86_64','files':files}
        manifest=root/'resources.json';manifest.write_text(json.dumps(value))
        return manifest,build.file_digest(manifest),files

    def declaration(self,files):
        return {'files':dict(files),'managed_guest_resources':{'version':1,'manifest_sha256':'a'*64,
            'archive_limit_bytes':512*1024**2,'files':dict(files)}}

    def test_pinned_copy_and_drift_refusal(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve();source=root/'input';source.mkdir();output=root/'output';output.mkdir()
            manifest,pin,files=self.source(source)
            self.assertEqual(build.guest_resource_input(source,manifest,pin),files)
            build.copy_guest_resources(source,output,files)
            self.assertEqual({name:build.file_digest(output/name) for name in files},files)
            self.assertEqual((output/'lib/guest-tools/bin'/g.LOADER).stat().st_mode&0o777,0o700)
            self.assertEqual((output/'lib/guest-tools/lib/libc.so.6').stat().st_mode&0o777,0o600)
            path=source/'hosted-machines/images/os.qcow2';path.write_bytes(b'drift')
            with self.assertRaisesRegex(ValueError,'drift'):build.guest_resource_input(source,manifest,pin)
            with self.assertRaisesRegex(ValueError,'changed'):build.copy_guest_resources(source,root/'again',files)

    def test_wrong_pin_unknown_missing_and_symlink_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            source=Path(temp).resolve();manifest,pin,files=self.source(source)
            with self.assertRaisesRegex(ValueError,'pin mismatch'):build.guest_resource_input(source,manifest,'0'*64)
            for altered in ({**files,'lib/guest-tools/bin/sh':'a'*64},{k:v for k,v in files.items() if k!='lib/guest-tools/bin/'+g.LOADER}):
                with self.assertRaises(ValueError):g.resource_paths(altered)
            image=source/'hosted-machines/images/os.qcow2';image.unlink();image.symlink_to(manifest)
            with self.assertRaisesRegex(ValueError,'Regular'):build.guest_resource_input(source,manifest,pin)

    def test_elf_dependencies_must_be_contained_no_searchpath_escape(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve();manifest,pin,files=self.source(root)
            tool=root/'lib/guest-tools/bin/qemu-img'
            tool.write_bytes(elf(('libmissing.so.1',)))
            with self.assertRaisesRegex(ValueError,'missing contained'):build.verify_guest_elf_closure(root,files)
            tool.write_bytes(elf(('libc.so.6',),rpath=True))
            with self.assertRaisesRegex(ValueError,'RPATH'):build.guest_elf_needed(tool)
            tool.write_bytes(b'not executable')
            with self.assertRaisesRegex(ValueError,'ELF64'):build.guest_elf_needed(tool)

    def test_archive_cap_only_exact_guest_inventory(self):
        files={name:'a'*64 for name in g.RESOURCE_REQUIRED};value=self.declaration(files)
        self.assertEqual(b.master_archive_limit(value),512*1024**2)
        self.assertEqual(g.resource_file_pins(value),files)
        self.assertEqual(b.master_archive_limit({'files':{'bin/synergy-node':'a'*64}}),256*1024**2)
        for altered in (dict(value,managed_guest_resources=None),dict(value,files={**files,'hosted-machines/unknown':'a'*64})):
            with self.assertRaises(ValueError):b.master_archive_limit(altered)
        for cap in (True,2*1024**3):
            altered=copy.deepcopy(value);altered['managed_guest_resources']['archive_limit_bytes']=cap
            with self.assertRaises(ValueError):b.master_archive_limit(altered)

    def test_stream_copy_is_chunked_exclusive_and_hash_verified(self):
        class Bounded(io.BytesIO):
            def read(self,n=-1):
                if not 0<n<=1024*1024:raise AssertionError('Unbounded member read')
                return super().read(n)
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'image';payload=b'x'*(3*1024*1024+7)
            b.save_stream(path,Bounded(payload),len(payload),hashlib.sha256(payload).hexdigest())
            with self.assertRaises(FileExistsError):b.save_stream(path,Bounded(b'evil'),4,'0'*64)
            self.assertEqual(path.read_bytes(),payload)
            with self.assertRaisesRegex(ValueError,'Truncated'):b.save_stream(path.with_name('short'),Bounded(b'1'),3,'0'*64)
            with self.assertRaisesRegex(ValueError,'digest'):b.save_stream(path.with_name('wrong'),Bounded(b'1'),1,'0'*64)

    def test_atomic_resource_upgrade_preserves_old_bytes_on_drift(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve();source=root/'source';source.write_bytes(b'new resource'*200000)
            destination=root/'image';destination.write_bytes(b'old resource')
            with self.assertRaisesRegex(ValueError,'changed during upgrade'):
                lifecycle._replace_guest_resource(root,destination,source,'0'*64,0o600,'a'*64)
            self.assertEqual(destination.read_bytes(),b'old resource')
            self.assertEqual(set(root.iterdir()),{source,destination})
            pin=build.file_digest(source)
            lifecycle._replace_guest_resource(root,destination,source,pin,0o600,'a'*64)
            self.assertEqual(build.file_digest(destination),pin)
            self.assertEqual(destination.stat().st_mode&0o777,0o600)

    def test_active_host_exception_is_guest_policy_only(self):
        policy={'validator_identity_network':{'genesis.json':'a'*64}}
        doc={'requests':[{'operation':'guest_create','request_sha256':'b'*64}],
             'genesis_pins':policy['validator_identity_network'],'target':{'kind':'remote'}}
        self.assertTrue(b.active_guest_policy_only(True,{'managed-guest.json':b'public'},doc,policy))
        for continuation,inputs,change in [(False,{'managed-guest.json':b''},{}),
                (True,{'managed-guest.json':b'','formation-context.json':b''},{}),
                (True,{'managed-guest.json':b''},{'genesis_pins':None}),
                (True,{'managed-guest.json':b''},{'requests':[{'operation':'start'}]}),
                (True,{'managed-guest.json':b''},{'target':{'guest':{}}})]:
            self.assertFalse(b.active_guest_policy_only(continuation,inputs,{**doc,**change},policy))

    def test_atomic_active_host_policy_grant_replay_and_mismatch_refusal(self):
        case=fixtures.GuestTests();case.setUp()
        try:
            root=case.root;control=root/'tmp/controller'
            for name in ('','tools','grants','host'):(control/name).mkdir(parents=True,exist_ok=True,mode=0o700)
            pins={}
            for name in c.ENGINE_MODULES:
                path=control/name if name=='controller.py' else control/'tools'/name
                path.write_bytes(('engine-'+name).encode());path.chmod(0o600);pins[name]=hashlib.sha256(path.read_bytes()).hexdigest()
            keypath=control/'host/authorized_keys'
            keypath.write_bytes(b.host_contents(fixtures.KEY)['authorized_keys']);keypath.chmod(0o600)
            selection={'release_id':'independent-master','manifest_sha256':'b'*64,'network_id':'isolated-network','chain_id':99999,'node_name':'validator-test'}
            target={'kind':'remote','host':'127.0.0.1','port':22281,'root':str(root),'machine_id_sha256':None,'host_key':'[127.0.0.1]:22281 '+fixtures.KEY}
            genesis={name:'d'*64 for name in ('genesis.json','authority.json','authority-root.pub')}
            policy={'format':'synergy-nodenetwork-host-policy-v1','root':str(root),'community_enrollment':False,'qualified_operations':[],
                'engine_files':pins,'host_files':{'authorized_keys':hashlib.sha256(keypath.read_bytes()).hexdigest(),'sshd.conf':'0'*64,'sudoers':'0'*64},
                'releases':{'independent-master':{'manifest_sha256':'b'*64,'inventory_authenticated':True,'networks':{'isolated-network':99999}}},
                'engineering_target':target,'engineering_selection':selection,'validator_formation_sha256':'a'*64,
                'engineering_initial_authorization_sha256':'e'*64,'engineering_authorization':{'sha256':'f'*64,'sequence':1,'expires_at':999},
                'validator_identity_network':genesis}
            # This fixture exercises the real atomic controller exchange. Only
            # OS ownership, process state and the already-qualified master read
            # are supplied by adapters; no VM or authorization issuer is mocked.
            for name in ('sshd.conf','sudoers'):
                path=control/'host'/name;path.write_bytes(b'fixture public registration');path.chmod(0o600)
                policy['host_files'][name]=hashlib.sha256(path.read_bytes()).hexdigest()
            policy_path=control/'policy.json';policy_path.write_bytes(c.canonical(policy));policy_path.chmod(0o600)
            receipt={**selection,'package_sha256':'b'*64,'role':'validator'}
            (root/'installation.json').write_text('{}')
            files={'hosted-machines/images/os.qcow2':case.spec['image_sha256'],'lib/guest-tools/bios.bin':case.spec['bios_sha256'],
                **{'lib/guest-tools/bin/'+name:pin for name,pin in case.spec['tools'].items()},**case.spec['runtime_files']}
            manifest=self.declaration(files)
            payload=c.canonical(case.spec)
            request={'version':1,'operation':'guest_create','parameters':case.params};request_pin=c.request_digest(request)
            doc={'version':1,'profile':b.AUTHORIZATION_PROFILE,'target':target,**selection,'sequence':2,'expires_at':1060,
                'artifacts':{'managed-guest.json':hashlib.sha256(payload).hexdigest()},'genesis_pins':genesis,
                'requests':[{'operation':'guest_create','request_sha256':request_pin}]}
            raw=json.dumps(doc,separators=(',',':'));pin=hashlib.sha256(raw.encode()).hexdigest()
            wire=json.dumps({'authorization':raw,'artifacts':{'managed-guest.json':base64.b64encode(payload).decode()}}).encode()
            real_stat,real_lstat=Path.stat,Path.lstat
            def owned(method):
                def inspect(path,*args,**kwargs):
                    result=list(method(path,*args,**kwargs));result[4]=0;return os.stat_result(result)
                return inspect
            def exchange(_a,left,_b,right,_flags):
                left,right=Path(os.fsdecode(left)),Path(os.fsdecode(right));swap=left.with_name('exchange-fixture')
                left.rename(swap);right.rename(left);swap.rename(right);return 0
            with ExitStack() as stack:
                for obj,name,value in ((b,'ROOT',root),(b.os,'geteuid',lambda:0),(b.sys,'platform','linux'),
                    (b.os,'uname',lambda:SimpleNamespace(machine='x86_64')),(sys,'path',sys.path.copy()),
                    (Path,'stat',owned(real_stat)),(Path,'lstat',owned(real_lstat)),
                    (ctypes,'CDLL',lambda *a,**kw:SimpleNamespace(renameat2=exchange)),
                    (lifecycle,'_sealed_receipt',lambda r:(receipt,manifest))):stack.enter_context(patch.object(obj,name,value))
                stack.enter_context(patch.object(lifecycle,'_unit_state',return_value={'MainPID':'123','ActiveState':'active'}))
                stack.enter_context(patch('time.time',return_value=1000))
                for name,value in {'NATIVE_AUTHENTICATED_AUTHORIZATION_SHA256':pin,
                    'NATIVE_AUTHENTICATED_AUTHORIZATION_INITIAL_SHA256':'e'*64,
                    'NATIVE_AUTHENTICATED_AUTHORIZATION_PARENT_SHA256':'f'*64,
                    'NATIVE_AUTHENTICATED_AUTHORIZATION_FORMATION_SHA256':'a'*64}.items():stack.enter_context(patch.object(b,name,value,create=True))
                before=policy_path.read_bytes();manifest['files']['lib/guest-tools/lib/libc.so.6']='0'*64
                with self.assertRaisesRegex(ValueError,'differs'):b.stage_engineering_authorization(io.BytesIO(wire))
                self.assertEqual(policy_path.read_bytes(),before)
                manifest['files']['lib/guest-tools/lib/libc.so.6']=files['lib/guest-tools/lib/libc.so.6']
                self.assertTrue(b.stage_engineering_authorization(io.BytesIO(wire))['applied'])
                result=json.loads(policy_path.read_bytes());self.assertEqual(result['managed_guest'],case.spec)
                self.assertEqual(result['validator_identity_network'],genesis)
                c.Controller(root).authorize(request)
                self.assertTrue(b.stage_engineering_authorization(io.BytesIO(wire))['reconciled'])
                self.assertFalse((control/'grants'/(request_pin+'.json')).exists())
        finally:case.doCleanups()

    def test_resource_read_rejects_enrolled_logical_guest_scope(self):
        import synergy_linux
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve();owner=c.Controller(root)
            files={name:'a'*64 for name in g.RESOURCE_REQUIRED}
            manifest={**self.declaration(files),'release_id':'pinned-guest-master'}
            receipt={'package_sha256':'b'*64}
            request={'version':1,'operation':'guest_resources','parameters':{}}
            with patch.object(c.platform,'system',return_value='Linux'),patch.object(c.platform,'machine',return_value='x86_64'),\
                    patch.object(synergy_linux,'safe_root'),patch.object(lifecycle,'_sealed_receipt',return_value=(receipt,manifest)),\
                    patch.object(g,'operator_public_key',return_value=fixtures.KEY),\
                    patch.object(owner,'policy',return_value={'engineering_target':{'kind':'remote'}}) as policy:
                result=owner.dispatch(request)
                self.assertEqual(result['files'],files);self.assertEqual(result['operator_ssh_public_key'],fixtures.KEY)
                policy.return_value={'engineering_target':{'kind':'remote','guest':{'guest_id':'pinned-guest'}}}
                with self.assertRaisesRegex(c.Refused,'physical target'):owner.dispatch(request)

    def test_resource_read_wire_is_parameterless(self):
        request={'version':1,'operation':'guest_resources','parameters':{}}
        self.assertEqual(c.parse_request(c.canonical(request)),request)
        with self.assertRaises(c.Refused):c.parse_request(c.canonical({**request,'parameters':{'path':'/etc'}}))
        self.assertEqual(lifecycle._software_path(Path('/safe'),'hosted-machines/images/os.qcow2'),Path('/safe/hosted-machines/images/os.qcow2'))
        with self.assertRaises(ValueError):lifecycle._software_path(Path('/safe'),'hosted-machines/arbitrary')

    def test_exact_policy_pins_and_operator_and_contained_runtime_argv(self):
        case=fixtures.GuestTests();case.setUp()
        try:
            spec=case.spec
            files={'hosted-machines/images/os.qcow2':spec['image_sha256'],'lib/guest-tools/bios.bin':spec['bios_sha256'],
                **{'lib/guest-tools/bin/'+name:pin for name,pin in spec['tools'].items()},**spec['runtime_files']}
            self.assertEqual(g.validate_resource_policy(case.root,spec,files,fixtures.KEY),spec)
            with self.assertRaisesRegex(ValueError,'differs'):g.validate_resource_policy(case.root,spec,{**files,'lib/guest-tools/lib/extra.so':'a'*64},fixtures.KEY)
            with self.assertRaisesRegex(ValueError,'differs'):g.validate_resource_policy(case.root,spec,files,'wrong operator')
            argv=case.manager.argv()
            self.assertEqual(argv[:5],[str(case.root/'lib/guest-tools/bin'/g.LOADER),'--inhibit-cache','--library-path',str(case.root/'lib/guest-tools/lib'),str(case.root/'lib/guest-tools/bin/qemu-system-x86_64')])
            self.assertIn('romfile=', ' '.join(argv));self.assertIn('-L',argv)
            self.assertIn('QEMU_MODULE_DIR='+str(case.root/'lib/guest-tools/modules'),case.manager.unit().decode())
        finally:case.doCleanups()

if __name__=='__main__':unittest.main()
