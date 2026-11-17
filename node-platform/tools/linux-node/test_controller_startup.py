"""Real isolated-process startup; unit pre-imports cannot mask the boundary."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
import tempfile
import unittest
import controller
import bootstrap

class IsolatedControllerStartupTests(unittest.TestCase):
    def run_enrolled(self,root,raw=b'{"version":1,"operation":"target","parameters":{}}',linux=False):
        program='''import importlib.util,json,sys
from pathlib import Path
root=Path(sys.argv[1]);p=root/'tmp/controller/controller.py'
s=importlib.util.spec_from_file_location('enrolled_entrypoint',p)
m=importlib.util.module_from_spec(s);sys.modules[s.name]=m;s.loader.exec_module(m)
assert 'apqe_layout' not in sys.modules and 'lifecycle' not in sys.modules
assert str(root/'tmp/controller/tools') not in sys.path
# Run actual main; only its OS-root gate is skipped for the portable fixture.
# The real current UID still governs every filesystem ownership/hash check.
original_require=m.require
def fixture_require(condition,message,code='operation_refused'):
 return original_require(True if message=='Controller requires the enrolled privileged host interface' else condition,message,code)
m.require=fixture_require
m.ROOT=root;m.Controller.__init__.__defaults__=(root,)
if sys.argv[2]=='linux':
 m.platform.system=lambda:'Linux'
 m.platform.machine=lambda:'x86_64'
sys.argv=[str(p)]
try:
 m.main()
except m.Refused as e:
 print(json.dumps({'ok':False,'error':{'code':e.code,'message':str(e)}}))
'''
        return subprocess.run([sys.executable,'-I','-B','-c',program,str(root),'linux' if linux else 'native'],
            input=raw,
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True,timeout=15)

    def fixture(self,temporary):
        root=Path(temporary).resolve()/'synergy';control=root/'tmp/controller'
        (control/'tools').mkdir(parents=True,mode=0o700)
        (control/'grants').mkdir(mode=0o700)
        for path in (root,root/'tmp',control):path.chmod(0o700)
        pins={};source=Path(controller.__file__).parent
        for name in controller.ENGINE_MODULES:
            path=control/name if name=='controller.py' else control/'tools'/name
            raw=(source/name).read_bytes();path.write_bytes(raw);path.chmod(0o600)
            pins[name]=hashlib.sha256(raw).hexdigest()
        policy={'format':'synergy-nodenetwork-host-policy-v1','root':str(root),
                'community_enrollment':False,'qualified_operations':[],
                'releases':{},'engine_files':pins}
        path=control/'policy.json';path.write_text(json.dumps(policy));path.chmod(0o600)
        return root

    def test_initial_bootstrap_pins_exact_legacy_or_guest_engine(self):
        with tempfile.TemporaryDirectory() as temporary:
            stage=Path(temporary);(stage/'tools').mkdir()
            files={}
            for name in (*bootstrap.ENGINE,'guest_lifecycle.py','unapproved.py'):
                raw=('pinned-'+name).encode();(stage/'tools'/name).write_bytes(raw)
                files['tools/'+name]=hashlib.sha256(raw).hexdigest()
            full=bootstrap.initial_engine_pins(stage,{'files':files})
            self.assertEqual(set(full),set(controller.ENGINE_MODULES))
            self.assertEqual(full['guest_lifecycle.py'],files['tools/guest_lifecycle.py'])
            self.assertNotIn('unapproved.py',full)
            del files['tools/guest_lifecycle.py']
            self.assertEqual(set(bootstrap.initial_engine_pins(stage,{'files':files})),set(bootstrap.ENGINE))

    def test_isolated_target_read_verifies_engine_before_tool_import(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=self.fixture(temporary);result=self.run_enrolled(root)
            self.assertEqual(result.stderr,b'');reply=json.loads(result.stdout)
            self.assertTrue(reply['ok'],reply)
            self.assertFalse(reply['result']['installed'])
            self.assertFalse(reply['result']['communityEnrollment'])
            self.assertEqual(reply['result']['root'],str(root))
            self.assertFalse(list(root.rglob('__pycache__')))

    def test_authorization_status_before_install_from_isolated_enrolled_entrypoint(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=self.fixture(temporary);control=root/'tmp/controller'
            path=control/'policy.json';policy=json.loads(path.read_bytes())
            selection={'release_id':'approved-master','manifest_sha256':'b'*64,'network_id':'isolated-formation','chain_id':99999,'node_name':'test-validator'}
            record={'sha256':'a'*64,'sequence':1,'expires_at':int(time.time())+60}
            policy.update(engineering_authorization=record,engineering_initial_authorization_sha256='a'*64,
                          engineering_selection=selection,validator_formation_sha256='c'*64,
                          engineering_target={'kind':'remote','host':'127.0.0.1','port':22280,'root':str(root)})
            path.write_text(json.dumps(policy))
            for pin,expiry in (('d'*64,int(time.time())+60),('e'*64,0)):
                grant=control/'grants'/(pin+'.json');grant.write_text(json.dumps({'expires_at':expiry}));grant.chmod(0o600)
            raw=b'{"version":1,"operation":"authorization_status","parameters":{}}'
            result=self.run_enrolled(root,raw,linux=True)
            self.assertEqual(result.stderr,b'');reply=json.loads(result.stdout)
            self.assertTrue(reply['ok'],reply)
            self.assertEqual(reply['result']['authorization'],record)
            self.assertEqual(reply['result']['selection'],selection)
            self.assertEqual(reply['result']['pending_grants'],['d'*64])
            self.assertFalse((root/'installation.json').exists())
            # The early pre-install read must still verify all engine hashes.
            (control/'tools/lifecycle.py').write_text("print('UNTRUSTED_TOOL_EXECUTED')")
            result=self.run_enrolled(root,raw,linux=True);reply=json.loads(result.stdout)
            self.assertFalse(reply['ok']);self.assertIn('engine bytes differ',reply['error']['message'])
            self.assertNotIn(b'UNTRUSTED_TOOL_EXECUTED',result.stdout)
            self.assertFalse(list(root.rglob('__pycache__')))

    def test_guest_channel_failure_never_emits_json_into_raw_ssh(self):
        import guest_lifecycle
        header={'guest_id':'fifth','create_request_sha256':'a'*64,'ssh_host_fingerprint':'SHA256:'+'A'*43}
        raw=guest_lifecycle.GUEST_SSH_MAGIC+json.dumps(header,sort_keys=True,separators=(',',':')).encode()+b'\n'
        with tempfile.TemporaryDirectory() as temporary:
            root=self.fixture(temporary);result=self.run_enrolled(root,raw)
            self.assertEqual(result.stdout,b'')
            self.assertEqual(result.stderr,b'Managed guest channel refused\n')
            self.assertFalse(list(root.rglob('__pycache__')))

    def test_drift_refuses_before_malicious_tool_can_execute(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=self.fixture(temporary);path=root/'tmp/controller/tools/apqe_layout.py'
            path.write_text("print('UNTRUSTED_TOOL_EXECUTED');raise RuntimeError('must not import')")
            result=self.run_enrolled(root)
            self.assertEqual(result.stderr,b'');reply=json.loads(result.stdout)
            self.assertFalse(reply['ok'])
            self.assertIn('engine bytes differ',reply['error']['message'])
            self.assertNotIn(b'UNTRUSTED_TOOL_EXECUTED',result.stdout)
            self.assertFalse(list(root.rglob('__pycache__')))

if __name__=='__main__':unittest.main()
