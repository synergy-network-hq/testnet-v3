"""Native-controller safety boundaries, without generating custody or operating hosts."""
import contextlib
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import controller as c
import synergy_linux as linux
from test_controller import ControllerTests, request

class NetworkFormationTests(unittest.TestCase):
    setUp=ControllerTests.setUp
    tearDown=ControllerTests.tearDown
    save=ControllerTests.save
    def test_input_scope_unicode_hash_and_strict_limits(self):
        p={'formation_sha256':'a'*64,'recipe_json':'{"name":"é"}', 'registrations_json':['{}']*5}
        req=request('network_formation_prepare',p)
        wire=json.dumps(req,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
        self.assertEqual(c.parse_request(wire),req)
        self.assertEqual(c.request_digest(req),hashlib.sha256(wire).hexdigest())
        for bad in [{**p,'registrations_json':['{}']*4},{**p,'recipe_json':'x'*(1024*1024+1)},{**p,'path':'/etc/shadow'}]:
            with self.assertRaises(c.Refused):c.parse_request(c.canonical(request('network_formation_prepare',bad)))
        with self.assertRaises(c.Refused):c.parse_request(c.canonical(request('network_formation_sign',{'review_sha256':'bad'})))
    def test_prepare_consumes_exact_grant_once_and_status_never_regenerates(self):
        req=request('network_formation_prepare',{'formation_sha256':'a'*64,'recipe_json':'{}','registrations_json':['{}']*5})
        pin=c.request_digest(req);self.policy['qualified_operations']=['network_formation_prepare','network_formation_sign'];self.save(self.control/'policy.json',self.policy)
        import time
        self.save(self.control/'grants'/(pin+'.json'),{'root':str(self.root),'request_sha256':pin,'expires_at':int(time.time())+60})
        selection={'formation_sha256':'a'*64,'network_id':'isolated-network','chain_id':'99999'}
        receipt={'schema':'nodenetwork-network-formation-v1','pending':True,'signed':False,'request_sha256':pin,**selection}
        calls=[]
        def native(argv,**kwargs):
            calls.append(argv[1]);
            if argv[1]=='prepare-network-formation':
                self.assertEqual(Path(argv[4]).read_bytes(),json.dumps(req,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode())
                self.assertEqual(argv[5],pin);Path(argv[6]).mkdir(mode=0o700)
            return json.dumps(receipt).encode()
        with patch.object(self.controller,'formation_context',return_value=(selection,[])),patch('lifecycle._lifecycle_lock',side_effect=lambda _:contextlib.nullcontext()),patch('lifecycle._unit_state',return_value={'ActiveState':'inactive','MainPID':'0'}),patch('lifecycle._assert_no_application_processes'),patch.object(linux,'native',side_effect=native):
            result=self.controller.network_formation(req);self.assertEqual(result,receipt)
            self.assertFalse((self.control/'grants'/(pin+'.json')).exists())
            with self.assertRaisesRegex(c.Refused,'reconciled'):self.controller.network_formation(req)
            self.assertEqual(self.controller.network_formation(request('network_formation_status')),receipt)
            with self.assertRaisesRegex(c.Refused,'changed'):self.controller.network_formation(request('network_formation_sign',{'review_sha256':'b'*64}))
        self.assertEqual(calls,['prepare-network-formation','review-network-formation','review-network-formation'])
        self.assertFalse((self.root/'tmp/network-formation-sign-request.json').exists())
    def test_native_export_bound_is_explicit_and_does_not_relax_default(self):
        with patch.object(linux.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout=b'x'*(1024*1024+1))):
            with self.assertRaisesRegex(ValueError,'bound'):linux.native(['public-tool'])
            self.assertEqual(len(linux.native(['public-tool'],maximum_stdout=2*1024*1024)),1024*1024+1)
        with patch.object(linux.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout=b'x'*(2*1024*1024+1))):
            with self.assertRaisesRegex(ValueError,'bound'):linux.native(['public-tool'],maximum_stdout=2*1024*1024)
        with self.assertRaises(ValueError):linux.native(['public-tool'],maximum_stdout=2*1024*1024+1)
