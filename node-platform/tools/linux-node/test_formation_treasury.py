"""Treasury application boundary; no keys, hosts or node processes."""
import contextlib
import json
import time
import unittest
from unittest.mock import patch
import controller as c
import conformance
import test_controller as fixture


class TreasuryTests(unittest.TestCase):
    setUp=fixture.ControllerTests.setUp
    tearDown=fixture.ControllerTests.tearDown
    save=fixture.ControllerTests.save
    def test_exact_grammar_and_no_arbitrary_export(self):
        good={'formation_sha256':'a'*64,'effective_at_unix':100}
        self.assertEqual(c.parse_request(c.canonical(fixture.request('treasury_prepare',good)))['parameters'],good)
        for bad in ({**good,'path':'/etc/shadow'},{**good,'effective_at_unix':True},{**good,'effective_at_unix':0},{**good,'formation_sha256':'wrong'}):
            with self.assertRaises(c.Refused):c.parse_request(c.canonical(fixture.request('treasury_prepare',bad)))
        with self.assertRaises(c.Refused):c.parse_request(c.canonical(fixture.request('treasury_export',{'path':'private'})))

    def test_prepare_grant_once_readback_and_interrupted_no_regeneration(self):
        (self.root/'keys').mkdir(mode=0o700)
        selection={'network_id':'new-network','chain_id':'99999','formation_sha256':'a'*64}
        req=fixture.request('treasury_prepare',{'formation_sha256':'a'*64,'effective_at_unix':int(time.time())})
        key=c.request_digest(req);grant=self.control/'grants'/(key+'.json')
        self.policy['qualified_operations']=['treasury_prepare'];self.save(self.control/'policy.json',self.policy)
        self.save(grant,{'root':str(self.root),'request_sha256':key,'expires_at':int(time.time())+60})
        receipt={'schema':'nodenetwork-formation-treasury-v1','pending':True,'possession_verified':True,'address':'syna1public',
            'request_sha256':key,'effective_at_unix':req['parameters']['effective_at_unix'],'allocation_nwei':'5000000000000000',**selection}
        calls=[]
        def native(argv,**kwargs):
            calls.append(argv[1]);self.assertEqual(kwargs,{'maximum_stdout':128*1024})
            if argv[1]=='prepare-formation-treasury':
                self.assertEqual(argv[4].read_bytes(),c.canonical(req));argv[6].mkdir(mode=0o700)
            return json.dumps(receipt).encode()
        with patch.object(self.controller,'formation_context',return_value=(selection,[])),\
             patch('lifecycle._lifecycle_lock',side_effect=lambda _:contextlib.nullcontext()),\
             patch('lifecycle._unit_state',return_value={'ActiveState':'inactive','MainPID':'0'}),\
             patch('lifecycle._assert_no_application_processes'),patch('synergy_linux.native',side_effect=native):
            self.assertEqual(self.controller.treasury(fixture.request('treasury_status')),{'pending':False})
            self.assertEqual(self.controller.treasury(req),receipt);self.assertFalse(grant.exists())
            with self.assertRaisesRegex(c.Refused,'reconciled'):self.controller.treasury(req)
            self.assertEqual(self.controller.treasury(fixture.request('treasury_status')),receipt)
            receipt['request_sha256']='b'*64
            with self.assertRaisesRegex(c.Refused,'differs'):self.controller.treasury(fixture.request('treasury_status'))
        self.assertEqual(calls,['prepare-formation-treasury','review-formation-treasury','review-formation-treasury'])

    def test_conformance_complete_native_verified_inventory_only(self):
        selection={'network_id':'new-network','chain_id':'99999','formation_sha256':'a'*64}
        (self.root/'keys').mkdir(mode=0o700);directory=self.root/'keys/formation-treasury';directory.mkdir(mode=0o700)
        req=fixture.request('treasury_prepare',{'formation_sha256':'a'*64,'effective_at_unix':100})
        intent=self.root/'tmp/treasury-prepare-request.json';self.save(intent,req)
        for name in ('request.json','treasury-public.json','treasury.enc.json','unlock'):self.save(directory/name,req if name=='request.json' else {})
        result={'schema':'nodenetwork-formation-treasury-v1','pending':True,'possession_verified':True,
                'request_sha256':c.request_digest(req),'effective_at_unix':100,**selection}
        with patch.object(c.Controller,'formation_context',return_value=(selection,[])),\
             patch('apqe_layout.require_frozen_tree'),patch('synergy_linux.native',return_value=json.dumps(result).encode()):
            self.assertEqual(len(conformance.approved_treasury_members(self.root)),6)
            (directory/'unknown').write_text('no')
            with self.assertRaisesRegex(ValueError,'inventory'):conformance.approved_treasury_members(self.root)
            (directory/'unknown').unlink();(directory/'unlock').unlink()
            with self.assertRaisesRegex(ValueError,'inventory'):conformance.approved_treasury_members(self.root)
