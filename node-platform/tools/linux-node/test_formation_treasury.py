"""Treasury application boundary; no keys, hosts or node processes."""
import contextlib
import json
import os
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

    def send_fixture(self):
        """Fake public DTOs qualify inventory delegation, never cryptography."""
        selection={'network_id':'new-network','chain_id':'99999','formation_sha256':'a'*64}
        (self.root/'keys').mkdir(mode=0o700)
        directory=self.root/'keys/formation-treasury';directory.mkdir(mode=0o700)
        req=fixture.request('treasury_prepare',{'formation_sha256':'a'*64,'effective_at_unix':100})
        self.save(self.root/'tmp/treasury-prepare-request.json',req)
        for name in ('request.json','treasury-public.json','treasury.enc.json','unlock'):
            self.save(directory/name,req if name=='request.json' else {})
        treasury={'schema':'nodenetwork-formation-treasury-v1','pending':True,'possession_verified':True,
                  'request_sha256':c.request_digest(req),'effective_at_unix':100,'address':'syna1public',**selection}
        sends=directory/'sends';sends.mkdir(mode=0o700)
        slot=sends/'00000000000000000000';slot.mkdir(mode=0o700)
        for name in ('request.json','prepared.json','admission.json'):self.save(slot/name,{'test':True})
        receipt={'schema':'nodenetwork-formation-treasury-send-v1','request_sha256':'b'*64,
                 'formation_sha256':'a'*64,'genesis_sha256':'c'*64,'transaction_id':'d'*64,
                 'receipt_id':'e'*128,'admission_sha256':'f'*64,'sender':'syna1public','receiver':'syna1receiver',
                 'amount_nwei':'1000000','nonce':0,'fee_nwei':'840000','state':'prepared','automatic_retry':False}
        calls=[]
        def native(argv,**kwargs):
            calls.append(argv[1:]);self.assertEqual(kwargs,{'maximum_stdout':128*1024})
            if argv[1]=='review-formation-treasury':return json.dumps(treasury).encode()
            self.assertEqual(argv[1:],['review-formation-treasury-send',directory,'0'])
            return json.dumps(receipt).encode()
        stack=contextlib.ExitStack();self.addCleanup(stack.close)
        stack.enter_context(patch.object(c.Controller,'formation_context',return_value=(selection,[])))
        stack.enter_context(patch('apqe_layout.require_frozen_tree'))
        stack.enter_context(patch('synergy_linux.native',side_effect=native))
        return directory,slot,receipt,calls

    def test_send_restart_keeps_exact_prepared_and_unknown_fence(self):
        _,slot,receipt,calls=self.send_fixture()
        prepared=conformance.approved_treasury_members(self.root)
        self.assertEqual(len(prepared),11)
        self.assertEqual(prepared,conformance.approved_treasury_members(self.root))
        self.save(slot/'dispatch-intent.json',{'test':'native-verified fence'});receipt['state']='dispatch_unknown'
        unknown=conformance.approved_treasury_members(self.root)
        self.assertEqual(unknown,prepared|{'keys/formation-treasury/sends/00000000000000000000/dispatch-intent.json'})
        self.assertEqual(unknown,conformance.approved_treasury_members(self.root))
        self.assertTrue((slot/'dispatch-intent.json').exists())
        self.assertTrue(all(call[0].startswith('review-') for call in calls))

    def test_send_partial_and_foreign_inventory_refused_before_native_send_review(self):
        _,slot,_,calls=self.send_fixture()
        for name in ('request.json','prepared.json','admission.json'):
            raw=(slot/name).read_bytes();(slot/name).unlink()
            with self.assertRaisesRegex(ValueError,'Incomplete treasury send reservation'):
                conformance.approved_treasury_members(self.root)
            self.save(slot/name,json.loads(raw))
        self.save(slot/'foreign.json',{})
        with self.assertRaisesRegex(ValueError,'Unexpected treasury send inventory'):
            conformance.approved_treasury_members(self.root)
        self.assertFalse(any(call[0]=='review-formation-treasury-send' for call in calls))

    def test_send_links_modes_size_and_nonce_aliases_refused(self):
        directory,slot,_,_=self.send_fixture()
        original=slot/'admission.json';raw=original.read_bytes()
        original.unlink();original.symlink_to(directory/'treasury.enc.json')
        with self.assertRaisesRegex(ValueError,'links differ'):conformance.approved_treasury_members(self.root)
        original.unlink();os.link(directory/'treasury.enc.json',original)
        with self.assertRaisesRegex(ValueError,'links differ'):conformance.approved_treasury_members(self.root)
        original.unlink();self.save(original,json.loads(raw));original.chmod(0o644)
        with self.assertRaisesRegex(ValueError,'permissions or links'):conformance.approved_treasury_members(self.root)
        original.chmod(0o600)
        with original.open('r+b') as stream:stream.truncate(1024*1024+1)
        with self.assertRaisesRegex(ValueError,'size'):conformance.approved_treasury_members(self.root)
        self.save(original,json.loads(raw))
        for name in ('0','18446744073709551615','0000000000000000000x'):
            other=directory/'sends'/name;other.mkdir(mode=0o700)
            with self.assertRaisesRegex(ValueError,'nonce directory'):conformance.approved_treasury_members(self.root)
            other.rmdir()
        moved=self.root/'tmp/saved-slot';slot.rename(moved);slot.symlink_to(moved,target_is_directory=True)
        with self.assertRaisesRegex(ValueError,'links differ'):conformance.approved_treasury_members(self.root)
        slot.unlink();moved.rename(slot)
        sends=directory/'sends';moved=self.root/'tmp/saved-sends';sends.rename(moved);sends.symlink_to(moved,target_is_directory=True)
        with self.assertRaisesRegex(ValueError,'links differ'):conformance.approved_treasury_members(self.root)

    def test_send_native_scope_and_unknown_state_must_match(self):
        _,slot,receipt,_=self.send_fixture()
        for key,value in [('formation_sha256','b'*64),('sender','syna1foreign'),('nonce',1),('nonce',False),
                          ('request_sha256','wrong'),('automatic_retry',True),('state','dispatch_unknown'),
                          ('admission',{}),('fee_nwei','0')]:
            old=receipt.get(key);receipt[key]=value
            with self.assertRaisesRegex(ValueError,'verification or scope'):conformance.approved_treasury_members(self.root)
            if old is None:del receipt[key]
            else:receipt[key]=old
        self.save(slot/'dispatch-intent.json',{})
        with self.assertRaisesRegex(ValueError,'verification or scope'):conformance.approved_treasury_members(self.root)

    def test_send_native_tamper_failure_preserves_all_files(self):
        _,slot,_,_=self.send_fixture()
        before={p.name:p.read_bytes() for p in slot.iterdir()}
        from synergy_linux import native as delegate
        def rejected(argv,**kwargs):
            if argv[1]=='review-formation-treasury-send':raise ValueError('Immutable treasury admission journal differs')
            return delegate(argv,**kwargs)
        with patch('synergy_linux.native',side_effect=rejected):
            with self.assertRaisesRegex(ValueError,'journal differs'):conformance.approved_treasury_members(self.root)
        self.assertEqual(before,{p.name:p.read_bytes() for p in slot.iterdir()})

    def test_send_inventory_bound_fails_closed(self):
        directory,_,_,calls=self.send_fixture()
        (directory/'sends/00000000000000000001').mkdir(mode=0o700)
        # A reduced diagnostic cap exercises the identical pre-review bound.
        # Exhaustion is not a consensus quota and never retires durable records.
        with patch.object(conformance,'TREASURY_SEND_LIMIT',1):
            with self.assertRaisesRegex(ValueError,'inventory bound'):conformance.approved_treasury_members(self.root)
        self.assertFalse(any(call[0]=='review-formation-treasury-send' for call in calls))


    def test_send_treasury_root_symlink_refused_before_inventory_or_native(self):
        directory,_,_,calls=self.send_fixture()
        moved=self.root/'tmp/foreign-treasury';directory.rename(moved)
        directory.symlink_to(moved,target_is_directory=True)
        with self.assertRaisesRegex(ValueError,'directory must be direct'):
            conformance.approved_treasury_members(self.root)
        self.assertEqual(calls,[])
