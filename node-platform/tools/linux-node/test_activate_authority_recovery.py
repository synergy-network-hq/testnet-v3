"""Lifecycle transaction tests only; native APQE/certificate tests run in Rust."""
import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import activate_authority_recovery as recovery
import lifecycle as life
from apqe_layout import PUBLIC


class ActivationTests(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        base=Path(temporary.name).resolve();self.root=base/'synergy';self.stage=base/'stage'
        self.root.mkdir(mode=0o700);self.stage.mkdir(mode=0o700)
        self.role='validator';self.network='disposable-canary';self.calls=[]
        self.initial_receipt={'role':'validator','chain_id':99999,'network_id':self.network,'package_sha256':'f'*64}
        self.old_authority=recovery.encode({'payload':{'epoch':1,'chain_id':99999,'network_id':self.network}})
        self.new_authority=recovery.encode({'payload':{'epoch':2,'chain_id':99999,'network_id':self.network}})
        self.registry={'payload':{'epoch':1,'generation':4,'authority_binding_sha256':recovery.sha(self.old_authority),
            'chain_id':99999,'network_id':self.network,'valid_from_unix':1,'expires_at_unix':9999999999,
            'validators':[{'node_address':'disposable','dial_address':'10.0.0.1:9000'}]}}
        self.next_registry=copy.deepcopy(self.registry)
        self.next_registry['payload'].update(epoch=2,generation=5,authority_binding_sha256=recovery.sha(self.new_authority))
        config={'chain_id':99999,'network_id':self.network,'genesis_path':str(self.root/'network/genesis.json'),
            'consensus':{'authority_binding':str(self.root/recovery.AUTHORITY),
                'authority_trust_key_path':str(self.root/'network/authority-root.pub')},
            'apqe_transport':{'registry_path':str(self.root/recovery.REGISTRY)}}
        self.write(self.root/recovery.RECEIPT,recovery.encode(self.initial_receipt))
        self.write(self.root/recovery.CONFIG,recovery.encode(config))
        for name in PUBLIC:self.write(self.root/'network'/name,b'original-'+name.encode())
        self.write(self.root/recovery.AUTHORITY,self.old_authority)
        self.write(self.root/recovery.REGISTRY,recovery.encode(self.registry))
        startup={'chain_id':99999,'network_id':self.network,'all_validators_ready':True,
            'public_file_sha256':{name:recovery.sha((self.root/'network'/name).read_bytes()) for name in PUBLIC}}
        self.write(self.root/recovery.START,recovery.encode(startup))
        cert={'previous_authority_binding':list(self.old_authority),'successor_authority_binding':list(self.new_authority)}
        self.write(self.stage/Path(recovery.CERT).name,recovery.encode(cert))
        self.write(self.stage/Path(recovery.REGISTRY).name,recovery.encode(self.next_registry))
        self.protected={'data/consensus/posy/sign-once.json':b'never-touch-signing-journal',
            'data/state/execution/finalized-state.json':b'never-touch-certified-state','keys/apqe/custody.json':b'never-read-custody'}
        for name,raw in self.protected.items():self.write(self.root/name,raw)
        for name,value in (('_require_operator',None),('_reject_installation_mounts',None),('_assert_no_application_processes',None)):
            p=patch.object(life,name,return_value=value);p.start();self.addCleanup(p.stop)
        p=patch.object(life,'_sealed_receipt',side_effect=lambda root:(json.loads((root/recovery.RECEIPT).read_bytes()),{}));p.start();self.addCleanup(p.stop)
        self.units={life.UNITS[0]:{'ActiveState':'inactive','MainPID':'0'},
            life.UNITS[1]:{'ActiveState':'active','MainPID':'42'}}
        p=patch.object(life,'_attributed_units',side_effect=lambda root:self.units);p.start();self.addCleanup(p.stop)
        p=patch.object(recovery,'native',side_effect=self.native);p.start();self.addCleanup(p.stop)
        self.pin=None

    def write(self,path,raw):
        path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
        path.write_bytes(raw);path.chmod(0o600)

    def native(self,args):
        args=[str(v) for v in args];self.calls.append(args)
        if args[1:3]==['authority-recovery','check']:
            raw=Path(args[4]).read_bytes()
            cert=json.loads(raw)
            return recovery.encode({'status':'quorum-certificate-verified','certificate_sha256':recovery.sha(raw),
                'successor_authority_sha256':recovery.sha(bytes(cert['successor_authority_binding'])),
                'genesis_trust_pin_preserved':True})
        if args[1:3] in (['authority-recovery','activate'],['authority-recovery','activate-observer']):
            self.write(self.root/recovery.AUTHORITY,self.new_authority)
            return recovery.encode({'status':'observer-trust-activated' if args[2]=='activate-observer' else 'activated',
                'genesis_trust_pin_preserved':True})
        return recovery.encode({'signed_authority_verified':True,'signed_genesis_verified':True})

    def plan(self):
        result=recovery.prepare(self.root,self.stage);self.pin=result['plan_sha256'];return result

    def protected_unchanged(self):
        for name,raw in self.protected.items():self.assertEqual((self.root/name).read_bytes(),raw)

    def test_plan_is_read_only_apply_and_repeat_do_not_touch_safety_state(self):
        result=self.plan();self.assertFalse(result['installed_files_changed'])
        self.assertEqual((self.root/recovery.AUTHORITY).read_bytes(),self.old_authority)
        self.assertFalse((self.root/recovery.CERT).exists())
        result=recovery.apply(self.root,self.stage,self.pin)
        self.assertTrue(result['activation_installed']);self.assertFalse(result['services_started'])
        policy=json.loads((self.root/recovery.START).read_bytes())
        self.assertEqual(set(policy['public_file_sha256']),set(PUBLIC))
        life.verify_authority_recovery_pin(self.root,json.loads((self.root/recovery.CONFIG).read_bytes()),
            json.loads((self.root/recovery.RECEIPT).read_bytes()),policy)
        calls=len([v for v in self.calls if v[1:3]==['authority-recovery','activate']])
        self.assertTrue(recovery.apply(self.root,self.stage,self.pin)['repeated'])
        self.assertEqual(calls,len([v for v in self.calls if v[1:3]==['authority-recovery','activate']]))
        self.assertFalse((self.root/recovery.INTENT).exists());self.protected_unchanged()

    def reset(self):
        p,before,_=recovery.load_plan(self.root,self.stage,self.pin)
        for name,raw in before.items():
            path=self.root/name
            if raw is None:
                if path.exists():path.unlink()
            else:self.write(path,raw)
        for name in (recovery.INTENT,recovery.COMPLETED):
            if (self.root/name).exists():(self.root/name).unlink()

    def test_interruptions_block_startup_and_resume_exact_plan(self):
        self.plan();real=life._replace_bytes
        for failing in (recovery.CERT,recovery.CONFIG,recovery.REGISTRY,recovery.START,recovery.RECEIPT,recovery.COMPLETED):
            with self.subTest(failing=failing):
                self.reset()
                def interrupt(root,path,*args):
                    if path==root/failing:raise OSError('interrupted transaction')
                    return real(root,path,*args)
                with patch.object(life,'_replace_bytes',side_effect=interrupt):
                    with self.assertRaisesRegex(OSError,'interrupted'):recovery.apply(self.root,self.stage,self.pin)
                self.assertTrue((self.root/recovery.INTENT).exists())
                with self.assertRaisesRegex(ValueError,'authority recovery'):life._start_check_locked(self.root)
                with self.assertRaisesRegex(ValueError,'lifecycle intent'):life.relay_start_check(self.root)
                self.assertTrue(recovery.apply(self.root,self.stage,self.pin)['activation_installed'])
                self.protected_unchanged()

    def test_failed_native_activation_retains_intent_without_rollback(self):
        self.plan();real=self.native
        def fail(args):
            if str(args[2])=='activate':raise ValueError('durable state mismatch')
            return real(args)
        with patch.object(recovery,'native',side_effect=fail):
            with self.assertRaisesRegex(ValueError,'durable state'):recovery.apply(self.root,self.stage,self.pin)
        self.assertTrue((self.root/recovery.INTENT).exists())
        self.assertEqual((self.root/recovery.AUTHORITY).read_bytes(),self.old_authority)
        self.assertTrue(recovery.apply(self.root,self.stage,self.pin)['activation_installed']);self.protected_unchanged()

    def test_conflicting_intent_changed_originals_and_bad_stage_fail_closed(self):
        self.plan()
        self.write(self.root/recovery.INTENT,recovery.encode({'format':recovery.FORMAT,'root':str(self.root),'plan_sha256':'0'*64}))
        with self.assertRaisesRegex(ValueError,'original exact plan'):recovery.apply(self.root,self.stage,self.pin)
        (self.root/recovery.INTENT).unlink()
        original=(self.root/'network/genesis.json').read_bytes()
        self.write(self.root/'network/genesis.json',b'foreign-genesis')
        with self.assertRaisesRegex(ValueError,'Genesis or trust root'):recovery.apply(self.root,self.stage,self.pin)
        self.write(self.root/'network/genesis.json',original)
        self.write(self.stage/recovery.staged_name('after',recovery.CERT),b'corrupt')
        with self.assertRaisesRegex(ValueError,'staged activation input pin'):recovery.apply(self.root,self.stage,self.pin)
        self.assertFalse((self.root/recovery.INTENT).exists());self.protected_unchanged()

    def test_running_node_and_failed_native_certificate_cannot_create_intent(self):
        self.plan();self.units[life.UNITS[0]]={'ActiveState':'active','MainPID':'99'}
        with self.assertRaisesRegex(ValueError,'stop attributed'):recovery.apply(self.root,self.stage,self.pin)
        self.units[life.UNITS[0]]={'ActiveState':'inactive','MainPID':'0'}
        with patch.object(recovery,'native',side_effect=ValueError('invalid quorum')):
            with self.assertRaisesRegex(ValueError,'invalid quorum'):recovery.apply(self.root,self.stage,self.pin)
        self.assertFalse((self.root/recovery.INTENT).exists());self.protected_unchanged()

    def test_gateway_uses_observer_activation_and_admission_without_startup_policy(self):
        receipt=dict(self.initial_receipt,role='rpc_gateway',gateway_commissioned=True)
        self.write(self.root/recovery.RECEIPT,recovery.encode(receipt))
        (self.root/recovery.START).unlink();self.write(self.root/recovery.RELAY,b'{}')
        self.units[life.RELAY_UNIT]={'ActiveState':'inactive','MainPID':'0'}
        base={'epoch':1,'generation':4,'authority_binding_sha256':recovery.sha(self.old_authority),
            'validator_registry_sha256':recovery.sha(recovery.encode(self.registry)),
            'gateways':[{'node_address':'service-gateway','transport_key_id':'unchanged'}]}
        new=dict(base,epoch=2,generation=5,authority_binding_sha256=recovery.sha(self.new_authority),
            validator_registry_sha256=recovery.sha(recovery.encode(self.next_registry)))
        self.write(self.root/recovery.ADMISSION,recovery.encode({'payload':base}))
        self.write(self.stage/Path(recovery.ADMISSION).name,recovery.encode({'payload':new}))
        self.plan();recovery.apply(self.root,self.stage,self.pin)
        self.assertTrue(any(v[1:3]==['authority-recovery','activate-observer'] for v in self.calls))
        self.assertFalse((self.root/recovery.START).exists());self.protected_unchanged()

    def test_observer_storage_exemption_allows_only_public_transition_namespace(self):
        import canary_rpc_relay as relay
        # Separate disposable gateway with only public trust, never validator state.
        for name in self.protected: (self.root/name).unlink()
        import shutil
        shutil.rmtree(self.root/'data')
        self.plan();recovery.apply(self.root,self.stage,self.pin)
        config=json.loads((self.root/recovery.CONFIG).read_bytes())
        receipt=json.loads((self.root/recovery.RECEIPT).read_bytes())
        proof=self.root/'data/consensus/authority-transitions/epoch-00000000000000000002.json'
        self.write(proof,b'public-certified-witness')
        self.write(proof.parent/'.synergy-writer.lock',b'public-lock')
        relay.validate_observer_transition_layout(self.root,config,receipt)
        hostile=self.root/'data/state/finalized.json';self.write(hostile,b'forbidden')
        with self.assertRaisesRegex(ValueError,'chain storage'):
            relay.validate_observer_transition_layout(self.root,config,receipt)

    def test_certificate_pin_mismatch_and_symlink_reject_startup(self):
        self.plan();recovery.apply(self.root,self.stage,self.pin)
        config=json.loads((self.root/recovery.CONFIG).read_bytes());receipt=json.loads((self.root/recovery.RECEIPT).read_bytes())
        policy=json.loads((self.root/recovery.START).read_bytes())
        policy['authority_recovery_certificate_sha256']='0'*64
        with self.assertRaisesRegex(ValueError,'separately pinned'):life.verify_authority_recovery_pin(self.root,config,receipt,policy)
        path=self.root/recovery.CERT;raw=path.read_bytes();path.unlink();other=self.stage/'alias';self.write(other,raw);path.symlink_to(other)
        with self.assertRaisesRegex(ValueError,'activation pin'):life.verify_authority_recovery_pin(self.root,config,receipt)


if __name__=='__main__':unittest.main()
