"""Operational evidence tests; no peers, chain processes or authority fixtures."""
import base64
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import apqe_layout as layout
import controller
import lifecycle
from test_lifecycle import save


def pin(value):return hashlib.sha256(value.encode()).hexdigest()

def observations():
    roster=['synv1'+str(n) for n in range(5)]
    ips={a:'100.97.0.'+str(n+1) for n,a in enumerate(roster)}
    public={name:pin(name) for name in layout.PUBLIC}
    values=[]
    for n,address in enumerate(roster):
        own={'account_id':'account','peer_id':'peer'+str(n),'ip':ips[address],
            'wireguard_public_key':base64.b64encode(bytes([n+1])*32).decode(),
            'enrollment_sha256':pin('vpn'+address),'server_binding_sha256':pin('binding'+address)}
        values.append({'schema':'nodenetwork-commissioning-observation-v1','observed_at_unix':1000,
            'target':{'kind':'remote','host':'host'+str(n),'port':22,'root':'/opt/synergy','host_key':'ssh-ed25519 test'+str(n),'machine_id_sha256':None},
            'manifest_sha256':pin('master'),'provider_report_sha256':pin('provider'),'vpn_provider_sha256':pin('vpn-provider'),
            'network_id':'fresh','chain_id':'99999','formation_sha256':pin('formation'),'address':address,'enrollment_sha256':pin(address),
            'public_file_sha256':public.copy(),'commissioning_file_sha256':{**{'network/'+k:v for k,v in public.items()},
                'config/node.json':pin('config'+address),'config/start-authorized.json':pin('draft'+address)},
            'validator_addresses':roster.copy(),'registry_peer_ips':ips.copy(),'vpn_binding':own,'peers':{}})
    for value in values:
        value['peers']={other['address']:{'ip':other['vpn_binding']['ip'],'wireguard_public_key':other['vpn_binding']['wireguard_public_key'],
            'interface':'wt0','reachable':True} for other in values if other is not value}
    return {'schema':'nodenetwork-commissioning-readiness-v1','observations':values}


class ReadinessTests(unittest.TestCase):
    def setUp(self):
        self.value=observations();self.local=copy.deepcopy(self.value['observations'][0])
    def validate(self,value=None,now=1000):return layout.validate_commissioning_readiness(value or self.value,self.local,now)
    def test_exact_five_twenty_edges_and_freshness_boundaries(self):
        self.assertTrue(self.validate());self.assertTrue(self.validate(now=1300));self.assertTrue(self.validate(now=970))
        for now in (1301,969):
            with self.assertRaisesRegex(ValueError,'expired'):self.validate(now=now)
    def test_each_shared_context_pin_and_unknown_field_rejected(self):
        for field in ('manifest_sha256','provider_report_sha256','vpn_provider_sha256','formation_sha256','network_id','chain_id'):
            with self.subTest(field=field):
                value=copy.deepcopy(self.value);value['observations'][1][field]='wrong'
                with self.assertRaises(ValueError):self.validate(value)
        value=copy.deepcopy(self.value);value['observations'][1]['trust_me']=True
        with self.assertRaises(ValueError):self.validate(value)
    def test_roster_order_missing_member_duplicate_target_and_custody_rejected(self):
        mutations=[lambda o:o.pop(),lambda o:o.reverse(),lambda o:o[1].update(target=o[0]['target']),
            lambda o:o[1].update(enrollment_sha256=o[0]['enrollment_sha256'])]
        for mutate in mutations:
            value=copy.deepcopy(self.value);mutate(value['observations'])
            with self.assertRaises(ValueError):self.validate(value)
    def test_all_directed_edges_identity_and_reachability_required(self):
        for field,bad in [('wireguard_public_key',base64.b64encode(b'x'*32).decode()),('ip','100.97.0.99'),('interface','eth0'),('reachable',False),('reachable',1)]:
            value=copy.deepcopy(self.value);value['observations'][1]['peers']['synv12'][field]=bad
            with self.assertRaisesRegex(ValueError,'Directed'):self.validate(value)
        value=copy.deepcopy(self.value);del value['observations'][1]['peers']['synv12']
        with self.assertRaisesRegex(ValueError,'directed'):self.validate(value)
    def test_local_change_pin_substitution_vpn_duplicates_and_forged_guest_rejected(self):
        mutations=[lambda o:o[0]['target'].update(host='changed'),
            lambda o:o[1]['commissioning_file_sha256'].update({'network/genesis.json':pin('substitute')}),
            lambda o:o[1]['vpn_binding'].update(account_id='other-account'),
            lambda o:o[1]['vpn_binding'].update(peer_id=o[0]['vpn_binding']['peer_id']),
            lambda o:o[1]['target'].update(guest={'guest_id':'g','create_request_sha256':pin('request'),'ssh_host_public_key':'bad','ssh_host_fingerprint':'wrong'})]
        for mutate in mutations:
            value=copy.deepcopy(self.value);mutate(value['observations'])
            with self.assertRaises(ValueError):self.validate(value)


class ObservationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name).resolve()/'synergy';self.root.mkdir(mode=0o700)
        (self.root/'tmp').mkdir(mode=0o700)
        self.c=controller.Controller(self.root);self.value=observations()['observations'][0]
        self.provider={'version':1,'profile':'nodenetwork-debug-vpn-provider-v1','account_id':'account'}
        save(self.root/'tmp/controller/authorization/inputs/vpn-provider.json',self.provider)
        save(self.root/'tmp/pending-validator-custody/bundle/enrollment-request.json',{'payload':{'identity':{'address':'synv10'}}})
        enrollment=layout.digest(self.root/'tmp/pending-validator-custody/bundle/enrollment-request.json')
        self.registry={'payload':{'validators':[{'node_address':a,'revoked':False,'dial_address':ip+':5622','enrollment_sha256':enrollment if a=='synv10' else pin(a)} for a,ip in self.value['registry_peer_ips'].items()]}}
        self.config={'network_id':'fresh','chain_id':99999,'node_name':'node0','aegis_provider':{'authenticated_report_sha256':pin('provider')}}
        self.contents={name:(b'{}',pin(name)) for name in layout.INPUTS}
        self.contents['network/authority.json']=(json.dumps({'payload':{'validators':[{'record':{'validator_id':a,'frozen_voting_weight':100,'status':'active'}} for a in self.value['validator_addresses']]}}).encode(),pin('authority'))
        self.contents.update({'config/node.json':(json.dumps(self.config).encode(),pin('config')),
            'keys/apqe/validator.pub.json':(b'{"node_address":"synv10"}',pin('identity')),
            'network/transport-registry.json':(json.dumps(self.registry).encode(),pin('registry')),
            'keys/apqe/enrollment.json':((self.root/'tmp/pending-validator-custody/bundle/enrollment-request.json').read_bytes(),enrollment)})
        self.policy={'validator_commissioning_files':self.value['commissioning_file_sha256'],
            'authorization_files':{'vpn-provider.json':layout.digest(self.root/'tmp/controller/authorization/inputs/vpn-provider.json')},'engineering_target':self.value['target']}
        self.vpn={'connected':True,'server_bound':True,'server_binding':self.value['vpn_binding'],
            'enrollment_sha256':pin('enroll'),'server_binding_sha256':pin('binding')}
        self.live={'management':{'connected':True},'signal':{'connected':True},'publicKey':self.value['vpn_binding']['wireguard_public_key'],'netbirdIp':'100.97.0.1/16',
            'peers':{'details':[{'netbirdIp':v['ip']+'/16','publicKey':v['wireguard_public_key'],'status':'Connected'} for v in self.value['peers'].values()]}}
    def tearDown(self):self.temp.cleanup()
    def run_observation(self,route='wt0',commissioned=False,valid_custody=True,online=None):
        if commissioned:(self.root/'data').mkdir(exist_ok=True)
        def verifier(root,stage,package,**kw):
            self.assertEqual((stage/'config/node.json').read_bytes(),self.contents['config/node.json'][0])
            self.assertEqual(kw,{'require_readiness':commissioned})
            return {}
        self.probes=[]
        def native(args,**kwargs):
            if str(args[0]).endswith('synergy-keytool'):
                self.assertEqual(args[1],'verify-validator-custody');directory=args[4]
                self.assertEqual((directory/'bundle/enrollment-request.json').read_bytes(),self.contents['keys/apqe/enrollment.json'][0])
                return json.dumps({'possession_verified':valid_custody,'address':'synv10','genesis_sha256':args[3],'chain_id_hex':args[2]}).encode()
            if args[0]=='ip':return json.dumps([{'dev':route}]).encode()
            self.assertEqual(args[:-1],['ping','-n','-I','wt0','-c','3','-W','2']);self.probes.append(args[-1]);return b''
        with patch.object(lifecycle,'_sealed_receipt',return_value=({'role':'validator','package_sha256':pin('master'),**{k:self.config[k] for k in ('network_id','chain_id','node_name')}},{})),\
             patch.object(lifecycle,'_unit_state',return_value={'MainPID':'0','ActiveState':'inactive'}),\
             patch.object(lifecycle,'_validate_commissioning_native',side_effect=verifier),\
             patch.object(self.c,'policy',return_value=self.policy),patch.object(self.c,'require_bound_validator_vpn'),\
             patch.object(self.c,'genesis_binding',return_value={'bound':True}) as binding,patch.object(self.c,'vpn_status',return_value=self.vpn),\
             patch.object(self.c,'formation_context',return_value=({'formation_sha256':pin('formation')},[])),\
             patch.object(layout,'formation_stage_contents',return_value=self.contents),patch.object(self.c,'commissioned_observation_contents',return_value=self.contents),patch('vpn.status',return_value=self.live),\
             patch('synergy_linux.native',side_effect=native):
            value=self.c.commissioning_observation(online_addresses=online)
            if commissioned:binding.assert_not_called()
            else:binding.assert_called_once_with(locked=True)
            return value
    def test_controlled_observation_binds_exact_installed_network_and_formation(self):
        self.policy['validator_formation_sha256']=pin('formation')
        self.provider.update(profile='nodenetwork-controlled-canary-v1',network_binding={
            'network_id':'fresh','chain_id':99999,'formation_sha256':pin('formation')})
        path=self.root/'tmp/controller/authorization/inputs/vpn-provider.json'
        save(path,self.provider);self.policy['authorization_files']['vpn-provider.json']=layout.digest(path)
        self.assertEqual(self.run_observation()['network_id'],'fresh')
        for field,value in [('network_id','wrong'),('chain_id',99998),('formation_sha256',pin('other'))]:
            original=self.provider['network_binding'][field];self.provider['network_binding'][field]=value
            save(path,self.provider);self.policy['authorization_files']['vpn-provider.json']=layout.digest(path)
            with self.assertRaisesRegex(ValueError,'Controlled Canary network'):self.run_observation()
            self.provider['network_binding'][field]=original

    def test_revoked_signed_member_refuses_before_any_probe(self):
        self.registry['payload']['validators'][1]['revoked']=True
        self.contents['network/transport-registry.json']=(json.dumps(self.registry).encode(),pin('registry'))
        with self.assertRaisesRegex(ValueError,'Signed transport roster'):self.run_observation()
        self.assertEqual(self.probes,[])

    def test_actual_native_staging_bytes_and_twenty_edge_contribution(self):
        value=self.run_observation();self.assertEqual(value['peers'],self.value['peers']);self.assertEqual(value['chain_id'],'99999')
        self.assertFalse(list((self.root/'tmp').glob('commission-observe-*')))
    def test_route_or_carrier_identity_failure_cleans_temporary_stage(self):
        with self.assertRaisesRegex(ValueError,'wt0'):self.run_observation('eth0')
        self.live['publicKey']=base64.b64encode(b'wrong-key-material-32-bytes!!xxxx').decode()
        with self.assertRaisesRegex(ValueError,'Live VPN'):self.run_observation()
        self.assertFalse(list((self.root/'tmp').glob('commission-observe-*')))
    def test_commissioned_observation_verifies_native_installed_custody_without_pending(self):
        self.assertEqual(self.run_observation(commissioned=True)['peers'],self.value['peers'])
        with self.assertRaisesRegex(ValueError,'custody possession'):
            self.run_observation(commissioned=True,valid_custody=False)
        self.assertFalse(list((self.root/'tmp').glob('commission-observe-*')))
    def test_installed_observation_content_binds_exact_draft_and_rejects_drift(self):
        artifact=controller.canonical(observations())
        save(self.c.control/'authorization/inputs'/layout.READINESS_FILE,artifact)
        pins={};readiness=hashlib.sha256(artifact).hexdigest();self.policy['authorization_files'][layout.READINESS_FILE]=readiness
        for name,(raw,_) in self.contents.items():
            if name=='config/start-authorized.json':raw=controller.canonical({'all_validators_ready':False,'all_pairs_vpn_verified':False})
            if name in layout.FORMATION_PUBLIC_INPUTS:
                save(self.c.control/'authorization/inputs/commissioning'/name,raw);pins[name]=hashlib.sha256(raw).hexdigest()
            if name=='config/start-authorized.json':raw=controller.canonical({'all_validators_ready':True,'all_pairs_vpn_verified':True,'commissioning_readiness_sha256':readiness})
            save(self.root/name,raw)
        import shutil
        shutil.rmtree(self.root/'tmp/pending-validator-custody')
        with patch.object(self.c,'policy',return_value=self.policy):
            self.assertEqual(set(self.c.commissioned_observation_contents(pins)),layout.INPUTS)
            original=(self.root/'config/start-authorized.json').read_bytes()
            save(self.root/'config/start-authorized.json',{'all_validators_ready':True,'all_pairs_vpn_verified':True,'commissioning_readiness_sha256':'f'*64})
            with self.assertRaisesRegex(ValueError,'policy changed'):self.c.commissioned_observation_contents(pins)
            save(self.root/'config/start-authorized.json',original)
            save(self.root/'network/genesis.json',b'tampered')
            with self.assertRaisesRegex(ValueError,'input changed'):self.c.commissioned_observation_contents(pins)


class ReadinessAuthorizationTests(unittest.TestCase):
    def test_fixed_artifact_only_exact_commission_grant(self):
        import bootstrap
        raw=controller.canonical(observations());encoded=base64.b64encode(raw).decode()
        doc={'artifacts':{layout.READINESS_FILE:hashlib.sha256(raw).hexdigest()},
             'requests':[{'operation':'commission','request_sha256':controller.request_digest({'version':1,'operation':'commission','parameters':{}})}]}
        self.assertEqual(bootstrap.authorization_inputs(doc,{layout.READINESS_FILE:encoded})[layout.READINESS_FILE],raw)
        for operation in ('start','restart','install'):
            changed=copy.deepcopy(doc);changed['requests'][0]['operation']=operation
            with self.assertRaisesRegex(ValueError,'one exact commissioning'):bootstrap.authorization_inputs(changed,{layout.READINESS_FILE:encoded})
        changed=copy.deepcopy(doc);changed['requests'][0]['request_sha256']='f'*64
        with self.assertRaises(ValueError):bootstrap.authorization_inputs(changed,{layout.READINESS_FILE:encoded})

    def test_locked_revalidation_precedes_stage_and_grant(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve()/'synergy';root.mkdir();(root/'tmp/pre-genesis-validator').mkdir(parents=True)
            for name in ('keys','config','network'):(root/name).mkdir(mode=0o700)
            authorize=unittest.mock.Mock()
            with patch.object(lifecycle,'_sealed_receipt',return_value=({},{})), \
                 patch.object(controller.Controller,'commissioning_readiness',side_effect=ValueError('expired')) as readiness, \
                 patch.object(layout,'assemble_formation_stage') as assemble:
                with self.assertRaisesRegex(ValueError,'expired'):
                    lifecycle._commission_locked(root,root/'tmp/commissioning',{},None,'a'*64,authorize)
                readiness.assert_called_once_with(locked=True);assemble.assert_not_called();authorize.assert_not_called()

class ReadinessRefreshTests(unittest.TestCase):
    def setUp(self):
        import bootstrap
        self.b=bootstrap;self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve()/'synergy';self.root.mkdir(mode=0o700)
        for name in ('config','network','keys'):(self.root/name).mkdir(mode=0o700)
        self.c=controller.Controller(self.root)
        self.key=controller.request_digest({'version':1,'operation':'commission','parameters':{}})
        self.old=controller.canonical(observations());fresh=observations()
        for observation in fresh['observations']:observation['observed_at_unix']=1400
        self.fresh=controller.canonical(fresh)
        self.path=self.root/'tmp/controller/authorization/inputs'/layout.READINESS_FILE;save(self.path,self.old)
        self.selection={'release_id':'master','manifest_sha256':pin('master'),'network_id':'fresh','chain_id':99999,'node_name':'node'}
        self.policy={'authorization_files':{layout.READINESS_FILE:hashlib.sha256(self.old).hexdigest()},
            'engineering_target':observations()['observations'][0]['target'],'engineering_selection':self.selection,
            'validator_identity_network':{name:pin(name) for name in ('genesis.json','authority.json','authority-root.pub')},
            'engineering_authorization':{'sha256':pin('old approval'),'sequence':1,'expires_at':1300}}
        self.doc={**self.selection,'target':self.policy['engineering_target'],'genesis_pins':self.policy['validator_identity_network'],
            'requests':[{'operation':'commission','request_sha256':self.key}]}
        self.policy['validator_commissioning_files']={}
        for name in layout.FORMATION_PUBLIC_INPUTS:
            raw=name.encode();save(self.c.control/'authorization/inputs/commissioning'/name,raw)
            self.policy['validator_commissioning_files'][name]=hashlib.sha256(raw).hexdigest()
        self.grant=self.c.control/'grants'/(self.key+'.json')
        save(self.grant,{'root':str(self.root),'operation':'commission','request_sha256':self.key,'expires_at':1300,
            'authorization_sha256':self.policy['engineering_authorization']['sha256'],'authorization_sequence':1})
    def refresh(self,**kw):
        return self.b.readiness_refresh_allowed(self.root,kw.get('policy',self.policy),kw.get('doc',self.doc),
            kw.get('inputs',{layout.READINESS_FILE:self.fresh}),kw.get('continuation',True),kw.get('consumed',set()))
    def test_expired_review_can_be_recollected_without_mutating_original(self):
        with self.assertRaisesRegex(ValueError,'expired'):
            layout.validate_commissioning_readiness(json.loads(self.old),observations()['observations'][0],1400)
        self.assertTrue(self.refresh());self.assertEqual(self.path.read_bytes(),self.old);self.assertTrue(self.grant.exists())
        current=json.loads(self.fresh);self.assertTrue(layout.validate_commissioning_readiness(current,current['observations'][0],1400))
    def test_consumed_missing_changed_grant_foreign_scope_and_state_refuse(self):
        for kwargs in ({'continuation':False},{'consumed':{self.key}},
            {'inputs':{layout.READINESS_FILE:self.fresh,'formation-context.json':b'{}'}}):
            with self.assertRaises(ValueError):self.refresh(**kwargs)
        for field in ('target','manifest_sha256','genesis_pins'):
            doc=copy.deepcopy(self.doc);doc[field]={} if isinstance(doc[field],dict) else 'f'*64
            with self.assertRaises(ValueError):self.refresh(doc=doc)
        original=self.grant.read_bytes();self.grant.unlink()
        with self.assertRaises(OSError):self.refresh()
        save(self.grant,b'{}')
        with self.assertRaises(ValueError):self.refresh()
        save(self.grant,original)
        for relative in ('tmp/commissioning','data','config/start-authorized.json','evidence/upgrade-intent.json','tmp/commission-prepare-interrupted'):
            path=self.root/relative;save(path,b'partial')
            with self.assertRaisesRegex(ValueError,'published or uncertain'):self.refresh()
            path.unlink()
        self.assertEqual(self.path.read_bytes(),self.old);self.assertEqual(self.grant.read_bytes(),original)
    def test_first_readiness_augments_the_same_live_unused_grant(self):
        self.path.unlink();del self.policy['authorization_files'][layout.READINESS_FILE]
        self.policy['engineering_authorization']['expires_at']=1800
        grant=json.loads(self.grant.read_bytes());grant['expires_at']=1800;save(self.grant,grant)
        self.assertTrue(self.refresh())
        self.assertFalse(self.path.exists());self.assertTrue(self.grant.exists())
        changed=self.c.control/'authorization/inputs/commissioning/config/node.json'
        save(changed,b'changed')
        with self.assertRaisesRegex(ValueError,'commissioning input changed'):self.refresh()

    def test_first_readiness_after_real_consumed_upgrade_needs_no_retired_transport_grant(self):
        # Transport approved the immutable eight public inputs and commission{}.
        self.path.unlink();del self.policy['authorization_files'][layout.READINESS_FILE]
        self.grant.unlink() # General continuation retired that expired transport grant.
        previous=copy.deepcopy(self.selection)
        selected={**previous,'release_id':'new-master','manifest_sha256':pin('new-master')}
        self.policy['engineering_authorization']={'sha256':pin('upgrade approval'),'sequence':14,'expires_at':1800}
        self.policy['qualified_operations']=['upgrade']
        self.policy['engineering_update']={'previous_selection':previous,'selection':selected}
        request={'version':1,'operation':'upgrade','parameters':{k:selected[k] for k in controller.SELECT}}
        key=controller.request_digest(request);upgrade=self.c.control/'grants'/(key+'.json')
        save(upgrade,{'root':str(self.root),'operation':'upgrade','request_sha256':key,'expires_at':1800,
            'authorization_sha256':pin('upgrade approval'),'authorization_sequence':14})
        with patch.object(self.c,'policy',return_value=self.policy),patch.object(controller,'engineering_effective_selection',return_value=previous),patch.object(controller.time,'time',return_value=1500):
            self.c.authorize(request)
        self.assertFalse(upgrade.exists())
        consumed={json.loads(line)['request_sha256'] for line in (self.c.control/'audit.jsonl').read_bytes().splitlines()}
        self.assertEqual(consumed,{key});self.assertNotIn(self.key,consumed)
        self.policy['engineering_initial_authorization_sha256']=pin('initial')
        self.policy['validator_formation_sha256']=pin('formation')
        self.policy['engineering_update'].update(initial_sha256=pin('initial'),formation_sha256=pin('formation'))
        self.policy['releases']={value['release_id']:{'manifest_sha256':value['manifest_sha256'],
            'inventory_authenticated':True,'networks':{value['network_id']:value['chain_id']}} for value in (previous,selected)}
        self.doc.update(selected)
        before={p.relative_to(self.root):p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        with patch.object(lifecycle,'_sealed_receipt',return_value=({**selected,'package_sha256':selected['manifest_sha256']},{'release_id':selected['release_id']})):
            self.assertTrue(self.refresh(consumed=consumed))
        self.assertEqual(before,{p.relative_to(self.root):p.read_bytes() for p in self.root.rglob('*') if p.is_file()})
        self.assertFalse(self.grant.exists());self.assertFalse(self.path.exists())
        self.selection.update(selected);del self.policy['engineering_update']
        with self.assertRaisesRegex(ValueError,'Consumed'):self.refresh(consumed=consumed|{self.key})

    def test_first_readiness_missing_grant_still_refuses_partial_or_foreign_approval(self):
        self.grant.unlink()
        # Existing readiness may never lose its unused exact grant.
        with self.assertRaises(OSError):self.refresh()
        self.path.unlink()
        with self.assertRaisesRegex(ValueError,'incomplete'):self.refresh()
        del self.policy['authorization_files'][layout.READINESS_FILE]
        self.assertTrue(self.refresh())
        save(self.path,self.old)
        with self.assertRaisesRegex(ValueError,'incomplete'):self.refresh()
        self.path.unlink()
        save(self.grant,{'root':str(self.root),'operation':'commission','request_sha256':self.key,'expires_at':1300,
            'authorization_sha256':pin('older parent'),'authorization_sequence':0})
        with self.assertRaisesRegex(ValueError,'Original commissioning grant'):self.refresh()
        self.grant.unlink()
        doc=copy.deepcopy(self.doc);doc['requests'].append({'operation':'start','request_sha256':pin('start')})
        with self.assertRaisesRegex(ValueError,'Consumed or foreign'):self.refresh(doc=doc)
        for relative in ('data','tmp/commissioning','evidence/upgrade-intent.json'):
            path=self.root/relative;save(path,b'partial')
            with self.assertRaisesRegex(ValueError,'published or uncertain'):self.refresh()
            path.unlink()
        source=self.c.control/'authorization/inputs/commissioning/config/node.json'
        save(source,b'changed')
        with self.assertRaisesRegex(ValueError,'commissioning input changed'):self.refresh()

    def test_existing_native_treasury_is_preserved_but_unknown_linked_or_replayed_refresh_refuses(self):
        import test_commission_treasury as treasury_fixture
        fixture=treasury_fixture.CommissionTreasuryTests()
        selection={'network_id':'fresh','chain_id':'99999','formation_sha256':'a'*64}
        request={'version':1,'operation':'treasury_prepare','parameters':{'formation_sha256':'a'*64,'effective_at_unix':100}}
        result={'schema':'nodenetwork-formation-treasury-v1','pending':True,'possession_verified':True,
                'request_sha256':controller.request_digest(request),'effective_at_unix':100,**selection}
        directory=self.root/'keys/formation-treasury';directory.mkdir(mode=0o700)
        save(self.root/'tmp/treasury-prepare-request.json',controller.canonical(request))
        save(directory/'request.json',controller.canonical(request))
        for name in ('treasury-public.json','treasury.enc.json','unlock'):save(directory/name,b'opaque test fixture, not keys')
        before={p.relative_to(self.root):p.read_bytes() for p in self.root.rglob('*') if p.is_file()}
        with fixture.verified(selection,result):
            self.assertTrue(self.refresh())
            self.assertEqual(before,{p.relative_to(self.root):p.read_bytes() for p in self.root.rglob('*') if p.is_file()})
            unknown=self.root/'keys/unknown';save(unknown,b'unknown')
            with self.assertRaises(ValueError):self.refresh()
            unknown.unlink()
            unlock=directory/'unlock';raw=unlock.read_bytes();unlock.unlink();unlock.symlink_to(directory/'treasury.enc.json')
            with self.assertRaises(ValueError):self.refresh()
            unlock.unlink();save(unlock,raw)
            with self.assertRaisesRegex(ValueError,'Consumed'):self.refresh(consumed={self.key})
            self.assertEqual(before,{p.relative_to(self.root):p.read_bytes() for p in self.root.rglob('*') if p.is_file()})

    def test_atomic_exchange_reconciliation_does_not_regenerate_grant(self):
        # Existing exchange protocol applies equally to a refreshed review: exact
        # committed receipt wins, even after expiry; no re-issuance is implied.
        raw=self.fresh.decode();sha=hashlib.sha256(self.fresh).hexdigest()
        policy={'engineering_authorization':{'sha256':sha,'sequence':2,'expires_at':1500}}
        result=self.b.authorization_reconciliation(policy,sha,raw)
        self.assertTrue(result['reconciled']);self.assertFalse(result['grants_recreated'])
        with self.assertRaises(ValueError):self.b.authorization_reconciliation(policy,sha,raw+' ')

if __name__=='__main__':unittest.main()
