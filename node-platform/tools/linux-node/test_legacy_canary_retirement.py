"""Exact obsolete scope only. No services, keys, provider or hosts are used."""
import copy
import json
from pathlib import Path
from unittest.mock import patch
import unittest
import bootstrap as b
import test_gateway_handoff as handoff

class LegacyCanaryRetirementTests(unittest.TestCase):
    def public_fixture(self):
        node={'network_id':'posy-apqe-canary-process-49028','chain_id':99999,'role':'rpc_gateway','genesis_path':'/opt/Synergy/network/genesis.json'}
        local={'native_enrollment_verified':True,'hostname':'synergy-canary-rpc-99999','overlay_address':'10.69.51.205/16','management_url':'https://vpn-coordinator.synergy-network.io:443','wireguard_public_key':'EhHDd/L7fXX+c8x2nyJx8wWUwGRij3AmioVZKiH4/2M='}
        remote={'server_binding_verified':True,'peer_name':local['hostname'],'hostname':'vmi3381382','peer_id':'dboqb9if611ohpqo0e1g','ip':'10.69.51.205','wireguard_public_key':local['wireguard_public_key']}
        return {'package.json':('ef491eddd06e4145abc1f396b3c363cb2a7f2ec2d582d1d05cf5d28c6dfc679f',{'files':{'README.md':'9'*64}}),'README.md':('9'*64,{}),'node.json':('1'*64,node),'canary-rpc-relay.json':('2'*64,{'node_config_path':'/opt/Synergy/config/node.json','listen_address':'127.0.0.1:8552'}),'genesis.json':('d28ab09b6857f670482580a786edd939b090e88aa9378cdd0ad91379a724a9d7',{}),'vpn-enrollment.json':('f27a0e0031ba00f2a234e77e55449ca5f4b9a15dec7e2c8da3da5bde6ea37573',local),'vpn-server-binding.json':('1629d857606c040ecbd7ed9d5dc692ac697dda3b129cc1f8b2bb9834e594d5f2',remote)}

    def identity(self,files=None,receipt=False):
        files=files or self.public_fixture()
        def public(path,*args):
            pin,value=files[Path(path).name];return pin,json.dumps(value).encode()
        with patch.object(b,'_handoff_public',side_effect=public),patch.object(Path,'exists',return_value=receipt),patch.object(Path,'is_symlink',return_value=False):
            return b._legacy_canary_identity()

    def test_exact_peer_is_attribution_not_provider_absence(self):
        network,peer=self.identity()
        self.assertEqual(network['network_id'],'posy-apqe-canary-process-49028')
        self.assertEqual(peer['peer_id'],'dboqb9if611ohpqo0e1g');self.assertFalse(peer['retirement_verified'])
        with self.assertRaises(ValueError):self.identity(receipt=True)

    def test_current_or_foreign_origin_and_peer_refuse(self):
        for file,key,value in [('node.json','network_id','synergy-posy-canary-20261117'),('node.json','chain_id',1266),('node.json','genesis_path','/opt/synergy/network/genesis.json'),('vpn-server-binding.json','peer_id','foreign'),('vpn-server-binding.json','wireguard_public_key','foreign'),('vpn-enrollment.json','management_url','https://foreign.invalid')]:
            files=self.public_fixture();files[file][1][key]=value
            with self.subTest(file=file,key=key),self.assertRaises(ValueError):self.identity(files)
        for file in ['genesis.json','package.json','README.md']:
            files=self.public_fixture();files[file]=('a'*64,{})
            with self.subTest(file=file),self.assertRaises(ValueError):self.identity(files)

    def test_new_mode_is_readonly_and_hash_bound(self):
        old=handoff.GatewayHandoffTests();old.setUp();facts=copy.deepcopy(old.facts)
        facts['candidate_units']=list(b.HANDOFF_UNITS[1:]);facts['blockers']=['explicit_retirement_approval_required','legacy_inventory_requires_attribution','legacy_peer_retirement_required']
        with patch.object(b.os,'geteuid',return_value=0),patch('time.time',return_value=1000),patch.object(b,'_handoff_machine',return_value=old.wire['context']['machine_id_sha256']),patch.object(b,'_gateway_handoff_snapshot',return_value=facts) as snapshot:
            result=b.gateway_handoff_plan(old.wire,canary_only=True)
        self.assertEqual(result['schema'],'nodenetwork-legacy-canary-retirement-plan-v1')
        self.assertFalse(result['removal_authorized']);self.assertFalse(result['mutation_performed'])
        self.assertEqual(snapshot.call_args.kwargs,{'canary_only':True})

    def test_separate_scope_omits_untrusted_protected_binary_without_weakening_old_reader(self):
        fixture=handoff.GatewayHandoffTests()
        result=fixture.snapshot_fixture(canary_only=True,insecure_protected_binary=True)
        self.assertNotIn('chain1266_executable_sha256',result['legacy'])
        self.assertEqual(result['candidate_units'],list(b.HANDOFF_UNITS[1:]))
        self.assertEqual(result['legacy']['canary_pid'],12)
        self.assertEqual(result['preserved']['metrics_pid'],11)
        self.assertIn('canary_frontend',result['preserved']['files'])
        with self.assertRaises(ValueError):fixture.snapshot_fixture(insecure_protected_binary=True)

    def test_only_upper_inventory_can_block_old_canary_attribution(self):
        fixture=handoff.GatewayHandoffTests()
        result=fixture.snapshot_fixture(canary_only=True,lower_foreign=True)
        self.assertNotIn('foreign_resources',result['blockers'])
        self.assertIn('foreign_resources',fixture.snapshot_fixture(canary_only=True,upper_foreign=True)['blockers'])
        self.assertIn('foreign_resources',fixture.snapshot_fixture(lower_foreign=True)['blockers'])

    def test_observed_readme_requires_regular_root_owned_private_file(self):
        import tempfile
        import os
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();readme=root/'README.md';readme.write_bytes(b'public legacy README');readme.chmod(0o600)
            original=Path.lstat
            def owned(path):return handoff.GatewayHandoffTests.root_owned(original(path))
            from contextlib import contextmanager
            from types import SimpleNamespace
            scan=os.scandir
            @contextmanager
            def entries(path):
                with scan(path) as stream:
                    yield iter([SimpleNamespace(name=e.name,stat=lambda follow_symlinks=False,e=e:handoff.GatewayHandoffTests.root_owned(e.stat(follow_symlinks=follow_symlinks))) for e in stream])
            with patch.object(Path,'lstat',owned),patch.object(b.os,'scandir',entries):
                _,blocked=b._handoff_root_entries(root,{'README.md'})
                self.assertEqual(blocked,set())
                readme.chmod(0o644)
                self.assertIn('foreign_resources',b._handoff_root_entries(root,{'README.md'})[1])
                readme.unlink();readme.mkdir()
                self.assertIn('foreign_resources',b._handoff_root_entries(root,{'README.md'})[1])

if __name__=='__main__':unittest.main()
