"""Bounded read-only legacy plan qualification; never invokes hosts or services."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

import bootstrap as b


class GatewayHandoffTests(unittest.TestCase):
    def setUp(self):
        self.facts={
            'preserved':{'files':{k:'a'*64 for k in b.HANDOFF_FILES},'tunnel_active':True,
                         'rpc_listener_owned':True,'ws_listener_owned':True},
            'metrics':{'unit_sha256':'b'*64,'service_active':True,'listener_owned':True,
                       'consumer_ip':'209.145.50.9','resolution':'unresolved'},
            'legacy':{'chain1266_executable_sha256':'c'*64,'canary_executable_sha256':'d'*64,
                      'canary_unit_sha256':'e'*64,'vpn_unit_sha256':'f'*64,
                      'canary_active':True,'vpn_active':True,
                      'lower_root_entries_sha256':'1'*64,'upper_root_entries_sha256':'2'*64},
            'candidate_units':list(b.HANDOFF_UNITS),
            'blockers':['explicit_retirement_approval_required','legacy_inventory_requires_attribution',
                        'metrics_resolution_required']}
        self.wire={'context':{'target':{'kind':'remote','host':'167.86.83.83','port':22,'root':'/opt/synergy'},
                             'machine_id_sha256':hashlib.sha256(b'0'*32).hexdigest(),'expires_at':1100},'challenge':'4'*64}

    def run_plan(self,wire=None,snapshots=None):
        with patch.object(b.os,'geteuid',return_value=0),patch('time.time',return_value=1000),\
             patch.object(b,'_handoff_public',return_value=('3'*64,b'0'*32+b'\n')),\
             patch.object(b,'_gateway_handoff_snapshot',side_effect=snapshots or [copy.deepcopy(self.facts),copy.deepcopy(self.facts)]):
            return b.gateway_handoff_plan(wire or self.wire)

    def test_exact_plan_digest_no_authority_or_secret_content(self):
        out=self.run_plan()
        self.assertEqual(len(out),13)
        committed={k:out[k] for k in ('target','machine_id_sha256','preserved','metrics','legacy','candidate_units','blockers')}
        self.assertEqual(out['plan_sha256'],hashlib.sha256(json.dumps(committed,sort_keys=True,separators=(',',':')).encode()).hexdigest())
        for k in ('mutation_performed','removal_authorized','automatic_retry'):self.assertIs(out[k],False)
        self.assertNotIn('not disclosed',json.dumps(out))
        self.assertEqual(out['candidate_units'],list(b.HANDOFF_UNITS))

    def test_wrong_target_machine_expiry_extra_field_and_scope_drift_refuse(self):
        for defect in ('target','machine','expiry','extra'):
            wire=copy.deepcopy(self.wire)
            if defect=='target':wire['context']['target']['host']='209.145.50.9'
            if defect=='machine':wire['context']['machine_id_sha256']='5'*64
            if defect=='expiry':wire['context']['expires_at']=1121
            if defect=='extra':wire['context']['execute']=True
            with self.subTest(defect=defect),self.assertRaises(ValueError):self.run_plan(wire)
        for k in ('preserved','metrics','legacy'):
            changed=copy.deepcopy(self.facts);changed[k]['unexpected']=True
            with self.subTest(drift=k),self.assertRaises(ValueError):self.run_plan(snapshots=[self.facts,changed])

    def test_main_closed_wire_and_fixed_refusal_never_reveal_exception(self):
        import contextlib
        import sys
        stream=type('Input',(),{'buffer':io.BytesIO(json.dumps(self.wire).encode())})()
        output=io.StringIO()
        with patch.object(sys,'argv',['bootstrap','--gateway-handoff-plan']),patch.object(sys,'stdin',stream),\
             patch.object(b,'gateway_handoff_plan',side_effect=ValueError('PRIVATE /keys/token')),contextlib.redirect_stdout(output):
            b.main()
        self.assertEqual(json.loads(output.getvalue()),{'version':1,'ok':False,'error':{
            'code':'gateway_handoff_refused','message':'Legacy gateway handoff observation refused; no resources changed'}})

    @staticmethod
    def root_owned(info):
        fields=list(info);fields[4]=0;fields[5]=0
        return os.stat_result(fields)

    def test_depth_one_inventory_never_opens_private_contents_and_foreign_blocks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();(root/'keys').mkdir();(root/'keys/private.key').write_text('PRIVATE')
            (root/'foreign').mkdir();(root/'link').symlink_to(root/'keys')
            original=Path.lstat
            with patch.object(Path,'lstat',lambda path: self.root_owned(original(path))),\
                 patch.object(Path,'read_bytes',side_effect=AssertionError('private content read')):
                pin,blockers=b._handoff_root_entries(root,{'keys'})
            self.assertEqual(len(pin),64);self.assertEqual(blockers,{'foreign_resources'})

    def test_inventory_entry_ceiling_returns_blocker_not_complete_claim(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve()
            for i in range(65):(root/str(i)).mkdir()
            original=Path.lstat
            with patch.object(Path,'lstat',lambda path:self.root_owned(original(path))):
                _,blockers=b._handoff_root_entries(root,{str(i) for i in range(65)})
            self.assertIn('inventory_bound_exceeded',blockers)

    def test_public_reader_refuses_symlink_and_never_mutates_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve();p=root/'public';p.write_bytes(b'public bytes');p.chmod(0o600)
            alias=root/'alias';alias.symlink_to(p)
            original_lstat=Path.lstat;original_fstat=os.fstat
            with patch.object(Path,'lstat',lambda path:self.root_owned(original_lstat(path))),\
                 patch.object(b.os,'fstat',lambda fd:self.root_owned(original_fstat(fd))):
                self.assertEqual(b._handoff_public(p),(hashlib.sha256(b'public bytes').hexdigest(),b'public bytes'))
                with self.assertRaises(ValueError):b._handoff_public(alias)
                with self.assertRaises(ValueError):b._handoff_public(p,2)
            self.assertEqual(p.read_bytes(),b'public bytes');self.assertEqual(stat.S_IMODE(p.stat().st_mode),0o600)

    def test_unit_pin_accepts_the_exact_managed_link_and_refuses_substitution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary).resolve()
            target=root/'managed.service'
            target.write_bytes(b'public unit')
            fragment=root/'registered.service'
            fragment.symlink_to(target)
            original_lstat=Path.lstat;original_fstat=os.fstat
            with patch.dict(b.HANDOFF_MANAGED_UNIT_LINKS,{str(fragment):str(target)},clear=True),\
                 patch.object(Path,'lstat',lambda path:self.root_owned(original_lstat(path))),\
                 patch.object(b.os,'fstat',lambda fd:self.root_owned(original_fstat(fd))):
                self.assertEqual(b._handoff_unit_pin(str(fragment)),hashlib.sha256(b'public unit').hexdigest())
                replacement=root/'replacement.service'
                replacement.symlink_to(target)
                original_public=b._handoff_public
                def replace_link(path):
                    result=original_public(path)
                    replacement.replace(fragment)
                    return result
                with patch.object(b,'_handoff_public',side_effect=replace_link),self.assertRaisesRegex(ValueError,'link changed'):
                    b._handoff_unit_pin(str(fragment))
                fragment.unlink()
                fragment.symlink_to(root/'foreign.service')
                with self.assertRaisesRegex(ValueError,'Unexpected legacy unit link'):
                    b._handoff_unit_pin(str(fragment))

    def test_machine_pin_uses_verified_normalized_convention_not_raw_file_digest(self):
        for raw in (b'0'*32,b'0'*32+b'\n'):
            with patch.object(b,'_handoff_public',return_value=('a'*64,raw)):
                self.assertEqual(b._handoff_machine(),hashlib.sha256(b'0'*32).hexdigest())
        for raw in (b'FOREIGN',b'A'*32,b'0'*31,b'0'*33):
            with patch.object(b,'_handoff_public',return_value=('a'*64,raw)),self.assertRaises(ValueError):b._handoff_machine()

    def snapshot_fixture(self,foreign_route=False,foreign_process=False,foreign_forward=False,foreign_listener=False,foreign_consumer=False,commented_consumer=False,reversed_acl=False):
        from types import SimpleNamespace
        enabled=Path('/etc/nginx/sites-enabled/testnet-core-rpc.synergy-network.io')
        fragments={
            'synergy-chain1266-rpc-tunnel.service':b.HANDOFF_FILES['tunnel_unit'],
            b.HANDOFF_UNITS[0]:'/etc/systemd/system/synergy-chain1266-role@.service',
            **{name:'/etc/systemd/system/'+name for name in b.HANDOFF_UNITS[1:]}}
        pids={name:str(i+10) for i,name in enumerate(fragments)}
        executables={'10':'/usr/bin/ssh','11':'/opt/synergy/chain1266/releases/chain1266-incarnation-4-rc30/bin/synergy-rpc-gateway-node',
                     '12':'/opt/Synergy/bin/synergy-node','13':'/opt/Synergy/bin/netbird'}
        routes=b'\n'.join(b'proxy_pass '+value+b';' for value in [b'http://127.0.0.1:5640',b'http://127.0.0.1:5660',
                           b'http://127.0.0.1:9100/metrics'])
        acl=b'allow '+(b'foreign' if foreign_consumer else b'209.145.50.9')+b'; deny all;'
        if reversed_acl:acl=b'deny all; allow 209.145.50.9;'
        metrics_route=b'location = /metrics/node-rpc { '+acl+b' proxy_pass http://127.0.0.1:6030/metrics; }'
        if commented_consumer:
            routes+=b'\n#location = /metrics/node-rpc { allow 209.145.50.9; deny all; proxy_pass http://127.0.0.1:6030/metrics; }'
            if foreign_consumer:routes+=b'\n'+metrics_route
            else:routes+=b'\nproxy_pass http://127.0.0.1:6030/metrics;'
        else:routes+=b'\n'+metrics_route
        if foreign_route:routes+=b'\nproxy_pass http://foreign.invalid;'
        def command(args,*unused):
            if args[0]=='/usr/bin/ss':
                return (('LISTEN 0 128 127.0.0.1:5640 0.0.0.0:* users:(("ssh",pid='+('99' if foreign_listener else '10')+',fd=4))\n'
                        'LISTEN 0 128 127.0.0.1:5660 0.0.0.0:* users:(("ssh",pid=10,fd=5))\n'
                        'LISTEN 0 128 127.0.0.1:6030 0.0.0.0:* users:(("gateway",pid=11,fd=6))').encode())
            self.assertEqual(args[:2],['/usr/bin/systemctl','show'])
            name=args[2]
            self.assertIn(name,fragments)
            return ('ActiveState=active\nMainPID='+pids[name]+'\nFragmentPath='+fragments[name]+'\nDropInPaths=\n').encode()
        args=[b'/usr/bin/ssh',b'-N',b'-L',b'127.0.0.1:5640:127.0.0.1:5640',b'-L',b'127.0.0.1:5660:127.0.0.1:5660']
        if foreign_forward:args.extend([b'-R',b'foreign'])
        args.append(b'root@62.146.182.207')
        def public(path,*unused):return 'a'*64,routes if str(path)==b.HANDOFF_FILES['nginx_rpc'] else b'public'
        with patch.object(b,'_handoff_public',side_effect=public),patch.object(b,'_handoff_command',side_effect=command),\
             patch.object(b,'_handoff_unit_pin',side_effect=lambda fragment:public(fragment)[0]),\
             patch.object(b,'_handoff_root_entries',return_value=('b'*64,set())),\
             patch.object(Path,'is_symlink',side_effect=lambda:True),\
             patch.object(Path,'lstat',return_value=SimpleNamespace(st_uid=0)),\
             patch.object(Path,'resolve',return_value=Path(b.HANDOFF_FILES['nginx_rpc'])),\
             patch.object(Path,'open',side_effect=lambda *a,**k:io.BytesIO(b'\0'.join(args)+b'\0')),\
             patch.object(b.os,'readlink',side_effect=lambda p:'/foreign/process' if foreign_process else executables[p.split('/')[2]]):
            return b._gateway_handoff_snapshot()

    def test_real_snapshot_projection_preserves_routes_and_blocks_foreign_ownership(self):
        out=self.snapshot_fixture()
        self.assertTrue(out['preserved']['rpc_listener_owned']);self.assertTrue(out['metrics']['listener_owned'])
        self.assertEqual(set(out['preserved']['files']),set(b.HANDOFF_FILES))
        self.assertEqual(out['candidate_units'],list(b.HANDOFF_UNITS))
        self.assertEqual(out['metrics']['resolution'],'unresolved')
        self.assertIn('legacy_inventory_requires_attribution',out['blockers'])
        for defect in ('foreign_route','foreign_process','foreign_consumer','commented_consumer','reversed_acl'):
            with self.subTest(defect=defect),self.assertRaises(ValueError):self.snapshot_fixture(**{defect:True})
        with self.assertRaises(ValueError):self.snapshot_fixture(commented_consumer=True,foreign_consumer=True)
        for defect in ('foreign_forward','foreign_listener'):
            with self.subTest(defect=defect):
                out=self.snapshot_fixture(**{defect:True})
                self.assertIn('protected_attribution_failed',out['blockers'])

    def test_command_output_and_time_are_bounded_without_files(self):
        import sys
        self.assertEqual(b._handoff_command([sys.executable,'-c','print("ok")']),b'ok\n')
        with self.assertRaises(ValueError):
            b._handoff_command([sys.executable,'-c','print("x"*1000)'],limit=8)
        with self.assertRaises(ValueError):
            b._handoff_command([sys.executable,'-c','import time;time.sleep(60)'],timeout=0.05)


if __name__=='__main__':unittest.main()
