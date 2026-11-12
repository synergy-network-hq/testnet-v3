"""Offline refusal tests; these are not native Linux/VPN acceptance evidence."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import lifecycle
import synergy_linux as node
import vpn

class RefusalTests(unittest.TestCase):
    def test_in_root_bootstrap_installs_only_pinned_master_into_empty_root(self):
        import hashlib
        from conformance import DIRECTORIES
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()/'Synergy'
            stage = root/node.BOOTSTRAP_MASTER
            stage.mkdir(parents=True, mode=0o700)
            root.chmod(0o700); (root/'tmp').chmod(0o700)
            for name in DIRECTORIES: (stage/name).mkdir(mode=0o700)
            roles = ['validator'] + [f'role-{i}' for i in range(19)]
            for role in roles: (stage/'roles'/role).mkdir(mode=0o700)
            node.write_new(stage/'roles/roles.json', {'roles':roles,'implemented':['validator']})
            for name in ('synergy-node','synergy-keytool','synergy-genesis','netbird'):
                (stage/'bin'/name).write_bytes(b'\x7fELF\x02\x01\x01'+bytes(11)+b'\x3e\x00')
            files={p.relative_to(stage).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
                   for p in stage.rglob('*') if p.is_file()}
            node.write_new(stage/'package.json', {'format':node.MARKER,'architecture':'x86_64','files':files})
            pin=node.digest(stage/'package.json')
            with patch.object(node,'_require_install_operator'), patch.object(lifecycle,'_mountinfo_text',return_value=''), patch.object(node,'native') as operation:
                with self.assertRaisesRegex(ValueError,'digest'):
                    node._staged_master(root,stage,'0'*64)
                foreign=root/'existing'; foreign.write_text('must survive')
                with self.assertRaisesRegex(ValueError,'existing installation'):
                    node._staged_master(root,stage,pin)
                self.assertEqual(foreign.read_text(),'must survive')
                foreign.unlink()
                operation.assert_not_called()
                result=node.install(stage,root,'validator','offline-fixture',99999,'fixture',
                                    staged_master_sha256=pin)
                operation.assert_called_once_with([root/'bin/synergy-node','version'])
            self.assertEqual(result['package_sha256'],pin)
            self.assertFalse(result['consensus_started'])
            self.assertFalse(stage.exists())
            self.assertFalse((root/'data').exists())
            self.assertFalse(list((root/'keys').iterdir()))

    def test_role_key_ids_are_unique_across_nodes_and_roles(self):
        ids = {node.operational_key_id(role, address) for role in ('p2p','consensus','ingress')
               for address in ('synv1identitya','synv1identityb')}
        self.assertEqual(len(ids), 6)

    def test_root_refuses_symlink_existing_and_broad_targets(self):
        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp).resolve()
            for value in ('/', '/Synergy', str(parent / 'Other'), str(parent / '..' / 'Synergy')):
                with self.assertRaises(ValueError): node.safe_root(value, existing=False)
            actual = parent / 'actual'; actual.mkdir()
            link = parent / 'alias'; link.symlink_to(actual, target_is_directory=True)
            with self.assertRaises(ValueError): node.safe_root(str(link / 'Synergy'), existing=False)
            root = parent / 'Synergy'; root.mkdir()
            with self.assertRaises(ValueError): node.safe_root(str(root), existing=False)

    def test_public_receipts_are_exclusive(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'receipt.json'
            node.write_new(path, {'first': True})
            with self.assertRaises(FileExistsError): node.write_new(path, {'second': True})
            self.assertEqual(node.read(path), {'first': True})

    def test_package_rejects_unlisted_directory_symlinks_before_elf_checks(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp)
            node.write_new(p / 'package.json', {'format': node.MARKER,'architecture':'x86_64','files':{}})
            (p / 'unlisted').symlink_to(p.parent, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, 'symlink'): node.verify_package(p)

    def test_server_binding_refuses_stale_or_unattributed_peer_without_writes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); (root / 'evidence').mkdir()
            node.write_new(root / 'evidence/vpn-enrollment.json',
                           {'wireguard_public_key':'public-only','overlay_address':'100.64.1.2/16','hostname':'unique'})
            for peer in ({'name':'wrong'}, {'name':'unique','new_peer_verified':False}):
                with self.assertRaises(ValueError): vpn.bind_server(root, peer)
            self.assertFalse((root / 'evidence/vpn-server-binding.json').exists())

    def test_peer_name_can_differ_from_operating_system_hostname(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); (root / 'evidence').mkdir()
            node.write_new(root / 'evidence/vpn-enrollment.json',
                           {'wireguard_public_key':'public-only', 'overlay_address':'100.64.1.2/16',
                            'hostname':'fresh-peer-name'})
            vpn.bind_server(root, {'id':'fresh-api-id', 'name':'fresh-peer-name',
                                  'hostname':'existing-os-hostname', 'ip':'100.64.1.2',
                                  'connected':True, 'new_peer_verified':True,
                                  'one_off_usage_verified':True,
                                  'one_off_usage_evidence':'authenticated peer.setupkey.add audit event'})
            saved = node.read(root / 'evidence/vpn-server-binding.json')
            self.assertEqual(saved['hostname'], 'existing-os-hostname')
            self.assertEqual(saved['peer_name'], 'fresh-peer-name')

    def test_uninstall_requires_nonempty_matching_server_retirement_before_any_service_operation(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp); (root / 'evidence').mkdir()
            node.write_new(root / 'evidence/vpn-enrollment.json', {})
            node.write_new(root / 'evidence/vpn-server-binding.json', {'peer_id':None})
            node.write_new(root / 'evidence/vpn-retirement.json', {'peer_id':None,'retired':True,'absence_verified':True})
            with patch.object(lifecycle.os, 'geteuid', return_value=0), patch.object(lifecycle.sys,'platform','linux'), patch.object(lifecycle,'native') as operation:
                with self.assertRaises(ValueError): lifecycle.remove(root, str(root))
                operation.assert_not_called()
            self.assertTrue(root.is_dir())

if __name__ == '__main__': unittest.main()
