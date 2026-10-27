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
