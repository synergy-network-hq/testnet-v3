"""Restricted enrollment tests; no host service or network mutations."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch
import lifecycle
import synergy_linux as node
import vpn


class GatewayVpnTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for name in ('run', 'vpn', 'evidence'):
            (self.root/name).mkdir()
        node.write_new(self.root/'installation.json', {'role':'rpc_gateway','chain_id':99999})
        self.target = {'ip':'10.69.1.2','port':8551}
        self.live = {'publicKey':'wg-public','netbirdIp':'10.69.1.3/16'}
        self.request = {'setup_key':'one-off','management_url':'https://vpn.example','hostname':'gateway',
                        'required_gateway_tcp':self.target}

    def enrollment(self):
        with patch.object(vpn.os,'geteuid',return_value=0), patch.object(vpn.sys,'platform','linux'), \
                patch.object(vpn,'native') as native, patch.object(vpn,'status',return_value=self.live), \
                patch.object(lifecycle,'mutate_owned_service'):
            result = vpn.enroll(self.root,json.dumps(self.request))
            self.assertFalse(any(call.args[0][0]=='ping' for call in native.call_args_list))
            self.assertFalse((self.root/'run/enrollment.key').exists())
            self.assertFalse(result['gateway_tcp_verified'])
            self.assertEqual(result['verified_peer_ips'],[])
            return result

    def bind(self):
        vpn.bind_server(self.root,{'id':'peer','name':'gateway','hostname':'gateway',
            'ip':'10.69.1.3','connected':True,'new_peer_verified':True,'one_off_usage_verified':True})

    def test_fresh_enrollment_is_pending_until_bound_wt0_tcp(self):
        self.enrollment()
        with patch.object(lifecycle,'_require_operator'), patch.object(lifecycle,'_sealed_receipt'):
            with self.assertRaises(FileNotFoundError):vpn.verify_gateway_route(self.root)
            self.bind()
            sock = MagicMock(); sock.__enter__.return_value = sock
            with patch.object(vpn,'status',return_value=self.live), patch.object(vpn,'native',return_value=b'[{"dev":"wt0"}]') as native, \
                    patch.object(vpn.socket,'SO_BINDTODEVICE',25,create=True),patch.object(vpn.socket,'socket',return_value=sock):
                result = vpn.verify_gateway_route(self.root)
                self.assertTrue(result['tcp_verified'])
                self.assertFalse(result['apqe_verified'])
                sock.bind.assert_called_once_with(('10.69.1.3',0))
                sock.connect.assert_called_once_with(('10.69.1.2',8551))
                sock.setsockopt.assert_called_once_with(vpn.socket.SOL_SOCKET,25,b'wt0\0')
                self.assertEqual(native.call_args.args[0],['ip','-j','route','get','10.69.1.2','from','10.69.1.3'])
                self.assertEqual(node.read(self.root/vpn.GATEWAY_RECEIPT),result)

    def test_non_overlay_route_identity_mismatch_and_tcp_refusal_never_grant_receipt(self):
        self.enrollment();self.bind()
        with patch.object(lifecycle,'_require_operator'), patch.object(lifecycle,'_sealed_receipt'), \
                patch.object(vpn,'native',return_value=b'[{"dev":"eth0"}]'),patch.object(vpn.socket,'socket') as factory:
            with patch.object(vpn,'status',return_value=dict(self.live,publicKey='substitution')):
                with self.assertRaisesRegex(ValueError,'identity/target'):vpn.verify_gateway_route(self.root)
            with patch.object(vpn,'status',return_value=self.live):
                with self.assertRaisesRegex(ValueError,'must use wt0'):vpn.verify_gateway_route(self.root)
            factory.assert_not_called()
        with patch.object(lifecycle,'_require_operator'),patch.object(lifecycle,'_sealed_receipt'), \
                patch.object(vpn,'status',return_value=self.live),patch.object(vpn,'native',return_value=b'[{"dev":"wt0"}]'), \
                patch.object(vpn.socket,'SO_BINDTODEVICE',25,create=True),patch.object(vpn.socket,'socket') as factory:
            factory.return_value.__enter__.return_value.connect.side_effect=ConnectionRefusedError
            with self.assertRaises(ConnectionRefusedError):vpn.verify_gateway_route(self.root)
        self.assertFalse((self.root/vpn.GATEWAY_RECEIPT).exists())

    def test_gateway_profile_disallows_unrestricted_ports_and_icmp(self):
        for target in ({'ip':'10.69.1.2','port':443},{'ip':'127.0.0.1','port':8551},
                       {'ip':'10.69.1.2','port':'8551'}):
            with self.assertRaises(ValueError):vpn.gateway_target(self.root,target)
        request=dict(self.request); del request['required_gateway_tcp']; request['required_peer_ips']=['10.69.1.2']
        with patch.object(vpn.os,'geteuid',return_value=0),patch.object(vpn.sys,'platform','linux'),patch.object(vpn,'native') as native:
            with self.assertRaisesRegex(ValueError,'restricted TCP'):vpn.enroll(self.root,json.dumps(request))
            native.assert_not_called()

    def test_validator_enrollment_still_probes_icmp_on_wt0(self):
        (self.root/'installation.json').write_text('{"role":"validator","chain_id":99999}')
        request=dict(self.request); del request['required_gateway_tcp']; request['required_peer_ips']=['10.69.1.2']
        with patch.object(vpn.os,'geteuid',return_value=0),patch.object(vpn.sys,'platform','linux'), \
                patch.object(vpn,'native') as native,patch.object(vpn,'status',return_value=self.live),patch.object(lifecycle,'mutate_owned_service'):
            result=vpn.enroll(self.root,json.dumps(request))
        up=[call.args[0] for call in native.call_args_list if 'up' in call.args[0]]
        self.assertEqual(len(up),1)
        self.assertIn('--disable-dns',up[0])
        self.assertIn(['ping','-n','-I','wt0','-c','1','-W','2','10.69.1.2'],[call.args[0] for call in native.call_args_list])
        self.assertNotIn('required_gateway_tcp',result)


if __name__=='__main__':unittest.main()
