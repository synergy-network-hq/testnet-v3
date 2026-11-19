"""Management-only signed-quorum subset; no chain/network/key generation."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import apqe_layout as layout
import controller
import test_commissioning_readiness as fixtures
observations=fixtures.observations
from test_lifecycle import save


def subset(n=4):
 value=observations();roster=value['observations'][0]['validator_addresses'];online=roster[:n]
 values=value['observations'][:n]
 for item in values:
  item.update(schema='nodenetwork-commissioning-observation-v2',online_addresses=online.copy(),
              frozen_voting_weights={a:'100' for a in roster},observation_kind='prestart_vpn')
  item['peers']={a:p for a,p in item['peers'].items() if a in online}
 return {'schema':'nodenetwork-commissioning-readiness-v2','online_addresses':online,
         'excluded_addresses':roster[n:],'observations':values}


class SubsetReadinessTests(unittest.TestCase):
 def setUp(self):self.value=subset();self.local=copy.deepcopy(self.value['observations'][0])
 def validate(self,value=None,local=None,now=1000):return layout.validate_commissioning_readiness(value or self.value,local or self.local,now)
 def test_four_twelve_edges_and_full_five_twenty_edges(self):
  self.assertTrue(self.validate());self.assertEqual(sum(len(o['peers']) for o in self.value['observations']),12)
  full=subset(5);self.assertTrue(self.validate(full,full['observations'][0]));self.assertEqual(sum(len(o['peers']) for o in full['observations']),20)
  self.assertEqual(self.value['excluded_addresses'],['synv14']);self.assertFalse(any('offline' in k for k in self.value))
 def test_count_weight_exact_two_thirds_and_overflow_fail_closed(self):
  roster=self.local['validator_addresses'];online=roster[:4]
  for weights,chosen in (([1,1,1,1,100],online),([100,100,100,1,1],roster[:3]),([1,1,1,1,2],online),([2**127]*5,online)):
   with self.subTest(weights=weights),self.assertRaises(ValueError):layout.require_online_quorum(roster,dict(zip(roster,map(str,weights))),chosen)
  with self.assertRaises(ValueError):self.validate(subset(3),subset(3)['observations'][0])
  for raw in ('0','01','-1',True,str(2**128)):
   weights={a:'100' for a in roster};weights[roster[0]]=raw
   with self.assertRaises(ValueError):layout.require_online_quorum(roster,weights,online)
 def test_scope_discovery_cannot_qualify_and_missing_edges_expiry_or_forgery_rejected(self):
  changes=[lambda v:v.update(online_addresses=[]),lambda v:v.update(excluded_addresses=[]),
   lambda v:v['observations'][1].update(online_addresses=self.local['validator_addresses']),
   lambda v:v['observations'][1].update(observation_kind='metadata_only'),
   lambda v:v['observations'][1]['frozen_voting_weights'].update(synv14='1'),
   lambda v:v['observations'][1]['peers'].pop('synv10'),
   lambda v:v['observations'][1].update(manifest_sha256='f'*64),
   lambda v:v['observations'][1].update(validator_addresses=['foreign']),
   lambda v:v['observations'][1]['public_file_sha256'].update({'genesis.json':'f'*64})]
  for change in changes:
   bad=copy.deepcopy(self.value);change(bad)
   with self.assertRaises((ValueError,KeyError)):self.validate(bad)
  for now in (969,1301):
   with self.assertRaises(ValueError):self.validate(now=now)
 def test_signed_authority_weights_not_caller_claims(self):
  roster=self.local['validator_addresses'];authority={'validators':[{'record':{'validator_id':a,'frozen_voting_weight':100,'status':'active'}} for a in roster]}
  self.assertEqual(layout.signed_voting_weights(authority,roster),self.local['frozen_voting_weights'])
  for field,value in (('frozen_voting_weight',0),('frozen_voting_weight',True),('frozen_voting_weight',2**128),('status','inactive'),('validator_id',roster[1])):
   bad=copy.deepcopy(authority);bad['validators'][0]['record'][field]=value
   with self.assertRaises(ValueError):layout.signed_voting_weights(bad,roster)
 def test_startup_truthfully_declares_subset_and_checks_retained_provenance(self):
  draft={'validator_addresses':self.local['validator_addresses'],'all_validators_ready':False,'all_pairs_vpn_verified':False}
  raw=controller.canonical(self.value);pin=hashlib.sha256(raw).hexdigest()
  policy=layout.readiness_startup_policy(draft,self.value,pin)
  self.assertFalse(policy['all_validators_ready']);self.assertFalse(policy['all_pairs_vpn_verified'])
  self.assertTrue(policy['quorum_validators_ready']);self.assertTrue(policy['online_pairs_vpn_verified'])
  self.assertEqual(policy['unobserved_validator_addresses'],['synv14'])
  with tempfile.TemporaryDirectory() as directory:
   root=Path(directory).resolve()/'synergy';root.mkdir(mode=0o700);owner=controller.Controller(root)
   save(owner.control/'authorization/inputs'/layout.READINESS_FILE,raw)
   draft_raw=controller.canonical(draft);save(owner.control/'authorization/inputs/commissioning/config/start-authorized.json',draft_raw)
   authority={'payload':{'validators':[{'record':{'validator_id':a,'frozen_voting_weight':100,'status':'active'}} for a in draft['validator_addresses']]}}
   save(root/'network/authority.json',authority)
   approved={'authorization_files':{layout.READINESS_FILE:pin},'validator_commissioning_files':{'config/start-authorized.json':hashlib.sha256(draft_raw).hexdigest()}}
   with patch.object(controller.Controller,'policy',return_value=approved):
    self.assertTrue(layout.startup_readiness_authorized(root,policy,'synv10'))
    stage=root/'tmp/commissioning';save(stage/'network/authority.json',authority)
    (root/'network/authority.json').unlink()
    self.assertTrue(layout.startup_readiness_authorized(root,policy,'synv10',authority_source=stage))
    save(root/'network/authority.json',authority)
    with self.assertRaisesRegex(ValueError,'Unobserved'):layout.startup_readiness_authorized(root,policy,'synv14')
    changed=copy.deepcopy(policy);changed['all_validators_ready']=True
    with self.assertRaises(ValueError):layout.startup_readiness_authorized(root,changed,'synv10')
    authority['payload']['validators'][0]['record']['frozen_voting_weight']=1;save(root/'network/authority.json',authority)
    with self.assertRaisesRegex(ValueError,'weights'):layout.startup_readiness_authorized(root,policy,'synv10')
 def test_real_observation_discovery_has_no_probes_then_exact_subset_three_probes(self):
  h=fixtures.ObservationTests('test_actual_native_staging_bytes_and_twenty_edge_contribution');h.setUp();self.addCleanup(h.tearDown)
  discover=h.run_observation(online=[]);self.assertEqual(discover['observation_kind'],'metadata_only');self.assertEqual(discover['peers'],{});self.assertEqual(h.probes,[])
  online=discover['validator_addresses'][:4]
  actual=h.run_observation(online=online);self.assertEqual(actual['observation_kind'],'prestart_vpn');self.assertEqual(len(h.probes),3);self.assertNotIn('100.97.0.5',h.probes)
  with self.assertRaises(ValueError):h.run_observation(online=online[:3])
  request={'version':1,'operation':'commissioning_observation','parameters':{'online_addresses':online}}
  self.assertEqual(controller.parse_request(controller.canonical(request)),request)
  request['parameters']['online_addresses']=online+online[:1]
  with self.assertRaises(ValueError):controller.parse_request(controller.canonical(request))

if __name__=='__main__':unittest.main()
