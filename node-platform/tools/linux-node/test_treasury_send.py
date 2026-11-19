"""Offline integration boundaries; retained keytool fixture qualifies real APQE."""
import copy,hashlib,json,tempfile,unittest
from pathlib import Path
from contextlib import nullcontext
from unittest.mock import patch
import controller
import treasury_send as t
SCOPE={'formation_sha256':'a'*64,'network_id':'fresh-engineering','chain_id':'999998'}
SENDER='syna1publicsender';RECEIVER='syna1publicreceiver'
GENESIS=t.canonical({'genesis_hash':'9'*64,'unsigned':{'fixture':True}})
def prepared():return {'schema':'nodenetwork-formation-treasury-send-v1','request_sha256':'b'*64,'formation_sha256':'a'*64,'genesis_sha256':hashlib.sha256(GENESIS).hexdigest(),'transaction_id':'c'*64,'receipt_id':'d'*128,'admission_sha256':'e'*64,'sender':SENDER,'receiver':RECEIVER,'amount_nwei':'1','nonce':0,'fee_nwei':'840000','state':'prepared','automatic_retry':False}
class TreasurySendTests(unittest.TestCase):
 def test_strict_request_scope_amount_and_no_foreign_url(self):
  r={'version':1,'operation':'treasury_send_preflight','parameters':{'receiver':RECEIVER,'amount_nwei':'1'}}
  self.assertEqual(controller.parse_request(t.canonical(r)),r)
  for p in ({'receiver':RECEIVER,'amount_nwei':'01'},{'receiver':RECEIVER,'amount_nwei':True},{'receiver':RECEIVER,'amount_nwei':'1','url':'http://foreign'}):
   with self.assertRaises(ValueError):controller.parse_request(t.canonical({**r,'parameters':p}))
  for p in ({'nonce':True},{'nonce':'0'},{'nonce':2**64-1}):
   with self.assertRaises(ValueError):t.validate('treasury_send_status',p)
 def test_foreign_rpc_listener_refuses_before_proc_network(self):
  with patch('lifecycle._attributed_units',return_value={'synergy-node.service':{'MainPID':'42','ActiveState':'active'}}):
   for address in ('example.com:1234','100.97.1.1:1234','127.0.0.1:0','127.0.0.1:1234/path'):
    with self.assertRaises(ValueError):t.listener(Path('/not-accessed'),{'rpc':{'enabled':True,'listen_address':address}})
 def test_live_identity_requires_network_chain_genesis_and_process(self):
  rpc=object.__new__(t.LocalRpc);rpc.scope=SCOPE;rpc.genesis='f'*64;rpc.pid=42
  good={'network_identity':SCOPE['network_id'],'chain_id':999998,'genesis_hash':'f'*64,'process_id':42}
  rpc.call=lambda *_:good;self.assertEqual(rpc.verify(),good)
  for key,value in [('network_identity','foreign'),('chain_id',99999),('genesis_hash','0'*64),('process_id',43)]:
   bad={**good,key:value};rpc.call=lambda *_,bad=bad:bad
   with self.assertRaises(ValueError):rpc.verify()
 def run_fixture(self,op,p,record=None,post_error=False,account_nonce=0,finalized=False):
  temp=tempfile.TemporaryDirectory();self.addCleanup(temp.cleanup);root=Path(temp.name);(root/'network').mkdir();(root/'network/genesis.json').write_bytes(GENESIS);(root/'tmp').mkdir()
  self.authorized=[];self.posts=[];self.native_calls=[];record=record or prepared()
  class C:
   def __init__(inner):inner.root=root
   def formation_context(inner):return SCOPE,[]
   def formation_context_path(inner):return root/'context'
   def direct(inner,path,private):return path
   def authorize(inner,r):self.authorized.append(copy.deepcopy(r))
  class Rpc:
   def __init__(inner,c,scope,genesis):
    self.assertEqual(genesis,'9'*64);self.assertNotEqual(genesis,hashlib.sha256(GENESIS).hexdigest())
   def verify(inner):return {}
   def call(inner,method,params):
    if method=='synergy_getAccount':return {'address':params['address'],'nonce':(1 if params['address']==SENDER else 0) if finalized else account_nonce,'balance_nwei':'4999999999159999' if params['address']==SENDER and finalized else '1' if finalized else '5000000000000000','finalized_height':params.get('at_height') or 3,'finalized_block_hash':'1'*64,'state_root':'2'*64}
    if method=='synergy_getProcessingContextV1':return {'profile_id':'fixture'}
    if method=='synergy_submitProcessingTransactionV1':
     self.posts.append(copy.deepcopy(params))
     if post_error:raise OSError('lost reply')
     return {}
    if method=='synergy_getTransaction':return {'transaction_id':record['transaction_id'],'status':'applied','block_height':6,'block_hash':'1'*64,'finality_certificate_id':'3'*64} if finalized else None
    raise AssertionError(method)
  def native(args,**_):
   self.native_calls.append(args[1]);command=args[1]
   if command=='review-formation-treasury':return t.canonical({'possession_verified':True,**SCOPE,'address':SENDER})
   if command=='review-formation-treasury-send':return t.canonical(record)
   if command=='take-formation-treasury-send':
    if record['state']!='prepared':raise ValueError('fenced')
    record['state']='dispatch_unknown';return t.canonical({**record,'admission':{'request':{'encrypted':'ciphertext'},'identity_authorization':{'public':'carrier'}}})
   if command=='prepare-formation-treasury-send':
    r=json.loads(Path(args[5]).read_bytes());self.assertEqual(args[6],hashlib.sha256(t.canonical(r)).hexdigest());record['request_sha256']=args[6];return t.canonical(record)
   raise AssertionError(command)
  with patch('lifecycle._lifecycle_lock',return_value=nullcontext()),patch.object(t,'LocalRpc',Rpc),patch('synergy_linux.native',side_effect=native):return t.run(C(),{'version':1,'operation':op,'parameters':p})
 def test_original_intent_status_returns_both_finalized_balances_without_submit(self):
  result=self.run_fixture('treasury_send_status',{'nonce':0},finalized=True)
  self.assertEqual(result['account_observations']['sender']['balance_nwei'],'4999999999159999')
  self.assertEqual(result['account_observations']['receiver']['balance_nwei'],'1')
  self.assertEqual(result['account_observations']['receiver']['finalized_height'],result['finalized_observation']['block_height'])
  self.assertEqual(self.posts,[]);self.assertEqual(self.authorized,[])
 def test_finalized_accounts_share_exact_transaction_block_and_state(self):
  current=prepared();f={'status':'applied','block_height':6,'block_hash':'1'*64};calls=[]
  values={address:{'address':address,'balance_nwei':balance,'nonce':n,'finalized_height':6,'finalized_block_hash':'1'*64,'state_root':'2'*64,'authorization_binding':{'not':'exported'}} for address,balance,n in [(SENDER,'4999999999159999',1),(RECEIVER,'1',0)]}
  class Rpc:
   def call(inner,method,params):calls.append((method,params));return values[params['address']]
  rpc=Rpc();result=t.finalized_accounts(rpc,current,f)
  self.assertEqual(result['receiver']['balance_nwei'],'1');self.assertNotIn('authorization_binding',result['sender'])
  self.assertEqual(calls,[('synergy_getAccount',{'address':address,'at_height':6}) for address in (SENDER,RECEIVER)])
  for address,field,value in [(RECEIVER,'finalized_height',7),(RECEIVER,'finalized_block_hash','0'*64),(RECEIVER,'state_root','0'*64),(SENDER,'address',RECEIVER),(SENDER,'nonce',0),(SENDER,'nonce',True),(RECEIVER,'nonce','0'),(RECEIVER,'balance_nwei','01'),(RECEIVER,'balance_nwei',str(2**128))]:
   old=values[address][field];values[address][field]=value
   with self.assertRaises(ValueError):t.finalized_accounts(rpc,current,f)
   values[address][field]=old
  values[SENDER]['nonce']=2 # Later same-block transactions may also consume nonce.
  self.assertEqual(t.finalized_accounts(rpc,current,f)['sender']['nonce'],2)
  values[RECEIVER]=None
  with self.assertRaises(ValueError):t.finalized_accounts(rpc,current,f)
  calls.clear()
  self.assertIsNone(t.finalized_accounts(rpc,current,None));self.assertIsNone(t.finalized_accounts(rpc,current,{**f,'status':'reverted'}));self.assertEqual(calls,[])
 def test_autonomous_quote_requires_exact_native_owner_commitments(self):
  with tempfile.TemporaryDirectory() as temp:
   root=Path(temp);(root/'tmp').mkdir()
   c=type('C',(),{'root':root})()
   raw=t.canonical({'context':{'authority':{'epoch':2}}}).decode()
   request={'version':1,'operation':'treasury_send_prepare','parameters':{'genesis_sha256':'a'*64,'processing_context_json':raw,'processing_context_sha256':hashlib.sha256(raw.encode()).hexdigest()}}
   calls=[]
   def checked(args,**kwargs):
    calls.append(args);self.assertEqual(args[:4],[root/'bin/synergy-node','authority-successor','check-processing-context',root/'config/node.json']);self.assertEqual(kwargs['maximum_stdout'],8192)
    exact=Path(args[4]).read_bytes();self.assertEqual(exact,t.canonical(request))
    return t.canonical({'schema':'nodenetwork-verified-treasury-context-v1','request_sha256':hashlib.sha256(exact).hexdigest(),'genesis_sha256':'a'*64,'processing_context_sha256':request['parameters']['processing_context_sha256'],'epoch':2})
   with patch('synergy_linux.native',side_effect=checked):self.assertEqual(t.verify_lineage(c,request),'signed-formation-autonomous-lineage-v1')
   self.assertEqual(len(calls),1);self.assertEqual(list((root/'tmp').iterdir()),[])
   for field,value in [('schema','foreign'),('request_sha256','0'*64),('genesis_sha256','0'*64),('processing_context_sha256','0'*64),('epoch',3)]:
    def wrong(args,field=field,value=value,**kwargs):
     result=json.loads(checked(args,**kwargs));result[field]=value;return t.canonical(result)
    with patch('synergy_linux.native',side_effect=wrong):
     with self.assertRaisesRegex(ValueError,'Native autonomous'):t.verify_lineage(c,request)
    self.assertEqual(list((root/'tmp').iterdir()),[])
 def test_take_precedes_single_lost_reply_no_reexport(self):
  record=prepared();result=self.run_fixture('treasury_send_submit',{'nonce':0,'request_sha256':'b'*64},record,True)
  self.assertEqual(len(self.posts),1);self.assertEqual(result['prepared']['state'],'dispatch_unknown');self.assertIsNone(result['finalized_observation']);self.assertNotIn('admission',result)
  with self.assertRaisesRegex(ValueError,'uncertain dispatch cannot retry'):self.run_fixture('treasury_send_submit',{'nonce':0,'request_sha256':'b'*64},record)
  self.assertEqual(self.posts,[]);self.assertNotIn('take-formation-treasury-send',self.native_calls)
 def test_status_never_takes_or_submits_and_disclosure_refuses(self):
  result=self.run_fixture('treasury_send_status',{'nonce':0});self.assertEqual(result['prepared']['nonce'],0);self.assertEqual(self.posts,[]);self.assertEqual(self.authorized,[])
  bad=prepared();bad['admission']={}
  with self.assertRaises(ValueError):self.run_fixture('treasury_send_status',{'nonce':0},bad)
 def test_quote_exact_prepare_and_changed_nonce_scope_time_refuse(self):
  quote=self.run_fixture('treasury_send_preflight',{'receiver':RECEIVER,'amount_nwei':'1'});p=quote['request']['parameters']
  self.assertEqual(quote['authority_coverage'],'signed-formation-e1-only');self.assertEqual(self.authorized,[])
  result=self.run_fixture('treasury_send_prepare',p);self.assertEqual(result['request_sha256'],hashlib.sha256(t.canonical(quote['request'])).hexdigest());self.assertEqual(self.posts,[])
  with self.assertRaisesRegex(ValueError,'account changed'):self.run_fixture('treasury_send_prepare',p,account_nonce=1)
  self.assertEqual(self.authorized,[])
  for key,value in [('formation_sha256','f'*64),('genesis_sha256','f'*64),('timestamp_unix',1),('processing_context_sha256','f'*64)]:
   with self.assertRaises(ValueError):self.run_fixture('treasury_send_prepare',{**p,key:value})
if __name__=='__main__':unittest.main()
