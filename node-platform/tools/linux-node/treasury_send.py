"""Custody-backed ordinary engineering transfers; no remote URL or replay path.

RPC balance/nonce are finalized local-node observations, not account proofs.
The keytool independently authenticates the encryption registry against signed
formation Genesis. Only its one-use take can expose ciphertext, to this module.
Autonomous contexts are checked by the existing native authority owner, not by
trusting a newer epoch number or an RPC-provided encryption registry.
"""
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import tempfile
import time

LIMIT=2*1024*1024
PREPARE_FIELDS={'formation_sha256','genesis_sha256','processing_context_json','processing_context_sha256','receiver','amount_nwei','nonce','observed_balance_nwei','timestamp_unix'}

def require(value,message):
    if not value:raise ValueError(message)

def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def pin(value):return isinstance(value,str) and re.fullmatch('[a-f0-9]{64}',value) is not None
def nonce(value):return type(value) is int and 0<=value<2**64-1

def transfer(parameters):
    require(isinstance(parameters,dict) and set(parameters)=={'receiver','amount_nwei'},'Exact transfer recipient and nWei amount required')
    require(isinstance(parameters['receiver'],str) and re.fullmatch('syna1[a-z0-9]{10,123}',parameters['receiver']),'Ordinary syna recipient required')
    value=parameters['amount_nwei']
    require(isinstance(value,str) and re.fullmatch('[1-9][0-9]{0,38}',value) and int(value)<2**128,'Positive canonical u128 nWei required')

def validate(operation,p):
    if operation=='treasury_send_preflight':transfer(p)
    elif operation=='treasury_send_prepare':
        require(set(p)==PREPARE_FIELDS,'Exact immutable treasury send required')
        transfer({k:p[k] for k in ('receiver','amount_nwei')})
        require(pin(p['formation_sha256']) and pin(p['genesis_sha256']) and pin(p['processing_context_sha256']) and nonce(p['nonce']) and type(p['timestamp_unix']) is int and 0<p['timestamp_unix']<2**53,'Invalid treasury scope, nonce or timestamp')
        require(isinstance(p['observed_balance_nwei'],str) and re.fullmatch('0|[1-9][0-9]{0,38}',p['observed_balance_nwei']) and int(p['observed_balance_nwei'])<2**128,'Invalid observed balance')
        raw=p['processing_context_json']
        require(isinstance(raw,str) and 0<len(raw.encode())<=1024*1024 and hashlib.sha256(raw.encode()).hexdigest()==p['processing_context_sha256'],'Exact bounded processing context required')
    else:
        require(operation in ('treasury_send_status','treasury_send_submit') and set(p)==({'nonce'} if operation.endswith('status') else {'nonce','request_sha256'}) and nonce(p['nonce']),'Exact treasury nonce required')
        if operation.endswith('submit'):require(pin(p['request_sha256']),'Exact prepared request pin required')

def listener(root,config):
    """Prove the numeric local listener belongs to the attributed node PID."""
    import lifecycle as life
    state=life._attributed_units(root).get('synergy-node.service',{})
    pid=state.get('MainPID')
    require(state.get('ActiveState')=='active' and isinstance(pid,str) and pid.isdecimal() and int(pid)>0,'Treasury RPC requires an active attributed validator')
    rpc=config.get('rpc',{});address=rpc.get('listen_address')
    require(rpc.get('enabled') is True and isinstance(address,str),'Configured local native RPC required')
    host,separator,port=address.rpartition(':')
    require(separator and host in ('127.0.0.1','0.0.0.0') and port.isdecimal() and 0<int(port)<65536,'Treasury requires a local IPv4 native RPC listener')
    inodes=set()
    for fd in (Path('/proc')/pid/'fd').iterdir():
        try:target=os.readlink(fd)
        except FileNotFoundError:continue
        match=re.fullmatch(r'socket:\[([0-9]+)\]',target)
        if match:inodes.add(match[1])
    expected=('0100007F' if host=='127.0.0.1' else '00000000')+':'+format(int(port),'04X')
    rows=(Path('/proc')/pid/'net/tcp').read_text().splitlines()[1:]
    require(any(len(fields:=row.split())>9 and fields[1]==expected and fields[3]=='0A' and fields[9] in inodes for row in rows),'Configured RPC listener is not owned by the attributed validator')
    return int(pid),int(port)

class LocalRpc:
    def __init__(self,controller,scope,genesis):
        self.controller=controller;self.scope=scope;self.genesis=genesis
        config=controller.public_json(controller.root/'config/node.json',True)
        self.pid,self.port=listener(controller.root,config)
    def call(self,method,params):
        allowed={'synergy_chainTelemetry','synergy_getProcessingContextV1','synergy_getAccount','synergy_getTransaction','synergy_submitProcessingTransactionV1'}
        require(method in allowed,'Unsupported treasury RPC method')
        # Recheck ownership before every exchange, including the one-use send.
        config=self.controller.public_json(self.controller.root/'config/node.json',True)
        require(listener(self.controller.root,config)==(self.pid,self.port),'RPC ownership changed')
        raw=canonical({'jsonrpc':'2.0','id':1,'method':method,'params':params})
        require(len(raw)<=LIMIT,'RPC request exceeds bound')
        connection=http.client.HTTPConnection('127.0.0.1',self.port,timeout=10)
        try:
            connection.request('POST','/rpc',body=raw,headers={'Content-Type':'application/json','Connection':'close'})
            response=connection.getresponse();body=response.read(LIMIT+1)
            require(response.status==200 and len(body)<=LIMIT,'Bounded native RPC response required')
            value=json.loads(body)
            require(isinstance(value,dict) and value.get('jsonrpc')=='2.0' and type(value.get('id')) is int and value['id']==1 and set(value)=={'jsonrpc','id','result'},'Native RPC refused or returned an ambiguous response')
            return value['result']
        finally:connection.close()
    def verify(self):
        value=self.call('synergy_chainTelemetry',{})
        require(value.get('network_identity')==self.scope['network_id'] and value.get('chain_id')==int(self.scope['chain_id']) and value.get('genesis_hash')==self.genesis and value.get('process_id')==self.pid,'Live RPC differs from authenticated formation/network/Genesis/process')
        return value

def receipt(value,scope,nonce_value):
    fields={'schema','request_sha256','formation_sha256','genesis_sha256','transaction_id','receipt_id','admission_sha256','sender','receiver','amount_nwei','nonce','fee_nwei','state','automatic_retry'}
    require(isinstance(value,dict) and set(value)==fields and value['schema']=='nodenetwork-formation-treasury-send-v1' and value['formation_sha256']==scope['formation_sha256'] and value['nonce']==nonce_value and value['state'] in ('prepared','dispatch_unknown') and value['automatic_retry'] is False and value['fee_nwei']=='840000','Invalid native treasury send receipt')
    require(all(pin(value[k]) for k in ('request_sha256','genesis_sha256','transaction_id','admission_sha256')) and isinstance(value['receipt_id'],str) and re.fullmatch('[a-f0-9]{128}',value['receipt_id']),'Invalid native send commitments')
    transfer({k:value[k] for k in ('receiver','amount_nwei')})
    return value

def finalized_accounts(rpc,current,finalized):
    """Same-block local finalized observations, never a Merkle/account proof."""
    if finalized is None or finalized['status']!='applied':return None
    views={}
    for role in ('sender','receiver'):
        address=current[role]
        value=rpc.call('synergy_getAccount',{'address':address,'at_height':finalized['block_height']})
        require(isinstance(value,dict) and value.get('address')==address
            and type(value.get('finalized_height')) is int and value['finalized_height']==finalized['block_height']
            and value.get('finalized_block_hash')==finalized['block_hash'] and pin(value.get('state_root'))
            and nonce(value.get('nonce')) and isinstance(value.get('balance_nwei'),str)
            and re.fullmatch('0|[1-9][0-9]{0,38}',value['balance_nwei']) and int(value['balance_nwei'])<2**128,
            'Same-finalized-block treasury account observation unavailable')
        views[role]={key:value[key] for key in ('address','balance_nwei','nonce','finalized_height','finalized_block_hash','state_root')}
    require(views['sender']['state_root']==views['receiver']['state_root']
        and views['sender']['nonce']>=current['nonce']+1,
        'Finalized treasury accounts differ in state context or consumed nonce')
    return {'schema':'nodenetwork-treasury-accounts-v1',**views}

def verify_lineage(controller,request):
    from synergy_linux import native
    p=request['parameters'];response=json.loads(p['processing_context_json'])
    epoch=response.get('context',{}).get('authority',{}).get('epoch')
    if type(epoch) is not int or epoch<=1:return 'signed-formation-e1-only'
    with tempfile.TemporaryDirectory(prefix='treasury-context-',dir=controller.root/'tmp') as scratch:
        path=Path(scratch)/'request.json'
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        raw=canonical(request)
        with os.fdopen(fd,'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
        result=json.loads(native([controller.root/'bin/synergy-node','authority-successor','check-processing-context',controller.root/'config/node.json',path],maximum_stdout=8192))
    require(isinstance(result,dict) and result.get('schema')=='nodenetwork-verified-treasury-context-v1'
        and result.get('request_sha256')==hashlib.sha256(raw).hexdigest()
        and result.get('genesis_sha256')==p['genesis_sha256']
        and result.get('processing_context_sha256')==p['processing_context_sha256']
        and result.get('epoch')==epoch,'Native autonomous treasury context differs')
    return 'signed-formation-autonomous-lineage-v1'

def run(controller,request):
    import lifecycle as life
    from synergy_linux import native
    operation=request['operation'];p=request['parameters'];validate(operation,p)
    with life._lifecycle_lock(controller.root):
        scope,flags=controller.formation_context()
        root=controller.root;treasury=root/'keys/formation-treasury'
        # Keytool verifies the signed formation and decrypts custody privately.
        treasury_public=json.loads(native([root/'bin/synergy-keytool','review-formation-treasury',controller.formation_context_path(),scope['formation_sha256'],treasury,*flags],maximum_stdout=128*1024))
        require(treasury_public.get('possession_verified') is True and all(treasury_public.get(k)==scope[k] for k in ('formation_sha256','network_id','chain_id')),'Treasury custody scope differs')
        genesis_raw=controller.direct(root/'network/genesis.json',True).read_bytes()
        genesis=hashlib.sha256(genesis_raw).hexdigest()
        logical_genesis=json.loads(genesis_raw).get('genesis_hash')
        require(pin(logical_genesis),'Signed logical Genesis commitment required')
        # Artifact SHA binds custody/keytool input; runtime reports the signed
        # logical genesis_hash. They are distinct commitments, never aliases.
        rpc=LocalRpc(controller,scope,logical_genesis);rpc.verify()
        def account():
            value=rpc.call('synergy_getAccount',{'address':treasury_public['address'],'at_height':None})
            require(isinstance(value,dict) and value.get('address')==treasury_public['address'] and nonce(value.get('nonce')) and type(value.get('finalized_height')) is int and value['finalized_height']>0 and pin(value.get('finalized_block_hash')) and pin(value.get('state_root')),'Finalized treasury account unavailable')
            require(isinstance(value.get('balance_nwei'),str) and re.fullmatch('0|[1-9][0-9]{0,38}',value['balance_nwei']) and int(value['balance_nwei'])<2**128,'Invalid finalized account balance')
            return value
        if operation=='treasury_send_preflight':
            observed=account();context=rpc.call('synergy_getProcessingContextV1',{})
            raw=canonical(context).decode()
            immutable={'formation_sha256':scope['formation_sha256'],'genesis_sha256':genesis,'processing_context_json':raw,'processing_context_sha256':hashlib.sha256(raw.encode()).hexdigest(),**p,'nonce':observed['nonce'],'observed_balance_nwei':observed['balance_nwei'],'timestamp_unix':int(time.time())}
            validate('treasury_send_prepare',immutable)
            prepared_request={'version':1,'operation':'treasury_send_prepare','parameters':immutable}
            coverage=verify_lineage(controller,prepared_request)
            return {'schema':'nodenetwork-treasury-send-preflight-v1','sender':treasury_public['address'],'network_id':scope['network_id'],'chain_id':scope['chain_id'],'finalized_height':observed['finalized_height'],'request':prepared_request,'authority_coverage':coverage,'fee_nwei':'840000'}
        if operation=='treasury_send_prepare':
            require(p['formation_sha256']==scope['formation_sha256'] and p['genesis_sha256']==genesis and 0<=time.time()-p['timestamp_unix']<=120,'Treasury review expired or scope changed')
            observed=account()
            require(observed['nonce']==p['nonce'] and observed['balance_nwei']==p['observed_balance_nwei'],'Treasury account changed; review a fresh immutable intent')
            controller.authorize(request)
            with tempfile.TemporaryDirectory(prefix='treasury-send-',dir=root/'tmp') as scratch:
                path=Path(scratch)/'request.json'
                fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
                with os.fdopen(fd,'wb') as stream:stream.write(canonical(request));stream.flush();os.fsync(stream.fileno())
                result=json.loads(native([root/'bin/synergy-keytool','prepare-formation-treasury-send',controller.formation_context_path(),scope['formation_sha256'],root/'tmp/network-formation',path,hashlib.sha256(canonical(request)).hexdigest(),treasury,*flags],maximum_stdout=128*1024))
            verified=receipt(result,scope,p['nonce'])
            require(verified['request_sha256']==hashlib.sha256(canonical(request)).hexdigest() and verified['sender']==treasury_public['address'] and verified['genesis_sha256']==genesis,'Prepared immutable intent differs')
            return verified
        current=receipt(json.loads(native([root/'bin/synergy-keytool','review-formation-treasury-send',treasury,str(p['nonce']),*flags],maximum_stdout=128*1024)),scope,p['nonce'])
        require(current['sender']==treasury_public['address'] and current['genesis_sha256']==genesis,'Prepared treasury origin changed')
        if operation=='treasury_send_submit':
            require(current['state']=='prepared' and current['request_sha256']==p['request_sha256'],'Exact prepared unconsumed intent required; uncertain dispatch cannot retry')
            controller.authorize(request)
            # Durable native take fence precedes the ONLY network submission.
            taken=json.loads(native([root/'bin/synergy-keytool','take-formation-treasury-send',treasury,str(p['nonce']),p['request_sha256'],*flags],maximum_stdout=LIMIT))
            admission=taken.pop('admission',None)
            require(receipt(taken,scope,p['nonce'])=={**current,'state':'dispatch_unknown'} and isinstance(admission,dict),'One-use admission differs from prepared receipt')
            # Admission is never returned to the caller, including on refusal.
            rpc.verify()
            try:rpc.call('synergy_submitProcessingTransactionV1',admission)
            except (ValueError,OSError,http.client.HTTPException):pass
            current=taken
        finalized=rpc.call('synergy_getTransaction',{'transaction_id':current['transaction_id']})
        observation=None
        if finalized is not None:
            require(isinstance(finalized,dict) and finalized.get('transaction_id')==current['transaction_id'] and finalized.get('status') in ('applied','reverted') and type(finalized.get('block_height')) is int and finalized['block_height']>0 and pin(finalized.get('block_hash')) and pin(finalized.get('finality_certificate_id')),'Malformed finalized transaction observation')
            observation={k:finalized[k] for k in ('transaction_id','block_height','block_hash','finality_certificate_id','status')}
        return {'schema':'nodenetwork-treasury-send-status-v1','prepared':current,'finalized_observation':observation,'account_observations':finalized_accounts(rpc,current,observation),'automatic_retry':False}
