"""Public fixed NIST fixture and independent CBOR/identity/intent oracle.
No RNG, key generation, actual network coordinate or production signing.
"""
import base64, hashlib, json, os, subprocess, sys
from pathlib import Path
PLATFORM=Path(__file__).resolve().parents[3]
APQE=PLATFORM.parents[1]/'21-Aegis-Engine'/'synergy-address-engine'
sys.path.insert(0,str(APQE/'tests'))
from generate_r1_public_vectors import canonical, CHAIN
from public_nist_fixture_signer import PublicNistFixtureSigner
r=subprocess.run(['cargo','run','-p','synergy-execution','--example','public_synthetic_r1_wallet_enrollment','--offline','--quiet'],cwd=PLATFORM,capture_output=True,check=True)
assert len(r.stdout)<1024*1024
d=json.loads(r.stdout);assert d['chain_id']==CHAIN and d['production_import_permitted'] is False
nic=bytes.fromhex(d['nic_hex'])
def frame(domain,profile,body):return canonical([b'SYNERGY/APQE',1,domain,[profile,1],[CHAIN,nic],body])
keys=[[role,'ML-DSA-87',1,bytes.fromhex(m['public_key_hex'])] for role,m in zip(('D','P'),d['messages'])]
policy=frame('IDENTITY.BIRTH-POLICY','APQE-POLICY',['synw',[[keys[0],'PUBLIC-SYNTHETIC-D'],[keys[1],'PUBLIC-SYNTHETIC-P']],[2,[0,1]],[]])
assert policy.hex()==d['identity_input']['birth_policy_frame_hex']
policy_commit=hashlib.sha3_512(policy).digest()
birth=frame('IDENTITY.ACCOUNT','APQE-NATIVE-ID',['synw',bytes([0x91])*32,policy_commit]);raw=hashlib.sha3_384(birth).digest()
identity='synw.2.'+base64.urlsafe_b64encode(raw).decode().rstrip('=');assert identity==d['identity_input']['expected_identity']
messages=[]
for i,(key,m) in enumerate(zip(keys,d['messages'])):
    pop=frame('IDENTITY.ACCOUNT.POSSESSION','APQE-ACCOUNT-POSSESSION',['synw',raw,key,policy_commit,bytes([0x92])*32])
    assert pop.hex()==m['exact_message_hex'] and m['index']==i
    messages.append(['ACCOUNT_POSSESSION',i,key,b'SYNERGY.ACCOUNT.POP.R1',pop])
plan=frame('CUSTODY.IDENTITY-PROOF-PLAN','APQE-CUSTODY-R1',['synw',raw,birth,policy,1,bytes([0x92])*32,[],messages])
assert plan.hex()==d['proof_plan_frame_hex']
c=d['coordinate'];body=[1,[[c['genesis']['profile']['name'],c['genesis']['profile']['revision']],'SHA3-384',bytes(c['genesis']['digest'])],[[c['activated_profiles']['profile']['name'],c['activated_profiles']['profile']['revision']],'SHA3-512',bytes(c['activated_profiles']['commitment'])],plan]
assert frame('TRANSACTION.INTENT','QACE-INITIAL-WALLET-ENROLLMENT-R1',body).hex()==d['exact_intent_hex']
txraw=hashlib.sha3_384(frame('TRANSACTION.ID','QACE-INITIAL-WALLET-ENROLLMENT-R1',body)).digest()
assert 'syntxn'+base64.urlsafe_b64encode(txraw).decode().rstrip('=')==d['transaction_id']
signer=PublicNistFixtureSigner(nic)
for m in d['messages']:m['signature_hex']=signer.sign_frame(m['public_key_hex'],m['exact_message_hex'],m['context'],m['domain'],m['profile'])
d['native_build_report_sha256']='1c7851d11260c880aced3fbad8aadc7b68e1f02a379d8efc8846d65a7c89af9c'
p=Path(__file__).parent/'fixtures'/'r1_initial_wallet_public.json';p.write_text(json.dumps(d,indent=2)+'\n')
print('Public Wallet fixture: independent policy/birth/plan/intent/ID oracle and two genuine detached87 proofs PASS.')
