"""Independent fixed public C14N02 payload oracle; no keys/network/authority."""
import hashlib,json,struct
from pathlib import Path
u16=lambda n:struct.pack('>H',n)
u32=lambda n:struct.pack('>I',n)
u64=lambda n:struct.pack('>Q',n)
u128=lambda n:n.to_bytes(16,'big')
blob=lambda b:u32(len(b))+b
profile=lambda name:blob(name.encode('ascii'))+u32(1)
digest=lambda n:bytes([n])*48
coordinate=u64(2**64-2)+bytes([1])*64+profile('SYNERGY-GENESIS-R1')+digest(2)+profile('APQE-PROFILE-SET')+bytes([3])*64
# One ordinary user and one mandatory post-user system transition. Empty
# protected list means no fabricated PEC for this nonprotected codec fixture.
core=u16(3)+coordinate+u64(1)+u64(1)+b''.join(digest(n) for n in range(4,10))
core+=u32(1)+bytes([0])+digest(10)
core+=u32(1)+bytes([1])+u32(0)+digest(11)+u16(1)+digest(12)+digest(13)
H=lambda tag,body:hashlib.sha3_384(u16(2)+blob(tag.encode('ascii'))+body).digest()
txleaf=H('QACE/TXN-LEAF/02',u32(0)+bytes([0])+digest(10))
txroot=H('QACE/TXN-ROOT/02',u32(1)+txleaf)
core+=u32(0)+txroot+digest(15)+digest(16)
core+=b''.join(u64(n) for n in [7,11,13,17,19,23])
core+=b''.join(u128(n) for n in [7,5,2,4,1,0,0])+digest(17)+digest(18)
wrapped=u16(2)+blob(b'QACE/EXECUTION/03')+core
p=Path(__file__).parent/'fixtures/r1_payload_public.json'
def txroot(count):
    if not count:return H('QACE/TXN-EMPTY/02',u32(0))
    m=1<<(count-1).bit_length()
    layer=[H('QACE/TXN-LEAF/02',u32(i)+bytes([i%2])+digest(i+1)) if i<count else H('QACE/TXN-PAD/02',u32(i)) for i in range(m)]
    level=1
    while len(layer)>1:
        layer=[H('QACE/TXN-NODE/02',u32(level)+layer[i]+layer[i+1]) for i in range(0,len(layer),2)]
        level+=1
    return H('QACE/TXN-ROOT/02',u32(count)+layer[0])
cases=[{'count':n,'root_hex':txroot(n).hex()} for n in [0,1,3,9]]
p.write_text(json.dumps({'transaction_cases':cases,'purpose' :'PUBLIC_SYNTHETIC_PAYLOAD_CODEC_ONLY','production_import_permitted':False,'core_hex':core.hex(),'execution_digest_hex':hashlib.sha3_384(wrapped).hexdigest()},indent=2)+'\n')
