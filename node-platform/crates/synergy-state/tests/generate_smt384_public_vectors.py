"""Independent exact QACE /02 hashes of public synthetic state; no key material."""
import hashlib,json
from pathlib import Path
def u(n,size):return n.to_bytes(size,'big')
def text(s):b=s.encode('ascii');return u(len(b),4)+b
def h(tag,body=b''):return hashlib.sha3_384(u(2,2)+text(tag)+body).digest()
def key(n):return u(2,2)+u(1,2)+text('syns')+bytes([n])*48+u(0,4)
def value(n):return u(1,2)+u(1,2)+u(n,16)
empty=[None]*385;empty[384]=h('QACE/STATE/EMPTY/02')
def node(d,l,r):return h('QACE/STATE/NODE/02',u(d,2)+l+r)
for d in range(383,-1,-1):empty[d]=node(d,empty[d+1],empty[d+1])
def root(items,d=0):
 if not items:return empty[d]
 if d==384:
  assert len(items)==1
  return items[0][1]
 left=[x for x in items if not(x[0][d//8]&(128>>(d%8)))];right=[x for x in items if x not in left]
 return node(d,root(left,d+1),root(right,d+1))
cases=[]
for rows in [[],[(1,0)],[(1,2**128-1)],[(1,2**128-1),(2,0)]]:
 items=[(h('QACE/STATE/PATH/02',key(n)),h('QACE/STATE/LEAF/02',key(n)+value(amount))) for n,amount in rows]
 cases.append({'entries':[{'public_raw_byte':n,'amount_nwei':str(amount)} for n,amount in rows],'root_hex':root(items).hex()})
output={'scope':'PUBLIC_SYNTHETIC_FIXTURE_ONLY_NO_NETWORK_AUTHORITY','profile':'QACE-SMT384-R1/1','canonical_wrapper':2,'bit_order':'most-significant-bit first','cases':cases}
p=Path(__file__).parent/'fixtures/qace_smt384_public.json';p.parent.mkdir(exist_ok=True);p.write_text(json.dumps(output,indent=2)+'\n')
print('Wrote four independent public vectors; no keys, signatures or network state')
