"""Independent restricted-CBOR/SHA3 R1 public vectors. No keys/RNG/signing."""
import base64
import hashlib
import json
from pathlib import Path


def c(value):
    def head(kind, n):
        for maximum, size, marker in ((23, 0, 0), (255, 1, 24),
                                      (65535, 2, 25), (2**32-1, 4, 26), (2**64-1, 8, 27)):
            if n <= maximum:
                return bytes([kind << 5 | (n if size == 0 else marker)]) + (n.to_bytes(size, 'big') if size else b'')
        raise ValueError('unsigned64 bound')
    if isinstance(value, int):
        return head(0, value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode('ascii')
        return head(3, len(raw)) + raw
    if isinstance(value, list):
        return head(4, len(value)) + b''.join(c(v) for v in value)
    raise ValueError('restricted type')


if __name__ == '__main__':
    profile = ['QACE-NATIVE-TX-R1', 1]
    network = [2**64-2, bytes([1])*64]
    body = [1, [['SYNERGY-GENESIS-R1', 1], 'SHA3-384', bytes([2])*48],
            [['APQE-PROFILE-SET', 1], 'SHA3-512', bytes([3])*64],
            ['syns', bytes([4])*48], 1, 0, 1, 100, 21000, 1,
            [0, ['syns', bytes([5])*48], (7).to_bytes(16, 'big')]]
    signing = c([b'SYNERGY/APQE', 1, 'TRANSACTION.INTENT', profile, network, body])
    identity = c([b'SYNERGY/APQE', 1, 'TRANSACTION.ID', profile, network, body])
    digest = hashlib.sha3_384(identity).digest()
    output = {'scope': 'PUBLIC_SYNTHETIC_ONLY_NO_NETWORK_AUTHORITY',
              'profile': profile, 'signing_frame_hex': signing.hex(),
              'id_frame_hex': identity.hex(),
              'transaction_id': 'syntxn' + base64.urlsafe_b64encode(digest).decode().rstrip('=')}
    path = Path(__file__).parent/'fixtures'/'r1_native_transaction_public.json'
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps(output, indent=2)+'\n')
