"""Independent public QACE receipt-root vectors; no keys, RNG or live I/O."""
import hashlib
import json
import pathlib
import struct


def u32(value):
    return struct.pack('>I', value)


def h(tag, value):
    tag = tag.encode('ascii')
    return hashlib.sha3_384(struct.pack('>H', 2) + u32(len(tag)) + tag + value).digest()


def receipt(i):
    return (struct.pack('>HB', 1, 0) + bytes([i + 1]) * 48 + u32(i)
            + b'\0' + struct.pack('>Q', 7) + ((1 << 128) - 1).to_bytes(16, 'big')
            + bytes(16) + bytes([2]) * 48 + bytes([3]) * 48 + b'\0' + u32(0))


def root(n):
    if n == 0:
        return h('QACE/RCT-EMPTY/02', u32(0))
    m = 1 << (n - 1).bit_length()
    layer = [h('QACE/RCT-LEAF/02', u32(i) + receipt(i)) if i < n
             else h('QACE/RCT-PAD/02', u32(i)) for i in range(m)]
    level = 1
    while len(layer) > 1:
        layer = [h('QACE/RCT-NODE/02', u32(level) + layer[i] + layer[i + 1])
                 for i in range(0, len(layer), 2)]
        level += 1
    return h('QACE/RCT-ROOT/02', u32(n) + layer[0])


if __name__ == '__main__':
    output = {'profile': ['QACE-RECEIPT-R1', 1],
              'cases': [{'count': n, 'root_hex': root(n).hex()}
                        for n in (0, 1, 3, 9)]}
    path = pathlib.Path(__file__).parent / 'fixtures' / 'qace_receipts_public.json'
    path.write_text(json.dumps(output, indent=2) + '\n')
