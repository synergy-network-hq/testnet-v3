import json
import os
import re
import tempfile
from pathlib import Path

base = Path(os.environ.get("SYNERGY_ROLLBACK_DATA_DIR", "/var/lib/synergy/validator/data"))
cut = int(os.environ.get("SYNERGY_ROLLBACK_CUT_HEIGHT", "1150717"))
conflict = int(os.environ.get("SYNERGY_ROLLBACK_CONFLICT_HEIGHT", str(cut + 1)))


def atomic(path: Path, data: bytes) -> None:
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".fast.", suffix=".tmp", dir=str(path.parent))
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def height_of(line: bytes):
    try:
        obj = json.loads(line)
        heights = []
        for key in ("height", "block_height", "block_index"):
            if isinstance(obj.get(key), int):
                heights.append(obj[key])
        block = obj.get("block")
        if isinstance(block, dict) and isinstance(block.get("block_index"), int):
            heights.append(block["block_index"])
        return max(heights) if heights else None
    except Exception:
        match = re.search(rb'"(?:height|block_height|block_index)"\s*:\s*(\d+)', line)
        return int(match.group(1)) if match else None


def truncate_jsonl_tail(path: Path) -> str:
    if not path.exists():
        return "missing"
    size = path.stat().st_size
    keep_end = 0
    with open(path, "rb+") as f:
        pos = size
        carry = b""
        found = False
        while pos > 0 and not found:
            step = min(1024 * 1024, pos)
            pos -= step
            f.seek(pos)
            chunk = f.read(step) + carry
            parts = chunk.split(b"\n")
            carry = parts[0]
            lines = parts[1:] if pos > 0 else parts
            offset = pos + (len(carry) + 1 if pos > 0 else 0)
            starts = []
            cur = offset
            for line in lines:
                starts.append(cur)
                cur += len(line) + 1
            for line, start in reversed(list(zip(lines, starts))):
                if not line.strip():
                    continue
                height = height_of(line)
                if height is None or height <= cut:
                    keep_end = start + len(line) + 1
                    found = True
                    break
        if keep_end and keep_end < size:
            f.truncate(keep_end)
            f.flush()
            os.fsync(f.fileno())
            return f"truncated {size}->{keep_end}"
        return f"unchanged {size}"


locks = base / "canonical_locks.json"
if locks.exists():
    data = json.load(open(locks))
    before = len(data)
    data = {k: v for k, v in data.items() if str(k).isdigit() and int(k) <= cut}
    atomic(locks, json.dumps(data, separators=(",", ":"), sort_keys=True).encode() + b"\n")
    print("canonical_locks", before, "->", len(data), data.get(str(cut), {}).get("block_hash"))

vote_locks = base / "consensus_vote_locks.json"
if vote_locks.exists():
    try:
        data = json.load(open(vote_locks))
        before = len(data) if isinstance(data, dict) else "na"
        if isinstance(data, dict):
            filtered = {}
            for key, value in data.items():
                keep = True
                if str(key).isdigit() and int(key) > cut:
                    keep = False
                if isinstance(value, dict):
                    for height_key in ("height", "block_height", "block_index"):
                        if isinstance(value.get(height_key), int) and value[height_key] > cut:
                            keep = False
                if keep:
                    filtered[key] = value
            atomic(vote_locks, json.dumps(filtered, separators=(",", ":"), sort_keys=True).encode() + b"\n")
            print("vote_locks", before, "->", len(filtered))
    except Exception as error:
        print("vote_locks skipped", error)

for name in ("committed_blocks.jsonl", "committed_qcs.jsonl"):
    print(name, truncate_jsonl_tail(base / name))

chain = base / "chain.json"
if chain.exists():
    with open(chain, "rb+") as f:
        f.seek(0, os.SEEK_END)
        size = f.tell()
        read = min(size, 8 * 1024 * 1024)
        f.seek(size - read)
        tail = f.read(read)
        marker = b',{"block_index":%d' % conflict
        idx = tail.rfind(marker)
        if idx >= 0:
            new_size = size - read + idx
            f.truncate(new_size)
            f.seek(new_size)
            f.write(b"]")
            f.flush()
            os.fsync(f.fileno())
            print("chain tail truncated", size, "->", new_size + 1)
        else:
            print("chain marker not found in tail; unchanged", size)
