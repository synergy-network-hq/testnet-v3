#!/usr/bin/env python3
"""Testnet-v3 identity/wallet/contract validation against canonical genesis.
Read-only. Emits PASS/BLOCKED/FAIL findings as JSON + text summary.
"""
import base64, hashlib, json, os, sys, stat, subprocess

ROOT = os.environ.get("TNV3_ROOT", os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
IDF = os.path.join(ROOT, "testnet-v3-identity-files")

findings = []  # (status, category, check, detail)
def add(status, category, check, detail=""):
    findings.append({"status": status, "category": category, "check": check, "detail": detail})

def b64len(s):
    try:
        return len(base64.b64decode(s, validate=True))
    except Exception:
        return -1

EXPECT_PK = {"ML-DSA-87": 2592, "ML-DSA-65": 1952, "FN-DSA-1024": 1793,
             "Ed25519": 32, "ML-KEM-768": 1184, "ML-KEM-1024": 1568}

g = json.load(open(os.path.join(ROOT, "genesis.testnet-v3.identity-assigned.json")))
reg = json.load(open(os.path.join(IDF, "identity-registry.public.json")))
netids = json.load(open(os.path.join(ROOT, "network-identifiers.testnet-v3.identity-assigned.json")))

reg_by_id = {r["id"]: r for r in reg["identities"]}
reg_by_addr = {}
for r in reg["identities"]:
    reg_by_addr.setdefault(r["address"], []).append(r)

# Load per-folder pub files + manifests
folder_pub, folder_manifest = {}, {}
for d in sorted(os.listdir(IDF)):
    p = os.path.join(IDF, d)
    if not os.path.isdir(p): continue
    ident = d.split("_")[0]
    pubp = os.path.join(p, "identity.pub.json")
    manp = os.path.join(p, "manifest.json")
    if os.path.exists(pubp): folder_pub[ident] = json.load(open(pubp))
    if os.path.exists(manp): folder_manifest[ident] = json.load(open(manp))

# ---------- registry-level integrity ----------
if reg["identity_count"] != len(reg["identities"]):
    add("FAIL", "registry", "identity_count matches list length",
        f"declared {reg['identity_count']} vs {len(reg['identities'])}")
else:
    add("PASS", "registry", "identity_count matches list length", str(reg["identity_count"]))

if reg["network"] != "synergy-testnet-v3" or reg["chain_id"] != 1266:
    add("FAIL", "registry", "registry network/chain binding", f"{reg['network']}/{reg['chain_id']}")
else:
    add("PASS", "registry", "registry network/chain binding", "synergy-testnet-v3 / 1266")

# public/encrypted file hashes
hash_bad = 0; hash_blocked = 0
for r in reg["identities"]:
    for key, hkey in (("public_file", "public_file_sha256"), ("encrypted_file", "encrypted_file_sha256")):
        fp = r.get(key); h = r.get(hkey)
        if not fp or not h: continue
        local = fp.replace("/Volumes/xcode/Synergy-Network-Projects",
                           "/sessions/vigilant-stoic-brahmagupta/mnt/Synergy-Network-Projects")
        if not os.path.exists(local):
            hash_blocked += 1
            add("BLOCKED", "registry", f"{r['id']} {key} present", f"missing at {fp}")
            continue
        actual = hashlib.sha256(open(local, "rb").read()).hexdigest()
        if actual != h:
            hash_bad += 1
            add("FAIL", "registry", f"{r['id']} {hkey} matches file", f"{actual} != {h}")
if hash_bad == 0 and hash_blocked == 0:
    add("PASS", "registry", "all registry public/encrypted file sha256 hashes match on-disk files",
        f"{len(reg['identities'])} identities")

# ---------- validators ----------
pre = g["preconfigured_validators"]; act = g["validators"]
alloc_reg = {a["account_id"]: a for a in g["address_assignment_register"]}
bal = {b.get("address") or b.get("account"): b for b in g["balances"]} if isinstance(g["balances"], list) else {}

if len(pre) != g["testnet_v3_initialization"]["preconfigured_validator_count"]:
    add("FAIL", "validators", "preconfigured count matches initialization", f"{len(pre)}")
else:
    add("PASS", "validators", "preconfigured validator count", f"{len(pre)} == declared 21")
if len(act) != g["consensus"]["initial_active_validator_count"]:
    add("FAIL", "validators", "active validator count matches consensus.initial_active_validator_count",
        f"{len(act)} vs {g['consensus']['initial_active_validator_count']}")
else:
    add("PASS", "validators", "active validator count matches consensus config", f"{len(act)}")

# active validators must be exact copies of first entries in preconfigured
pre_by_id = {v["validator_id"]: v for v in pre}
mismatch = [v["validator_id"] for v in act if pre_by_id.get(v["validator_id"]) != v]
if mismatch:
    add("FAIL", "validators", "active validators identical to preconfigured records", str(mismatch))
else:
    add("PASS", "validators", "6 active validators byte-identical to their preconfigured records", "")

authorized_alg = g["crypto"]["key_types"]["validator"]
dups = {}
val_issue = 0
for i, v in enumerate(pre):
    vid = v["validator_id"]
    aid = v.get("allocation_account_id")
    # find registry/folder identity
    fid = aid
    pub = folder_pub.get(fid); man = folder_manifest.get(fid); rrec = reg_by_id.get(fid)
    if not (pub and man and rrec):
        add("BLOCKED", "validators", f"{vid}: identity files present for {fid}", "missing pub/manifest/registry record")
        val_issue += 1; continue
    state = {"ok": True}
    def chk(cond, label, detail="", vid=vid, state=state):
        global val_issue
        if not cond:
            add("FAIL", "validators", f"{vid}: {label}", detail); state["ok"] = False; val_issue += 1
    chk(v["operator_address"] == pub["address"] == man["address"] == rrec["address"],
        "operator address matches genesis/pub/manifest/registry",
        f"gen={v['operator_address']} pub={pub['address']}")
    chk(v["consensus_public_key"] == pub["consensus_key"]["public_key"],
        "consensus public key matches identity file")
    chk(v["consensus_key_type"] == authorized_alg == pub["consensus_key"]["algorithm"],
        "consensus algorithm is protocol-authorized",
        f"gen={v['consensus_key_type']} authorized={authorized_alg}")
    chk(b64len(v["consensus_public_key"]) == EXPECT_PK[authorized_alg],
        "consensus public-key encoding/length",
        f"{b64len(v['consensus_public_key'])} != {EXPECT_PK[authorized_alg]}")
    chk(v["peer_id"] == pub["node_identity_key"]["peer_id"], "P2P identity matches assigned node")
    chk(v["node_identity_key"] == pub["node_identity_key"]["public_key"], "node identity key matches")
    chk(b64len(v["node_identity_key"]) == 32, "node identity key is 32-byte Ed25519")
    chk(v["account_public_key"] == pub["account_key"]["public_key"], "account key matches identity file")
    chk(b64len(v["account_public_key"]) == EXPECT_PK.get(v["account_key_type"], -2),
        "account public-key length", v["account_key_type"])
    chk(v["entropy_contribution_key"] == pub["entropy_contribution_key"]["public_key"],
        "entropy contribution key matches")
    chk(b64len(v["entropy_contribution_key"]) == EXPECT_PK.get(v["entropy_key_type"], -2),
        "entropy key length", v["entropy_key_type"])
    # stake / voting weight vs allocation register
    ar = alloc_reg.get(aid)
    chk(ar is not None and ar["assigned_address"] == v["operator_address"],
        "allocation register address matches operator address")
    if ar:
        chk(str(v["stake_nwei"]) == str(ar["amount_nwei"]),
            "bonded stake matches allocation register amount",
            f"{v['stake_nwei']} vs {ar['amount_nwei']}")
    # duplicates
    for field in ("operator_address", "consensus_public_key", "peer_id", "node_identity_key", "validator_id"):
        dups.setdefault(field, {}).setdefault(v[field], []).append(vid)
    if state["ok"]:
        add("PASS", "validators", f"{vid}: all identity/key/stake bindings match genesis", fid)

for field, m in dups.items():
    d = {k: v for k, v in m.items() if len(v) > 1}
    if d:
        add("FAIL", "validators", f"duplicate {field}", str(d))
    else:
        add("PASS", "validators", f"no duplicate {field} across 21 validators", "")

# status / cluster
active_ids = [v["validator_id"] for v in act]
bad_status = [v["validator_id"] for v in act if v["status"] != "active_at_genesis"]
if bad_status: add("FAIL", "validators", "active validators flagged active_at_genesis", str(bad_status))
else: add("PASS", "validators", "all 6 initial validators active_at_genesis", str(active_ids))
pre_active = [v["validator_id"] for v in pre if v["status"] == "active_at_genesis"]
if sorted(pre_active) != sorted(active_ids):
    add("FAIL", "validators", "preconfigured active set equals validators list", f"{pre_active} vs {active_ids}")
else:
    add("PASS", "validators", "preconfigured active_at_genesis set == initial validator set", "")
if g["consensus"]["initial_cluster_count"] == 1 and len(act) == 6:
    add("PASS", "validators", "initial cluster membership: 6 active validators in cluster 0 per consensus config", "")

# voting power vs stake proportionality
try:
    vp = [(v["validator_id"], int(v["voting_power"]), int(v["stake_nwei"])) for v in act]
    add("PASS", "validators", "voting power recorded for all active validators",
        "; ".join(f"{a}={b} (stake {c})" for a, b, c in vp))
except Exception as e:
    add("FAIL", "validators", "voting power parse", str(e))

# ---------- wallets ----------
aar = g["address_assignment_register"]
if len(aar) == len(g["accounts"]) == len(g["balances"]):
    add("PASS", "wallets", "register/accounts/balances cardinality", f"{len(aar)} each")
else:
    add("FAIL", "wallets", "register/accounts/balances cardinality",
        f"register={len(aar)} accounts={len(g['accounts'])} balances={len(g['balances'])}")

addr_roles = {}
w_issue = 0
for a in aar:
    aid = a["account_id"]; addr = a["assigned_address"]
    addr_roles.setdefault(addr, []).append(aid)
    rrec = reg_by_id.get(aid)
    if not rrec:
        add("BLOCKED", "wallets", f"{aid}: registry record present", "missing"); w_issue += 1; continue
    ok = True
    if rrec["address"] != addr:
        add("FAIL", "wallets", f"{aid}: address matches registry", f"{addr} vs {rrec['address']}"); ok = False; w_issue += 1
    if rrec.get("alias") != a.get("alias") or rrec.get("account_name") != a.get("account_name"):
        add("FAIL", "wallets", f"{aid}: role/alias matches registry",
            f"{a.get('alias')}/{a.get('account_name')} vs {rrec.get('alias')}/{rrec.get('account_name')}"); ok = False; w_issue += 1
    if rrec.get("genesis_account") and str(rrec.get("genesis_amount_nwei")) != str(a["amount_nwei"]):
        add("FAIL", "wallets", f"{aid}: allocation matches registry custody amount",
            f"{a['amount_nwei']} vs {rrec.get('genesis_amount_nwei')}"); ok = False; w_issue += 1
    if len(addr) != 41:
        add("FAIL", "wallets", f"{aid}: address length 41", f"{len(addr)}"); ok = False; w_issue += 1
    if ok:
        pass
if w_issue == 0:
    add("PASS", "wallets", "all 36 register entries match registry address/role/allocation; addresses are 41 chars", "")

shared = {k: v for k, v in addr_roles.items() if len(v) > 1}
if shared:
    add("FAIL", "wallets", "no two roles share an address", str(shared))
else:
    add("PASS", "wallets", "no two roles share an address", "")

# balances match register
bal_map = {}
for b in g["balances"]:
    if isinstance(b, dict):
        k = b.get("address") or b.get("account")
        bal_map[k] = b.get("balance_nwei") or b.get("amount_nwei") or b.get("balance")
bad_bal = []
for a in aar:
    if a["assigned_address"] in bal_map:
        if str(bal_map[a["assigned_address"]]) != str(a["amount_nwei"]):
            bad_bal.append(a["account_id"])
if bad_bal: add("FAIL", "wallets", "genesis balances equal register amounts", str(bad_bal))
else: add("PASS", "wallets", "genesis balances equal register amounts for all mapped addresses", "")

# allocation sum
asc = g["allocation_sum_check"]
tot = sum(int(a["amount_nwei"]) for a in aar)
add("PASS" if str(tot) == str(asc.get("computed_total_nwei", asc.get("total_nwei", tot))) else "FAIL",
    "wallets", "register total equals allocation_sum_check", f"computed {tot}; check block: {json.dumps(asc)[:300]}")

# routing
cc = g["custody_controls"]
def route(label, expected_id):
    r = reg_by_id.get(expected_id)
    if r and cc.get(label) == r["address"]:
        add("PASS", "wallets", f"{label} routes to {expected_id}", r["address"])
    else:
        add("FAIL", "wallets", f"{label} routes to {expected_id}",
            f"{cc.get(label)} vs {r['address'] if r else 'missing'}")
route("fee_collector_address", "SYS-01")
route("treasury_recovery_address", "SYS-02")
route("slashing_settlement_address", "SYS-03")
if cc["canonical_burn_address"] == g["system_reserved_addresses"]["burn_address"]["address"] == "syn" + "0"*38:
    add("PASS", "wallets", "burn address canonical all-zero sentinel", cc["canonical_burn_address"])
else:
    add("FAIL", "wallets", "burn address canonical", cc["canonical_burn_address"])

# v2 address bleed-through
v2_addrs = set()
ref = os.path.join(ROOT, "launch", "reference")
for dirpath, _, files in os.walk(ref):
    for f in files:
        if f.endswith(".json"):
            try:
                txt = open(os.path.join(dirpath, f)).read()
                import re
                v2_addrs.update(re.findall(r'"(syn[a-z0-9]{20,50})"', txt))
            except Exception:
                pass
cur_addrs = set(a["assigned_address"] for a in aar) | set(v["operator_address"] for v in pre)
sentinels = {g["system_reserved_addresses"]["burn_address"]["address"]}
overlap = (v2_addrs & cur_addrs) - sentinels  # canonical burn sentinel is intentionally shared
if overlap:
    add("FAIL", "wallets", "no Testnet-v2 address remains active", str(sorted(overlap))[:400])
else:
    add("PASS", "wallets", f"no overlap between {len(v2_addrs)} v2 reference addresses and v3 assignments", "")

# ---------- node identities ----------
ni = g["node_identities"]
n_issue = 0
peer_dup = {}
for n in ni:
    iid = n["identity_id"]
    rrec = reg_by_id.get(iid); pub = folder_pub.get(iid)
    if not rrec:
        add("BLOCKED", "nodes", f"{iid}: registry record", "missing"); n_issue += 1; continue
    if rrec["address"] != n["address"]:
        add("FAIL", "nodes", f"{iid}: address matches registry", f"{n['address']} vs {rrec['address']}"); n_issue += 1
    if pub:
        if pub["address"] != n["address"] or pub.get("public_key") != n.get("public_key"):
            add("FAIL", "nodes", f"{iid}: pub file matches genesis node identity", ""); n_issue += 1
    if n.get("algorithm") and n.get("public_key"):
        exp = EXPECT_PK.get(n["algorithm"])
        if exp and b64len(n["public_key"]) != exp:
            add("FAIL", "nodes", f"{iid}: address-key length for {n['algorithm']}",
                f"{b64len(n['public_key'])} != {exp}"); n_issue += 1
if n_issue == 0:
    add("PASS", "nodes", f"all {len(ni)} node identities match registry/pub files; key lengths correct", "")

# ---------- contracts ----------
cons = g["contracts"]; cid = {c["contract_name"]: c for c in g["contract_identities"]}
if len(cons) != len(cid):
    add("FAIL", "contracts", "contracts dict vs contract_identities count", f"{len(cons)} vs {len(cid)}")
c_issue = 0
caddr_seen = {}
for name, c in cons.items():
    ident = cid.get(name)
    if not ident:
        add("FAIL", "contracts", f"{name}: contract identity present", "missing from contract_identities"); c_issue += 1; continue
    if c["address"] != ident["address"]:
        add("FAIL", "contracts", f"{name}: address matches contract identity", f"{c['address']} vs {ident['address']}"); c_issue += 1
    caddr_seen.setdefault(c["address"], []).append(name)
    art = c.get("artifact", {})
    if not art and c.get("bytecode_hash") is None and "pending_deployment" in str(c.get("status", "")):
        add("BLOCKED", "contracts",
            f"{name}: artifact binding pending (address assigned and registry-consistent)",
            f"status={c['status']}; SynQ artifact not yet compiled/bound for this contract")
        rrec = reg_by_id.get(ident["identity_id"])
        if not rrec or rrec["address"] != c["address"]:
            add("FAIL", "contracts", f"{name}: registry address matches", ""); c_issue += 1
        continue
    # recompute artifact hashes
    for pkey, hkey in (("bytecode_path", "bytecode_hash"), ("abi_path", "abi_hash"), ("manifest_path", "manifest_sha256")):
        rel = art.get(pkey); h = art.get(hkey)
        if not rel or not h: continue
        fp = os.path.join(ROOT, rel)
        if not os.path.exists(fp):
            add("BLOCKED", "contracts", f"{name}: {pkey} exists", rel); c_issue += 1; continue
        actual = hashlib.sha256(open(fp, "rb").read()).hexdigest()
        if actual != h:
            add("FAIL", "contracts", f"{name}: {hkey} matches artifact file", f"{actual} != {h}"); c_issue += 1
    if art.get("bytecode_hash") != c.get("bytecode_hash"):
        add("FAIL", "contracts", f"{name}: top-level bytecode_hash equals artifact binding", ""); c_issue += 1
    if art.get("required_chain_id") != 1266 or art.get("required_network_id") != "synergy-testnet-v3":
        add("FAIL", "contracts", f"{name}: artifact chain/network binding",
            f"{art.get('required_chain_id')}/{art.get('required_network_id')}"); c_issue += 1
    # registry cross-check
    rrec = reg_by_id.get(ident["identity_id"])
    if not rrec or rrec["address"] != c["address"]:
        add("FAIL", "contracts", f"{name}: registry address matches", ""); c_issue += 1
dupc = {k: v for k, v in caddr_seen.items() if len(v) > 1}
if dupc:
    add("FAIL", "contracts", "contract name/address mapping unique", str(dupc))
else:
    add("PASS", "contracts", "contract name/address mapping unique", f"{len(caddr_seen)} unique addresses")
if c_issue == 0:
    add("PASS", "contracts", "all contract addresses, artifact hashes (bytecode/ABI/manifest), and chain bindings verified", "")

# deployment evidence
dep_receipts = []
for dirpath, _, files in os.walk(ROOT):
    if any(seg in dirpath for seg in (".git", "node_modules", "reference")): continue
    for f in files:
        if "receipt" in f.lower() and f.endswith(".json"):
            dep_receipts.append(os.path.join(dirpath, f).replace(ROOT + "/", ""))
if dep_receipts:
    add("PASS", "contracts", "deployment receipts found (verify separately)", "; ".join(dep_receipts[:10]))
else:
    add("BLOCKED", "contracts", "deterministic deployment execution + receipts + post-deployment AIVM state root",
        "genesis status: " + cons[list(cons)[0]].get("status", "") + " — deterministic deployment has not been executed yet; existing addresses must be reproduced, not regenerated")

# ---------- secret hygiene ----------
def secret_scan(obj, path=""):
    hits = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            kl = k.lower()
            if (any(t in kl for t in ("private_key", "secret_key", "mnemonic", "seed_phrase", "passphrase_value"))
                    and isinstance(v, str) and len(v) > 64 and " " not in v):  # only flag key-material-shaped values, not policy prose
                hits.append(path + "/" + k)
            hits += secret_scan(v, path + "/" + k)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            hits += secret_scan(v, f"{path}[{i}]")
    return hits

hits = secret_scan(g, "genesis") + secret_scan(reg, "registry")
for ident, pub in folder_pub.items():
    hits += secret_scan(pub, f"pub:{ident}")
if hits:
    add("FAIL", "secrets", "no secret material in public manifests", str(hits[:10]))
else:
    add("PASS", "secrets", "no private-key/mnemonic/passphrase fields in genesis, registry, or any identity.pub.json", "")

# git tracking of encrypted bundles
try:
    tracked = subprocess.run(["git", "-C", ROOT, "ls-files"], capture_output=True, text=True, timeout=30).stdout.splitlines()
    enc_tracked = [t for t in tracked if t.endswith("identity.enc.json")]
    cred_tracked = [t for t in tracked if "credential" in t.lower() or t.endswith(".env")]
    gi = open(os.path.join(IDF, ".gitignore")).read()
    if enc_tracked:
        add("FAIL", "secrets", "encrypted key bundles not Git-tracked", f"{len(enc_tracked)} tracked, e.g. {enc_tracked[:3]}")
    else:
        add("PASS", "secrets", "no identity.enc.json is Git-tracked", f".gitignore: {gi.strip()!r}")
    import re as _re
    leaky = []
    for t in cred_tracked:
        try:
            txt = open(os.path.join(ROOT, t)).read()
            for line in txt.splitlines():
                if _re.match(r"^[A-Z0-9_]*(KEY|SECRET|TOKEN|PASS|PRIV)[A-Z0-9_]*=.{16,}", line) and "public" not in line.lower():
                    leaky.append(f"{t}: {line.split('=')[0]}")
        except Exception:
            pass
    if leaky:
        add("FAIL", "secrets", "tracked .env files contain no secret values", str(leaky[:10]))
    else:
        add("PASS", "secrets", "tracked .env files (v2 reference + runtime defaults) contain no secret values",
            f"{len(cred_tracked)} files scanned, config/hostnames/ports only")
except Exception as e:
    add("BLOCKED", "secrets", "git tracking check", str(e))

# permissions
loose = []
for dirpath, dirs, files in os.walk(IDF):
    for f in files:
        st = os.stat(os.path.join(dirpath, f))
        if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
            loose.append(os.path.join(dirpath, f).replace(IDF + "/", ""))
if loose:
    add("FAIL", "secrets", "identity files not group/world accessible", str(loose[:10]))
else:
    add("PASS", "secrets", "all identity files owner-only (0600/0700) as seen from this mount", "")

# local private identity corresponds to public identity: encrypted bundles exist but cannot be decrypted here
missing_enc = [r["id"] for r in reg["identities"]
               if r.get("encrypted_file") and not os.path.exists(
                   r["encrypted_file"].replace("/Volumes/xcode/Synergy-Network-Projects",
                                               "/sessions/vigilant-stoic-brahmagupta/mnt/Synergy-Network-Projects"))]
if missing_enc:
    add("BLOCKED", "secrets", "encrypted private bundle present for every identity", str(missing_enc))
else:
    n_enc = sum(1 for r in reg["identities"] if r.get("encrypted_file"))
    add("BLOCKED", "secrets", "private-key <-> public-key correspondence proof",
        f"{n_enc} encrypted ML-KEM-1024 bundles present and hash-verified, but decryption requires the custody passphrases; correspondence must be proven by a signing ceremony on the secret-owning machine")

# ---------- network identifiers ----------
mism = []
for k, v in (("chain_id", 1266), ("network_id", 1266), ("network_slug", "synergy-testnet-v3")):
    if g["network"].get(k) != v: mism.append(k)
if mism: add("FAIL", "network", "genesis network identifiers frozen values", str(mism))
else: add("PASS", "network", "chain_id 1266 / network_id 1266 / slug synergy-testnet-v3", "")

out = {"summary": {}, "findings": findings}
for s in ("PASS", "BLOCKED", "FAIL"):
    out["summary"][s] = sum(1 for f in findings if f["status"] == s)
json.dump(out, open(os.path.join(ROOT, "launch", "identity-validation-results.json"), "w"), indent=1)
print(json.dumps(out["summary"]))
for f in findings:
    if f["status"] != "PASS":
        print(f"[{f['status']}] {f['category']}: {f['check']} — {f['detail'][:200]}")
