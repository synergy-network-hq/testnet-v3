#!/usr/bin/env python3
"""Guarded synthetic Linux process qualification. Default: read-only preflight.

Requires an externally issued fixture, pinned ELF and source hashes. Does not
issue keys, copy source, create namespaces, alter routes, or claim TPS. Current
artifacts without standalone preflight remain blocked before launch.
"""
import argparse
import hashlib
import ipaddress
import json
import os
import re
from pathlib import Path
import stat
import subprocess
import sys
import time
import threading

MAX_JSON = 1024 * 1024
# Complete parent-checkout inventories include canonical symlink target trees.
# The 2026-10-19 pinned build contains 129,086 entries. Keep an explicit bounded
# margin without discarding inputs; the independent 64 MiB byte cap still applies.
MAX_COMPLETE_INPUT_ENTRIES = 200_000
CANONICAL_TARGET = Path(__file__).absolute().parents[2] / "target"
FIXTURE_KIND = "posy-isolated-synthetic-v1"


class QualificationError(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise QualificationError(reason)


def safe_path(path, root=None, exists=True):
    path = Path(path)
    require(path.is_absolute() and ".." not in path.parts, "absolute canonical path required")
    for ancestor in (path, *path.parents):
        require(not ancestor.is_symlink(), "symlink prohibited")
    if root is not None:
        require(path != root and path.is_relative_to(root), "fixture path escapes root")
    production_prefix = str(path).startswith(("/etc/synergy", "/var/lib/synergy", "/run/synergy", "/Users/", "/home/"))
    require(not production_prefix or path.is_relative_to(CANONICAL_TARGET), "production/custody prefix prohibited")
    if exists:
        require(path.exists(), "fixture path missing")
    return path


def read_json(path):
    require(path.is_file() and path.stat().st_size <= MAX_JSON, "JSON input missing or oversized")
    value = json.loads(path.read_text())
    require(isinstance(value, dict), "JSON object required")
    return value


def sha3(path):
    digest = hashlib.sha3_256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_address(value, allowed):
    require(isinstance(value, str), "literal address required")
    value = value.removeprefix("tcp://")
    try:
        host, port = value.rsplit(":", 1)
        address = ipaddress.ip_address(host.strip("[]"))
        require(0 < int(port) < 65536, "invalid port")
    except (ValueError, TypeError) as error:
        raise QualificationError("literal socket address required") from error
    require(address.is_loopback or address in allowed, "external or wildcard bind prohibited")


def fixture_root_allowed(root):
    return root.name.startswith("posy-isolated-") and len(root.name) <= 128 and root.parent in {Path("/tmp"), Path("/var/tmp"), CANONICAL_TARGET}



def verify_portable_provenance(path, expected_sha3, artifact_sha3):
    require(isinstance(expected_sha3, str) and re.fullmatch(r"[0-9a-f]{64}", expected_sha3),
            "independent portable provenance SHA3 pin required")
    path = safe_path(path)
    require(path.is_file() and path.stat().st_size <= 64 * 1024 * 1024, "bounded complete public provenance required")
    require(sha3(path) == expected_sha3, "portable provenance pin mismatch")
    document = json.loads(path.read_text())
    if document.get("format_version") == 1 and document.get("qualification_state") == "unqualified_candidate":
        require(document.get("artifact", {}).get("sha3_256") == artifact_sha3
                and document.get("before") == document.get("after"), "complete provenance candidate/source binding mismatch")
        require(document.get("target") == "x86_64-unknown-linux-gnu"
                and document.get("build_config", {}).get("profile") == "release"
                and document.get("build_config", {}).get("locked") is True
                and "qualification-timing" in document.get("build_config", {}).get("features", []),
                "exact locked qualification Linux profile required")
        rustc = document.get("toolchain", {}).get("rustc", "")
        require(isinstance(rustc, str) and len(rustc) <= 8192
                and re.search(r"commit-hash: [0-9a-f]{40}", rustc), "exact native compiler identity required")
        companions = document.get("companions", {})
        require(set(companions) == {"synergy-keytool", "synergy-genesis", "synergy-fixture-exporter"}, "exact native companion artifacts missing")
        for companion in companions.values():
            require(type(companion.get("length")) is int and 64 <= companion["length"] <= 256*1024*1024
                    and re.fullmatch(r"[0-9a-f]{64}", str(companion.get("sha3_256", ""))), "invalid exact companion pin")
        count = 0
        seen = set()
        def public_tree(tree, prefix=""):
            nonlocal count
            require(re.fullmatch(r"[0-9a-f]{40}", str(tree.get("source_revision", ""))), "reviewable source revision missing")
            require(isinstance(tree.get("files"), list), "complete input inventory missing")
            for entry in tree["files"]:
                count += 1
                require(count <= MAX_COMPLETE_INPUT_ENTRIES and isinstance(entry, dict), "complete input inventory count bound exceeded")
                relative = entry.get("path")
                require(isinstance(relative, str) and 0 < len(relative) <= 1024, "bounded public relative input path required")
                source = Path(relative)
                normalized=source.as_posix()
                # Older exact pinned inventories retain Git's single trailing slash
                # for nested-repository directories. Only that directory spelling
                # is equivalent; collision checks always use the canonical name.
                legacy_directory=("submodule" in entry and relative==normalized+"/")
                full = prefix + normalized
                require(not source.is_absolute() and ".." not in source.parts
                        and (normalized == relative or legacy_directory)
                        and full not in seen, "public input path escapes or duplicates")
                seen.add(full)
                if "submodule" in entry: public_tree(entry["submodule"], full + "/")
                elif entry.get("state") in {"symlink_input", "canonical_directory_input"}:
                    require(entry.get("state") == "canonical_directory_input" or
                            (isinstance(entry.get("target"), str) and len(entry["target"]) <= 4096
                             and re.fullmatch(r"[0-9a-f]{64}", str(entry.get("target_sha256", "")))
                             and hashlib.sha256(os.fsencode(entry["target"])).hexdigest() == entry["target_sha256"]
                             and type(entry.get("promotion_eligible")) is bool), "symlink public target binding malformed")
                    if entry.get("state") == "symlink_input":
                        resolution=entry.get("resolution")
                        require(resolution in {"unresolved", "outside_checkout", "directory_cycle", "unsupported_target", "canonical_file", "canonical_directory"}, "unknown public symlink resolution")
                        require(entry["promotion_eligible"] == (resolution in {"canonical_file", "canonical_directory"}), "symlink promotion eligibility mismatch")
                        if entry["promotion_eligible"]:
                            resolved=entry.get("resolved_path")
                            require(isinstance(resolved,str) and resolved and not Path(resolved).is_absolute()
                                    and ".." not in Path(resolved).parts and Path(resolved).as_posix()==resolved,
                                    "canonical symlink target escapes checkout")
                    if entry.get("resolution") == "canonical_file":
                        require(type(entry.get("length")) is int and entry["length"] >= 0
                                and re.fullmatch(r"[0-9a-f]{64}", str(entry.get("sha256", ""))), "canonical symlink bytes missing")
                    if "files" in entry:
                        # Child paths are canonical checkout-relative and may overlap
                        # directly tracked entries; each link tree is separately scoped.
                        public_tree({"source_revision":tree["source_revision"],"clean":tree.get("clean"),"files":entry["files"]},full + "/@target/")
                elif entry.get("state") == "missing_tracked_input":
                    require(set(entry) == {"path", "state"} and tree.get("clean") is False,
                            "missing tracked input must preserve explicit dirty source state")
                else:
                    require(type(entry.get("length")) is int and entry["length"] >= 0
                            and re.fullmatch(r"[0-9a-f]{64}", str(entry.get("sha256", ""))), "public input digest malformed")
        public_tree(document["before"])
        require({"node-platform/Cargo.toml", "node-platform/Cargo.lock", "node-platform/bin/synergy-node/Cargo.toml"}.issubset(seen),
                "canonical workspace/package/lock inventory missing")
        return {"mode":"complete_pinned_build_provenance", "transported_provenance_pin_verified":True,
                "provenance_sha3_256":expected_sha3,"linux_source_files_verified":False,
                "companions":companions,"source_inventory_count":count,"GateD_qualified":False}

    require(document.get("schema_version") == 1 and document.get("kind") == "posy-linux-build-provenance-v1",
            "unsupported build provenance schema")
    require(document.get("artifact_sha3_256") == artifact_sha3, "provenance candidate artifact mismatch")
    require(document.get("target") == "x86_64-unknown-linux-gnu", "exact Linux build target required")
    toolchain = document.get("toolchain")
    require(isinstance(toolchain, dict) and all(isinstance(toolchain.get(k), str) and toolchain[k]
            and len(toolchain[k]) <= 512 for k in ("rustc_version", "cargo_version", "rustc_commit_hash")),
            "pinned build toolchain required")
    require(re.fullmatch(r"[0-9a-f]{40}", toolchain["rustc_commit_hash"]), "exact compiler commit required")
    build = document.get("build_config")
    require(isinstance(build, dict) and build.get("profile") == "release"
            and build.get("package") == "synergy-node" and build.get("locked") is True,
            "locked native release build configuration required")
    features = build.get("features")
    require(isinstance(features, list) and features == sorted(set(features))
            and "qualification-timing" in features
            and all(isinstance(f, str) and re.fullmatch(r"[a-z0-9_-]+", f) for f in features),
            "explicit qualification feature list required")
    require(isinstance(build.get("rustflags"), list)
            and all(isinstance(flag, str) and len(flag) <= 512 for flag in build["rustflags"]),
            "explicit compiler flags required")
    sources = document.get("sources")
    require(isinstance(sources, list) and 1 <= len(sources) <= 10000, "bounded source digest inventory required")
    seen = set()
    for entry in sources:
        require(isinstance(entry, dict), "source digest object required")
        relative = entry.get("path")
        require(isinstance(relative, str) and relative and len(relative) <= 512, "relative source path required")
        source = Path(relative)
        require(not source.is_absolute() and ".." not in source.parts and source.as_posix() == relative
                and relative not in seen, "invalid or duplicate public source path")
        require(re.fullmatch(r"[0-9a-f]{64}", str(entry.get("sha3_256", ""))), "invalid source digest")
        seen.add(relative)
    require({"Cargo.toml", "Cargo.lock", "bin/synergy-node/Cargo.toml"}.issubset(seen),
            "workspace/package/lock provenance missing")
    return {"mode": "externally_pinned_build_provenance", "transported_provenance_pin_verified": True,
            "provenance_sha3_256": expected_sha3, "linux_source_files_verified": False,
            "GateD_qualified": False}



def verify_native_manifest_separation(control_path, config, root):
    native_path = safe_path(config["manifest_path"], root)
    require(native_path != control_path, "qualification control cannot replace native chain manifest")
    native = read_json(native_path)
    require(type(native.get("chain_id")) is int and native["chain_id"] == config.get("chain_id")
            and native.get("network_id") == config.get("network_id"),
            "native chain manifest/config identity mismatch")



def verify_genuine_genesis(manifest, configs, root, binary_path=None, expected_sha3=None,
                           required=False, run=subprocess.run):
    """A fixture's issuance flag is never verification or qualification evidence."""
    report = {"full_signed_genesis_claimed": manifest.get("full_signed_genesis") is True,
              "native_genesis_verified": False, "genesis_authority_binding_verified": False,
              "signed_authority_preflight_verified": False, "GateD_qualified": False}
    if binary_path is None:
        require(expected_sha3 is None, "Genesis verifier path missing for artifact pin")
        require(not required and manifest.get("diagnostic_only") is True,
                "genuine qualification requires an independently pinned native Genesis verifier")
        report["reason"] = "explicit diagnostic mode; Genesis issuance is not qualification"
        return report
    require(sys.platform == "linux", "exact Linux Genesis verifier requires Linux")
    binary = safe_path(binary_path)
    require(binary.is_file() and os.access(binary, os.X_OK), "Genesis verifier executable unavailable")
    require(isinstance(expected_sha3, str) and re.fullmatch(r"[0-9a-f]{64}", expected_sha3),
            "independent Genesis verifier SHA3 pin required")
    with binary.open("rb") as source:
        require(source.read(4) == b"\x7fELF", "Genesis verifier must be exact Linux ELF")
    require(sha3(binary) == expected_sha3, "Genesis verifier artifact pin mismatch")
    genesis = safe_path(manifest.get("genesis_path", str(root / "genesis.sgen")), root)
    require(genesis.is_file() and 0 < genesis.stat().st_size <= 16 * MAX_JSON,
            "bounded signed Genesis required")
    signed = json.loads(genesis.read_text())
    require(isinstance(signed, dict) and isinstance(signed.get("unsigned"), dict),
            "native signed Genesis object required")
    unsigned = signed["unsigned"]
    genesis_hash = signed.get("genesis_hash")
    require(isinstance(genesis_hash, str) and re.fullmatch(r"[0-9a-f]{64}", genesis_hash),
            "canonical Genesis hash required")
    require(unsigned.get("network", {}).get("network_id") == manifest["network_id"],
            "Genesis/qualification incarnation mismatch")
    genesis_digest = sha3(genesis)
    verified = set()
    for config_path in configs:
        config = read_json(config_path)
        native = read_json(safe_path(config["manifest_path"], root))
        require(native.get("genesis_hash") == genesis_hash
                and native.get("chain_id") == unsigned["network"].get("chain_id")
                and native.get("network_id") == unsigned["network"].get("network_id")
                and native.get("protocol_version") == unsigned["network"].get("protocol_version"),
                "signed Genesis/native manifest identity mismatch")
        authority_path = safe_path(config["consensus"]["authority_binding"], root)
        trust_path = safe_path(config["consensus"]["authority_trust_key_path"], root)
        require(authority_path.is_file() and 0 < authority_path.stat().st_size <= MAX_JSON,
                "bounded signed authority required")
        require(trust_path.is_file() and 0 < trust_path.stat().st_size <= 8192,
                "bounded public Genesis trust pin required")
        authority = json.loads(authority_path.read_text())
        payload = authority.get("payload", {})
        parent = payload.get("anchor_parent", {})
        anchor = parent.get("reference", {})
        # Native verify-binding verifies signatures, state commitment and policy;
        # these structural comparisons also pin the launcher to each node config.
        require(payload.get("chain_id") == native["chain_id"]
                and payload.get("network_id") == native["network_id"]
                and parent.get("kind") == "genesis"
                and anchor.get("genesis_hash") == genesis_hash
                and anchor.get("block_id") == genesis_hash,
                "Genesis/authority identity or structural anchor mismatch")
        # GenesisValidator and AuthorityValidator have different schemas. The
        # pinned native verifier checks matching record/algorithm/public_key,
        # exact canonical reference_id, policy roots, world state and signatures.
        provider = config.get("aegis_provider")
        require(isinstance(provider, dict), "explicit authenticated APQE provider required for native Genesis verification")
        report_path = safe_path(provider.get("report_path", ""), root)
        report_digest = provider.get("authenticated_report_sha256", "")
        require(re.fullmatch(r"[0-9a-f]{64}", str(report_digest)), "authenticated APQE report SHA256 required")
        key = (str(authority_path), sha3(authority_path), str(trust_path), sha3(trust_path), str(report_path), report_digest)
        if key not in verified:
            result = run([str(binary), "verify-binding", str(genesis), str(trust_path), str(authority_path), "--apqe-report", str(report_path), "--apqe-report-sha256", report_digest],
                         check=True, capture_output=True, timeout=30)
            require(len(result.stdout) <= MAX_JSON and len(result.stderr) <= MAX_JSON,
                    "native Genesis verification response oversized")
            require(result.stdout.strip() == f"verified Genesis/authority binding genesis_hash={genesis_hash}".encode(),
                    "native Genesis/authority binding verification incomplete")
            require(sha3(binary) == expected_sha3 and sha3(genesis) == genesis_digest
                    and sha3(authority_path) == key[1] and sha3(trust_path) == key[3],
                    "Genesis verifier or bound public inputs changed during verification")
            verified.add(key)
    report.update(native_genesis_verified=True, genesis_authority_binding_verified=True,
                  genesis_sha3_256=genesis_digest, genesis_hash=genesis_hash,
                  verifier_artifact_sha3_256=expected_sha3,
                  reason="native signed Genesis binding verified; process survival is not Gate D")
    return report


def preflight(manifest_path, portable_path=None, expected_provenance_sha3=None, resume=False,
              genesis_binary=None, expected_genesis_sha3=None, require_genuine_genesis=False):
    manifest_path = safe_path(manifest_path)
    root = manifest_path.parent
    require(fixture_root_allowed(root), "dedicated isolated fixture root required")
    require(stat.S_IMODE(root.stat().st_mode) == 0o700, "fixture root must be 0700")
    manifest = read_json(manifest_path)
    require(manifest.get("fixture_kind") == FIXTURE_KIND and manifest.get("synthetic_keys_only") is True,
            "unknown or non-synthetic fixture identity")
    network_id = manifest.get("network_id")
    require(isinstance(network_id, str) and network_id.startswith("posy-isolated-") and len(network_id) < 128,
            "isolated network identity required")
    allowed = ipaddress.ip_network(manifest.get("isolated_network", ""))
    require(allowed.version == 4 and allowed == ipaddress.ip_network("10.69.10.0/24"),
            "fixture network must be native-policy 10.69.10/24 in isolated namespace")
    binary = safe_path(manifest["binary_path"])
    require(binary.is_file() and os.access(binary, os.X_OK), "candidate executable unavailable")
    with binary.open("rb") as source:
        require(source.read(4) == b"\x7fELF", "candidate must be exact Linux ELF")
    require(sha3(binary) == manifest.get("artifact_sha3_256"), "candidate artifact digest mismatch")
    if portable_path is not None:
        provenance_report = verify_portable_provenance(portable_path, expected_provenance_sha3,
                                                     manifest["artifact_sha3_256"])
        if "companions" in provenance_report:
            expected = provenance_report["companions"]["synergy-genesis"]
            require(genesis_binary is not None and expected_genesis_sha3 == expected["sha3_256"]
                    and Path(genesis_binary).stat().st_size == expected["length"], "native Genesis verifier differs from complete build provenance")

    else:
        require(expected_provenance_sha3 is None, "portable provenance path missing for pin")
        provenance = manifest.get("source_provenance")
        require(isinstance(provenance, list) and provenance, "source provenance absent")
        for entry in provenance:
            source = safe_path(entry["path"])
            require(source.suffix in {".rs", ".toml", ".py", ".md"} and not source.is_relative_to(root),
                    "public canonical source provenance required; fixture/key material prohibited")
            require(source.is_file() and source.stat().st_size <= 16 * MAX_JSON
                    and sha3(source) == entry.get("sha3_256"), "source provenance digest mismatch")
        provenance_report = {"mode":"direct_canonical_files", "linux_source_files_verified":sys.platform == "linux",
                             "canonical_source_files_verified":True, "transported_provenance_pin_verified":False,
                             "GateD_qualified":False}
    nodes = manifest.get("nodes")
    require(isinstance(nodes, list) and len(nodes) == 5, "exactly five node configs required")
    seen, data_paths, sockets, configs, transports = set(), set(), set(), [], set()
    def check_paths(value):
        if isinstance(value, dict):
            for key, child in value.items():
                if key in {"bootnodes", "bootstrap_peers", "seed_peers"}:
                    require(not child, "external bootstrap overrides prohibited")
                elif isinstance(child, str) and (key.endswith("_path") or key == "data_directory"):
                    path = safe_path(child, root, exists=key not in {"admin_socket_path", "data_directory"})
                    if "secret" in key or "signing_key" in key:
                        require(stat.S_IMODE(path.stat().st_mode) == 0o600, "synthetic signer must be 0600")
                else:
                    check_paths(child)
        elif isinstance(value, list):
            for child in value:
                check_paths(child)
    for node in nodes:
        require(node.get("id") not in seen and isinstance(node.get("id"), str), "duplicate node identity")
        seen.add(node["id"])
        config_path = safe_path(node["config_path"], root)
        config = read_json(config_path)
        require(config.get("network_id") == network_id and config.get("role") == "validator", "config fixture identity mismatch")
        require(config.get("consensus", {}).get("mode") == "validate_and_vote", "native validator mode required")
        require(config.get("vpn", {}).get("mode") == "required", "native VPN validation cannot be bypassed")
        check_paths(config)
        verify_native_manifest_separation(manifest_path, config, root)
        identity = read_json(safe_path(config["public_identity_path"], root))
        require(node["id"] == identity.get("node_address"), "manifest id must match native public NodeAddress")
        listen = config.get("network", {}).get("listen_addresses")
        advertised = config.get("network", {}).get("advertised_addresses")
        allowed_transports = {f"10.69.10.{i}:5622" for i in range(2, 7)}
        require(isinstance(listen, list) and len(listen) == 1 and listen[0] in allowed_transports,
                "exact native-policy validator transport required")
        require(advertised == listen and listen[0] not in transports, "unique matching native transport required")
        transports.add(listen[0])
        data = config["storage"]["data_directory"]
        socket = config["admin_socket_path"]
        require(data not in data_paths and socket not in sockets, "shared validator state/admin socket prohibited")
        if resume:
            require(manifest.get("diagnostic_only") is True and manifest.get("resume_authority_network_id") == network_id,
                    "resume requires diagnostic-only same-authority network binding")
            require(not Path(socket).exists(), "resume requires stopped native admin socket")
            if Path(data).exists():
                safe_path(data, root)
                require(Path(data).is_dir(), "resume state must be native directory")
        else:
            require(not Path(data).exists() and not Path(socket).exists(), "fresh synthetic state required")
        data_paths.add(data)
        sockets.add(socket)
        for key in ("listen_addresses", "advertised_addresses"):
            addresses = config.get("network", {}).get(key)
            require(isinstance(addresses, list) and addresses, "network endpoints absent")
            for value in addresses:
                validate_address(value, allowed)
        validate_address(config.get("rpc", {}).get("listen_address"), allowed)
        configs.append(config_path)
    manifest["_verified_genesis_report"] = verify_genuine_genesis(
        manifest, configs, root, genesis_binary, expected_genesis_sha3,
        required=require_genuine_genesis or manifest.get("diagnostic_only") is not True)
    manifest["_verified_provenance_report"] = provenance_report
    return manifest, binary, configs


def validate_namespace(manifest, run=subprocess.run):
    require(sys.platform == "linux", "execution requires Linux")
    inode = os.stat("/proc/self/ns/net").st_ino
    require(inode == manifest.get("network_namespace_inode") and inode != os.stat("/proc/1/ns/net").st_ino,
            "explicit distinct isolated network namespace required")
    routes = []
    for family in ("-4", "-6"):
        result = run(["ip", family, "-j", "route", "show", "table", "all"], check=True, capture_output=True, timeout=5)
        routes.extend(json.loads(result.stdout))
    allowed = ipaddress.ip_network(manifest["isolated_network"])
    for route in routes:
        destination = route.get("dst")
        require(destination and destination != "default" and not route.get("gateway"), "external/default route prohibited")
        network = ipaddress.ip_network(destination, strict=False)
        eligible = (network.version == 4 and
                    (network.subnet_of(allowed) or network.subnet_of(ipaddress.ip_network("127.0.0.0/8"))))
        eligible = eligible or (network.version == 6 and network == ipaddress.ip_network("::1/128"))
        require(eligible, "route escapes isolated network")
    links = run(["ip", "-j", "link", "show"], check=True, capture_output=True, timeout=5)
    for link in json.loads(links.stdout):
        allowed_links = {"lo", "wt0"}
        if manifest.get("node_namespaces") is not None:
            sealed = manifest.get("bridge_interfaces")
            require(isinstance(sealed, list) and len(sealed) == 6 and sealed[0] == "br0"
                    and len(set(sealed)) == 6 and all(re.fullmatch(r"pv[0-4]", n) for n in sealed[1:]),
                    "sealed bridge interface declaration required")
            allowed_links = {"lo", *sealed}
        require(link.get("ifname") in allowed_links, "external namespace interface prohibited")



def node_namespace_prefixes(manifest, run=subprocess.run):
    nodes = manifest["nodes"]
    mapping = manifest.get("node_namespaces")
    if mapping is None:
        return [[] for _ in nodes]
    require(isinstance(mapping, dict) and set(mapping) == {n["id"] for n in nodes}, "exact node namespace map required")
    host_inode = os.stat("/proc/1/ns/net").st_ino
    parent_inode = os.stat("/proc/self/ns/net").st_ino
    seen = {host_inode, parent_inode}
    prefixes = []
    for node in nodes:
        entry = mapping[node["id"]]
        pid, inode = entry.get("keeper_pid"), entry.get("network_namespace_inode")
        require(type(pid) is int and pid > 1 and type(inode) is int and inode not in seen,
                "unique live isolated node namespace required")
        require(os.stat(f"/proc/{pid}/ns/net").st_ino == inode, "keeper namespace identity changed")
        seen.add(inode)
        prefix = ["nsenter", "-t", str(pid), "-n"]
        config = read_json(Path(node["config_path"]))
        expected_ip = config["network"]["listen_addresses"][0].split(":")[0]
        links = json.loads(run(prefix + ["ip", "-j", "address", "show"], check=True, capture_output=True, timeout=5).stdout)
        require({link["ifname"] for link in links} == {"lo", "wt0"}, "child namespace interfaces invalid")
        addresses = [a["local"] for link in links if link["ifname"] == "wt0" for a in link.get("addr_info", [])]
        require(addresses == [expected_ip], "child namespace must own only its validator IP")
        for family in ("-4", "-6"):
            routes = json.loads(run(prefix + ["ip", family, "-j", "route", "show", "table", "all"], check=True, capture_output=True, timeout=5).stdout)
            check_isolated_routes(routes, manifest["isolated_network"])
        prefixes.append(prefix)
    return prefixes


def check_isolated_routes(routes, subnet):
    allowed = ipaddress.ip_network(subnet)
    for route in routes:
        destination = route.get("dst")
        require(destination and destination != "default" and not route.get("gateway"), "external/default route prohibited")
        network = ipaddress.ip_network(destination, strict=False)
        eligible = network.version == 4 and (network.subnet_of(allowed) or network.subnet_of(ipaddress.ip_network("127.0.0.0/8")))
        eligible = eligible or (network.version == 6 and network == ipaddress.ip_network("::1/128"))
        require(eligible, "route escapes isolated network")


def cleanup(processes, grace=5):
    # Only exact Popen handles owned by this invocation; no PID files or killall.
    for process in processes:
        if process.poll() is None:
            process.terminate()
    deadline = time.monotonic() + grace
    for process in processes:
        try:
            process.wait(timeout=max(0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


MAX_DIAGNOSTIC_BYTES = 64 * 1024


def timing_environment(manifest, config_path):
    root = config_path.parent.parent
    native = read_json(config_path)
    node = next((n for n in manifest["nodes"] if n["config_path"] == str(config_path)), None)
    require(node is not None, "missing per-node timing binding")
    path = safe_path(node["timing_config_path"], root)
    require(stat.S_IMODE(path.stat().st_mode) == 0o600, "timing config must be 0600")
    timing = read_json(path)
    require(set(timing) == {"run_id", "artifact_sha3_256", "node_id", "clock_id", "output"}, "timing config schema mismatch")
    require(timing["artifact_sha3_256"] == manifest["artifact_sha3_256"]
            and timing["run_id"] == manifest["run_id"] and timing["node_id"] == native["node_name"],
            "timing artifact/run/node binding mismatch")
    require(isinstance(timing["clock_id"], str) and timing["clock_id"], "timing clock identity missing")
    output = safe_path(timing["output"], path.parent, exists=False)
    require(not output.exists(), "timing output must be new")
    env = {key: value for key, value in os.environ.items() if not key.startswith("SYNERGY_")}
    env["SYNERGY_POSY_QUALIFICATION_TIMING_CONFIG"] = str(path)
    # Explicit simulated provider executable must be inside the synthetic root.
    provider = safe_path(manifest["simulated_provider_binary"], root)
    require(provider.is_file() and os.access(provider, os.X_OK), "synthetic provider executable unavailable")
    env["SYNERGY_NETBIRD_BINARY"] = str(provider)
    return env


def drain_diagnostic(stream, tail):
    try:
        while True:
            chunk = stream.read(4096)
            if not chunk:
                break
            tail.extend(chunk)
            if len(tail) > MAX_DIAGNOSTIC_BYTES:
                del tail[:-MAX_DIAGNOSTIC_BYTES]
    finally:
        stream.close()


def validate_fault_schedule(manifest, configs, seconds):
    schedule = manifest.get("fault_schedule", [])
    require(isinstance(schedule, list) and len(schedule) <= 1, "at most one declared validator fault supported")
    if not schedule:
        return None
    fault = schedule[0]
    if isinstance(fault, dict) and fault.get("kind") == "quorum_recovery":
        require(set(fault) == {"kind", "validators", "halt_settle_seconds", "halt_observe_seconds"},
                "quorum recovery schedule schema mismatch")
        entries = fault["validators"]
        require(isinstance(entries, list) and len(entries) == 2, "exactly two stopped validators required")
        settle, observe = fault["halt_settle_seconds"], fault["halt_observe_seconds"]
        require(type(settle) in (int, float) and type(observe) in (int, float)
                and 5 <= settle <= 120 and 5 <= observe <= 120, "bounded predeclared halt observation required")
        faults = []
        for entry in entries:
            child = dict(manifest, fault_schedule=[entry])
            faults.append(validate_fault_schedule(child, configs, seconds))
        require(faults[0]["index"] != faults[1]["index"], "quorum fault identities must be distinct")
        require(faults[0]["stop_after_seconds"] == faults[1]["stop_after_seconds"],
                "quorum fault uses one declared stop boundary")
        require(faults[0]["stop_after_seconds"] + settle + observe < faults[0]["restart_after_seconds"]
                and faults[0]["restart_after_seconds"] + 5 < faults[1]["restart_after_seconds"]
                and faults[1]["restart_after_seconds"] + 5 < seconds,
                "halt, fourth restoration and fifth rejoin windows must be ordered")
        require(read_json(faults[0]["config"])["admin_socket_path"] !=
                read_json(faults[1]["config"])["admin_socket_path"], "replacement admin sockets must be distinct")
        require(faults[0]["config"] != faults[1]["config"]
                and faults[0]["environment"] != faults[1]["environment"], "replacement ownership must be distinct")
        return dict(kind="quorum_recovery", faults=faults, halt_settle_seconds=settle,
                    halt_observe_seconds=observe, report_path=faults[0]["report_path"])
    require(isinstance(fault, dict) and set(fault) == {
        "kind", "node_id", "stop_after_seconds", "restart_after_seconds",
        "restart_config_path", "restart_timing_config_path"}, "fault schedule schema mismatch")
    require(fault["kind"] == "validator_restart", "unsupported validator fault")
    require(manifest.get("synthetic_keys_only") is True and manifest.get("diagnostic_only") is True
            and manifest.get("resume_authority_network_id") == manifest.get("network_id")
            and manifest.get("safety_journal_contract") == "native-retained-journals-v1",
            "fault requires explicit synthetic retained-journal contract")
    stop, restart = fault["stop_after_seconds"], fault["restart_after_seconds"]
    require(type(stop) in (int, float) and type(restart) in (int, float)
            and 0 < stop < restart < seconds - 5, "fault times must be ordered within bounded run")
    indices = [i for i, n in enumerate(manifest["nodes"]) if n["id"] == fault["node_id"]]
    require(len(indices) == 1, "fault node must belong to owned fleet")
    index = indices[0]
    original = read_json(configs[index])
    root = configs[index].parent.parent
    replacement_path = safe_path(fault["restart_config_path"], root)
    require(replacement_path.parent == configs[index].parent, "restart config must stay in owned node directory")
    replacement = read_json(replacement_path)
    old_admin, new_admin = original["admin_socket_path"], replacement.get("admin_socket_path")
    require(isinstance(new_admin, str) and new_admin != old_admin, "restart requires fresh admin socket")
    require(not safe_path(new_admin, root, exists=False).exists(), "restart admin socket already exists")
    expected = dict(original, admin_socket_path=new_admin)
    require(replacement == expected, "restart cannot change state, signer, authority or native configuration")
    require(new_admin not in [read_json(c)["admin_socket_path"] for c in configs], "restart admin socket conflicts")
    restart_manifest = dict(manifest)
    restart_manifest["nodes"] = [dict(n) for n in manifest["nodes"]]
    restart_manifest["nodes"][index].update(config_path=str(replacement_path),
        timing_config_path=fault["restart_timing_config_path"])
    environment = timing_environment(restart_manifest, replacement_path)
    old_timing = read_json(safe_path(manifest["nodes"][index]["timing_config_path"], root))
    new_timing = read_json(safe_path(fault["restart_timing_config_path"], root))
    require(old_timing["clock_id"] != new_timing["clock_id"] and old_timing["output"] != new_timing["output"],
            "restart timing clock and output must be new")
    log_path = replacement_path.parent / "qualification-restart-diagnostic-tail.log"
    require(not log_path.exists(), "restart diagnostic output must be new")
    report_path = root / "qualification-fault-events.json"
    require(not report_path.exists(), "fault report must be new")
    return dict(fault, index=index, config=replacement_path, environment=environment, log_path=log_path, report_path=report_path)



RPC_OBSERVATION_PROGRAM = r"""
import http.client,json,sys
host,port=sys.argv[1].rsplit(":",1)
body=json.dumps({"jsonrpc":"2.0","id":1,"method":"synergy_chainTelemetry","params":json.loads(sys.argv[2])})
connection=http.client.HTTPConnection(host.strip("[]"),int(port),timeout=float(sys.argv[3]))
try:
 connection.request("POST","/",body,{"Content-Type":"application/json"})
 response=connection.getresponse()
 data=response.read(1048577)
 if response.status!=200 or len(data)>1048576: raise ValueError("bounded native RPC failed")
 value=json.loads(data)
 if value.get("id")!=1 or value.get("error") is not None or not isinstance(value.get("result"),dict): raise ValueError("native RPC observation rejected")
 print(json.dumps(value["result"],separators=(",",":")))
finally: connection.close()
"""


def sample_common_commitment(manifest, configs, prefixes, indices, elapsed, phase, run=subprocess.run):
    """Native observations only; identical at_height prevents false tip disagreement."""
    require(1 <= len(indices) <= 5, "bounded live observation set required")
    sampled_at = time.monotonic()
    deadline = sampled_at + 5
    latest_query_bounds = {}
    def rpc(index, params):
        timeout = min(1.5, deadline - time.monotonic())
        require(timeout > 0, "fleet observation budget exhausted")
        config = read_json(configs[index])
        address = config.get("rpc", {}).get("listen_address")
        validate_address(address, ipaddress.ip_network(manifest["isolated_network"]))
        query_start = elapsed + time.monotonic() - sampled_at
        result = run(prefixes[index] + [sys.executable, "-c", RPC_OBSERVATION_PROGRAM,
                                       address, json.dumps(params), str(timeout)],
                     check=True, capture_output=True, timeout=timeout + .5)
        query_end = elapsed + time.monotonic() - sampled_at
        if not params:
            latest_query_bounds[manifest["nodes"][index]["id"]] = {"start": query_start, "end": query_end}
        require(len(result.stdout) <= MAX_JSON, "native commitment observation oversized")
        value = json.loads(result.stdout)
        require(value.get("network_identity") == manifest["network_id"]
                and type(value.get("finalized_height")) is int and value["finalized_height"] > 0,
                "native commitment lacks matching incarnation/finality")
        return value
    latest = {index: rpc(index, {}) for index in indices}
    height = min(value["finalized_height"] for value in latest.values())
    commitments = []
    for index in indices:
        value = latest[index]
        if (value.get("common_finalized_commitment") or {}).get("height") != height:
            value = rpc(index, {"at_height": height})
        commitment = value.get("common_finalized_commitment")
        require(isinstance(commitment, dict) and commitment.get("height") == height
                and all(isinstance(commitment.get(key), str) and commitment[key]
                        for key in ("block_id", "state_root", "finality_certificate_id")),
                "exact durable native finalized commitment unavailable")
        commitments.append(commitment)
    require(all(value == commitments[0] for value in commitments), "common finalized commitments disagree")
    return dict(elapsed_seconds=elapsed, phase=phase,
                live_node_ids=[manifest["nodes"][i]["id"] for i in indices],
                finalized_heights={manifest["nodes"][i]["id"]: latest[i]["finalized_height"] for i in indices},
                latest_query_bounds=latest_query_bounds,
                commitments_by_node={manifest["nodes"][index]["id"]: commitment
                                     for index, commitment in zip(indices, commitments)},
                common_finalized_commitment=commitments[0])


def summarize_quorum_samples(samples, fault):
    halt = [sample for sample in samples if sample["phase"] == "below_quorum"]
    four = [sample for sample in samples if sample["phase"] == "four_validators"]
    five = [sample for sample in samples if sample["phase"] == "five_rejoined"]
    halted = len(halt) >= 2 and halt[-1]["elapsed_seconds"] - halt[0]["elapsed_seconds"] >= fault["halt_observe_seconds"]
    if halted:
        halted = all(sample["finalized_heights"] == halt[0]["finalized_heights"] for sample in halt)
        first, last = halt[0].get("latest_query_bounds", {}), halt[-1].get("latest_query_bounds", {})
        halted = halted and set(first) == set(last) == set(halt[0]["finalized_heights"]) and all(
            last[node]["start"] - first[node]["end"] >= fault["halt_observe_seconds"] for node in first)
    base = halt[-1]["common_finalized_commitment"]["height"] if halt else None
    restored = halted and bool(four) and four[-1]["common_finalized_commitment"]["height"] > base
    rejoined = restored and bool(five) and five[-1]["common_finalized_commitment"]["height"] > four[-1]["common_finalized_commitment"]["height"]
    return {"below_quorum_halt": bool(halted), "fourth_validator_restoration": bool(restored),
            "fifth_validator_rejoin": bool(rejoined), "common_commitments": bool(halt and four and five),
            "funded_wallet_effects_verified": False,
            "basis": "bounded native RPC pinned common finalized commitments; independent funded-wallet proof still required"}


def execute(manifest, binary, configs, seconds, run=subprocess.run, popen=subprocess.Popen):
    require(1 <= seconds <= 3600, "qualification duration must be bounded 1–3600 seconds")
    validate_namespace(manifest, run)
    prefixes = node_namespace_prefixes(manifest, run)
    help_result = run([str(binary), "--help"], check=True, capture_output=True, timeout=5)
    require(b"preflight --config" in help_result.stdout, "candidate lacks standalone native prelaunch validation")
    for config, prefix in zip(configs, prefixes):
        result = run(prefix + [str(binary), "preflight", "--config", str(config), "--output", "json"],
                     check=True, capture_output=True, timeout=30)
        require(len(result.stdout) <= MAX_JSON, "native preflight response oversized")
        report = json.loads(result.stdout)
        require(all(report.get(key) is True for key in
                    ("configuration_verified", "signed_authority_verified", "startup_plan_verified")),
                "native structural/signed-authority preflight incomplete")
        require(report.get("network_id") == manifest["network_id"], "native authority fixture network mismatch")
    manifest.setdefault("_verified_genesis_report", {})["signed_authority_preflight_verified"] = True
    environments = [timing_environment(manifest, config) for config in configs]
    for config in configs:
        require(not (config.parent / "qualification-diagnostic-tail.log").exists(), "diagnostic output must be new")
    fault = validate_fault_schedule(manifest, configs, seconds)
    processes, diagnostics, readers, diagnostic_paths = [], [], [], []
    fault_events = []
    faults = fault.get("faults", [fault]) if fault else []
    stopped_indices, restarted_indices = set(), set()
    phase_samples, observation_errors = [], []
    last_sample = -1.0
    try:
        for config, env, prefix in zip(configs, environments, prefixes):
            process = popen(prefix + [str(binary), "start", "--config", str(config)],
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, close_fds=True, env=env)
            processes.append(process)
            tail = bytearray()
            diagnostics.append(tail)
            diagnostic_paths.append(config.parent / "qualification-diagnostic-tail.log")
            reader = threading.Thread(target=drain_diagnostic, args=(process.stdout, tail), daemon=True)
            reader.start()
            readers.append(reader)
        started = time.monotonic()
        deadline = started + seconds
        while time.monotonic() < deadline:
            elapsed = time.monotonic() - started
            for index, process in enumerate(processes[:len(configs)]):
                if index not in stopped_indices or index in restarted_indices:
                    require(process.poll() is None, "native process exited during qualification")
            for active_fault in faults:
                index = active_fault["index"]
                if index not in stopped_indices and elapsed >= active_fault["stop_after_seconds"]:
                    fault_events.append(dict(event="stop_requested", node_id=active_fault["node_id"], elapsed_seconds=elapsed))
                    cleanup([processes[index]], grace=min(5, max(0, deadline - time.monotonic())))
                    require(processes[index].poll() is not None, "old signer not confirmed stopped")
                    stopped_indices.add(index)
                    fault_events.append(dict(event="old_signer_stopped", node_id=active_fault["node_id"],
                                             elapsed_seconds=time.monotonic() - started))
                if index in stopped_indices and index not in restarted_indices and time.monotonic() - started >= active_fault["restart_after_seconds"]:
                    require(time.monotonic() < deadline - 5, "restart deadline exhausted")
                    if fault.get("kind") == "quorum_recovery":
                        checks = summarize_quorum_samples(phase_samples, fault)
                        if not restarted_indices:
                            require(checks["below_quorum_halt"], "declared below-quorum halt observation incomplete")
                        else:
                            require(checks["fourth_validator_restoration"], "fourth validator restoration did not resume finality")
                    config, prefix = active_fault["config"], prefixes[index]
                    result = run(prefix + [str(binary), "preflight", "--config", str(config), "--output", "json"],
                                 check=True, capture_output=True, timeout=min(30, max(1, deadline-time.monotonic())))
                    require(len(result.stdout) <= MAX_JSON, "restart preflight response oversized")
                    report = json.loads(result.stdout)
                    require(all(report.get(k) is True for k in
                                ("configuration_verified", "signed_authority_verified", "startup_plan_verified"))
                            and report.get("network_id") == manifest["network_id"], "restart native preflight failed")
                    require(time.monotonic() < deadline - 5 and processes[index].poll() is not None,
                            "restart deadline exhausted or old identity still active")
                    process = popen(prefix + [str(binary), "start", "--config", str(config)],
                                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    close_fds=True, env=active_fault["environment"])
                    processes.append(processes[index])
                    processes[index] = process
                    tail = bytearray()
                    diagnostics.append(tail)
                    diagnostic_paths.append(active_fault["log_path"])
                    reader = threading.Thread(target=drain_diagnostic, args=(process.stdout, tail), daemon=True)
                    reader.start()
                    readers.append(reader)
                    restarted_indices.add(index)
                    fault_events.append(dict(event="replacement_started", node_id=active_fault["node_id"],
                                             elapsed_seconds=time.monotonic() - started))
            if fault and fault.get("kind") == "quorum_recovery":
                now = time.monotonic() - started
                phase = None
                if len(stopped_indices) == 2 and not restarted_indices:
                    last_stop = max(event["elapsed_seconds"] for event in fault_events if event["event"] == "old_signer_stopped")
                    if now >= last_stop + fault["halt_settle_seconds"]: phase = "below_quorum"
                elif len(restarted_indices) == 1: phase = "four_validators"
                elif len(restarted_indices) == 2: phase = "five_rejoined"
                if phase and now - last_sample >= 1:
                    last_sample = now
                    indices = [i for i in range(len(configs)) if i not in stopped_indices or i in restarted_indices]
                    try:
                        sample = sample_common_commitment(manifest, configs, prefixes, indices, now, phase, run)
                        require(len(phase_samples) < 512, "quorum observation retention limit reached")
                        phase_samples.append(sample)
                    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
                        if isinstance(error, QualificationError) and "disagree" in str(error): raise
                        if len(observation_errors) < 128:
                            observation_errors.append(dict(phase=phase, elapsed_seconds=now, reason=type(error).__name__))
            time.sleep(min(.1, max(0, deadline - time.monotonic())))
        schedule_completed = not fault or len(restarted_indices) == len(faults)
        require(schedule_completed, "declared fault schedule incomplete")
        if fault and fault.get("kind") == "quorum_recovery":
            require(summarize_quorum_samples(phase_samples, fault)["fifth_validator_rejoin"],
                    "fifth validator did not reach later identical finalized commitments")
    finally:
        cleanup(processes)
        for reader in readers:
            reader.join(timeout=5)
        # Raw output stays private in the synthetic fixture; never print it.
        for path, tail in zip(diagnostic_paths, diagnostics):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as output:
                output.write(tail)
        if fault:
            fd = os.open(fault["report_path"], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as output:
                json.dump({"schema_version": 1, "kind": fault["kind"],
                           "fault_events": fault_events, "schedule_completed": len(restarted_indices) == len(faults),
                           "phase_samples": phase_samples, "observation_errors": observation_errors,
                           "checks": summarize_quorum_samples(phase_samples, fault) if fault["kind"] == "quorum_recovery" else None,
                           "recovery_verified": False,
                           "GateD_qualified": False}, output)
    return {"process_survival_only": True, "timing_qualified": False, "tps_qualified": False,
            "fault_events": fault_events, "fault_schedule_completed": bool(fault and len(restarted_indices) == len(faults)),
            "quorum_recovery": summarize_quorum_samples(phase_samples, fault) if fault and fault["kind"] == "quorum_recovery" else None,
            "recovery_verified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--resume-existing-state", action="store_true")
    parser.add_argument("--build-provenance", type=Path)
    parser.add_argument("--expected-provenance-sha3", help="independently obtained public SHA3 pin; required for portable mode")
    parser.add_argument("--genesis-binary", type=Path, help="exact candidate Linux synergy-genesis executable")
    parser.add_argument("--expected-genesis-sha3", help="independently obtained exact Genesis verifier artifact pin")
    parser.add_argument("--require-genuine-genesis", action="store_true", help="refuse diagnostic fixtures without native signed Genesis/authority verification")
    parser.add_argument("--duration-seconds", type=int, default=60)
    args = parser.parse_args()
    try:
        manifest, binary, configs = preflight(args.manifest, args.build_provenance, args.expected_provenance_sha3,
                                               args.resume_existing_state, args.genesis_binary,
                                               args.expected_genesis_sha3, args.require_genuine_genesis)
        result = {"preflight_passed": True, "native_validation_verified": False,
                  "processes_launched": False, "timing_qualified": False, "tps_qualified": False}
        result["provenance"] = manifest["_verified_provenance_report"]
        result["genesis"] = manifest["_verified_genesis_report"]
        result.update(artifact_sha3_256=manifest["artifact_sha3_256"],network_id=manifest["network_id"],run_id=manifest["run_id"])
        result["GateD_qualified"] = False
        result["qualification_limit"] = "native preflight/process survival only; funded execution, common commitments and mandatory fault evidence require independent verification"
        if args.execute:
            result.update(execute(manifest, binary, configs, args.duration_seconds))
            result["processes_launched"] = True
            result["native_validation_verified"] = True
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        parser.exit(2, f"isolated qualification refused: {type(error).__name__}: {error}\n")
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
