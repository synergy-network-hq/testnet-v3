import io
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("qualify", Path(__file__).with_name("qualify-posy-process-fleet.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class FakeProcess:
    def __init__(self, stuck=False):
        self.stdout = io.BytesIO(b"synthetic failure detail")
        self.alive, self.stuck, self.terminated, self.killed = True, stuck, False, False
    def poll(self):
        return None if self.alive else 0
    def terminate(self):
        self.terminated = True
        if not self.stuck:
            self.alive = False
    def wait(self, timeout):
        if self.alive:
            raise subprocess.TimeoutExpired("owned", timeout)
        return 0
    def kill(self):
        self.killed, self.alive = True, False


class QualificationTests(unittest.TestCase):
    def test_cleanup_targets_only_owned_handles_and_escalates_stuck_process(self):
        healthy, stuck, unrelated = FakeProcess(), FakeProcess(True), FakeProcess()
        module.cleanup([healthy, stuck], grace=0)
        self.assertTrue(healthy.terminated)
        self.assertFalse(healthy.killed)
        self.assertTrue(stuck.killed)
        self.assertFalse(unrelated.terminated)

    def test_symlinks_escape_and_production_prefix_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            file = root / "file"
            file.touch()
            (root / "link").symlink_to(file)
            for value in (root / "link", Path("/etc/synergy/node.json"), root / ".." / "file"):
                with self.assertRaises(module.QualificationError):
                    module.safe_path(value, root)
            with self.assertRaises(module.QualificationError):
                module.safe_path(root.parent / "outside", root, False)

    def test_wildcard_external_bind_and_dns_rejected(self):
        allowed = module.ipaddress.ip_network("10.69.10.0/24")
        for address in ("0.0.0.0:8545", "8.8.8.8:8545", "example.org:8545", "127.0.0.1:0"):
            with self.assertRaises(module.QualificationError):
                module.validate_address(address, allowed)
        module.validate_address("127.0.0.1:8545", allowed)
        module.validate_address("tcp://10.69.10.2:30303", allowed)

    def test_missing_native_capability_never_launches(self):
        run = lambda *_a, **_k: SimpleNamespace(stdout=b"start --config")
        with patch.object(module, "validate_namespace"), patch.object(module, "node_namespace_prefixes", return_value=[[],[],[],[],[]]), patch.object(module.subprocess, "Popen") as popen:
            with self.assertRaisesRegex(module.QualificationError, "lacks standalone"):
                module.execute({}, Path("/candidate"), [], 1, run=run, popen=popen)
            popen.assert_not_called()

    def test_native_authority_failure_never_launches(self):
        def run(args, **_kwargs):
            return SimpleNamespace(stdout=(b"preflight --config" if args[-1] == "--help" else b'{}'))
        with patch.object(module, "validate_namespace"), patch.object(module, "node_namespace_prefixes", return_value=[[],[],[],[],[]]), patch.object(module.subprocess, "Popen") as popen:
            with self.assertRaisesRegex(module.QualificationError, "incomplete"):
                module.execute({"network_id": "posy-isolated-test"}, Path("/candidate"), [Path("/config")], 1, run, popen)
            popen.assert_not_called()

    def test_partial_launch_failure_cleans_previously_owned_child(self):
        owned = FakeProcess()
        def run(args, **_kwargs):
            data = dict(configuration_verified=True, signed_authority_verified=True,
                        startup_plan_verified=True, network_id="posy-isolated-test")
            return SimpleNamespace(stdout=(b"preflight --config" if args[-1] == "--help" else json.dumps(data).encode()))
        with patch.object(module, "validate_namespace"), patch.object(module, "node_namespace_prefixes", return_value=[[],[],[],[],[]]), patch.object(module, "timing_environment", return_value={}), patch.object(module.os, "open", side_effect=OSError("diagnostic path unavailable")), patch.object(module.subprocess, "Popen", side_effect=[owned, OSError("injected")]) as popen:
            with self.assertRaises(OSError):
                module.execute({"network_id": "posy-isolated-test"}, Path("/candidate"), [Path("/config1"), Path("/config2")], 1, run, popen)
        self.assertTrue(owned.terminated)

    def test_manifest_wrong_exact_artifact_bytes_rejected(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp" if Path("/private/tmp").is_dir() else "/tmp") as directory:
            root = Path(directory)
            root.chmod(0o700)
            binary = root / "candidate"
            binary.write_bytes(b"\x7fELFsynthetic-test-bytes")
            binary.chmod(0o700)
            manifest = root / "fixture.json"
            manifest.write_text(json.dumps(dict(fixture_kind=module.FIXTURE_KIND,
                synthetic_keys_only=True, network_id="posy-isolated-test",
                isolated_network="10.69.10.0/24", binary_path=str(binary),
                artifact_sha3_256="0" * 64)))
            with patch.object(module, "fixture_root_allowed", return_value=True):
                with self.assertRaisesRegex(module.QualificationError, "artifact digest mismatch"):
                    module.preflight(manifest)
            binary.write_bytes(b"not-an-ELF")
            with patch.object(module, "fixture_root_allowed", return_value=True):
                with self.assertRaisesRegex(module.QualificationError, "Linux ELF"):
                    module.preflight(manifest)

    def test_namespace_rejects_external_default_route(self):
        def stat_result(path):
            return SimpleNamespace(st_ino=200 if str(path) == "/proc/self/ns/net" else 100)
        run = lambda *_a, **_k: SimpleNamespace(stdout=b'[{"dst":"default","gateway":"10.69.10.1"}]')
        with patch.object(module.sys, "platform", "linux"), patch.object(module.os, "stat", side_effect=stat_result):
            with self.assertRaisesRegex(module.QualificationError, "external/default"):
                module.validate_namespace({"network_namespace_inode":200,"isolated_network":"10.69.10.0/24"}, run)

    def test_dedicated_root_whitelist(self):
        self.assertTrue(module.fixture_root_allowed(Path("/tmp/posy-isolated-test")))
        self.assertTrue(module.fixture_root_allowed(Path("/var/tmp/posy-isolated-test")))
        self.assertTrue(module.fixture_root_allowed(module.CANONICAL_TARGET / "posy-isolated-test"))
        for root in (Path("/tmp/arbitrary"), Path("/var/tmp/arbitrary"), Path("/var/tmp/nested/posy-isolated-test"), Path("/home/user/posy-isolated-test"), Path("/var/lib/synergy/posy-isolated-test")):
            self.assertFalse(module.fixture_root_allowed(root))

    def test_timing_environment_rejects_wrong_node_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            node_dir = root / "node-0"
            node_dir.mkdir()
            config = node_dir / "config.json"
            config.write_text(json.dumps({"node_name":"socket-0"}))
            timing = node_dir / "timing.json"
            timing.write_text(json.dumps(dict(run_id="run", artifact_sha3_256="a"*64,
                node_id="wrong-node", clock_id="clock", output=str(node_dir/"events.jsonl"))))
            timing.chmod(0o600)
            manifest = dict(run_id="run", artifact_sha3_256="a"*64,
                nodes=[dict(config_path=str(config), timing_config_path=str(timing))])
            # Temporary macOS roots may contain an OS-owned symlink; path safety is tested separately.
            with patch.object(module, "safe_path", side_effect=lambda path, *_a, **_k: Path(path)):
                with self.assertRaisesRegex(module.QualificationError, "binding mismatch"):
                    module.timing_environment(manifest, config)

    def test_diagnostic_tail_bounded_without_blocking_on_output(self):
        tail = bytearray()
        module.drain_diagnostic(io.BytesIO(b"x" * (module.MAX_DIAGNOSTIC_BYTES + 5000)), tail)
        self.assertEqual(len(tail), module.MAX_DIAGNOSTIC_BYTES)

    def test_portable_provenance_requires_independent_pin_and_exact_artifact(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp" if Path("/private/tmp").exists() else "/tmp") as directory:
            path = Path(directory) / "provenance.json"
            document = dict(schema_version=1, kind="posy-linux-build-provenance-v1",
                artifact_sha3_256="a"*64, target="x86_64-unknown-linux-gnu",
                toolchain=dict(rustc_version="rustc 1.89",cargo_version="cargo 1.89",rustc_commit_hash="b"*40),
                build_config=dict(profile="release",package="synergy-node",locked=True,
                                  features=["qualification-timing"],rustflags=[]),
                sources=[dict(path=p,sha3_256="c"*64) for p in
                         ["Cargo.toml","Cargo.lock","bin/synergy-node/Cargo.toml"]])
            path.write_text(json.dumps(document))
            pin = module.sha3(path)
            for expected, artifact in [(None,"a"*64),("0"*64,"a"*64),(pin,"d"*64)]:
                with self.assertRaises(module.QualificationError):
                    module.verify_portable_provenance(path, expected, artifact)
            report = module.verify_portable_provenance(path,pin,"a"*64)
            self.assertTrue(report["transported_provenance_pin_verified"])
            self.assertFalse(report["linux_source_files_verified"])
            self.assertFalse(report["GateD_qualified"])
            document["sources"][0]["path"] = "../private.key"
            path.write_text(json.dumps(document))
            with self.assertRaises(module.QualificationError):
                module.verify_portable_provenance(path,module.sha3(path),"a"*64)

    @staticmethod
    def complete_provenance(files):
        tree = dict(source_revision="b" * 40, clean=False, files=files)
        return dict(format_version=1, qualification_state="unqualified_candidate",
            artifact=dict(length=64, sha3_256="a" * 64), before=tree, after=tree,
            target="x86_64-unknown-linux-gnu",
            build_config=dict(profile="release", locked=True, features=["qualification-timing"]),
            toolchain=dict(rustc="rustc test\ncommit-hash: " + "b" * 40),
            companions={name:dict(length=64, sha3_256="c" * 64) for name in
                ("synergy-keytool", "synergy-genesis", "synergy-fixture-exporter")})

    def test_complete_provenance_entry_budget_is_global_inclusive_and_bounded(self):
        required = [dict(path=path, length=0, sha256="c" * 64) for path in
            ("node-platform/Cargo.toml", "node-platform/Cargo.lock", "node-platform/bin/synergy-node/Cargo.toml")]
        # Exercise the real limit across a nested tree, not a patched lower
        # constant: every input remains pinned and the 64 MiB cap still applies.
        children = [dict(path=f"input/{index}", length=0, sha256="c" * 64)
            for index in range(module.MAX_COMPLETE_INPUT_ENTRIES - len(required) - 1)]
        files = required + [dict(path="nested", submodule=dict(source_revision="b" * 40, clean=False, files=children))]
        document = self.complete_provenance(files)
        with tempfile.TemporaryDirectory(dir="/private/tmp" if Path("/private/tmp").exists() else "/tmp") as directory:
            path = Path(directory) / "provenance.json"
            path.write_text(json.dumps(document, separators=(",", ":")))
            self.assertLessEqual(path.stat().st_size, 64 * 1024 * 1024)
            report = module.verify_portable_provenance(path, module.sha3(path), "a" * 64)
            self.assertEqual(report["source_inventory_count"], module.MAX_COMPLETE_INPUT_ENTRIES)
            self.assertFalse(report["GateD_qualified"])
            children.append(dict(path="one-over-budget", length=0, sha256="c" * 64))
            path.write_text(json.dumps(document, separators=(",", ":")))
            with self.assertRaisesRegex(module.QualificationError, "count bound exceeded"):
                module.verify_portable_provenance(path, module.sha3(path), "a" * 64)

    def test_complete_provenance_larger_budget_preserves_bindings_and_path_guards(self):
        files = [dict(path=path, length=0, sha256="c" * 64) for path in
            ("node-platform/Cargo.toml", "node-platform/Cargo.lock", "node-platform/bin/synergy-node/Cargo.toml")]
        with tempfile.TemporaryDirectory(dir="/private/tmp" if Path("/private/tmp").exists() else "/tmp") as directory:
            path = Path(directory) / "provenance.json"
            for bad in ("../outside", "/absolute", "node-platform/Cargo.toml"):
                with self.subTest(path=bad):
                    path.write_text(json.dumps(self.complete_provenance(files + [dict(path=bad, length=0, sha256="c" * 64)])))
                    with self.assertRaisesRegex(module.QualificationError, "escapes or duplicates"):
                        module.verify_portable_provenance(path, module.sha3(path), "a" * 64)
            path.write_text(json.dumps(self.complete_provenance(files)))
            pin = module.sha3(path)
            for expected, artifact in (("0" * 64, "a" * 64), (pin, "d" * 64)):
                with self.assertRaises(module.QualificationError):
                    module.verify_portable_provenance(path, expected, artifact)
            with path.open("wb") as stream:
                stream.truncate(64 * 1024 * 1024 + 1)
            with self.assertRaisesRegex(module.QualificationError, "bounded complete public provenance"):
                module.verify_portable_provenance(path, "0" * 64, "a" * 64)

    def test_control_cannot_replace_native_manifest_and_native_identity_required(self):
        with tempfile.TemporaryDirectory(dir="/private/tmp" if Path("/private/tmp").exists() else "/tmp") as directory:
            root = Path(directory)
            native = root / "manifest.json"
            control = root / "qualification-manifest.json"
            native.write_text(json.dumps(dict(chain_id=1266,network_id="posy-isolated-test")))
            config = dict(manifest_path=str(native),chain_id=1266,network_id="posy-isolated-test")
            module.verify_native_manifest_separation(control, config, root)
            with self.assertRaisesRegex(module.QualificationError, "cannot replace"):
                module.verify_native_manifest_separation(native, config, root)
            native.write_text(json.dumps(dict(fixture_kind=module.FIXTURE_KIND)))
            with self.assertRaisesRegex(module.QualificationError, "identity mismatch"):
                module.verify_native_manifest_separation(control, config, root)
            native.write_text(json.dumps(dict(chain_id=1266,network_id="wrong-network")))
            with self.assertRaisesRegex(module.QualificationError, "identity mismatch"):
                module.verify_native_manifest_separation(control, config, root)

    def test_per_node_namespace_rejects_host_or_duplicate_identity(self):
        nodes = [{"id":"node0","config_path":"/unused"}]
        manifest = {"nodes":nodes,"node_namespaces":{"node0":{"keeper_pid":42,"network_namespace_inode":100}}}
        with patch.object(module.os, "stat", return_value=SimpleNamespace(st_ino=100)):
            with self.assertRaisesRegex(module.QualificationError, "unique"):
                module.node_namespace_prefixes(manifest)

    def test_namespace_routes_forbid_gateway_and_external_ipv6(self):
        for routes in ([{"dst":"default"}], [{"dst":"10.69.10.0/24","gateway":"10.69.10.1"}], [{"dst":"2001:db8::/32"}]):
            with self.assertRaises(module.QualificationError):
                module.check_isolated_routes(routes,"10.69.10.0/24")
        module.check_isolated_routes([{"dst":"10.69.10.0/24"},{"dst":"127.0.0.0/8"}],"10.69.10.0/24")

    def test_fault_schedule_rejects_unsupported_or_unbounded_contracts(self):
        base = dict(synthetic_keys_only=True, diagnostic_only=True, network_id="posy-isolated-test",
                    resume_authority_network_id="posy-isolated-test", safety_journal_contract="native-retained-journals-v1",
                    nodes=[dict(id="node0")])
        fault = dict(kind="validator_restart", node_id="node0", stop_after_seconds=2,
                     restart_after_seconds=4, restart_config_path="/unused", restart_timing_config_path="/unused")
        self.assertIsNone(module.validate_fault_schedule({}, [], 20))
        for changes in (dict(stop_after_seconds=0), dict(restart_after_seconds=2),
                        dict(restart_after_seconds=15), dict(node_id="unknown"), dict(kind="reset"),
                        dict(stop_after_seconds=True), dict(restart_after_seconds=float("nan"))):
            with self.assertRaises(module.QualificationError):
                module.validate_fault_schedule(dict(base, fault_schedule=[dict(fault, **changes)]), [], 20)
        for changes in (dict(fault_schedule=[fault, fault]), dict(safety_journal_contract="unknown"),
                        dict(diagnostic_only=False), dict(resume_authority_network_id="wrong")):
            with self.assertRaises(module.QualificationError):
                module.validate_fault_schedule({**base, "fault_schedule":[fault], **changes}, [], 20)

    def test_fault_replacement_cannot_change_journals_signer_or_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            node = root / "node0"
            node.mkdir()
            original = node / "config.json"
            replacement = node / "restart.json"
            value = dict(admin_socket_path=str(node/"admin.sock"), storage=dict(data_directory=str(node/"state")),
                         consensus=dict(signing_key_path=str(node/"key")))
            original.write_text(json.dumps(value))
            replacement.write_text(json.dumps(dict(value, admin_socket_path=str(node/"restart.sock"),
                                                   storage=dict(data_directory=str(node/"other")))))
            manifest = dict(synthetic_keys_only=True, diagnostic_only=True, network_id="posy-isolated-test",
                resume_authority_network_id="posy-isolated-test", safety_journal_contract="native-retained-journals-v1",
                nodes=[dict(id="node0",config_path=str(original))], fault_schedule=[dict(kind="validator_restart",
                    node_id="node0",stop_after_seconds=2,restart_after_seconds=4,
                    restart_config_path=str(replacement),restart_timing_config_path=str(node/"timing.json"))])
            with patch.object(module,"safe_path",side_effect=lambda p,*_a,**_k:Path(p)):
                with self.assertRaisesRegex(module.QualificationError,"cannot change state"):
                    module.validate_fault_schedule(manifest,[original],20)

    def test_fault_validated_restart_preserves_state_and_requires_new_clock(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            node = root / "node0"
            node.mkdir()
            original, replacement = node/"config.json", node/"restart.json"
            original.write_text(json.dumps(dict(admin_socket_path=str(node/"admin.sock"),
                                                storage=dict(data_directory=str(node/"state")))))
            replacement.write_text(json.dumps(dict(admin_socket_path=str(node/"restart.sock"),
                                                   storage=dict(data_directory=str(node/"state")))))
            old, new = node/"timing.json", node/"restart-timing.json"
            old.write_text(json.dumps(dict(clock_id="old",output=str(node/"old-events"))))
            new.write_text(json.dumps(dict(clock_id="new",output=str(node/"new-events"))))
            manifest = dict(synthetic_keys_only=True,diagnostic_only=True,network_id="posy-isolated-test",
                resume_authority_network_id="posy-isolated-test",safety_journal_contract="native-retained-journals-v1",
                nodes=[dict(id="node0",config_path=str(original),timing_config_path=str(old))],
                fault_schedule=[dict(kind="validator_restart",node_id="node0",stop_after_seconds=2,
                    restart_after_seconds=4,restart_config_path=str(replacement),restart_timing_config_path=str(new))])
            with patch.object(module,"safe_path",side_effect=lambda p,*_a,**_k:Path(p)), \
                 patch.object(module,"timing_environment",return_value={}):
                self.assertEqual(module.validate_fault_schedule(manifest,[original],20)["index"],0)
                new.write_text(json.dumps(dict(clock_id="old",output=str(node/"new-events"))))
                with self.assertRaisesRegex(module.QualificationError,"clock and output"):
                    module.validate_fault_schedule(manifest,[original],20)

    def test_fault_stops_old_signer_before_replacement_and_cleans_both(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            configs = [root/str(i)/"config.json" for i in range(5)]
            for config in configs:
                config.parent.mkdir()
            initial = [FakeProcess() for _ in range(5)]
            replacement = FakeProcess()
            spawned = []
            def popen(*_a,**_k):
                if len(spawned) == 5:
                    self.assertTrue(initial[0].terminated)
                    self.assertIsNotNone(initial[0].poll())
                    process = replacement
                else:
                    process = initial[len(spawned)]
                spawned.append(process)
                return process
            def run(args,**_k):
                return SimpleNamespace(stdout=(b"preflight --config" if args[-1]=="--help" else json.dumps(dict(
                    configuration_verified=True,signed_authority_verified=True,startup_plan_verified=True,
                    network_id="posy-isolated-test")).encode()))
            fault = dict(kind="validator_restart",index=0,node_id="node0",stop_after_seconds=1,restart_after_seconds=2,
                         config=root/"restart.json",environment={},log_path=root/"restart.log",report_path=root/"fault.json")
            clock = [0.0]
            def sleep(seconds): clock[0] += seconds
            with patch.object(module,"validate_namespace"), patch.object(module,"node_namespace_prefixes",return_value=[[]]*5), \
                 patch.object(module,"timing_environment",return_value={}), patch.object(module,"validate_fault_schedule",return_value=fault), \
                 patch.object(module.time,"monotonic",side_effect=lambda:clock[0]), patch.object(module.time,"sleep",side_effect=sleep):
                report=module.execute(dict(network_id="posy-isolated-test"),Path("/candidate"),configs,10,run,popen)
            self.assertEqual([e["event"] for e in report["fault_events"]],
                             ["stop_requested","old_signer_stopped","replacement_started"])
            self.assertTrue(report["fault_schedule_completed"])
            self.assertTrue(all(p.terminated for p in spawned))
            self.assertFalse(json.loads((root/"fault.json").read_text())["recovery_verified"])

    def test_oversized_json_rejected_before_read(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "large"
            with path.open("wb") as stream:
                stream.truncate(module.MAX_JSON + 1)
            with self.assertRaises(module.QualificationError):
                module.read_json(path)



class QuorumEvidenceTests(unittest.TestCase):
    def sample(self, phase, time, height, ids):
        commitment = dict(height=height, block_id=f"block-{height}", state_root=f"state-{height}",
                          finality_certificate_id=f"qc-{height}", protected_execution_root=f"execution-{height}")
        return dict(phase=phase, elapsed_seconds=time, live_node_ids=ids,
                    finalized_heights={node: height for node in ids},
                    latest_query_bounds={node: {"start": time, "end": time} for node in ids},
                    commitments_by_node={node: dict(commitment) for node in ids},
                    common_finalized_commitment=commitment)

    def test_quorum_proof_requires_halt_fourth_progress_and_later_fifth_commitment(self):
        ids = ["a", "b", "c"]
        samples = [self.sample("below_quorum", 10, 40, ids),
                   self.sample("below_quorum", 15, 40, ids),
                   self.sample("four_validators", 25, 43, ids + ["d"]),
                   self.sample("five_rejoined", 35, 46, ids + ["d", "e"])]
        checks = module.summarize_quorum_samples(samples, {"halt_observe_seconds": 5})
        self.assertTrue(checks["below_quorum_halt"])
        self.assertTrue(checks["fourth_validator_restoration"])
        self.assertTrue(checks["fifth_validator_rejoin"])
        self.assertFalse(checks["funded_wallet_effects_verified"])

    def test_below_quorum_progress_invalidates_halt_and_recovery(self):
        samples = [self.sample("below_quorum", 10, 40, ["a", "b", "c"]),
                   self.sample("below_quorum", 15, 41, ["a", "b", "c"]),
                   self.sample("four_validators", 25, 43, ["a", "b", "c", "d"]),
                   self.sample("five_rejoined", 35, 46, ["a", "b", "c", "d", "e"])]
        checks = module.summarize_quorum_samples(samples, {"halt_observe_seconds": 5})
        self.assertFalse(checks["below_quorum_halt"])
        self.assertFalse(checks["fourth_validator_restoration"])
        self.assertFalse(checks["fifth_validator_rejoin"])

    def test_fifth_process_start_without_later_common_finality_does_not_pass(self):
        samples = [self.sample("below_quorum", 10, 40, ["a", "b", "c"]),
                   self.sample("below_quorum", 15, 40, ["a", "b", "c"]),
                   self.sample("four_validators", 25, 43, ["a", "b", "c", "d"]),
                   self.sample("five_rejoined", 35, 43, ["a", "b", "c", "d", "e"])]
        checks = module.summarize_quorum_samples(samples, {"halt_observe_seconds": 5})
        self.assertTrue(checks["fourth_validator_restoration"])
        self.assertFalse(checks["fifth_validator_rejoin"])



class CompleteInventoryPathTests(unittest.TestCase):
    def verify(self,extra):
        digest="1"*64
        file=lambda path:dict(path=path,length=1,sha256=digest)
        tree=dict(source_revision="a"*40,clean=False,files=[file("node-platform/Cargo.toml"),file("node-platform/Cargo.lock"),file("node-platform/bin/synergy-node/Cargo.toml"),*extra])
        document=dict(format_version=1,qualification_state="unqualified_candidate",artifact={"sha3_256":digest},before=tree,after=tree,target="x86_64-unknown-linux-gnu",build_config=dict(profile="release",locked=True,features=["qualification-timing"]),toolchain={"rustc":"rustc pinned\ncommit-hash: "+"b"*40},companions={name:{"length":120,"sha3_256":digest} for name in ["synergy-keytool","synergy-genesis","synergy-fixture-exporter"]})
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"provenance.json";path.write_text(json.dumps(document))
            # This is public evidence schema validation, not a host-path permission test.
            with patch.object(module,"safe_path",side_effect=Path):
                return module.verify_portable_provenance(path,module.sha3(path),digest)

    def directory(self,path):
        return dict(path=path,submodule=dict(source_revision="c"*40,clean=False,files=[dict(path="Cargo.toml",length=1,sha256="2"*64)]))

    def test_existing_git_trailing_directory_slash_is_canonicalized(self):
        result=self.verify([self.directory("testnet-v3/")])
        self.assertEqual(result["source_inventory_count"],5)
        self.assertFalse(result["GateD_qualified"])

    def test_current_canonical_directory_spelling_is_accepted(self):
        self.verify([self.directory("testnet-v3")])

    def test_equivalent_directory_spellings_cannot_hide_duplicate(self):
        with self.assertRaises(module.QualificationError):
            self.verify([self.directory("testnet-v3"),self.directory("testnet-v3/")])

    def test_file_trailing_slash_double_slash_and_parent_escape_rejected(self):
        for entry in [dict(path="file/",length=1,sha256="2"*64),self.directory("testnet-v3//"),self.directory("../testnet-v3/")]:
            with self.subTest(path=entry["path"]),self.assertRaises(module.QualificationError):self.verify([entry])

    def test_link_expansion_is_distinct_from_direct_tracked_target(self):
        import hashlib
        target="node-platform";digest="2"*64
        link=dict(path="alias",state="symlink_input",target=target,target_sha256=hashlib.sha256(target.encode()).hexdigest(),promotion_eligible=True,resolution="canonical_directory",resolved_path=target,files=[dict(path="node-platform/Cargo.toml",length=1,sha256=digest)])
        self.verify([link])


class NativeGenesisWrapperTests(unittest.TestCase):
    def setUp(self):
        self.directory=tempfile.TemporaryDirectory();self.addCleanup(self.directory.cleanup)
        self.root=Path(self.directory.name)
        self.binary=self.root/"synergy-genesis";self.binary.write_bytes(b"\x7fELF"+bytes(60));self.binary.chmod(0o700)
        self.genesis_hash="a"*64
        network=dict(chain_id=1266,network_id="posy-isolated-wrapper",protocol_version="native-profile")
        validator=dict(record={"validator_id":"synthetic"},algorithm="ml_dsa65",public_key=[1,2])
        self.genesis=self.root/"genesis.sgen";self.genesis.write_text(json.dumps(dict(genesis_hash=self.genesis_hash,unsigned=dict(network=network,validators=[validator]))))
        self.authority=self.root/"authority.json"
        self.payload=dict(chain_id=1266,network_id=network["network_id"],anchor_parent=dict(kind="genesis",reference=dict(genesis_hash=self.genesis_hash,block_id=self.genesis_hash,reference_id="b"*64)),validators=[dict(validator,authority_specific_field="native-only")])
        self.authority.write_text(json.dumps({"payload":self.payload}))
        self.trust=self.root/"trust.pub";self.trust.write_bytes(b"public synthetic test pin")
        manifest=self.root/"manifest.json";manifest.write_text(json.dumps(dict(network,genesis_hash=self.genesis_hash)))
        self.report=self.root/"native-report.json";self.report.write_text("{}")
        self.config=self.root/"config.json";self.config.write_text(json.dumps(dict(aegis_provider=dict(report_path=str(self.report),authenticated_report_sha256="d"*64),manifest_path=str(manifest),consensus=dict(authority_binding=str(self.authority),authority_trust_key_path=str(self.trust)))))
        self.manifest=dict(network_id=network["network_id"],genesis_path=str(self.genesis),full_signed_genesis=True)
        self.success=lambda *args,**kwargs:SimpleNamespace(stdout=f"verified Genesis/authority binding genesis_hash={self.genesis_hash}".encode(),stderr=b"")

    def verify(self,run):
        # These tests exercise wrapper contracts; cryptographic proof comes from
        # the independently pinned native CLI in actual isolated qualification.
        with patch.object(module.sys,"platform","linux"),patch.object(module,"safe_path",side_effect=lambda path,*args,**kwargs:Path(path)):
            return module.verify_genuine_genesis(self.manifest,[self.config],self.root,self.binary,module.sha3(self.binary),True,run)

    def test_actual_tagged_anchor_and_different_validator_schemas_use_native_binding(self):
        calls=[]
        def verified(command,**kwargs):calls.append(command);return self.success()
        report=self.verify(verified)
        self.assertTrue(report["native_genesis_verified"])
        self.assertFalse(report["GateD_qualified"])
        self.assertEqual(calls[0],[str(self.binary),"verify-binding",str(self.genesis),str(self.trust),str(self.authority),"--apqe-report",str(self.report),"--apqe-report-sha256","d"*64])

    def test_native_verifier_failure_never_marks_binding_verified(self):
        def rejected(command,**kwargs):raise subprocess.CalledProcessError(1,command)
        with self.assertRaises(subprocess.CalledProcessError):self.verify(rejected)

    def test_wrong_tag_or_block_hash_is_rejected_before_native_call(self):
        for field,value in [("kind","quorum_certificate"),("block_id","c"*64)]:
            with self.subTest(field=field):
                original=json.loads(json.dumps(self.payload))
                if field=="kind":original["anchor_parent"][field]=value
                else:original["anchor_parent"]["reference"][field]=value
                self.authority.write_text(json.dumps({"payload":original}))
                with self.assertRaises(module.QualificationError):self.verify(self.success)

    def test_public_authority_change_during_native_verification_is_rejected(self):
        def changed(command,**kwargs):
            self.authority.write_text(self.authority.read_text()+" ")
            return self.success()
        with self.assertRaisesRegex(module.QualificationError,"changed during verification"):self.verify(changed)

if __name__ == "__main__":
    unittest.main()
