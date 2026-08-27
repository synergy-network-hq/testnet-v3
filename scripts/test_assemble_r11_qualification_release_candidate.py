#!/usr/bin/env python3
"""Regression coverage for the source-only R11 release-candidate assembler."""

import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
ASSEMBLER = ROOT / "scripts" / "assemble-r11-qualification-release-candidate.py"
PREFLIGHT = ROOT / "runtime" / "scripts" / "testnet" / "preflight-r11-release-candidate.sh"
VALIDATORS = [f"validator-{number:02d}" for number in range(2, 7)]
REVISION = "a" * 40


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


class ReleaseCandidateTests(unittest.TestCase):
    def test_seals_public_h20_evidence_and_unsigned_v4_request(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            genesis = root / "genesis.json"
            write_json(genesis, {
                "network": {"chain_id": 1266},
                "consensus": {"posy_v3_activation": {"manifest": {
                    "protocol_version": "posy/3.0", "network_id": "testnet",
                    "initial_validator_ids": VALIDATORS, "target_block_time_ms": 500,
                }}},
            })
            configs = root / "configs"
            for validator in VALIDATORS:
                (configs / validator).mkdir(parents=True)
                (configs / validator / "config.toml").write_text(f"[identity]\nnode_id = \"{validator}\"\n")
            binary = root / "synergy-validator-node"
            binary.write_text("""#!/usr/bin/env python3
import re, sys
if sys.argv[1] != 'validate-config': raise SystemExit(2)
value = open(sys.argv[3]).read()
node = re.search(r'node_id = \"([^\"]+)\"', value).group(1)
print(f'validator_id={node} chain_id=1266 network_id=testnet protocol=posy/3.0 mode=posy_simplified_v3')
""")
            binary.chmod(0o755)
            desired_builder = root / "build-chain1266-desired-state"
            desired_builder.write_text("""#!/usr/bin/env python3
import hashlib, json, sys
def value(flag): return sys.argv[sys.argv.index(flag) + 1]
artifact = value('--artifact').split('=', 1)[1]
configs = {item.split('=', 1)[0]: item.split('=', 1)[1] for index, item in enumerate(sys.argv) if index and sys.argv[index - 1] == '--configuration'}
result = {
  'schema_version': 1,
  'chain': {'chain_id': 1266, 'incarnation': 5, 'genesis_hash': 'fixture'},
  'source': {'testnet_v3_revision': value('--testnet-revision'), 'synq_revision': value('--synq-revision'), 'aegis_revision': value('--aegis-revision')},
  'state': {'consensus_schema_version': 5, 'directory_namespace': 'chain-1266/incarnation-5', 'mode': 'posy_simplified_v3', 'coordinator_id': '', 'producer_ids': [], 'producer_turn_timeout_ms': 0},
  'artifacts': {'validator_node': hashlib.sha256(open(artifact, 'rb').read()).hexdigest()},
  'configuration': {role: hashlib.sha256(open(path, 'rb').read()).hexdigest() for role, path in configs.items()},
}
open(value('--output'), 'w').write(json.dumps(result))
""")
            desired_builder.chmod(0o755)
            approval = root / "testnet-v3-genesis-release-approval"
            approval.write_text("""#!/usr/bin/env python3
import json, sys
open(sys.argv[sys.argv.index('--output') + 1], 'w').write(json.dumps({
  'schema_version': 1, 'signature_algorithm': 'ML-DSA-87',
  'signature_domain': 'SYNERGY_TESTNET_V3_GENESIS_RELEASE_APPROVAL_V4',
  'action': 'APPROVE_FINAL_TESTNET_V3_GENESIS_CANDIDATE'
}))
""")
            approval.chmod(0o755)
            authority = root / "authorities.json"
            write_json(authority, {"authority_role": "TestnetV3ReleaseV4", "public_key": "fixture"})
            candidate = root / "candidate"
            for name in (
                "consensus-parameter-manifest.unsigned.json",
                "genesis-predeployment-candidate.unsigned.json",
                "desired-state-input.unsigned.json",
                "governance-signing-request.unsigned.json",
            ):
                write_json(candidate / name, {"public": True})
            write_json(candidate / "validation-report.json", {"NEW_TIMING": 500, "runtime_config_status": "MILLISECOND_CADENCE_FIELDS_BOUND"})
            registries = root / "registries"
            for height in range(3, 21):
                write_json(registries / f"h{height}.json", {
                    "format": "synergy-posy-simplified-ingress-kem-registry-v1", "epoch": 0, "target_height": height,
                    "registry": {"registry_version": 1, "chain_id": 1266, "network_id": "testnet", "protocol_version": "posy/3.0", "epoch": 0, "target_height": height, "records": [{}, {}, {}, {}, {}]},
                })
            evidence = root / "evidence"
            evidence.mkdir()
            evidence.joinpath("qualification-summary.txt").write_text(
                "H1_H2_BOOTSTRAP_FINALIZED=YES\nH3_NORMAL_ETDAG_FINALIZED=YES\nH4_STEADY_STATE_FINALIZED=YES\nHARNESS_20_BLOCK_PASS=YES\nVALIDATOR_RESTART_PASS=YES\n"
            )
            evidence.joinpath("block-timing-ms.tsv").write_text("".join(f"{height}->{height + 1}\t500\n" for height in range(3, 20)))
            output = root / "sealed-candidate"
            command = [
                "python3", str(ASSEMBLER), "--genesis", str(genesis), "--ingress-kem-registry-dir", str(registries),
                "--evidence-dir", str(evidence), "--validator-binary", str(binary), "--config-dir", str(configs),
                "--desired-state-builder", str(desired_builder), "--release-approval-tool", str(approval),
                "--authority-record", str(authority), "--candidate-input-dir", str(candidate),
                "--release-id", "r11-fixture", "--release-tag", "r11-fixture", "--testnet-v3-revision", REVISION,
                "--synq-revision", REVISION, "--aegis-revision", REVISION, "--output-dir", str(output),
            ]
            result = subprocess.run(command, check=True, text=True, capture_output=True)
            self.assertIn("R11_RELEASE_CANDIDATE_ASSEMBLED", result.stdout)
            manifest = json.loads((output / "package-manifest.json").read_text())
            self.assertEqual(manifest["status"], "LOCAL_R11_QUALIFIED_V4_REQUEST_UNSIGNED")
            self.assertEqual(len(manifest["artifacts"]["ingress_kem_registry_sha256"]), 18)
            self.assertTrue((output / "SHA256SUMS").is_file())
            checked = subprocess.run([str(PREFLIGHT), "--package", str(output)], check=True, text=True, capture_output=True)
            self.assertIn("R11_RELEASE_CANDIDATE_PREFLIGHT_PASS", checked.stdout)
            self.assertEqual(
                hashlib.sha256((output / "v4-governance-request.unsigned.json").read_bytes()).hexdigest(),
                manifest["artifacts"]["unsigned_v4_governance_request_sha256"],
            )
            self.assertFalse(any("private" in path.name.lower() for path in output.rglob("*")))


if __name__ == "__main__":
    unittest.main()
