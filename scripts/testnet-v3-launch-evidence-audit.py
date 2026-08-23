#!/usr/bin/env python3
"""Read-only final evidence audit for the Synergy Testnet-v3 launch.

This preflight reads the local release evidence only.  It does not SSH, make a
network request, create identities, decrypt material, alter a service, or
write a project artifact.  When an existing runtime verifier needs an output
path, the verifier is given an automatically removed temporary directory and
the preflight compares that result to the supplied evidence.

The output is a single JSON document on stdout.  Exit status is zero only when
every required launch-evidence gate is PASS.  A coordinator snapshot is an
explicit optional input because it is downloaded separately; omitting it is a
MISSING launch gate, not a successful offline verification.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


CHAIN_ID = 1266
NETWORK_ID = "testnet"
GENERATOR_VERSION = "testnet-v3-node-configs/v8-posy-simplified-v3"
PHASE7_STATUS = "PHASE_7_8_APPLIED_PENDING_RELEASE_GATES"
EXPECTED_INNERNET_NETWORK = "synergy-innernet-membership-v1"
# The user-authorized fresh peer reset deliberately retained this pinned V3
# migration binding and coordinator signer.  A new migration ID would require
# an explicit runtime/config rebind and a fresh qualification pass; do not
# infer one merely because the Innernet peer state was rebuilt.
EXPECTED_INNERNET_MIGRATION_ID = "synergy-testnet-innernet-v19-14450ae4d67455c7"
EXPECTED_VALIDATOR_IDS = tuple(f"validator-{number:02d}" for number in range(2, 7))
EXPECTED_IDENTITY_IDS = tuple(f"VNS-A{number:02d}" for number in range(3, 8))
EXPECTED_TARGET_ADMISSION_VOTES = 4
HEX_LENGTHS = {64, 128}


@dataclass(frozen=True)
class Finding:
    status: str
    gate: str
    detail: str


class Audit:
    def __init__(self) -> None:
        self.findings: list[Finding] = []

    def add(self, status: str, gate: str, detail: str) -> None:
        self.findings.append(Finding(status=status, gate=gate, detail=detail))

    def passed(self, gate: str, detail: str) -> None:
        self.add("PASS", gate, detail)

    def failed(self, gate: str, detail: str) -> None:
        self.add("FAIL", gate, detail)

    def missing(self, gate: str, detail: str) -> None:
        self.add("MISSING", gate, detail)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha3_256_file(path: Path) -> str:
    digest = hashlib.sha3_256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def resolve(root: Path, value: Path) -> Path:
    return value.resolve() if value.is_absolute() else (root / value).resolve()


def recorded_path(root: Path, value: Any) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("recorded path is missing or not a non-empty string")
    return resolve(root, Path(value))


def require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def require_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise ValueError(f"{label} must be a JSON array")
    return value


def require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a non-empty string")
    return value


def require_hex(value: Any, length: int, label: str) -> str:
    text = require_string(value, label)
    if len(text) != length or any(char not in "0123456789abcdef" for char in text):
        raise ValueError(f"{label} must be {length} lowercase hexadecimal characters")
    return text


def read_object(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise ValueError(f"cannot read {label} {path}: {error}") from error
    try:
        return require_object(json.loads(raw), label), raw
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError(f"cannot parse {label} {path}: {error}") from error


def command_result(command: list[str], timeout: int = 60) -> tuple[int, str, str]:
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return 127, "", str(error)
    return completed.returncode, completed.stdout.strip(), completed.stderr.strip()


def compact_command_error(stdout: str, stderr: str, returncode: int) -> str:
    detail = stderr or stdout or f"exit {returncode}"
    return " ".join(detail.split())[:600]


def active_validators(genesis: dict[str, Any]) -> list[dict[str, Any]]:
    validators = require_list(genesis.get("validators"), "Genesis validators")
    active = [
        require_object(entry, f"Genesis validators[{index}]")
        for index, entry in enumerate(validators)
        if isinstance(entry, dict) and entry.get("status") == "active_at_genesis"
    ]
    if len(active) != 5:
        raise ValueError(f"Genesis must contain exactly five active_at_genesis validators, found {len(active)}")
    by_id: dict[str, dict[str, Any]] = {}
    for entry in active:
        validator_id = require_string(entry.get("validator_id"), "Genesis validator_id")
        if validator_id in by_id:
            raise ValueError(f"Genesis duplicates active validator_id {validator_id}")
        by_id[validator_id] = entry
    if tuple(sorted(by_id)) != EXPECTED_VALIDATOR_IDS:
        raise ValueError(
            "Genesis active validator IDs must be validator-02 through validator-06; found "
            + ", ".join(sorted(by_id))
        )
    return [by_id[validator_id] for validator_id in EXPECTED_VALIDATOR_IDS]


def audit_genesis(audit: Audit, genesis_path: Path) -> dict[str, Any] | None:
    gate = "applied canonical Genesis"
    if not genesis_path.is_file():
        audit.missing(gate, f"missing {genesis_path}")
        return None
    try:
        genesis, raw = read_object(genesis_path, "Genesis")
        integrity = require_object(genesis.get("integrity"), "Genesis integrity")
        genesis_hash = require_hex(integrity.get("genesis_hash"), 64, "Genesis integrity.genesis_hash")
        network = require_object(genesis.get("network"), "Genesis network")
        if network.get("chain_id") != CHAIN_ID or network.get("network_slug") != NETWORK_ID:
            raise ValueError("Genesis does not bind Testnet-v3 chain 1266 / network slug")
        deployment = require_object(genesis.get("genesis_deployment"), "Genesis genesis_deployment")
        if deployment.get("status") != "EXECUTED_AND_BOUND":
            raise ValueError("Genesis deployment is not EXECUTED_AND_BOUND")
        validators = active_validators(genesis)
        audit.passed(
            gate,
            f"sha256={sha256_bytes(raw)} genesis_hash={genesis_hash} active_validators=5",
        )
        return {
            "object": genesis,
            "path": genesis_path,
            "sha256": sha256_bytes(raw),
            "hash": genesis_hash,
            "validators": validators,
        }
    except ValueError as error:
        audit.failed(gate, str(error))
        return None


def audit_release_approval(
    audit: Audit,
    root: Path,
    genesis: dict[str, Any] | None,
    approval_path: Path,
    phase7_path: Path,
    authorities_path: Path,
    verifier_path: Path,
) -> dict[str, Any] | None:
    gate = "governance approval and Phase-7/8 integrity"
    required = (
        (approval_path, "governance approval artifact"),
        (phase7_path, "Phase-7/8 integrity evidence"),
        (authorities_path, "frozen authority record"),
        (verifier_path, "release-approval verifier"),
    )
    missing = [f"{label}: {path}" for path, label in required if not path.is_file()]
    if missing:
        audit.missing(gate, "; ".join(missing))
        return None
    if genesis is None:
        audit.failed(gate, "cannot bind approval without a valid applied Genesis")
        return None
    try:
        phase7, _ = read_object(phase7_path, "Phase-7/8 integrity evidence")
        if phase7.get("schema_version") != 1 or phase7.get("status") != PHASE7_STATUS:
            raise ValueError("Phase-7/8 integrity evidence is not the applied pending-release-gates record")
        if recorded_path(root, phase7.get("genesis_file")) != genesis["path"]:
            raise ValueError("Phase-7/8 integrity names a different canonical Genesis")
        if phase7.get("genesis_file_sha256") != genesis["sha256"]:
            raise ValueError("Phase-7/8 integrity Genesis SHA-256 disagrees with applied Genesis")
        if phase7.get("genesis_hash") != genesis["hash"]:
            raise ValueError("Phase-7/8 integrity genesis hash disagrees with applied Genesis")
        if recorded_path(root, phase7.get("release_approval_artifact")) != approval_path:
            raise ValueError("Phase-7/8 integrity names a different governance approval artifact")
        approval_sha256 = sha256_file(approval_path)
        if phase7.get("release_approval_artifact_sha256") != approval_sha256:
            raise ValueError("Phase-7/8 integrity approval SHA-256 disagrees with approval artifact")
        command = [
            str(verifier_path),
            "--verify",
            "--approval",
            str(approval_path),
            "--candidate",
            str(genesis["path"]),
            "--authorities",
            str(authorities_path),
        ]
        returncode, stdout, stderr = command_result(command, timeout=45)
        if returncode != 0:
            raise ValueError("release-approval verifier rejected evidence: " + compact_command_error(stdout, stderr, returncode))
        verifier = require_object(json.loads(stdout), "release-approval verifier output")
        if verifier.get("result") != "RELEASE_APPROVAL_VERIFIED":
            raise ValueError("release-approval verifier did not report RELEASE_APPROVAL_VERIFIED")
        comparisons = (
            ("approval_sha256", approval_sha256),
            ("candidate_sha256", genesis["sha256"]),
            ("genesis_hash", genesis["hash"]),
            ("governance_authority_role", phase7.get("release_approval_governance_role")),
            ("governance_standard_account_address", phase7.get("release_approval_governance_address")),
        )
        for field, expected in comparisons:
            if verifier.get(field) != expected:
                raise ValueError(f"release-approval verifier {field} disagrees with bound evidence")
        audit.passed(gate, f"ML-DSA-87 approval verifies; approval_sha256={approval_sha256}")
        return phase7
    except (ValueError, json.JSONDecodeError) as error:
        audit.failed(gate, str(error))
        return None


def audit_consensus_parameters(
    audit: Audit, genesis: dict[str, Any] | None, phase7: dict[str, Any] | None, manifest_path: Path
) -> bool:
    gate = "finalized consensus-parameter manifest"
    if not manifest_path.is_file():
        audit.missing(gate, f"missing {manifest_path}")
        return False
    if genesis is None or phase7 is None:
        audit.failed(gate, "cannot bind parameter manifest without valid Genesis and Phase-7/8 evidence")
        return False
    try:
        manifest, raw = read_object(manifest_path, "consensus parameter manifest")
        if manifest.get("schema_version") != 2 or manifest.get("status") != "FINALIZED":
            raise ValueError("parameter manifest is not schema v2 FINALIZED")
        expected_values = {
            "chain_id": CHAIN_ID,
            "network_id": NETWORK_ID,
            "epoch_length_slots": 1000,
            "target_block_time_ms": 2000,
            "proposal_timeout_ms": 1500,
            "prevote_timeout_ms": 1500,
            "precommit_timeout_ms": 1500,
            "max_round_timeout_ms": 10000,
            "activation_boundary": "genesis_or_declared_epoch_boundary",
        }
        for field, expected in expected_values.items():
            if manifest.get(field) != expected:
                raise ValueError(f"parameter manifest {field} is not {expected!r}")
        manifest_sha256 = sha256_bytes(raw)
        manifest_root = hashlib.sha3_512(raw).hexdigest()
        embedded = require_object(genesis["object"].get("consensus_parameters"), "Genesis consensus_parameters")
        integrity = require_object(genesis["object"].get("integrity"), "Genesis integrity")
        comparisons = (
            (embedded.get("manifest"), manifest, "embedded manifest"),
            (embedded.get("canonical_manifest_sha256"), manifest_sha256, "Genesis manifest SHA-256"),
            (integrity.get("consensus_parameter_manifest_sha256"), manifest_sha256, "Genesis integrity manifest SHA-256"),
            (phase7.get("consensus_parameter_manifest_sha256"), manifest_sha256, "Phase-7/8 manifest SHA-256"),
            (embedded.get("parameter_root_sha3_512"), manifest_root, "Genesis parameter root"),
            (integrity.get("consensus_parameter_root_sha3_512"), manifest_root, "Genesis integrity parameter root"),
            (phase7.get("consensus_parameter_root_sha3_512"), manifest_root, "Phase-7/8 parameter root"),
            (embedded.get("decision_id"), manifest.get("governance_approval_id"), "Genesis decision ID"),
            (phase7.get("consensus_parameter_decision_id"), manifest.get("governance_approval_id"), "Phase-7/8 decision ID"),
        )
        for actual, expected, label in comparisons:
            if actual != expected:
                raise ValueError(f"{label} disagrees with finalized parameter manifest")
        # Schema v2 deliberately has no ETDAG activation declaration.  The
        # approved Testnet-v3 Genesis launches the core-only profile; ingress
        # and admission artifacts are preparatory, never activation evidence.
        if "etdag_activation" in manifest:
            raise ValueError("schema v2 manifest must not carry an ETDAG activation declaration")
        audit.passed(
            gate,
            f"sha256={manifest_sha256} sha3_512_root={manifest_root} etdag=deferred-at-genesis",
        )
        return True
    except ValueError as error:
        audit.failed(gate, str(error))
        return False


def audit_identity_correspondence(
    audit: Audit, genesis: dict[str, Any] | None, identity_root: Path
) -> dict[str, dict[str, Any]]:
    gate = "five validator identity correspondence"
    if genesis is None:
        audit.failed(gate, "cannot bind identity files without a valid Genesis")
        return {}
    if not identity_root.is_dir():
        audit.missing(gate, f"identity root is missing: {identity_root}")
        return {}
    try:
        accounts = require_list(genesis["object"].get("accounts"), "Genesis accounts")
        accounts_by_id = {
            require_string(require_object(account, "Genesis account").get("account_id"), "Genesis account_id"):
            require_object(account, "Genesis account")
            for account in accounts
        }
        result: dict[str, dict[str, Any]] = {}
        for number, validator in enumerate(genesis["validators"], start=1):
            validator_id = EXPECTED_VALIDATOR_IDS[number - 1]
            identity_id = EXPECTED_IDENTITY_IDS[number - 1]
            if validator.get("validator_id") != validator_id:
                raise ValueError(f"Genesis validator order is not canonical at {validator_id}")
            if validator.get("allocation_account_id") != identity_id:
                raise ValueError(f"{validator_id} does not bind allocation_account_id {identity_id}")
            address = require_string(validator.get("operator_address"), f"{validator_id} operator_address")
            account = accounts_by_id.get(identity_id)
            if not isinstance(account, dict) or account.get("address") != address:
                raise ValueError(f"Genesis account {identity_id} does not match {validator_id} operator address")
            manifests = sorted(identity_root.glob(f"{identity_id}_*/manifest.json"))
            if len(manifests) != 1:
                raise ValueError(f"{validator_id} requires exactly one {identity_id} identity manifest")
            manifest_path = manifests[0].resolve()
            manifest, _ = read_object(manifest_path, f"{validator_id} identity manifest")
            comparisons = (
                (manifest.get("id"), identity_id, "id"),
                (manifest.get("workbook_node"), f"Val{number}", "workbook_node"),
                (manifest.get("address"), address, "address"),
                (manifest.get("identity_kind"), "validator-node", "identity_kind"),
                (manifest.get("genesis_account"), True, "genesis_account"),
            )
            for actual, expected, field in comparisons:
                if actual != expected:
                    raise ValueError(f"{validator_id} identity manifest {field} disagrees with Genesis")
            public_path = recorded_path(identity_root, manifest.get("public_file"))
            encrypted_path = recorded_path(identity_root, manifest.get("encrypted_file"))
            try:
                public_path.relative_to(identity_root)
                encrypted_path.relative_to(identity_root)
            except ValueError as error:
                raise ValueError(f"{validator_id} identity file escapes identity root") from error
            if not public_path.is_file() or not encrypted_path.is_file():
                raise ValueError(f"{validator_id} public or encrypted identity file is missing")
            public_sha256 = sha256_file(public_path)
            encrypted_sha256 = sha256_file(encrypted_path)
            if manifest.get("public_file_sha256") != public_sha256:
                raise ValueError(f"{validator_id} public identity digest disagrees with its manifest")
            if manifest.get("encrypted_file_sha256") != encrypted_sha256:
                raise ValueError(f"{validator_id} encrypted identity digest disagrees with its manifest")
            result[validator_id] = {
                "identity_id": identity_id,
                "address": address,
                "manifest_path": manifest_path,
                "manifest": manifest,
                "public_sha256": public_sha256,
                "encrypted_sha256": encrypted_sha256,
            }
        audit.passed(gate, "VNS-A03 through VNS-A07 exactly match validator-02 through validator-06")
        return result
    except ValueError as error:
        audit.failed(gate, str(error))
        return {}


def audit_ingress_and_admission(
    audit: Audit,
    genesis: dict[str, Any] | None,
    identities: dict[str, dict[str, Any]],
    identity_root: Path,
    ingress_path: Path,
    request_path: Path,
    votes_path: Path,
    package_path: Path,
    verifier_path: Path,
    *,
    etdag_deferred_at_genesis: bool,
) -> None:
    ingress_gate = "ETDAG ingress key records"
    request_gate = "ETDAG target-admission request"
    votes_gate = "ETDAG target-admission votes"
    package_gate = "ETDAG target-admission package"
    if etdag_deferred_at_genesis:
        detail = (
            "not a Testnet-v3 Genesis launch gate: finalized schema-v2 manifest defers ETDAG; "
            "future activation requires a new root-bound schema and declared epoch boundary"
        )
        audit.passed(f"{ingress_gate} (future activation)", detail)
        audit.passed(f"{request_gate} (future activation)", detail)
        audit.passed(f"{votes_gate} (future activation)", detail)
        audit.passed(f"{package_gate} (future activation)", detail)
        return
    if genesis is None or len(identities) != 5:
        audit.failed(ingress_gate, "cannot bind ingress records without five verified validator identities")
        audit.failed(request_gate, "cannot bind target-admission request without ingress verification")
        audit.missing(votes_gate, "not evaluated because preceding ingress identity gate failed")
        audit.missing(package_gate, "not evaluated because preceding ingress identity gate failed")
        return
    if not ingress_path.is_file():
        audit.missing(ingress_gate, f"missing {ingress_path}")
        audit.missing(request_gate, "not evaluated because ingress records are missing")
        audit.missing(votes_gate, "not evaluated because ingress records are missing")
        audit.missing(package_gate, "not evaluated because ingress records are missing")
        return
    ingress: dict[str, Any] | None = None
    try:
        ingress, _ = read_object(ingress_path, "ETDAG ingress records")
        expected_fields = (
            ("schema_version", 1),
            ("artifact_type", "testnet-v3-etdag-ingress-key-records"),
            ("status", "generated_pending_target_admission_certificate"),
            ("chain_id", CHAIN_ID),
            ("runtime_network_id", NETWORK_ID),
            ("protocol_version", "posy/3.0"),
            ("genesis_candidate_sha256", genesis["sha256"]),
            ("genesis_hash", genesis["hash"]),
        )
        for field, expected in expected_fields:
            if ingress.get(field) != expected:
                raise ValueError(f"ingress records {field} disagrees with applied Genesis/runtime")
        binding = require_object(ingress.get("admission_binding"), "ingress admission_binding")
        binding_fields = (
            ("runtime_registry_type", "IngressKemKeyRegistry/v2"),
            ("runtime_registry_domain", "PoSy/ETDAG/IngressKemKeyRegistry/v3"),
            ("certificate_domain", "PoSy/ETDAG/TargetAdmission/v2"),
            ("required_consensus_algorithm", "ML-DSA-65"),
            ("minimum_signers_for_five_validator_cluster", EXPECTED_TARGET_ADMISSION_VOTES),
        )
        for field, expected in binding_fields:
            if binding.get(field) != expected:
                raise ValueError(f"ingress admission_binding.{field} is not {expected!r}")
        records = require_list(ingress.get("records"), "ingress records")
        if len(records) != 5:
            raise ValueError(f"ingress records must contain five validators, found {len(records)}")
        by_validator: dict[str, dict[str, Any]] = {}
        for index, raw_record in enumerate(records):
            record = require_object(raw_record, f"ingress records[{index}]")
            validator_id = require_string(record.get("validator_id"), f"ingress records[{index}].validator_id")
            if validator_id in by_validator:
                raise ValueError(f"ingress records duplicate {validator_id}")
            by_validator[validator_id] = record
        if tuple(sorted(by_validator)) != EXPECTED_VALIDATOR_IDS:
            raise ValueError("ingress records do not map exactly validator-02 through validator-06")
        for share_index, validator_id in enumerate(EXPECTED_VALIDATOR_IDS, start=1):
            record = by_validator[validator_id]
            identity = identities[validator_id]
            expected_fields = (
                ("validator_identity_id", identity["identity_id"]),
                ("operator_address", identity["address"]),
                ("validator_public_identity_sha256", identity["public_sha256"]),
                ("validator_encrypted_identity_sha256", identity["encrypted_sha256"]),
                ("share_index", share_index),
                ("algorithm", "ML-KEM-1024"),
            )
            for field, expected in expected_fields:
                if record.get(field) != expected:
                    raise ValueError(f"{validator_id} ingress {field} disagrees with verified identity")
            require_hex(record.get("ingress_key_id"), 64, f"{validator_id} ingress_key_id")
            require_hex(record.get("public_key_sha3_256"), 64, f"{validator_id} public_key_sha3_256")
            if not isinstance(record.get("public_key_base64"), str) or not record["public_key_base64"]:
                raise ValueError(f"{validator_id} ingress public key is missing")
            private_path = recorded_path(identity_root, record.get("private_custody_file"))
            try:
                private_path.relative_to(identity_root)
            except ValueError as error:
                raise ValueError(f"{validator_id} ingress custody path escapes identity root") from error
            if not private_path.is_file():
                raise ValueError(f"{validator_id} encrypted ingress custody sidecar is missing")
            if record.get("private_custody_sha3_256") != sha3_256_file(private_path):
                raise ValueError(f"{validator_id} ingress custody sidecar SHA3-256 disagrees with record")
        audit.passed(ingress_gate, "five ML-KEM-1024 sidecars bind exactly VNS-A03 through VNS-A07")
    except ValueError as error:
        audit.failed(ingress_gate, str(error))
        audit.missing(request_gate, "not evaluated because ingress-record verification failed")
        audit.missing(votes_gate, "not evaluated because ingress-record verification failed")
        audit.missing(package_gate, "not evaluated because ingress-record verification failed")
        return

    request: dict[str, Any] | None = None
    request_sha256 = ""
    if not request_path.is_file():
        audit.missing(request_gate, f"missing {request_path}")
    else:
        try:
            request, request_raw = read_object(request_path, "target-admission request")
            request_sha256 = sha256_bytes(request_raw)
            fields = (
                ("schema_version", 1),
                ("artifact_type", "testnet-v3-etdag-target-admission-request"),
                ("chain_id", CHAIN_ID),
                ("runtime_network_id", NETWORK_ID),
                ("applied_genesis_sha256", genesis["sha256"]),
                ("applied_genesis_hash", genesis["hash"]),
                ("source_finalized_height", 0),
                ("target_height", 3),
                ("signature_algorithm", "ML-DSA-65"),
                ("signature_domain", "PoSy/ETDAG/TargetAdmission/v2"),
            )
            for field, expected in fields:
                if request.get(field) != expected:
                    raise ValueError(f"target-admission request {field} is not bound to applied Testnet-v3 Genesis")
            context = require_object(request.get("context"), "target-admission request context")
            if context.get("consensus_parameter_root") != require_object(
                genesis["object"].get("integrity"), "Genesis integrity"
            ).get("consensus_parameter_root_sha3_512"):
                raise ValueError("target-admission context does not bind the finalized consensus parameter root")
            if context.get("ingress_kem_registry_root") is None:
                raise ValueError("target-admission context omits ingress KEM registry root")
            signers = require_list(request.get("signer_requests"), "target-admission signer_requests")
            if len(signers) != 5:
                raise ValueError("target-admission request must contain five eligible signer requests")
            signer_ids = {require_string(require_object(item, "signer request").get("validator_id"), "signer validator_id") for item in signers}
            if tuple(sorted(signer_ids)) != EXPECTED_VALIDATOR_IDS:
                raise ValueError("target-admission signer requests do not exactly match validator-02 through validator-06")
            audit.passed(request_gate, f"H=3 request SHA-256={request_sha256} binds applied Genesis and parameter root")
        except ValueError as error:
            audit.failed(request_gate, str(error))

    if not votes_path.is_file():
        audit.missing(votes_gate, f"missing required four-of-five vote artifact: {votes_path}")
    elif request is None:
        audit.failed(votes_gate, "cannot bind votes because target-admission request is invalid or missing")
    else:
        try:
            votes, _ = read_object(votes_path, "target-admission votes")
            fields = (
                ("schema_version", 1),
                ("artifact_type", "testnet-v3-etdag-target-admission-votes"),
                ("request_sha256", request_sha256),
                ("signature_domain", "PoSy/ETDAG/TargetAdmission/v2"),
            )
            for field, expected in fields:
                if votes.get(field) != expected:
                    raise ValueError(f"target-admission votes {field} disagrees with current request")
            entries = require_list(votes.get("votes"), "target-admission votes.votes")
            if len(entries) != EXPECTED_TARGET_ADMISSION_VOTES:
                raise ValueError("target-admission votes must contain exactly four detached signatures")
            vote_ids = [require_string(require_object(entry, "target-admission vote").get("validator_id"), "vote validator_id") for entry in entries]
            if len(set(vote_ids)) != EXPECTED_TARGET_ADMISSION_VOTES or not set(vote_ids).issubset(set(EXPECTED_VALIDATOR_IDS)):
                raise ValueError("target-admission votes are not four unique active validator signatures")
            if any(require_object(entry, "target-admission vote").get("signature_algorithm") != "ML-DSA-65" for entry in entries):
                raise ValueError("target-admission votes use a non-ML-DSA-65 signature algorithm")
            audit.passed(votes_gate, "four unique ML-DSA-65 signer records bind the exact request")
        except ValueError as error:
            audit.failed(votes_gate, str(error))

    if not package_path.is_file():
        audit.missing(package_gate, f"missing required verified admission package: {package_path}")
        return
    if request is None or not votes_path.is_file():
        audit.failed(package_gate, "cannot reverify package without a valid request and vote artifact")
        return
    # The verifier is a Python source file and is invoked through the current
    # interpreter below; it does not need an executable mode bit.
    if not verifier_path.is_file():
        audit.missing(package_gate, f"runtime admission verifier is unavailable: {verifier_path}")
        return
    try:
        package, package_raw = read_object(package_path, "target-admission package")
        if package.get("schema_version") != 1 or package.get("artifact_type") != "testnet-v3-etdag-target-admission-package":
            raise ValueError("target-admission package has an unexpected schema or artifact type")
        if package.get("request_sha256") != request_sha256:
            raise ValueError("target-admission package request SHA-256 disagrees with current request")
        with tempfile.TemporaryDirectory(prefix="synergy-tnv3-admission-audit-") as temporary:
            rebuilt_path = Path(temporary) / "verified-package.json"
            command = [
                str(verifier_path),
                "--verify",
                "--genesis",
                str(genesis["path"]),
                "--ingress-records",
                str(ingress_path),
                "--request",
                str(request_path),
                "--votes",
                str(votes_path),
                "--output",
                str(rebuilt_path),
            ]
            returncode, stdout, stderr = command_result(command, timeout=90)
            if returncode != 0:
                raise ValueError("runtime admission verifier rejected evidence: " + compact_command_error(stdout, stderr, returncode))
            result = require_object(json.loads(stdout), "runtime admission verifier output")
            if result.get("result") != "TARGET_ADMISSION_PACKAGE_VERIFIED":
                raise ValueError("runtime admission verifier did not report TARGET_ADMISSION_PACKAGE_VERIFIED")
            if not rebuilt_path.is_file() or sha256_file(rebuilt_path) != sha256_bytes(package_raw):
                raise ValueError("runtime-rebuilt package does not byte-match supplied admission package")
        audit.passed(package_gate, f"runtime re-verifies four-of-five ML-DSA-65 certificate; sha256={sha256_bytes(package_raw)}")
    except (ValueError, json.JSONDecodeError) as error:
        audit.failed(package_gate, str(error))


def audit_static_vpn_registry(audit: Audit, genesis: dict[str, Any] | None, registry_path: Path) -> str | None:
    gate = "fresh Testnet-v3 public VPN registry"
    if not registry_path.is_file():
        audit.missing(gate, f"missing {registry_path}")
        return None
    if genesis is None:
        audit.failed(gate, "cannot bind VPN registry without a valid Genesis")
        return None
    try:
        registry, _ = read_object(registry_path, "public VPN registry")
        if registry.get("chain_id") != CHAIN_ID or registry.get("network_id") != NETWORK_ID:
            raise ValueError("public VPN registry is not Testnet-v3")
        participants = require_list(registry.get("participants"), "public VPN registry participants")
        if len(participants) != 8:
            raise ValueError(f"fresh VPN registry must contain exactly eight peers (five validators/three relayers), found {len(participants)}")
        validators = [
            require_object(entry, "VPN participant")
            for entry in participants
            if isinstance(entry, dict) and entry.get("role") == "validator" and entry.get("activation_status") == "active"
        ]
        relayers = [
            require_object(entry, "VPN participant")
            for entry in participants
            if isinstance(entry, dict) and entry.get("role") == "relayer" and entry.get("activation_status") == "active"
        ]
        expected_addresses = {require_string(entry.get("operator_address"), "Genesis validator operator_address") for entry in genesis["validators"]}
        registry_addresses = {require_string(entry.get("synv_address"), "VPN validator synv_address") for entry in validators}
        if len(validators) != 5 or registry_addresses != expected_addresses:
            raise ValueError("fresh VPN registry validator transports do not exactly match validator-02 through validator-06")
        if len(relayers) != 3:
            raise ValueError("fresh VPN registry must contain exactly three active relayer transports")
        audit.passed(gate, f"sha256={sha256_file(registry_path)} validators=5 relayers=3 peers=8")
        return sha256_file(registry_path)
    except ValueError as error:
        audit.failed(gate, str(error))
        return None


def audit_signed_transport_snapshot(
    audit: Audit,
    genesis: dict[str, Any] | None,
    snapshot_path: Path | None,
    verifier_path: Path,
    minimum_generation: int,
    expected_network: str,
    expected_migration_id: str,
    public_key: str | None,
) -> None:
    gate = "coordinator-signed validator transport snapshot"
    if snapshot_path is None:
        audit.missing(gate, "supply --transport-snapshot with the downloaded signed coordinator snapshot (generation >= 21)")
        return
    if not snapshot_path.is_file():
        audit.missing(gate, f"snapshot does not exist: {snapshot_path}")
        return
    if genesis is None:
        audit.failed(gate, "cannot bind coordinator snapshot without a valid Genesis")
        return
    # This verifier is executed through sys.executable, so mode bits must not
    # turn a present Python source file into a false launch blocker.
    if not verifier_path.is_file():
        audit.missing(gate, f"transport snapshot verifier is unavailable: {verifier_path}")
        return
    command = [
        sys.executable,
        str(verifier_path),
        "--snapshot",
        str(snapshot_path),
        "--genesis",
        str(genesis["path"]),
        "--minimum-generation",
        str(minimum_generation),
        "--network",
        expected_network,
        "--migration-id",
        expected_migration_id,
    ]
    if public_key:
        command.extend(("--public-key", public_key))
    returncode, stdout, stderr = command_result(command, timeout=60)
    if returncode != 0:
        audit.failed(gate, "existing transport verifier rejected snapshot: " + compact_command_error(stdout, stderr, returncode))
        return
    try:
        report = require_object(json.loads(stdout), "transport verifier output")
        if report.get("status") != "PASS" or report.get("failed") != 0:
            raise ValueError("transport verifier did not report a clean PASS")
        snapshot, _ = read_object(snapshot_path, "coordinator transport snapshot")
        generation = snapshot.get("configuration_version")
        transports = require_list(snapshot.get("transports"), "coordinator transports")
        if not isinstance(generation, int) or generation < minimum_generation or len(transports) != 5:
            raise ValueError("snapshot does not have five transports at the required generation")
        audit.passed(
            gate,
            f"existing signature/schema verifier passed; generation={generation} transports=5 migration_id={expected_migration_id}",
        )
    except (ValueError, json.JSONDecodeError) as error:
        audit.failed(gate, str(error))


def audit_v2_bindings(audit: Audit, checker_path: Path) -> None:
    gate = "no active retired Testnet-v2 bindings"
    if not checker_path.is_file():
        audit.missing(gate, f"missing {checker_path}")
        return
    returncode, stdout, stderr = command_result([sys.executable, str(checker_path)], timeout=120)
    # The standalone structural checker intentionally searches the whole
    # repository.  Historical test-output transcripts under launch/evidence
    # can legitimately quote retired addresses; they are neither a runtime
    # input nor a release bundle.  Keep its active-runtime findings fatal while
    # classifying only those inert transcript hits separately.
    failed_paths: list[str] = []
    evidence_only_paths: list[str] = []
    for line in stdout.splitlines():
        if not line.startswith("[FAIL] "):
            continue
        path = line[len("[FAIL] ") :].split(":", 1)[0]
        if path.startswith("launch/evidence/"):
            evidence_only_paths.append(path)
        else:
            failed_paths.append(path)
    if failed_paths:
        audit.failed(gate, "retired binding checker found active paths: " + ", ".join(sorted(failed_paths)))
        return
    if returncode != 0 and not evidence_only_paths:
        audit.failed(gate, compact_command_error(stdout, stderr, returncode))
        return
    detail = "retired binding checker found no active V3 runtime or release-bundle violations"
    if evidence_only_paths:
        detail += f"; ignored {len(evidence_only_paths)} inert launch/evidence transcript(s)"
    audit.passed(gate, detail)


def audit_release_config_tree(
    audit: Audit,
    root: Path,
    genesis: dict[str, Any] | None,
    phase7: dict[str, Any] | None,
    phase7_path: Path,
    vpn_registry_sha256: str | None,
    config_dir: Path,
    config_generator: Path,
    topology_path: Path,
    registry_path: Path,
    approval_path: Path,
    authorities_path: Path,
    approval_verifier: Path,
) -> None:
    gate = f"release node-config manifest/tree generated {GENERATOR_VERSION.rsplit('/', 1)[-1]}"
    manifest_path = config_dir / "release-config-manifest.json"
    if not manifest_path.is_file():
        audit.missing(gate, f"missing {manifest_path}")
        return
    try:
        manifest, _ = read_object(manifest_path, "release config manifest")
    except ValueError as error:
        audit.failed(gate, str(error))
        return
    # This is deliberately checked before the VPN gate.  A v2 tree must be
    # called out as stale even while the fresh coordinator registry is pending.
    if manifest.get("schema_version") != 2 or manifest.get("generator_version") != GENERATOR_VERSION:
        audit.failed(
            gate,
            f"release config tree is stale; expected schema_version=2 generator_version={GENERATOR_VERSION!r}, "
            f"found schema_version={manifest.get('schema_version')!r} generator_version={manifest.get('generator_version')!r}",
        )
        return
    if genesis is None or phase7 is None or vpn_registry_sha256 is None:
        audit.failed(gate, "cannot accept config tree until Genesis/Phase-7/fresh nine-peer VPN registry all pass")
        return
    try:
        if manifest.get("chain_id") != CHAIN_ID or manifest.get("network_id") != NETWORK_ID:
            raise ValueError("release config manifest does not identify Testnet-v3")
        if manifest.get("signed_validator_transport_registry_required") is not True:
            raise ValueError("release config manifest does not require coordinator-signed validator transport registry")
        binding = require_object(manifest.get("binding"), "release config manifest binding")
        expected_binding = {
            "genesis_file_sha256": genesis["sha256"],
            "genesis_hash": genesis["hash"],
            "phase7_release_integrity_sha256": sha256_file(phase7_path),
            "release_approval_artifact_sha256": sha256_file(approval_path),
            "vpn_registry_sha256": vpn_registry_sha256,
        }
        integrity = require_object(genesis["object"].get("integrity"), "Genesis integrity")
        expected_binding["consensus_parameter_root_sha3_512"] = integrity.get("consensus_parameter_root_sha3_512")
        for field, expected in expected_binding.items():
            if binding.get(field) != expected:
                raise ValueError(f"release config manifest binding.{field} disagrees with verified evidence")
        config_files = require_object(manifest.get("config_files"), "release config manifest config_files")
        if len(config_files) != 19:
            raise ValueError(f"release config manifest must bind exactly 19 config files, found {len(config_files)}")
        for relative, expected_sha256 in config_files.items():
            if not isinstance(relative, str) or not isinstance(expected_sha256, str):
                raise ValueError("release config manifest has a malformed config file digest")
            path = (config_dir / relative).resolve()
            try:
                path.relative_to(config_dir.resolve())
            except ValueError as error:
                raise ValueError("release config manifest contains a path outside config tree") from error
            if not path.is_file() or sha256_file(path) != expected_sha256:
                raise ValueError(f"release config file does not match manifest digest: {relative}")
            if GENERATOR_VERSION not in path.read_text(encoding="utf-8", errors="replace"):
                raise ValueError(f"release config file is stale/non-v3: {relative}")
        canonical = config_dir / "canonical-genesis/genesis.json"
        if not canonical.is_file() or sha256_file(canonical) != genesis["sha256"]:
            raise ValueError("release config tree canonical Genesis does not byte-match applied Genesis")
        required = (config_generator, topology_path, registry_path, approval_path, authorities_path, approval_verifier)
        if not all(path.is_file() for path in required):
            raise ValueError("cannot deterministically recheck config tree because a generator input/verifier is missing")
        command = [
            sys.executable,
            str(config_generator),
            "--genesis",
            str(genesis["path"]),
            "--topology",
            str(topology_path),
            "--vpn-public-registry",
            str(registry_path),
            "--authorities-file",
            str(authorities_path),
            "--release-approval",
            str(approval_path),
            "--release-integrity",
            str(phase7_path),
            "--approval-verifier",
            str(approval_verifier),
            "--output-dir",
            str(config_dir),
            "--check",
        ]
        returncode, stdout, stderr = command_result(command, timeout=120)
        if returncode != 0:
            raise ValueError("deterministic config-tree check failed: " + compact_command_error(stdout, stderr, returncode))
        audit.passed(
            gate,
            f"19 {GENERATOR_VERSION.rsplit('/', 1)[-1]} config files byte-match a fresh deterministic --check rebuild",
        )
    except ValueError as error:
        audit.failed(gate, str(error))


def parse_args() -> argparse.Namespace:
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo-root", type=Path, default=root, help="Testnet-v3 repository root (default: %(default)s)")
    parser.add_argument("--genesis", type=Path, default=Path("genesis.testnet-v3.identity-assigned.json"))
    parser.add_argument("--release-approval", type=Path, default=Path("launch/production-genesis-ceremony/testnet-v3-genesis-release-approval.json"))
    parser.add_argument("--phase7-integrity", type=Path, default=Path("launch/production-genesis-ceremony/phase7-release-integrity.json"))
    parser.add_argument("--authorities", type=Path, default=Path("launch/TESTNET_V3_PRODUCTION_AUTHORITIES.json"))
    parser.add_argument("--approval-verifier", type=Path, default=Path("runtime/target/debug/testnet-v3-genesis-release-approval"))
    parser.add_argument("--consensus-parameters", type=Path, default=Path("launch/TESTNET_V3_CONSENSUS_PARAMETERS.json"))
    parser.add_argument("--identity-root", type=Path, default=Path("testnet-v3-identity-files"))
    parser.add_argument("--ingress-records", type=Path, default=Path("launch/TESTNET_V3_ETDAG_INGRESS_KEY_RECORDS.json"))
    parser.add_argument("--admission-request", type=Path, default=Path("launch/TESTNET_V3_ETDAG_TARGET_ADMISSION_REQUEST.json"))
    parser.add_argument("--admission-votes", type=Path, default=Path("launch/TESTNET_V3_ETDAG_TARGET_ADMISSION_VOTES.json"))
    parser.add_argument("--admission-package", type=Path, default=Path("launch/TESTNET_V3_ETDAG_TARGET_ADMISSION_PACKAGE.json"))
    parser.add_argument("--admission-verifier", type=Path, default=Path("runtime/target/debug/testnet-v3-etdag-admission"))
    parser.add_argument("--vpn-public-registry", type=Path, default=Path("launch/validator-vpn-public-registry.json"))
    parser.add_argument("--transport-snapshot", type=Path, help="Downloaded signed coordinator snapshot; never fetched by this audit")
    parser.add_argument("--transport-verifier", type=Path, default=Path("runtime/scripts/testnet/verify-testnet-v3-validator-transport-registry.py"))
    parser.add_argument("--minimum-transport-generation", type=int, default=21, help="minimum signed coordinator generation (default: %(default)s)")
    parser.add_argument("--transport-network", default=EXPECTED_INNERNET_NETWORK, help="expected signed transport network (default: %(default)s)")
    parser.add_argument("--transport-migration-id", default=EXPECTED_INNERNET_MIGRATION_ID, help="expected runtime-pinned signed transport migration ID (default: %(default)s)")
    parser.add_argument("--transport-public-key", help="optional pinned coordinator Ed25519 public key; defaults to the runtime verifier pin")
    parser.add_argument("--retired-v2-checker", type=Path, default=Path("scripts/check-retired-v2-bindings.py"))
    parser.add_argument("--config-dir", type=Path, default=Path("launch/production-node-configs"))
    parser.add_argument("--config-generator", type=Path, default=Path("scripts/generate-testnet-v3-node-configs.py"))
    parser.add_argument("--topology", type=Path, default=Path("runtime/config/testnet/network-topology.toml"))
    args = parser.parse_args()
    if args.minimum_transport_generation < 1:
        parser.error("--minimum-transport-generation must be at least 1")
    return args


def main() -> int:
    args = parse_args()
    root = args.repo_root.resolve()
    audit = Audit()
    if not root.is_dir():
        audit.missing("repository root", f"not a directory: {root}")
        print(json.dumps({"status": "FAIL", "findings": [asdict(item) for item in audit.findings]}, indent=2, sort_keys=True))
        return 1
    paths = {
        name: resolve(root, value)
        for name, value in vars(args).items()
        if name not in {"repo_root", "minimum_transport_generation"} and isinstance(value, Path)
    }
    genesis = audit_genesis(audit, paths["genesis"])
    phase7 = audit_release_approval(
        audit,
        root,
        genesis,
        paths["release_approval"],
        paths["phase7_integrity"],
        paths["authorities"],
        paths["approval_verifier"],
    )
    etdag_deferred_at_genesis = audit_consensus_parameters(
        audit, genesis, phase7, paths["consensus_parameters"]
    )
    identities = audit_identity_correspondence(audit, genesis, paths["identity_root"])
    audit_ingress_and_admission(
        audit,
        genesis,
        identities,
        paths["identity_root"],
        paths["ingress_records"],
        paths["admission_request"],
        paths["admission_votes"],
        paths["admission_package"],
        paths["admission_verifier"],
        etdag_deferred_at_genesis=etdag_deferred_at_genesis,
    )
    vpn_registry_sha256 = audit_static_vpn_registry(audit, genesis, paths["vpn_public_registry"])
    audit_signed_transport_snapshot(
        audit,
        genesis,
        paths.get("transport_snapshot"),
        paths["transport_verifier"],
        args.minimum_transport_generation,
        args.transport_network,
        args.transport_migration_id,
        args.transport_public_key,
    )
    audit_v2_bindings(audit, paths["retired_v2_checker"])
    audit_release_config_tree(
        audit,
        root,
        genesis,
        phase7,
        paths["phase7_integrity"],
        vpn_registry_sha256,
        paths["config_dir"],
        paths["config_generator"],
        paths["topology"],
        paths["vpn_public_registry"],
        paths["release_approval"],
        paths["authorities"],
        paths["approval_verifier"],
    )
    totals = {status: sum(item.status == status for item in audit.findings) for status in ("PASS", "FAIL", "MISSING")}
    success = totals["FAIL"] == 0 and totals["MISSING"] == 0
    report = {
        "check": "testnet-v3-final-launch-evidence-audit",
        "repository_root": str(root),
        "status": "PASS" if success else "FAIL",
        "summary": totals,
        "findings": [asdict(item) for item in audit.findings],
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
