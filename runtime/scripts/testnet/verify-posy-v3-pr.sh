#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
runtime_manifest="$repo_root/runtime/Cargo.toml"
mode="${1:-full}"

case "$mode" in
  static|full) ;;
  *)
    echo "usage: $0 [static|full]" >&2
    exit 2
    ;;
esac

export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-1}"
export CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"
export RUST_BACKTRACE="${RUST_BACKTRACE:-1}"

run() {
  printf '+ '
  printf '%q ' "$@"
  printf '\n'
  "$@"
}

cd "$repo_root"

run git diff --check
run git diff --cached --check
run bash -n \
  runtime/scripts/testnet/run-posy-simplified-five-node-harness.sh \
  runtime/scripts/testnet/run-posy-simplified-five-driver-harness.sh \
  runtime/scripts/testnet/verify-posy-v3-pr.sh
run cargo fmt --manifest-path "$runtime_manifest" --all -- --check
printf '+ cargo metadata --locked --manifest-path %q --no-deps --format-version 1\n' \
  "$runtime_manifest"
cargo metadata --locked --manifest-path "$runtime_manifest" --no-deps \
  --format-version 1 >/dev/null
run python3 scripts/validate-fresh-testnet-v3-network-identifiers.py
printf '+ unzip -t %q\n' \
  launch/PoSy_Consensus_Parameter_Control_Workbook_v3_PROPOSAL.xlsx
unzip -t launch/PoSy_Consensus_Parameter_Control_Workbook_v3_PROPOSAL.xlsx \
  >/dev/null

run python3 - \
  launch/TESTNET_V3_POSY_SIMPLIFIED_PARAMETER_PROPOSAL.json \
  launch/TESTNET_V3_POSY_SIMPLIFIED_PARAMETER_SCHEMA_V4.json \
  launch/TESTNET_V3_POSY_SIMPLIFIED_PARAMETER_PROPOSAL_VERIFICATION.json \
  launch/POSY_V3_PR_DEPENDENCIES.lock.json \
  launch/PoSy_Consensus_Parameter_Control_Workbook_v3_PROPOSAL.xlsx \
  runtime/config/testnet/posy-v3-five-validator/five-validator-topology.public.example.json \
  launch/posy-v3-genesis-inputs/validator-roster.json \
  runtime/standards/snts-01-address-registry-v1.3.json \
  runtime/standards/snts-01-address-engine-v1-vectors.json \
  launch/posy-v3-etdag-governance-inputs/etdag-parameter-manifest.input.json \
  launch/posy-v3-etdag-governance-inputs/etdag-fee-schedule-manifest.input.json \
  launch/posy-v3-etdag-governance-inputs/expected-derivations.json <<'PY'
import hashlib
import json
import sys
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path

(
    proposal_path,
    schema_path,
    verification_path,
    dependency_lock_path,
    workbook_path,
    topology_path,
    validator_roster_path,
    address_registry_path,
    address_vectors_path,
    parameter_path,
    fee_path,
    derivations_path,
) = map(Path, sys.argv[1:])

proposal_bytes = proposal_path.read_bytes()
proposal = json.loads(proposal_bytes)
schema = json.loads(schema_path.read_bytes())
verification = json.loads(verification_path.read_bytes())
dependency_lock = json.loads(dependency_lock_path.read_bytes())
topology = json.loads(topology_path.read_bytes())
validator_roster = json.loads(validator_roster_path.read_bytes())
address_registry_bytes = address_registry_path.read_bytes()
address_registry = json.loads(address_registry_bytes)
address_vectors_bytes = address_vectors_path.read_bytes()
address_vectors = json.loads(address_vectors_bytes)
parameter = json.loads(parameter_path.read_bytes())
fee = json.loads(fee_path.read_bytes())
derivations = json.loads(derivations_path.read_bytes())

with zipfile.ZipFile(workbook_path) as archive:
    workbook_xml = ET.fromstring(archive.read("xl/workbook.xml"))
    relationships_xml = ET.fromstring(archive.read("xl/_rels/workbook.xml.rels"))
    workbook_namespace = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
    relationship_namespace = "{http://schemas.openxmlformats.org/officeDocument/2006/relationships}"
    package_relationship_namespace = "{http://schemas.openxmlformats.org/package/2006/relationships}"
    workbook_sheets = workbook_xml.find(f"{workbook_namespace}sheets")
    if workbook_sheets is None:
        raise SystemExit("parameter-control workbook has no sheets")
    sheet_targets = {
        relationship.attrib["Id"]: relationship.attrib["Target"]
        for relationship in relationships_xml.findall(f"{package_relationship_namespace}Relationship")
    }
    workbook_sheet_map = {
        sheet.attrib["name"]: sheet_targets.get(sheet.attrib.get(f"{relationship_namespace}id", ""))
        for sheet in workbook_sheets
    }
    required_workbook_sheets = [
        "Control Summary",
        "Validator Weights",
        "Parameter Register",
        "Activation Checklist",
    ]
    if list(workbook_sheet_map) != required_workbook_sheets:
        raise SystemExit("parameter-control workbook sheets are not the canonical four-sheet register")
    validator_sheet_target = workbook_sheet_map["Validator Weights"]
    if not validator_sheet_target:
        raise SystemExit("parameter-control workbook cannot resolve Validator Weights sheet")
    def workbook_sheet_path(target):
        return target.lstrip("/") if target.startswith("/") else "xl/" + target

    validator_sheet_path = workbook_sheet_path(validator_sheet_target)
    validator_sheet_xml = ET.fromstring(archive.read(validator_sheet_path))
    activation_sheet_target = workbook_sheet_map["Activation Checklist"]
    if not activation_sheet_target:
        raise SystemExit("parameter-control workbook cannot resolve Activation Checklist sheet")
    activation_sheet_xml = ET.fromstring(archive.read(workbook_sheet_path(activation_sheet_target)))
    workbook_text = "\n".join(
        archive.read(name).decode("utf-8", errors="ignore")
        for name in archive.namelist()
        if name == "xl/sharedStrings.xml" or name.startswith("xl/worksheets/")
    )
    shared_strings = []
    if "xl/sharedStrings.xml" in archive.namelist():
        shared_xml = ET.fromstring(archive.read("xl/sharedStrings.xml"))
        shared_strings = [
            "".join(item.itertext())
            for item in shared_xml.findall(f"{workbook_namespace}si")
        ]

def workbook_cell_value(cell):
    cell_type = cell.attrib.get("t")
    if cell_type == "inlineStr":
        inline = cell.find(f"{workbook_namespace}is")
        return "" if inline is None else "".join(inline.itertext())
    value = cell.find(f"{workbook_namespace}v")
    if value is None or value.text is None:
        return None
    if cell_type == "s":
        return shared_strings[int(value.text)]
    return value.text

workbook_cells = {
    cell.attrib["r"]: cell
    for cell in validator_sheet_xml.findall(f".//{workbook_namespace}c")
    if "r" in cell.attrib
}
activation_workbook_cells = {
    cell.attrib["r"]: cell
    for cell in activation_sheet_xml.findall(f".//{workbook_namespace}c")
    if "r" in cell.attrib
}
expected_workbook_note = (
    "Initial epoch only: validator-02..validator-06 map to synergy-val2..synergy-val6. "
    "Later epochs use a governed dynamic topology. Public identifiers and proposed weights only; "
    "never place keys, credentials, or host secrets here."
)
if workbook_cell_value(workbook_cells.get("A2", ET.Element("c"))) != expected_workbook_note:
    raise SystemExit("parameter-control workbook has a stale Validator Weights topology note")
for row, validator_id in enumerate(
    ["validator-02", "validator-03", "validator-04", "validator-05", "validator-06"],
    start=6,
):
    if workbook_cell_value(workbook_cells.get(f"A{row}", ET.Element("c"))) != validator_id:
        raise SystemExit(f"parameter-control workbook validator row A{row} is not canonical")
expected_weight_formulas = {
    "C11": "SUM(C6:C10)",
    "C12": "COUNTA(A6:A10)",
    "C13": "INT((2*C12)/3)+1",
    "C14": 'IF(C13=4,"PASS","FAIL")',
    "C15": 'IF(COUNTIF(H6:H10,"FAIL")=0,"MODEL PASS","FAIL")',
}
for reference, expected_formula in expected_weight_formulas.items():
    formula = workbook_cells.get(reference, ET.Element("c")).find(f"{workbook_namespace}f")
    if formula is None or formula.text != expected_formula:
        raise SystemExit(f"parameter-control workbook formula {reference} is not canonical")
if workbook_cell_value(activation_workbook_cells.get("C6", ET.Element("c"))) != (
    "Ratified POSY-00E and updated simplified PoSy set"
):
    raise SystemExit("parameter-control workbook retains the retired coordinated-consensus checklist wording")
for retired_identifier in ("posy-validator", "coordinated set", "synergy-testnet-v3", "posy/2.2"):
    if retired_identifier in workbook_text:
        raise SystemExit(
            f"parameter-control workbook retains retired P3-facing wording: {retired_identifier}"
        )

expected_boundary = {
    "schema_version": 4,
    "release_id": "testnet-v3",
    "status": "PROPOSED_NOT_ACTIVATED",
    "governance_approval_id": None,
    "chain_id": 1266,
    "network_id": "testnet",
    "protocol_version": "posy/3.0",
    "activation_boundary": "fresh_genesis_block_zero",
    "activation_epoch": None,
    "activation_height": None,
    "active_validator_count": 5,
    "healthy_path": ["PROPOSAL", "VOTE", "QC"],
    "required_distinct_signers": 4,
    "leader_lease_blocks": 10,
    "chained_qc_commit_depth": 3,
    "allow_quorum_reduction": False,
    "allow_local_leader_election": False,
    "require_single_validator_failure_liveness": True,
    "signer_journal_required": True,
    "safety_halt_on_conflicting_valid_qcs": True,
    "etdag_finality_separation_required": True,
    "protected_execution_binding_required": True,
}
for key, expected in expected_boundary.items():
    actual = proposal.get(key)
    if actual != expected:
        raise SystemExit(f"proposal {key}: expected {expected!r}, found {actual!r}")

if schema.get("properties", {}).get("network_id", {}).get("const") != "testnet":
    raise SystemExit("schema does not freeze technical network_id to testnet")
if schema.get("properties", {}).get("protocol_version", {}).get("const") != "posy/3.0":
    raise SystemExit("schema does not freeze protocol_version to posy/3.0")

checks = {
    "canonical_byte_length": len(proposal_bytes),
    "sha256_file_digest": hashlib.sha256(proposal_bytes).hexdigest(),
    "sha512_file_digest": hashlib.sha512(proposal_bytes).hexdigest(),
    "consensus_parameter_root": hashlib.sha3_512(proposal_bytes).hexdigest(),
}
for key, actual in checks.items():
    expected = verification.get(key)
    if actual != expected:
        raise SystemExit(f"verification {key}: expected {expected!r}, computed {actual!r}")

if verification.get("status") != "PROPOSAL_VERIFIED_NOT_ACTIVATABLE":
    raise SystemExit("proposal verification must remain non-activatable")

expected_initial_validator_ids = [
    "validator-02",
    "validator-03",
    "validator-04",
    "validator-05",
    "validator-06",
]
topology_validators = topology.get("validators")
if not isinstance(topology_validators, list):
    raise SystemExit("public five-validator topology has no validators list")
actual_initial_validator_ids = [entry.get("validator_id") for entry in topology_validators]
if actual_initial_validator_ids != expected_initial_validator_ids:
    raise SystemExit(
        "public five-validator topology must list only the canonical initial "
        f"validator IDs {expected_initial_validator_ids!r}, found {actual_initial_validator_ids!r}"
    )
if any(
    "private" in str(key).lower() or "secret" in str(key).lower()
    for entry in topology_validators
    if isinstance(entry, dict)
    for key in entry
):
    raise SystemExit("public five-validator topology must not contain private or secret fields")

expected_inactive_validator_ids = [
    "validator-01",
    "validator-07",
    "validator-08",
    "validator-09",
    "validator-10",
    "validator-11",
    "validator-12",
    "validator-13",
    "validator-14",
    "validator-15",
    "validator-16",
    "validator-17",
    "validator-18",
    "validator-19",
    "validator-20",
    "validator-21",
]
if any(
    validator_roster.get(key) != expected
    for key, expected in {
        "chain_id": 1266,
        "network_id": "testnet",
        "release_id": "testnet-v3",
        "protocol_version": "posy/3.0",
        "identity_count": 21,
        "initial_active_validator_count": 5,
        "future_inactive_validator_count": 16,
        "membership_is_dynamic": True,
        "identity_generation_status": "COMPLETE_CANONICAL_ALL_21_CUSTODY_CEREMONY",
    }.items()
):
    raise SystemExit("validator roster does not match the canonical fresh-P3 identity boundary")
if validator_roster.get("initial_active_validator_ids") != expected_initial_validator_ids:
    raise SystemExit("validator roster initial active set is not validator-02 through validator-06")
if validator_roster.get("future_inactive_validator_ids") != expected_inactive_validator_ids:
    raise SystemExit("validator roster inactive inventory is not the canonical 16-slot set")
slots = validator_roster.get("validator_slots")
if not isinstance(slots, list) or [slot.get("validator_id") for slot in slots] != [
    f"validator-{index:02d}" for index in range(1, 22)
]:
    raise SystemExit("validator roster slots must enumerate validator-01 through validator-21 exactly once")
if [slot.get("validator_id") for slot in slots if slot.get("genesis_status") == "ACTIVE"] != expected_initial_validator_ids:
    raise SystemExit("validator roster activates an identity outside the five-validator genesis set")
for slot in slots:
    validator_id = slot["validator_id"]
    expected_status = "ACTIVE" if validator_id in expected_initial_validator_ids else "INACTIVE"
    if slot.get("genesis_status") != expected_status:
        raise SystemExit(f"validator roster assigns non-canonical Genesis status to {validator_id}")
expected_active_machine_aliases = {
    "validator-02": "synergy-val2",
    "validator-03": "synergy-val3",
    "validator-04": "synergy-val4",
    "validator-05": "synergy-val5",
    "validator-06": "synergy-val6",
}
for slot in slots:
    validator_id = slot["validator_id"]
    expected_alias = expected_active_machine_aliases.get(validator_id)
    if slot.get("machine_alias") != expected_alias:
        raise SystemExit(f"validator roster assigns non-canonical machine metadata to {validator_id}")

expected_registry_sha256 = "f0c5044508c27f6c53fa27b177b506a67764ebe8c95861ae1c8cb3e1c4177225"
expected_vector_sha256 = "f5a427d44c3c3b9269d52eb5b471a6ede9de4031b34f66433d86963ab0b36509"
if hashlib.sha256(address_registry_bytes).hexdigest() != expected_registry_sha256:
    raise SystemExit("SNTS-01 address registry hash does not match its pinned canonical value")
if hashlib.sha256(address_vectors_bytes).hexdigest() != expected_vector_sha256:
    raise SystemExit("SNTS-01 Address Engine vector-set hash does not match its pinned canonical value")
if any(
    address_registry.get(key) != expected
    for key, expected in {
        "registry_version": "SNTS-01-v1.3",
        "source_document_sha256": "7dbf3ac0333f8f40b51502b625ec9242de88b70d612d340581968e69c222635c",
        "address_engine_version": 1,
        "declared_protocol_namespace_count": 36,
        "human_table_namespace_count": 36,
    }.items()
):
    raise SystemExit("SNTS-01 address registry metadata is not canonical")
if address_vectors.get("registry_sha256") != expected_registry_sha256:
    raise SystemExit("SNTS-01 Address Engine vectors are not bound to the canonical registry")

expected_dependency_boundary = {
    "schema": "synergy-posy-v3-pr-dependencies-v1",
    "status": "PR_QUALIFICATION_INPUT_NOT_RELEASE_APPROVAL",
    "chain_id": 1266,
    "network_id": "testnet",
    "release_id": "testnet-v3",
    "protocol_version": "posy/3.0",
}
for key, expected in expected_dependency_boundary.items():
    actual = dependency_lock.get(key)
    if actual != expected:
        raise SystemExit(f"dependency lock {key}: expected {expected!r}, found {actual!r}")
for label, revision in (
    ("Core source base", dependency_lock.get("core", {}).get("source_base_revision")),
    ("SynQ", dependency_lock.get("synq", {}).get("revision")),
    (
        "SynQ Aegis submodule",
        dependency_lock.get("synq", {}).get("aegis_pqsynq_submodule_revision"),
    ),
    ("Core vendored Aegis", dependency_lock.get("aegis", {}).get("revision")),
):
    if not isinstance(revision, str) or len(revision) != 40:
        raise SystemExit(f"{label} revision is not a 40-character Git object ID")
    try:
        int(revision, 16)
    except ValueError as error:
        raise SystemExit(f"{label} revision is not lowercase hexadecimal") from error
    if revision.lower() != revision:
        raise SystemExit(f"{label} revision is not lowercase hexadecimal")

for label, artifact in (("parameter", parameter), ("fee", fee)):
    if artifact.get("chain_id") != 1266:
        raise SystemExit(f"{label} artifact chain_id is not 1266")
    if artifact.get("network_id") != "testnet":
        raise SystemExit(f"{label} artifact network_id is not testnet")
    if artifact.get("consensus_protocol_version") != "posy/3.0":
        raise SystemExit(f"{label} artifact protocol is not posy/3.0")

# The release generator serializes these typed manifests in Rust struct-field
# order before taking SHA3-512.  Reconstruct that ordering here rather than
# trusting a checked-in expected value: the fee manifest is deliberately bound
# to the parameter root, and either root changing must force a new unsigned
# release set and V4 approval request.
def canonical_json_bytes(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

parameter_canonical = {
    "schema": parameter["schema"],
    "governance_decision_id": parameter["governance_decision_id"],
    "chain_id": parameter["chain_id"],
    "network_id": parameter["network_id"],
    "consensus_protocol_version": parameter["consensus_protocol_version"],
    "parameters": {
        "profile_id": parameter["parameters"]["profile_id"],
        "target_height_offset_default": parameter["parameters"]["target_height_offset_default"],
        "max_outstanding_nonce_slots": parameter["parameters"]["max_outstanding_nonce_slots"],
        "max_protected_gas": parameter["parameters"]["max_protected_gas"],
        "max_protected_bytes": parameter["parameters"]["max_protected_bytes"],
        "ciphertext_size_classes": parameter["parameters"]["ciphertext_size_classes"],
    },
}
parameter_root = hashlib.sha3_512(canonical_json_bytes(parameter_canonical)).hexdigest()
if parameter_root != derivations.get("etdag_parameter_root_sha3_512"):
    raise SystemExit("ETDAG parameter root is not derived from the canonical typed manifest")

fee_canonical = {
    "schema": fee["schema"],
    "governance_decision_id": fee["governance_decision_id"],
    "chain_id": fee["chain_id"],
    "network_id": fee["network_id"],
    "consensus_protocol_version": fee["consensus_protocol_version"],
    "etdag_parameter_root_sha3_512": fee["etdag_parameter_root_sha3_512"],
    "fee_schedule": {
        "entries": [
            {
                "tx_type": entry["tx_type"],
                "amount_fee_bps": entry["amount_fee_bps"],
                "min_amount_fee_nwei": entry["min_amount_fee_nwei"],
                "max_amount_fee_nwei": entry["max_amount_fee_nwei"],
                "valuation_required": entry["valuation_required"],
                "storage_fee_enabled": entry["storage_fee_enabled"],
            }
            for entry in fee["fee_schedule"]["entries"]
        ]
    },
    "fee_market_params": {
        "fee_market_enabled": fee["fee_market_params"]["fee_market_enabled"],
        "base_fee_floor_nwei": fee["fee_market_params"]["base_fee_floor_nwei"],
        "initial_base_fee_nwei": fee["fee_market_params"]["initial_base_fee_nwei"],
        "target_block_gas": fee["fee_market_params"]["target_block_gas"],
        "max_block_gas": fee["fee_market_params"]["max_block_gas"],
        "base_fee_change_denominator": fee["fee_market_params"]["base_fee_change_denominator"],
        "pq_gas_multiplier": fee["fee_market_params"]["pq_gas_multiplier"],
        "max_block_pq_gas": fee["fee_market_params"]["max_block_pq_gas"],
        "target_block_pq_gas": fee["fee_market_params"]["target_block_pq_gas"],
        "activation_height": fee["fee_market_params"]["activation_height"],
        "fee_market_version": fee["fee_market_params"]["fee_market_version"],
    },
}
if fee["etdag_parameter_root_sha3_512"] != parameter_root:
    raise SystemExit("ETDAG fee manifest is not bound to the canonical parameter root")
fee_root = hashlib.sha3_512(canonical_json_bytes(fee_canonical)).hexdigest()
if fee_root != derivations.get("etdag_fee_schedule_root_sha3_512"):
    raise SystemExit("ETDAG fee root is not derived from the canonical typed manifest")
if fee.get("governance_decision_id") != parameter.get("governance_decision_id"):
    raise SystemExit("ETDAG parameter and fee manifests disagree on their governance decision")

if derivations.get("status") != "UNSIGNED_INPUTS_AWAITING_FROZEN_AUTHORITY_RELEASE_APPROVAL":
    raise SystemExit("ETDAG derivations must remain explicitly unsigned before approval")

print("PoSy V3 static artifact invariants passed")
PY

dependency_lock=launch/POSY_V3_PR_DEPENDENCIES.lock.json
source_base="$(jq -er '.core.source_base_revision' "$dependency_lock")"
if git show-ref --verify --quiet refs/remotes/origin/main; then
  actual_source_base="$(git merge-base HEAD origin/main)"
  [[ "$actual_source_base" == "$source_base" ]] || {
    echo "P3 dependency lock source base is stale: $source_base != $actual_source_base" >&2
    exit 1
  }
fi

synq_root="$(cd runtime/src/../../../synq-language && pwd -P)"
expected_synq="$(jq -er '.synq.revision' "$dependency_lock")"
expected_synq_aegis="$(jq -er '.synq.aegis_pqsynq_submodule_revision' "$dependency_lock")"
expected_core_aegis="$(jq -er '.aegis.revision' "$dependency_lock")"
[[ "$(git -C "$synq_root" rev-parse HEAD)" == "$expected_synq" ]]
[[ "$(git -C "$synq_root" rev-parse HEAD:aegis-pqsynq)" == "$expected_synq_aegis" ]]
[[ "$(git -C "$synq_root/aegis-pqsynq" rev-parse HEAD)" == "$expected_synq_aegis" ]]
[[ "$(git rev-parse HEAD:runtime/aegis-pqvm)" == "$expected_core_aegis" ]]
[[ -z "$(git status --porcelain -- runtime/aegis-pqvm)" ]]
echo "PoSy V3 dependency-lock identities passed"

if [[ "$mode" == "static" ]]; then
  echo "PoSy V3 static PR verification passed"
  exit 0
fi

evidence_root="${POSY_V3_EVIDENCE_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/posy-v3-pr-evidence.XXXXXX")}"
mkdir -p "$evidence_root"
printf '%s\n' "$evidence_root" >"$evidence_root/evidence-directory.txt"

scrub_ephemeral_harness_keys() {
  local harness_dir
  for harness_dir in \
    "$evidence_root/state-machine-five-node" \
    "$evidence_root/production-driver-five-node"
  do
    if [[ -d "$harness_dir" ]]; then
      find "$harness_dir" -maxdepth 1 -type f \
        -name 'validator-*-private-key.msgpack' -delete
    fi
  done
}
trap scrub_ephemeral_harness_keys EXIT

run_test_family() {
  local evidence_name="$1"
  local test_filter="$2"
  local list_path="$evidence_root/test-${evidence_name}.list"
  local log_path="$evidence_root/test-${evidence_name}.log"
  local test_count

  printf '+ cargo test --locked --manifest-path %q --package synergy-testnet --lib %q -- --list\n' \
    "$runtime_manifest" "$test_filter"
  cargo test --locked --manifest-path "$runtime_manifest" \
    --package synergy-testnet --lib "$test_filter" -- --list \
    | tee "$list_path"
  test_count="$(grep -c ': test$' "$list_path" || true)"
  if [[ ! "$test_count" =~ ^[1-9][0-9]*$ ]]; then
    echo "test family $evidence_name selected zero tests with filter $test_filter" >&2
    exit 1
  fi

  printf '+ cargo test --locked --manifest-path %q --package synergy-testnet --lib %q -- --test-threads=1\n' \
    "$runtime_manifest" "$test_filter"
  cargo test --locked --manifest-path "$runtime_manifest" \
    --package synergy-testnet --lib "$test_filter" -- --test-threads=1 \
    | tee "$log_path"
}

run_test_family simplified-consensus 'consensus::simplified_posy::'
run_test_family simplified-parameter-loader 'posy_simplified_parameters::tests::'
run_test_family finalized-parameter-loader 'consensus_parameters::tests::'
run_test_family etdag-governance 'etdag_governance::tests::'
run_test_family release-approval 'testnet_v3_release_approval::tests::'
run_test_family genesis 'genesis::tests::'
run_test_family etdag-admission 'testnet_v3_etdag_admission::tests::'
run_test_family execution-bootstrap 'testnet_v3_execution_bootstrap::tests::'
run_test_family fresh-config-boundary 'config::tests::fresh_testnet_v3_rejects_coordinator_mode_and_local_ring'
run_test_family canonical-address-engine 'address::tests::'
run_test_family snts-registry 'snts_registry::tests::'
run_test_family protocol-standards 'protocol_standards::tests::'
run_test_family identity-authorization 'identity_auth::tests::'
run_test_family production-role-runtime 'role_runtime::tests::'
run_test_family p2p-message-framing 'p2p::messages::tests::'
run_test_family p2p-simplified-networking 'p2p::networking::tests::simplified_'

printf '+ runtime/scripts/testnet/run-posy-simplified-five-node-harness.sh %q\n' \
  "$evidence_root/state-machine-five-node"
runtime/scripts/testnet/run-posy-simplified-five-node-harness.sh \
  "$evidence_root/state-machine-five-node" \
  | tee "$evidence_root/state-machine-five-node-report.json"

printf '+ runtime/scripts/testnet/run-posy-simplified-five-driver-harness.sh %q\n' \
  "$evidence_root/production-driver-five-node"
runtime/scripts/testnet/run-posy-simplified-five-driver-harness.sh \
  "$evidence_root/production-driver-five-node" \
  | tee "$evidence_root/production-driver-five-node-report.json"

run python3 - \
  "$evidence_root/state-machine-five-node-report.json" \
  "$evidence_root/production-driver-five-node-report.json" <<'PY'
import json
import sys
from pathlib import Path

state_machine = json.loads(Path(sys.argv[1]).read_text())
driver = json.loads(Path(sys.argv[2]).read_text())

if state_machine.get("status") != "PASS":
    raise SystemExit("state-machine five-node harness did not report PASS")
if driver.get("status") != "passed":
    raise SystemExit("production-driver five-node harness did not report passed")

required_state_scenarios = {
    "one_unavailable_four_of_five_qc_progress",
    "two_unavailable_three_of_five_fail_closed",
    "three_qc_chained_finality",
    "two_sequential_tc_lease_inheritance",
    "restart_preserves_verified_takeover",
    "restart_preserves_last_vote_and_signer_journal",
    "ten_block_lease_and_boundary_reset",
}
required_driver_scenarios = {
    "four_of_five_autonomous_progress",
    "three_of_five_fail_closed",
    "real_timer_leader_takeover",
    "future_qc_state_sync_heal",
    "durable_process_restart",
    "three_chain_finalization",
}
missing_state = required_state_scenarios - set(state_machine.get("scenarios", []))
missing_driver = required_driver_scenarios - set(driver.get("scenarios", []))
if missing_state:
    raise SystemExit(f"state-machine harness omitted scenarios: {sorted(missing_state)}")
if missing_driver:
    raise SystemExit(f"production-driver harness omitted scenarios: {sorted(missing_driver)}")
if driver.get("parent_constructed_votes_qcs_tcs") is not False:
    raise SystemExit("production-driver parent must not construct consensus authority")

print("PoSy V3 harness reports contain the required evidence")
PY

cat >"$evidence_root/verification-status.json" <<'JSON'
{"schema":"synergy-posy-v3-pr-verification-status-v1","chain_id":1266,"network_id":"testnet","release_id":"testnet-v3","protocol_version":"posy/3.0","focused_test_families":16,"focused_tests":"PASS","state_machine_five_node_harness":"PASS","production_driver_five_node_harness":"PASS"}
JSON

echo "PoSy V3 full PR verification passed; evidence: $evidence_root"
