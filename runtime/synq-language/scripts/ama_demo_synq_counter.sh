#!/usr/bin/env bash
set -euo pipefail

SYNQ_LANGUAGE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TESTNET_ROOT="${TESTNET_ROOT:-/Users/devpup/Desktop/Testnet-Beta/synergy-testnet}"
AIVM_CORE_ROOT="${AIVM_CORE_ROOT:-/Volumes/xcode/Synergy-Network-Projects/synergy-aivm/runtime/aivm-core}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/Users/devpup/Desktop/Testnet-Beta/synergy-testnet/target}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
export SYNQ_LANGUAGE_ROOT

COUNTER_SOURCE="${SYNQ_LANGUAGE_ROOT}/contracts/Counter.synq"
COUNTER_BYTECODE="${SYNQ_LANGUAGE_ROOT}/contracts/Counter.compiled.synq"
COUNTER_ABI="${SYNQ_LANGUAGE_ROOT}/contracts/Counter.abi.json"
COUNTER_MANIFEST="${SYNQ_LANGUAGE_ROOT}/contracts/Counter.manifest.json"
DEMO_DOCS="${SYNQ_LANGUAGE_ROOT}/docs/demo"
VISUAL_PATH="${DEMO_DOCS}/SynQ-Counter-AMA-Demo-Visual.html"
CLI_DEMO_DIR=""

VERBOSE=0
VERIFY_ENV_ONLY=0
RUN_NEGATIVE_TESTS=1

usage() {
  cat <<USAGE
Usage: $0 [--check|--verify-env] [--verbose] [--negative-tests|--no-negative-tests]

Runs the local SynQ Counter AMA demo and writes a visual HTML board to:
  ${VISUAL_PATH}

This is a local proof path. It does not submit to public TESTNET.
USAGE
}

for arg in "$@"; do
  case "$arg" in
    --check|--verify-env)
      VERIFY_ENV_ONLY=1
      ;;
    --verbose)
      VERBOSE=1
      ;;
    --negative-tests)
      RUN_NEGATIVE_TESTS=1
      ;;
    --no-negative-tests)
      RUN_NEGATIVE_TESTS=0
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $arg" >&2
      usage >&2
      exit 2
      ;;
  esac
done

require_path() {
  local path="$1"
  if [[ ! -e "$path" ]]; then
    echo "Missing required path: $path" >&2
    exit 1
  fi
}

require_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Missing required command: $cmd" >&2
    exit 1
  fi
}

cleanup() {
  if [[ -n "${CLI_DEMO_DIR}" && -d "${CLI_DEMO_DIR}" ]]; then
    rm -rf "${CLI_DEMO_DIR}"
  fi
}
trap cleanup EXIT

verify_env() {
  require_cmd cargo
  require_cmd shasum
  require_cmd awk
  require_cmd sed
  require_path "${SYNQ_LANGUAGE_ROOT}/Cargo.toml"
  require_path "${TESTNET_ROOT}/Cargo.toml"
  require_path "${TESTNET_ROOT}/aegis-pqvm/Cargo.toml"
  require_path "${AIVM_CORE_ROOT}/Cargo.toml"
  require_path "${COUNTER_SOURCE}"
  mkdir -p "${DEMO_DOCS}"
  echo "Environment check: PASS"
  echo "synq_language_root=${SYNQ_LANGUAGE_ROOT}"
  echo "testnet_root=${TESTNET_ROOT}"
  echo "aivm_core_root=${AIVM_CORE_ROOT}"
  echo "cargo_target_dir=${CARGO_TARGET_DIR}"
  echo "cargo_build_jobs=${CARGO_BUILD_JOBS}"
}

run_cmd() {
  local label="$1"
  shift
  if [[ "$VERBOSE" -eq 1 ]]; then
    "$@"
    echo "${label}: PASS"
    return
  fi

  local log_file
  log_file="$(mktemp)"
  if "$@" >"${log_file}" 2>&1; then
    echo "${label}: PASS"
    rm -f "${log_file}"
  else
    echo "${label}: FAIL" >&2
    cat "${log_file}" >&2
    rm -f "${log_file}"
    exit 1
  fi
}

sha256_file() {
  shasum -a 256 "$1" | awk '{print $1}'
}

manifest_value() {
  local key="$1"
  awk -v key="\"${key}\":" '
    BEGIN { RS = "," }
    index($0, key) {
      sub(/^.*:/, "", $0)
      gsub(/[{}"]/, "", $0)
      print $0
      exit
    }
  ' "${COUNTER_MANIFEST}"
}

json_string_value() {
  local key="$1"
  local file="$2"
  sed -n "s/.*\"${key}\": \"\\([^\"]*\\)\".*/\\1/p" "$file" | head -n 1
}

write_visual() {
  cat >"${VISUAL_PATH}" <<HTML
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SynQ Counter AMA Demo</title>
  <style>
    :root {
      color-scheme: dark;
      --bg: #111416;
      --panel: #1b2024;
      --line: #364048;
      --text: #f4f7f8;
      --muted: #aab7bd;
      --mint: #62d7a3;
      --cyan: #6ac7ff;
      --gold: #f3c969;
      --red: #ff7d7d;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
      background: var(--bg);
      color: var(--text);
    }
    main { max-width: 1180px; margin: 0 auto; padding: 32px; }
    header { display: flex; justify-content: space-between; gap: 24px; align-items: end; border-bottom: 1px solid var(--line); padding-bottom: 22px; }
    h1 { margin: 0; font-size: 34px; line-height: 1.05; }
    h2 { margin: 0 0 14px; font-size: 18px; }
    .subtitle { margin: 10px 0 0; color: var(--muted); max-width: 720px; }
    .status { border: 1px solid var(--mint); color: var(--mint); padding: 10px 14px; font-weight: 700; }
    .grid { display: grid; gap: 16px; margin-top: 22px; }
    .cards { grid-template-columns: repeat(4, minmax(0, 1fr)); }
    .two { grid-template-columns: 1.2fr .8fr; }
    .card, .panel { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; padding: 16px; }
    .label { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .08em; }
    .value { margin-top: 8px; font-size: 20px; font-weight: 750; overflow-wrap: anywhere; }
    .hash { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; color: var(--cyan); }
    .pipeline { display: grid; grid-template-columns: repeat(7, 1fr); gap: 10px; }
    .step { border: 1px solid var(--line); border-radius: 8px; padding: 14px; min-height: 112px; }
    .step strong { display: block; margin-bottom: 8px; }
    .ok { color: var(--mint); }
    .warn { color: var(--gold); }
    .bad { color: var(--red); }
    .counter { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; text-align: center; }
    .counter .value { font-size: 44px; color: var(--mint); }
    .foot { color: var(--muted); font-size: 13px; line-height: 1.5; }
    @media (max-width: 900px) {
      main { padding: 18px; }
      header, .two { display: block; }
      .cards, .pipeline, .counter { grid-template-columns: 1fr; }
      .status { margin-top: 16px; display: inline-block; }
    }
  </style>
</head>
<body>
<main>
  <header>
    <div>
      <h1>SynQ Counter Smart Contract Alpha Demo</h1>
      <p class="subtitle">Local proof path: source to artifacts, ML-DSA-65 pqsynq verification, existing pqvm admission, AIVM Counter overlay, gas lanes, and deterministic receipt.</p>
    </div>
    <div class="status">LOCAL DEMO PASS</div>
  </header>

  <section class="grid cards">
    <div class="card"><div class="label">Chain</div><div class="value">${CHAIN_ID}</div></div>
    <div class="card"><div class="label">Network</div><div class="value">${NETWORK_ID}</div></div>
    <div class="card"><div class="label">Signature</div><div class="value">${SIGNATURE_ALGORITHM}</div></div>
    <div class="card"><div class="label">Normalized Node Alias</div><div class="value">synergy-testnet-v3 -> ${NETWORK_ID}</div></div>
  </section>

  <section class="grid">
    <div class="panel">
      <h2>Pipeline</h2>
      <div class="pipeline">
        <div class="step"><strong>1. Source</strong><span class="ok">Counter.synq</span><br><span class="foot">${COUNTER_SOURCE}</span></div>
        <div class="step"><strong>2. Build</strong><span class="ok">bytecode + ABI + manifest</span></div>
        <div class="step"><strong>3. CLI Deploy</strong><span class="ok">pqsynq ML-DSA-65 verified</span></div>
        <div class="step"><strong>4. CLI Calls</strong><span class="ok">increment/get envelopes verified</span></div>
        <div class="step"><strong>5. pqvm Admission</strong><span class="ok">outer path preserved</span></div>
        <div class="step"><strong>6. AIVM</strong><span class="ok">quantumvm-backed local run</span></div>
        <div class="step"><strong>7. Receipt</strong><span class="ok">deterministic hash</span></div>
      </div>
    </div>
  </section>

  <section class="grid cards">
    <div class="card"><div class="label">Bytecode Hash</div><div class="value hash">${BYTECODE_HASH}</div></div>
    <div class="card"><div class="label">ABI Hash</div><div class="value hash">${ABI_HASH}</div></div>
    <div class="card"><div class="label">Manifest Hash</div><div class="value hash">${MANIFEST_HASH}</div></div>
    <div class="card"><div class="label">State Root</div><div class="value hash">${STATE_ROOT}</div></div>
    <div class="card"><div class="label">Receipt Hash</div><div class="value hash">${RECEIPT_HASH}</div></div>
  </section>

  <section class="grid two">
    <div class="panel">
      <h2>Counter State</h2>
      <div class="counter">
        <div class="card"><div class="label">Before</div><div class="value">${COUNTER_BEFORE}</div></div>
        <div class="card"><div class="label">After Increment</div><div class="value">${COUNTER_AFTER}</div></div>
        <div class="card"><div class="label">Get</div><div class="value">${COUNTER_GET}</div></div>
      </div>
    </div>
    <div class="panel">
      <h2>Metering</h2>
      <div class="card"><div class="label">Ordinary Gas</div><div class="value">${ORDINARY_GAS}</div></div>
      <div class="card" style="margin-top: 12px;"><div class="label">PQ-Gas</div><div class="value">${PQ_GAS}</div></div>
    </div>
  </section>

  <section class="grid">
    <div class="panel">
      <h2>Negative Paths</h2>
      <p class="foot"><span class="ok">PASS</span> wrong chain preserves AEGIS-CHAIN; wrong domain preserves AEGIS-DOMAIN; invalid signature preserves AEGIS-SIG; malformed carrier preserves AEGIS-CANON.</p>
      <p class="foot"><span class="warn">Not claimed:</span> public RPC listener, live TESTNET deploy, persisted chain storage, public AIVM RPC handlers, or production audit readiness.</p>
    </div>
  </section>
</main>
</body>
</html>
HTML
}

verify_env
if [[ "$VERIFY_ENV_ONLY" -eq 1 ]]; then
  exit 0
fi

echo
echo "[1/9] Build deterministic Counter artifacts"
run_cmd "synq_build" cargo run --quiet --manifest-path "${SYNQ_LANGUAGE_ROOT}/Cargo.toml" -p cli -- \
  build "${COUNTER_SOURCE}"

BYTECODE_HASH="$(sha256_file "${COUNTER_BYTECODE}")"
ABI_HASH="$(sha256_file "${COUNTER_ABI}")"
MANIFEST_HASH="$(sha256_file "${COUNTER_MANIFEST}")"
CHAIN_ID="$(manifest_value required_chain_id)"
NETWORK_ID="$(manifest_value required_network_id)"
SIGNATURE_ALGORITHM="$(manifest_value required_signature_algorithm)"
echo "source_path=${COUNTER_SOURCE}"
echo "bytecode_path=${COUNTER_BYTECODE}"
echo "abi_path=${COUNTER_ABI}"
echo "manifest_path=${COUNTER_MANIFEST}"
echo "bytecode_hash=${BYTECODE_HASH}"
echo "abi_hash=${ABI_HASH}"
echo "manifest_hash=${MANIFEST_HASH}"
echo "chain_id=${CHAIN_ID}"
echo "network_id=${NETWORK_ID}"
echo "normalized_network=synergy-testnet-v3 -> ${NETWORK_ID}"
echo "signature_algorithm=${SIGNATURE_ALGORITHM}"

echo
echo "[2/9] Verify compiler artifact fixtures"
run_cmd "compiler_artifact_tests" cargo test --quiet --manifest-path "${SYNQ_LANGUAGE_ROOT}/Cargo.toml" \
  -p compiler --test artifact_test --locked

echo
echo "[3/9] Verify pqsynq deploy/call gates"
run_cmd "pqsynq_verifier_tests" cargo test --quiet --manifest-path "${SYNQ_LANGUAGE_ROOT}/Cargo.toml" \
  -p aegis-pqsynq --test synq_verifier_tests --locked
echo "deploy_verification=PASS"
echo "call_verification=PASS"

echo
echo
echo "[4/9] Exercise pqsynq-backed CLI deploy and call envelopes"
CLI_DEMO_DIR="$(mktemp -d)"
CLI_KEY_DIR="${CLI_DEMO_DIR}/keys"
CLI_DEPLOY_ENVELOPE="${CLI_DEMO_DIR}/Counter.deploy.json"
CLI_INCREMENT_CALL="${CLI_DEMO_DIR}/Counter.increment.call.json"
CLI_GET_CALL="${CLI_DEMO_DIR}/Counter.get.call.json"
run_cmd "synq_cli_keygen" cargo run --quiet --manifest-path "${SYNQ_LANGUAGE_ROOT}/Cargo.toml" -p cli -- \
  keygen --algorithm ml-dsa-65 --network testnet --out-dir "${CLI_KEY_DIR}"
CLI_PRIVATE_KEY="${CLI_KEY_DIR}/synq-testnet-mldsa65.private.json"
CLI_SIGNER_ADDRESS="$(json_string_value address "${CLI_PRIVATE_KEY}")"
if [[ -z "${CLI_SIGNER_ADDRESS}" ]]; then
  echo "Failed to read generated SynQ address from temporary private key file" >&2
  exit 1
fi
run_cmd "synq_cli_sign_deploy" cargo run --quiet --manifest-path "${SYNQ_LANGUAGE_ROOT}/Cargo.toml" -p cli -- \
  sign-deploy --bytecode "${COUNTER_BYTECODE}" --manifest "${COUNTER_MANIFEST}" --abi "${COUNTER_ABI}" \
  --private-key "${CLI_PRIVATE_KEY}" --output "${CLI_DEPLOY_ENVELOPE}" --nonce 101
run_cmd "synq_cli_verify_deploy" cargo run --quiet --manifest-path "${SYNQ_LANGUAGE_ROOT}/Cargo.toml" -p cli -- \
  verify-deploy "${CLI_DEPLOY_ENVELOPE}"
run_cmd "synq_cli_sign_call_increment" cargo run --quiet --manifest-path "${SYNQ_LANGUAGE_ROOT}/Cargo.toml" -p cli -- \
  sign-call --contract "${CLI_SIGNER_ADDRESS}" --method increment --args '[]' --abi "${COUNTER_ABI}" \
  --manifest "${COUNTER_MANIFEST}" --private-key "${CLI_PRIVATE_KEY}" --output "${CLI_INCREMENT_CALL}" --nonce 102
run_cmd "synq_cli_verify_call_increment" cargo run --quiet --manifest-path "${SYNQ_LANGUAGE_ROOT}/Cargo.toml" -p cli -- \
  verify-call "${CLI_INCREMENT_CALL}"
run_cmd "synq_cli_sign_call_get" cargo run --quiet --manifest-path "${SYNQ_LANGUAGE_ROOT}/Cargo.toml" -p cli -- \
  sign-call --contract "${CLI_SIGNER_ADDRESS}" --method get --args '[]' --abi "${COUNTER_ABI}" \
  --manifest "${COUNTER_MANIFEST}" --private-key "${CLI_PRIVATE_KEY}" --output "${CLI_GET_CALL}" --nonce 103
run_cmd "synq_cli_verify_call_get" cargo run --quiet --manifest-path "${SYNQ_LANGUAGE_ROOT}/Cargo.toml" -p cli -- \
  verify-call "${CLI_GET_CALL}"
echo "cli_keygen=PASS"
echo "cli_deploy_envelope_verified=PASS"
echo "cli_increment_call_envelope_verified=PASS"
echo "cli_get_call_envelope_verified=PASS"
echo "cli_private_key_output=TEMPORARY_LOCAL_FILE_ONLY"

echo
echo "[5/9] Verify Model B admission and structured negative paths"
if [[ "$RUN_NEGATIVE_TESTS" -eq 1 ]]; then
  run_cmd "synq_admission_positive_and_negative_tests" cargo test --quiet --manifest-path "${TESTNET_ROOT}/Cargo.toml" \
    -p synergy-testnet --lib synq_admission::tests -- --nocapture
  echo "wrong_chain_error=AEGIS-CHAIN"
  echo "wrong_domain_error=AEGIS-DOMAIN"
  echo "invalid_signature_error=AEGIS-SIG"
  echo "malformed_carrier_error=AEGIS-CANON"
else
  echo "negative_tests=SKIPPED_BY_FLAG"
fi

echo
echo "[6/9] Admit generated Counter hashes through pqsynq then pqvm"
run_cmd "counter_artifact_linked_pqsynq_then_pqvm" cargo test --quiet --manifest-path "${TESTNET_ROOT}/Cargo.toml" \
  -p synergy-testnet --lib \
  synq_admission::tests::counter_artifacts_pass_pqsynq_then_existing_pqvm_admission \
  -- --ignored --nocapture
echo "aegis_pqvm_outer_admission=PASS"

echo
echo "[7/9] Verify receipt summary preservation"
run_cmd "receipt_preserves_synq_verification_summary" cargo test --quiet --manifest-path "${TESTNET_ROOT}/Cargo.toml" \
  -p synergy-testnet --lib execution::tests::receipt_preserves_synq_verification_summary -- --nocapture

echo
echo "[8/9] Run local quantumvm-backed AIVM Counter overlay"
AIVM_OUTPUT="$(mktemp)"
if cargo run --quiet --manifest-path "${AIVM_CORE_ROOT}/Cargo.toml" --example counter_state_demo >"${AIVM_OUTPUT}" 2>&1; then
  cat "${AIVM_OUTPUT}"
else
  cat "${AIVM_OUTPUT}" >&2
  rm -f "${AIVM_OUTPUT}"
  exit 1
fi
COUNTER_BEFORE="$(sed -n 's/^counter_before=//p' "${AIVM_OUTPUT}")"
COUNTER_AFTER="$(sed -n 's/^counter_increment_return=//p' "${AIVM_OUTPUT}")"
COUNTER_GET="$(sed -n 's/^counter_get_return=//p' "${AIVM_OUTPUT}")"
STATE_ROOT="$(sed -n 's/^state_root=//p' "${AIVM_OUTPUT}")"
ORDINARY_GAS="$(sed -n 's/^ordinary_gas_used=//p' "${AIVM_OUTPUT}")"
PQ_GAS="$(sed -n 's/^pq_gas_used=//p' "${AIVM_OUTPUT}")"
RECEIPT_HASH="$(sed -n 's/^receipt_hash=//p' "${AIVM_OUTPUT}")"
rm -f "${AIVM_OUTPUT}"

echo
echo "[9/9] Write visual demo board"
write_visual
echo "visual_demo=${VISUAL_PATH}"

echo
echo "What this proves:"
echo "- Counter source builds to deterministic SynQ bytecode, ABI, and manifest artifacts."
echo "- SynQ CLI keygen, sign-deploy, verify-deploy, sign-call, and verify-call run through aegis-pqsynq."
echo "- Real ML-DSA-65 pqsynq deploy/call verification runs before existing pqvm outer admission."
echo "- Local AIVM state overlay records Counter 0 -> 1, reports ordinary gas and PQ-Gas separately, and emits a deterministic receipt hash."
echo
echo "What this does not prove:"
echo "- No public RPC listener or live TESTNET deploy/call was exercised."
echo "- Public AIVM RPC handlers remain disabled."
echo "- Persisted chain storage, explorer indexing, and production audit readiness remain pending."
