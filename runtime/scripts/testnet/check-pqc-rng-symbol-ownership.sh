#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
aegis_utils="${repo_root}/aegis-pqvm/src/utils.rs"
pqrust_internals="${repo_root}/synq-language/pqrust/pqrust-internals/src/lib.rs"

for source in "${aegis_utils}" "${pqrust_internals}"; do
  if [[ ! -f "${source}" ]]; then
    echo "Required PQC RNG source is missing: ${source}" >&2
    exit 1
  fi
done

if grep -nE 'fn PQRUST_RUST_randombytes' "${aegis_utils}"; then
  echo "Aegis-PQVM must not export PQRUST_RUST_randombytes; pqrust-internals owns that process-wide symbol." >&2
  exit 1
fi

compat_export_count="$(grep -Ec 'fn PQRUST_RUST_randombytes' "${pqrust_internals}" || true)"
if [[ "${compat_export_count}" != "1" ]]; then
  echo "pqrust-internals must export exactly one PQRUST_RUST_randombytes implementation." >&2
  exit 1
fi

if ! grep -qE 'pqrust_internals::PQRUST_RUST_randombytes' "${aegis_utils}"; then
  echo "Aegis-PQVM randombytes must delegate to the pqrust-internals symbol owner." >&2
  exit 1
fi

echo "PQC RNG symbol ownership verified: pqrust-internals owns the compatibility export."
