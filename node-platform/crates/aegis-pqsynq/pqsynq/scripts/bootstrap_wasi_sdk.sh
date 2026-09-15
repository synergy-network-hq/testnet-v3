#!/usr/bin/env bash

set -euo pipefail

WASI_SDK_MAJOR="20"
WASI_SDK_VERSION="20.0"
INSTALL_ROOT="${HOME}/.cache/synq"
INSTALL_DIR="${INSTALL_ROOT}/wasi-sdk-${WASI_SDK_VERSION}"
TMP_ARCHIVE="${INSTALL_ROOT}/wasi-sdk-${WASI_SDK_VERSION}.tar.gz"

mkdir -p "${INSTALL_ROOT}"

if [[ -d "${INSTALL_DIR}/bin" && -d "${INSTALL_DIR}/share/wasi-sysroot" ]]; then
  echo "WASI SDK already present at ${INSTALL_DIR}"
else
  case "$(uname -s)" in
    Darwin) PLATFORM="macos" ;;
    Linux) PLATFORM="linux" ;;
    *)
      echo "Unsupported OS for automatic WASI SDK bootstrap: $(uname -s)" >&2
      exit 1
      ;;
  esac

  ASSET="wasi-sdk-${WASI_SDK_VERSION}-${PLATFORM}.tar.gz"
  URL="https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-${WASI_SDK_MAJOR}/${ASSET}"

  echo "Downloading ${URL}"
  curl -fL "${URL}" -o "${TMP_ARCHIVE}"

  rm -rf "${INSTALL_DIR}.tmp"
  mkdir -p "${INSTALL_DIR}.tmp"
  tar -xzf "${TMP_ARCHIVE}" -C "${INSTALL_DIR}.tmp"

  # Release archives contain a top-level wasi-sdk-<ver>-<platform> directory.
  EXTRACTED_DIR="$(find "${INSTALL_DIR}.tmp" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
  if [[ -z "${EXTRACTED_DIR}" ]]; then
    echo "Failed to locate extracted WASI SDK directory" >&2
    exit 1
  fi

  rm -rf "${INSTALL_DIR}"
  mv "${EXTRACTED_DIR}" "${INSTALL_DIR}"
  rm -rf "${INSTALL_DIR}.tmp"

  echo "Installed WASI SDK to ${INSTALL_DIR}"
fi

WASI_SYSROOT="${INSTALL_DIR}/share/wasi-sysroot"
WASI_CLANG="${INSTALL_DIR}/bin/clang"

echo
echo "Export these variables before running WASI checks:"
echo "export WASI_SDK_DIR=${WASI_SYSROOT}"
echo "export CC_wasm32_wasi=${WASI_CLANG}"
