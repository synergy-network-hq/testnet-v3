#!/usr/bin/env bash
set -euo pipefail

BIN_NAME="synergy-sts"
DEFAULT_REPO="synergy-network-hq/synergy-sts-cli-releases"
INSTALL_DIR="${SYNERGY_STS_INSTALL_DIR:-${HOME}/.local/bin}"
VERSION="${SYNERGY_STS_VERSION:-latest}"
REPO="${SYNERGY_STS_GITHUB_REPO:-$DEFAULT_REPO}"
TARGET="${SYNERGY_STS_TARGET:-}"
FROM_SOURCE=""
FROM_FILE=""
DOWNLOAD_URL=""
EXPECTED_SHA256="${SYNERGY_STS_SHA256:-}"
DRY_RUN=0
ADD_TO_PATH=0
NO_PATH_CHECK=0
SKIP_SHA256=0
LOCKED_FLAG="--locked"

usage() {
  cat <<'USAGE'
Install the Synergy Token System CLI.

Usage:
  install-synergy-sts.sh [options]

Install modes:
  --from-source <dir>       Build synergy-sts from a local synergy-testnet checkout.
  --from-file <path>        Install an existing synergy-sts binary.
  --url <url>               Download a binary from an explicit URL.
  --version <tag|latest>    GitHub release tag to install. Default: latest.
  --repo <owner/repo>       GitHub repository for release assets. Default: synergy-network-hq/synergy-sts-cli-releases.

Install options:
  --install-dir <dir>       Directory for the installed binary. Default: $HOME/.local/bin.
  --target <platform>       Override detected platform, for example linux-amd64 or macos-arm64.
  --sha256 <hex>            Expected binary SHA-256 for --url or --from-file.
  --skip-sha256             Do not require release .sha256 verification.
  --add-to-path             Append the install directory to a shell profile when it is not on PATH.
  --no-path-check           Skip PATH warnings.
  --no-locked               Build from source without cargo --locked.
  --dry-run                 Print actions without installing.
  -h, --help                Show this help.

Examples:
  curl -fsSL https://github.com/synergy-network-hq/synergy-sts-cli-releases/releases/latest/download/install-synergy-sts.sh | bash
  ./scripts/install-synergy-sts.sh --from-source .
  ./scripts/install-synergy-sts.sh --version synergy-sts-v15.0.14 --install-dir /usr/local/bin
USAGE
}

die() {
  echo "install-synergy-sts: $*" >&2
  exit 1
}

info() {
  echo "install-synergy-sts: $*"
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --from-source)
      FROM_SOURCE="${2:-}"
      shift 2
      ;;
    --from-file)
      FROM_FILE="${2:-}"
      shift 2
      ;;
    --url)
      DOWNLOAD_URL="${2:-}"
      shift 2
      ;;
    --version)
      VERSION="${2:-}"
      shift 2
      ;;
    --repo)
      REPO="${2:-}"
      shift 2
      ;;
    --install-dir)
      INSTALL_DIR="${2:-}"
      shift 2
      ;;
    --target)
      TARGET="${2:-}"
      shift 2
      ;;
    --sha256)
      EXPECTED_SHA256="${2:-}"
      shift 2
      ;;
    --skip-sha256)
      SKIP_SHA256=1
      shift
      ;;
    --add-to-path)
      ADD_TO_PATH=1
      shift
      ;;
    --no-path-check)
      NO_PATH_CHECK=1
      shift
      ;;
    --no-locked)
      LOCKED_FLAG=""
      shift
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
done

[[ -n "$INSTALL_DIR" ]] || die "--install-dir cannot be empty"

mode_count=0
[[ -n "$FROM_SOURCE" ]] && mode_count=$((mode_count + 1))
[[ -n "$FROM_FILE" ]] && mode_count=$((mode_count + 1))
[[ -n "$DOWNLOAD_URL" ]] && mode_count=$((mode_count + 1))
if [[ "$mode_count" -gt 1 ]]; then
  die "choose only one of --from-source, --from-file, or --url"
fi

detect_target() {
  local os arch
  case "$(uname -s)" in
    Linux) os="linux" ;;
    Darwin) os="macos" ;;
    *) die "unsupported OS for this installer: $(uname -s). Use install-synergy-sts.ps1 on Windows." ;;
  esac
  case "$(uname -m)" in
    x86_64|amd64) arch="amd64" ;;
    arm64|aarch64) arch="arm64" ;;
    *) die "unsupported CPU architecture: $(uname -m)" ;;
  esac
  printf '%s-%s\n' "$os" "$arch"
}

asset_name_for_target() {
  local target="$1"
  case "$target" in
    windows-*) printf '%s-%s.exe\n' "$BIN_NAME" "$target" ;;
    *) printf '%s-%s\n' "$BIN_NAME" "$target" ;;
  esac
}

release_url_for_asset() {
  local asset="$1"
  if [[ "$VERSION" == "latest" ]]; then
    printf 'https://github.com/%s/releases/latest/download/%s\n' "$REPO" "$asset"
  else
    printf 'https://github.com/%s/releases/download/%s/%s\n' "$REPO" "$VERSION" "$asset"
  fi
}

download_file() {
  local url="$1"
  local dest="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fL --retry 3 --connect-timeout 15 --output "$dest" "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$dest" "$url"
  else
    die "curl or wget is required to download $url"
  fi
}

sha256_file() {
  local path="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$path" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$path" | awk '{print $1}'
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 -r "$path" | awk '{print $1}'
  else
    die "sha256sum, shasum, or openssl is required for SHA-256 verification"
  fi
}

verify_sha256() {
  local path="$1"
  local expected="$2"
  [[ -n "$expected" ]] || die "missing expected SHA-256"
  local actual
  actual="$(sha256_file "$path")"
  if [[ "$actual" != "$expected" ]]; then
    die "SHA-256 mismatch for $path: expected $expected, got $actual"
  fi
}

extract_sha_from_sidecar() {
  local sidecar="$1"
  awk 'NF >= 1 {print $1; exit}' "$sidecar"
}

looks_like_repo_root() {
  local dir="$1"
  [[ -f "$dir/Cargo.toml" && -f "$dir/src/Cargo.toml" && -f "$dir/src/bin/synergy-sts.rs" ]]
}

TMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

if [[ -z "$TARGET" ]]; then
  TARGET="$(detect_target)"
fi

SOURCE_BINARY=""

if [[ -n "$FROM_FILE" ]]; then
  [[ -f "$FROM_FILE" ]] || die "--from-file does not exist: $FROM_FILE"
  SOURCE_BINARY="$FROM_FILE"
  if [[ -n "$EXPECTED_SHA256" ]]; then
    verify_sha256 "$SOURCE_BINARY" "$EXPECTED_SHA256"
  fi
elif [[ -n "$DOWNLOAD_URL" ]]; then
  SOURCE_BINARY="$TMP_DIR/$BIN_NAME"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    info "would download $DOWNLOAD_URL"
  else
    download_file "$DOWNLOAD_URL" "$SOURCE_BINARY"
    if [[ -n "$EXPECTED_SHA256" ]]; then
      verify_sha256 "$SOURCE_BINARY" "$EXPECTED_SHA256"
    elif [[ "$SKIP_SHA256" -eq 0 ]]; then
      info "warning: --url install has no --sha256; use --sha256 for pinned installs"
    fi
  fi
elif [[ -n "$FROM_SOURCE" ]]; then
  SOURCE_DIR="${FROM_SOURCE:-$PWD}"
  looks_like_repo_root "$SOURCE_DIR" || die "not a synergy-testnet repo root: $SOURCE_DIR"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    info "would build $BIN_NAME from $SOURCE_DIR"
    SOURCE_BINARY="$SOURCE_DIR/target/release/$BIN_NAME"
  else
    need_cmd cargo
    info "building $BIN_NAME from source in $SOURCE_DIR"
    if [[ -n "$LOCKED_FLAG" ]]; then
      cargo build --release --locked -p synergy-testnet --bin "$BIN_NAME" --manifest-path "$SOURCE_DIR/Cargo.toml"
    else
      cargo build --release -p synergy-testnet --bin "$BIN_NAME" --manifest-path "$SOURCE_DIR/Cargo.toml"
    fi
    SOURCE_BINARY="$SOURCE_DIR/target/release/$BIN_NAME"
    [[ -x "$SOURCE_BINARY" ]] || die "build completed but binary is missing: $SOURCE_BINARY"
  fi
else
  ASSET_NAME="$(asset_name_for_target "$TARGET")"
  DOWNLOAD_URL="$(release_url_for_asset "$ASSET_NAME")"
  SOURCE_BINARY="$TMP_DIR/$BIN_NAME"
  if [[ "$DRY_RUN" -eq 1 ]]; then
    info "would download $DOWNLOAD_URL"
  else
    info "downloading $ASSET_NAME from $REPO ($VERSION)"
    download_file "$DOWNLOAD_URL" "$SOURCE_BINARY"
    chmod 755 "$SOURCE_BINARY"
    if [[ "$SKIP_SHA256" -eq 0 ]]; then
      SIDECAR="$TMP_DIR/$ASSET_NAME.sha256"
      download_file "${DOWNLOAD_URL}.sha256" "$SIDECAR"
      verify_sha256 "$SOURCE_BINARY" "$(extract_sha_from_sidecar "$SIDECAR")"
    fi
  fi
fi

DEST="$INSTALL_DIR/$BIN_NAME"
if [[ "$DRY_RUN" -eq 1 ]]; then
  info "would install $SOURCE_BINARY to $DEST"
  exit 0
fi

mkdir -p "$INSTALL_DIR"
INSTALL_TMP="$INSTALL_DIR/.${BIN_NAME}.$$"
cp "$SOURCE_BINARY" "$INSTALL_TMP"
chmod 755 "$INSTALL_TMP"
mv "$INSTALL_TMP" "$DEST"

info "installed $DEST"
"$DEST" version
"$DEST" native-info --output compact-json >/dev/null
info "post-install smoke check passed"

path_contains_install_dir() {
  case ":${PATH:-}:" in
    *":$INSTALL_DIR:"*) return 0 ;;
    *) return 1 ;;
  esac
}

append_path_to_profile() {
  local profile
  if [[ "${SHELL:-}" == */zsh ]]; then
    profile="$HOME/.zshrc"
  elif [[ "${SHELL:-}" == */bash ]]; then
    profile="$HOME/.bashrc"
  else
    profile="$HOME/.profile"
  fi
  touch "$profile"
  if ! grep -F "export PATH=\"$INSTALL_DIR:\$PATH\"" "$profile" >/dev/null 2>&1; then
    printf '\n# Synergy STS CLI\nexport PATH="%s:$PATH"\n' "$INSTALL_DIR" >> "$profile"
  fi
  info "added $INSTALL_DIR to PATH in $profile"
}

if [[ "$NO_PATH_CHECK" -eq 0 ]]; then
  if path_contains_install_dir; then
    info "run with: $BIN_NAME native-info"
  elif [[ "$ADD_TO_PATH" -eq 1 ]]; then
    append_path_to_profile
    info "restart your shell or run: export PATH=\"$INSTALL_DIR:\$PATH\""
  else
    info "$INSTALL_DIR is not on PATH"
    info "for this shell: export PATH=\"$INSTALL_DIR:\$PATH\""
    info "or rerun with --add-to-path"
  fi
fi
