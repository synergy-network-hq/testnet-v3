#!/usr/bin/env bash
set -u

ROOTS=(
  "/Users/devpup/Desktop/Testnet-Beta"
  "/Volumes/xcode/Synergy-Network-Projects"
)

LOG_DIR="${HOME}/Library/Logs/SynergyGitCheckpoint"
LOCK_DIR="${TMPDIR:-/tmp}/synergy-weekly-github-checkpoint.lock"
DATE_STAMP="$(date +%F)"

mkdir -p "$LOG_DIR"

if ! mkdir "$LOCK_DIR" 2>/dev/null; then
  echo "Another Synergy GitHub checkpoint is already running."
  exit 0
fi
trap 'rmdir "$LOCK_DIR" 2>/dev/null || true' EXIT

is_generated_path() {
  case "$1" in
    node_modules/*|*/node_modules/*|sdk/node_modules/*|*/sdk/node_modules/*) return 0 ;;
    dist/*|*/dist/*|build/*|*/build/*|.next/*|*/.next/*) return 0 ;;
    target/*|*/target/*|coverage/*|*/coverage/*) return 0 ;;
    .playwright-cli/*|*/.playwright-cli/*|.playwright-mcp/*|*/.playwright-mcp/*) return 0 ;;
    bootstrap-bundles/*|*/bootstrap-bundles/*|release-artifacts/v*/*|*/release-artifacts/v*/*) return 0 ;;
    *.zip|*.tar|*.tar.gz|*.tgz|*.aab|*.apk|*.ipa|*.app|*.dSYM|*.log|*.log.*|*.tmp) return 0 ;;
    .DS_Store|*/.DS_Store) return 0 ;;
  esac
  return 1
}

has_secret_like_content() {
  local path="$1"
  LC_ALL=C rg -I -n --no-heading \
    -e 'gho_[A-Za-z0-9_]{20,}' \
    -e 'github_pat_[A-Za-z0-9_]{20,}' \
    -e '-----BEGIN [A-Z ]*PRIVATE KEY-----' \
    -e 'AKIA[0-9A-Z]{16}' \
    -e 'xox[baprs]-[A-Za-z0-9-]{20,}' \
    -e 'sk_live_[A-Za-z0-9]{20,}' \
    -e '(password|passphrase|private[_-]?key)[[:space:]]*[:=][[:space:]]*[^[:space:]#]+' \
    -- "$path" >/dev/null 2>&1
}

ensure_ignore_block() {
  local repo="$1"
  local ignore_file="$repo/.gitignore"
  [ -f "$ignore_file" ] || : >"$ignore_file"
  if ! grep -q 'Synergy generated checkpoint ignores' "$ignore_file"; then
    cat >>"$ignore_file" <<'EOF'

# Synergy generated checkpoint ignores
node_modules/
**/node_modules/
dist/
**/dist/
build/
**/build/
.next/
**/.next/
target/
**/target/
coverage/
**/coverage/
.playwright-cli/
.playwright-mcp/
bootstrap-bundles/
release-artifacts/v*/
*.zip
*.tar
*.tar.gz
*.tgz
*.aab
*.apk
*.ipa
*.app
*.dSYM
*.log
*.log.*
*.tmp
.DS_Store
EOF
  fi
}

process_repo() {
  local repo="$1"
  local origin branch changed staged_count

  origin="$(git -C "$repo" remote get-url origin 2>/dev/null || true)"
  case "$origin" in
    *github.com*) ;;
    *) echo "skip no-github-origin $repo"; return 0 ;;
  esac

  branch="$(git -C "$repo" branch --show-current 2>/dev/null || true)"
  if [ -z "$branch" ]; then
    echo "skip detached-head $repo"
    return 0
  fi

  changed="$(git -C "$repo" status --porcelain=v1 2>/dev/null || true)"
  if [ -z "$changed" ]; then
    echo "clean $repo"
    return 0
  fi

  echo "checkpoint $repo on $branch"
  ensure_ignore_block "$repo"

  git -C "$repo" ls-files -d -z | while IFS= read -r -d '' path; do
    if is_generated_path "$path"; then
      git -C "$repo" restore -- "$path" 2>/dev/null || true
    fi
  done

  git -C "$repo" add -A -- .

  git -C "$repo" diff --cached --name-only -z | while IFS= read -r -d '' path; do
    if is_generated_path "$path"; then
      git -C "$repo" reset -q HEAD -- "$path" 2>/dev/null || true
    fi
  done

  while IFS= read -r -d '' path; do
    [ -f "$repo/$path" ] || continue
    if has_secret_like_content "$repo/$path"; then
      echo "skip repo secret-like-content $repo $path"
      git -C "$repo" reset -q HEAD -- .
      return 1
    fi
  done < <(git -C "$repo" diff --cached --name-only -z)

  staged_count="$(git -C "$repo" diff --cached --name-only | wc -l | tr -d ' ')"
  if [ "$staged_count" = "0" ]; then
    echo "skip no-stageable-source-changes $repo"
    return 0
  fi

  git -C "$repo" commit -m "weekly checkpoint ${DATE_STAMP}"
  git -C "$repo" push -u origin "$branch"
}

main() {
  local root repo
  echo "Synergy GitHub checkpoint started at $(date -Is)"
  for root in "${ROOTS[@]}"; do
    [ -d "$root" ] || continue
    while IFS= read -r repo; do
      case "$repo" in
        */.tmp/*|*/node_modules/*|*/target/*|*/.relaunch-worktrees/*) continue ;;
      esac
      process_repo "$repo" || true
    done < <(find "$root" -path '*/.git' -type d -prune -print | sed 's#/.git$##' | sort -u)
  done
  echo "Synergy GitHub checkpoint finished at $(date -Is)"
}

main "$@"
