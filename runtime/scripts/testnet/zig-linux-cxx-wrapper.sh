#!/usr/bin/env bash
set -euo pipefail

args=()
for arg in "$@"; do
  case "$arg" in
    --target=x86_64-unknown-linux-gnu|--target=x86_64_unknown_linux_gnu)
      continue
      ;;
    *)
      args+=("$arg")
      ;;
  esac
done

exec zig c++ -target x86_64-linux-gnu "${args[@]}"
