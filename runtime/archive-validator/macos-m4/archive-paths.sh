#!/usr/bin/env bash

# One contract for the local runtime tree and the external publication tree.
archive_paths_load_defaults() {
  ARCHIVE_STORAGE_VOLUME="${SYNERGY_ARCHIVE_STORAGE_VOLUME:-/Volumes/Synergy_Archive}"
  ARCHIVE_APP_ROOT="${SYNERGY_ARCHIVE_APP_ROOT:-${SYNERGY_ARCHIVE_ROOT:-/Users/Shared/Synergy/archive-validator}}"
  ARCHIVE_PUBLISH_ROOT="${SYNERGY_SNAPSHOT_PUBLISH_ROOT:-${ARCHIVE_STORAGE_VOLUME}/archive-validator/snapshots}"
}

archive_paths_validate() {
  local path
  for path in "${ARCHIVE_STORAGE_VOLUME}" "${ARCHIVE_APP_ROOT}" "${ARCHIVE_PUBLISH_ROOT}"; do
    [[ "${path}" == /* && "${path}" != "/" ]] || {
      echo "archive path must be an absolute non-root path: ${path}" >&2
      return 1
    }
  done
  [[ "${ARCHIVE_APP_ROOT}" != "${ARCHIVE_PUBLISH_ROOT}" &&
    "${ARCHIVE_PUBLISH_ROOT}" != "${ARCHIVE_APP_ROOT}"/* ]] || {
    echo "archive app root and publish root must be separate trees" >&2
    return 1
  }
  case "${ARCHIVE_PUBLISH_ROOT}" in
    "${ARCHIVE_STORAGE_VOLUME}"/*) ;;
    *)
      echo "archive publish root must be below storage volume: ${ARCHIVE_PUBLISH_ROOT}" >&2
      return 1
      ;;
  esac
}

archive_paths_prefix() {
  local test_root="$1"
  local path="$2"
  if [[ -n "${test_root}" ]]; then
    printf '%s%s' "${test_root}" "${path}"
  else
    printf '%s' "${path}"
  fi
}
