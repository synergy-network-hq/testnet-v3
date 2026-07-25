#!/usr/bin/env python3
"""Repair electron-builder updater metadata after platform artifact naming.

electron-builder can emit updater YAML that uses the product-name slug while
the actual artifact names use the configured artifactName pattern. Release
metadata must point at files that are actually uploaded, otherwise updater
clients and package checks resolve a non-existent asset.
"""

from __future__ import annotations

import base64
import hashlib
import re
import sys
from pathlib import Path


URL_RE = re.compile(r"^(\s*-\s+url:\s+|\s*url:\s+)(.+?)(\s*)$")
PATH_RE = re.compile(r"^(\s*path:\s+)(.+?)(\s*)$")
SHA512_RE = re.compile(r"^(\s*sha512:\s+)(.*)$")
SIZE_RE = re.compile(r"^(\s*size:\s+)(.*)$")


def normalize_artifact_filenames(dist_dir: Path) -> list[str]:
    """Rename release artifacts to the names GitHub will expose.

    `gh release upload` publishes assets with spaces normalized to dots. If the
    updater YAML keeps the original space-containing electron-builder names,
    clients resolve non-existent release assets. Normalize before repairing the
    YAML so validation checks the same filenames that operators download.
    """
    release_suffixes = (
        ".AppImage",
        ".AppImage.blockmap",
        ".exe",
        ".exe.blockmap",
        ".dmg",
        ".dmg.blockmap",
        ".zip",
        ".zip.blockmap",
    )
    renamed: list[str] = []
    for path in sorted(dist_dir.iterdir()):
        if not path.is_file() or " " not in path.name:
            continue
        if not path.name.endswith(release_suffixes):
            continue
        normalized = path.name.replace(" ", ".")
        target = path.with_name(normalized)
        if target.exists() and target != path:
            raise FileExistsError(
                f"cannot normalize {path.name}: {target.name} already exists"
            )
        path.rename(target)
        renamed.append(f"{path.name} -> {target.name}")
    return renamed


def actual_by_suffix(dist_dir: Path) -> dict[str, str]:
    suffixes = (".AppImage", ".deb", ".dmg", ".zip", ".exe")
    matches: dict[str, str] = {}
    for suffix in suffixes:
        files = sorted(path.name for path in dist_dir.glob(f"*{suffix}"))
        if len(files) == 1:
            matches[suffix] = files[0]
    return matches


def repair_value(value: str, files_by_suffix: dict[str, str]) -> str:
    stripped = value.strip().strip('"').strip("'")
    for suffix, actual_name in files_by_suffix.items():
        if stripped.endswith(suffix) and stripped != actual_name:
            return value.replace(stripped, actual_name)
    return value


def artifact_metadata(dist_dir: Path, files_by_suffix: dict[str, str]) -> dict[str, tuple[str, int]]:
    metadata: dict[str, tuple[str, int]] = {}
    for filename in files_by_suffix.values():
        artifact = dist_dir / filename
        digest = base64.b64encode(hashlib.sha512(artifact.read_bytes()).digest()).decode("ascii")
        metadata[filename] = (digest, artifact.stat().st_size)
    return metadata


def repair_file(
    path: Path,
    files_by_suffix: dict[str, str],
    metadata_by_name: dict[str, tuple[str, int]],
) -> bool:
    original = path.read_text()
    repaired_lines: list[str] = []
    changed = False
    current_metadata: tuple[str, int] | None = None

    for line in original.splitlines():
        match = URL_RE.match(line) or PATH_RE.match(line)
        if match:
            next_value = repair_value(match.group(2), files_by_suffix)
            if next_value != match.group(2):
                changed = True
            repaired_line = f"{match.group(1)}{next_value}{match.group(3)}"
            filename = next_value.strip().strip('"').strip("'")
            current_metadata = metadata_by_name.get(filename)
            repaired_lines.append(repaired_line)
        elif current_metadata and (match := SHA512_RE.match(line)):
            repaired_line = f"{match.group(1)}{current_metadata[0]}"
            changed = changed or repaired_line != line
            repaired_lines.append(repaired_line)
        elif current_metadata and (match := SIZE_RE.match(line)):
            repaired_line = f"{match.group(1)}{current_metadata[1]}"
            changed = changed or repaired_line != line
            repaired_lines.append(repaired_line)
        else:
            repaired_lines.append(line)

    repaired = "\n".join(repaired_lines) + ("\n" if original.endswith("\n") else "")
    if changed:
        path.write_text(repaired)
    return changed


def validate_file(path: Path, files_by_suffix: dict[str, str]) -> list[str]:
    errors: list[str] = []
    for line in path.read_text().splitlines():
        match = URL_RE.match(line) or PATH_RE.match(line)
        if not match:
            continue
        value = match.group(2).strip().strip('"').strip("'")
        for suffix in files_by_suffix:
            if value.endswith(suffix) and not (path.parent / value).exists():
                errors.append(f"{path.name} references missing artifact: {value}")
    return errors


def main() -> int:
    dist_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("electron-dist")
    if not dist_dir.is_dir():
        print(f"{dist_dir} does not exist", file=sys.stderr)
        return 1

    renamed = normalize_artifact_filenames(dist_dir)
    files_by_suffix = actual_by_suffix(dist_dir)
    if not files_by_suffix:
        print(f"no release artifacts found in {dist_dir}", file=sys.stderr)
        return 1
    metadata_by_name = artifact_metadata(dist_dir, files_by_suffix)

    metadata_files = sorted(dist_dir.glob("latest*.yml")) + sorted(dist_dir.glob("latest*.yaml"))
    if not metadata_files:
        return 0

    changed = [
        path.name
        for path in metadata_files
        if repair_file(path, files_by_suffix, metadata_by_name)
    ]
    errors: list[str] = []
    for path in metadata_files:
        errors.extend(validate_file(path, files_by_suffix))

    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1

    if renamed:
        print("Normalized release artifact names:", ", ".join(renamed))
    if changed:
        print("Repaired updater metadata:", ", ".join(changed))
    else:
        print("Updater metadata already matches published artifact names.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
