#!/usr/bin/env python3
"""Read-only verifier for the ratified R1/R2/R3 activation text commitment."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys


HEADINGS = (
    "### Recovery clarification R1",
    "### Live lease convergence clarification R2",
    "### Recovery amendment R3",
)


def activation_payload(amendment: str) -> bytes:
    """Return the exact UTF-8 concatenation committed by sequence 15.

    Each approved section is included from its heading up to (but excluding)
    the first `Status:` line. The section body is normalized only to one final
    LF; all other source bytes, including UTF-8 punctuation, are preserved.
    """
    chunks: list[str] = []
    cursor = 0
    for heading in HEADINGS:
        start = amendment.find(heading, cursor)
        if start < 0:
            raise ValueError(f"missing or out-of-order amendment heading: {heading}")
        status = amendment.find("\nStatus:", start)
        if status < 0:
            raise ValueError(f"missing Status line after amendment heading: {heading}")
        section = amendment[start:status].rstrip("\n") + "\n"
        chunks.append(section)
        cursor = status + len("\nStatus:")
    return "".join(chunks).encode("utf-8")


def commitment(amendment: str) -> str:
    return "posy-r1-r2-r3:sha3-256:" + hashlib.sha3_256(activation_payload(amendment)).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("amendment", type=Path, help="canonical POSY-00E amendment Markdown")
    parser.add_argument("release", type=Path, help="unsigned or signed release JSON")
    args = parser.parse_args()

    try:
        actual = commitment(args.amendment.read_text(encoding="utf-8"))
        release = json.loads(args.release.read_text(encoding="utf-8"))
        expected = release.get("protocol_activation_commitment")
        if expected is None and isinstance(release.get("release"), dict):
            expected = release["release"].get("protocol_activation_commitment")
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        print(f"verification error: {exc}", file=sys.stderr)
        return 2

    if not isinstance(expected, str):
        print("release has no protocol_activation_commitment", file=sys.stderr)
        return 2
    print(f"derived:  {actual}")
    print(f"manifest: {expected}")
    if actual != expected:
        print("MISMATCH", file=sys.stderr)
        return 1
    print("MATCH")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
