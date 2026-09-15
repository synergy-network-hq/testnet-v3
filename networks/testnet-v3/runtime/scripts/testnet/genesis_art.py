#!/usr/bin/env python3
"""Deterministic Synergy Testnet genesis artwork generator.

This script produces release-artifact SVG/PNG artwork only. It does not touch
consensus, genesis, validator, or runtime configuration.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from blake3 import blake3


GENERATOR_VERSION = "synergy-genesis-art-v2.0.0"
EXPECTED_GENESIS_HASH = "85b26d520e1621adaa212012dae540dcb223e0a9648666b919d64cb8c4394c75"
EXPECTED_NETWORK_MAGIC = "e312fa40"
EXPECTED_CHAIN_ID = 1264

GENESIS_SHORT = "85b26d52...c4394c75"
FONT_STACK = "Sora, Rajdhani, Segoe UI, Arial, sans-serif"

BRAND = {
    "lime_posy": "#00ff66",
    "cyan_sxcp": "#00ced1",
    "blue_synq": "#0060ff",
    "purple_aegis": "#7d00ff",
    "electric_mint": "#00ffd4",
    "neon_magenta": "#ff00e5",
    "gold": "#ffd700",
    "background_base": "#030206",
    "background_primary": "#05070d",
    "background_secondary": "#0a0e18",
    "background_tertiary": "#111622",
    "text_bright": "#ffffff",
    "text_primary": "#f2f7ff",
    "text_secondary": "#c5d9e8",
    "text_muted": "#5e7280",
}

ARTIFACTS = {
    "minimal_svg": "synergy-testnet-genesis-sigil-minimal.svg",
    "minimal_png": "synergy-testnet-genesis-sigil-minimal.png",
    "sigil_svg": "synergy-testnet-genesis-sigil.svg",
    "sigil_png": "synergy-testnet-genesis-sigil.png",
    "poster_svg": "synergy-testnet-genesis-poster.svg",
    "poster_png": "synergy-testnet-genesis-poster.png",
    "engraving_svg": "synergy-testnet-genesis-sigil-engraving.svg",
    "engraving_png": "synergy-testnet-genesis-sigil-engraving.png",
    "animated_svg": "synergy-testnet-genesis-sigil-animated.svg",
    "certificate_svg": "synergy-testnet-genesis-certificate.svg",
    "certificate_png": "synergy-testnet-genesis-certificate.png",
    "styleguide": "synergy-art-styleguide.json",
    "manifest": "synergy-testnet-artwork-manifest.json",
}


@dataclass(frozen=True)
class CanonicalInputs:
    genesis_hash: str
    network_magic_bytes: str
    chain_id: int
    validator_set_hash: str
    state_root: str
    genesis_timestamp: int | str
    validators: list[dict[str, Any]]
    topology_metadata: dict[str, Any]


@dataclass(frozen=True)
class ValidatorArt:
    index: int
    validator_id: str
    moniker: str
    validator_address: str
    validator_address_short: str
    consensus_public_key: str
    validator_id_hash: str
    validator_art_fingerprint: str
    consensus_key_fingerprint: str
    x: float
    y: float
    angle: float
    color: str


def fail(message: str) -> None:
    raise SystemExit(f"error: {message}")


def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def write_text(path: Path, text_value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        handle.write(text_value)


def write_json(path: Path, payload: Any) -> None:
    write_text(path, json.dumps(payload, indent=2, sort_keys=True) + "\n")


def esc(value: Any) -> str:
    text = str(value)
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def fmt(value: float) -> str:
    rounded = f"{value:.3f}"
    return rounded.rstrip("0").rstrip(".")


def h(parts: list[str | int]) -> str:
    digest = blake3()
    for part in parts:
        digest.update(str(part).encode("utf-8"))
    return digest.hexdigest()


def metadata_payload(canonical: CanonicalInputs, art_seed: str, dag_seed: str, kind: str) -> str:
    payload = {
        "art_seed": art_seed,
        "chain_id": canonical.chain_id,
        "dag_topology_seed": dag_seed,
        "generator_version": GENERATOR_VERSION,
        "genesis_hash": canonical.genesis_hash,
        "kind": kind,
        "network_magic_bytes": canonical.network_magic_bytes,
        "state_root": canonical.state_root,
        "validator_set_hash": canonical.validator_set_hash,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def find_first(data: dict[str, Any], paths: list[tuple[str, ...]]) -> Any:
    for path in paths:
        current: Any = data
        for key in path:
            if not isinstance(current, dict) or key not in current:
                current = None
                break
            current = current[key]
        if current not in (None, ""):
            return current
    return None


def extract_canonical(genesis: dict[str, Any], identifiers: dict[str, Any]) -> CanonicalInputs:
    genesis_hash = find_first(genesis, [("integrity", "genesis_hash"), ("header", "genesis_hash"), ("genesis_hash",)])
    chain_id = find_first(genesis, [("network_identity", "synergy_native_chain_id"), ("chain_id",)])
    magic = find_first(genesis, [("p2p_identity", "network_magic_bytes"), ("network_magic_bytes",)])
    if not magic:
        magic = find_first(identifiers, [("network_magic_bytes",), ("p2p_identity", "network_magic_bytes")])
    validator_set_hash = find_first(
        genesis,
        [
            ("integrity", "validator_set_hash"),
            ("consensus", "validator_set_hash"),
            ("validator_set_hash",),
        ],
    )
    state_root = find_first(genesis, [("header", "state_root"), ("integrity", "state_root"), ("state_root",)])
    timestamp = find_first(genesis, [("header", "timestamp"), ("genesis_timestamp",), ("timestamp",)])
    validators = genesis.get("validators") or genesis.get("validator_set") or []
    if not isinstance(validators, list) or not validators:
        fail("genesis file does not contain validators")
    if genesis_hash != EXPECTED_GENESIS_HASH:
        fail(f"unexpected genesis hash {genesis_hash}")
    if magic != EXPECTED_NETWORK_MAGIC:
        fail(f"unexpected network magic bytes {magic}")
    if int(chain_id) != EXPECTED_CHAIN_ID:
        fail(f"unexpected chain id {chain_id}")
    if not validator_set_hash or not state_root or timestamp in (None, ""):
        fail("genesis file is missing validator_set_hash, state_root, or timestamp")
    topology = {
        "consensus_model": find_first(genesis, [("consensus", "model")]),
        "algorithm": find_first(genesis, [("consensus", "algorithm")]),
        "dag_data_plane": find_first(genesis, [("consensus", "dag_data_plane")]) or {},
        "finality": find_first(genesis, [("consensus", "finality")]) or {},
        "proposal_mechanism": find_first(genesis, [("consensus", "proposal_mechanism")]),
        "leader_selection": find_first(genesis, [("consensus", "leader_selection")]),
    }
    return CanonicalInputs(
        genesis_hash=str(genesis_hash),
        network_magic_bytes=str(magic),
        chain_id=int(chain_id),
        validator_set_hash=str(validator_set_hash),
        state_root=str(state_root),
        genesis_timestamp=timestamp,
        validators=validators,
        topology_metadata=topology,
    )


def derive_art_seed(canonical: CanonicalInputs) -> str:
    return h(
        [
            "synergy-genesis-art-v2",
            canonical.chain_id,
            canonical.genesis_hash,
            canonical.network_magic_bytes,
            canonical.validator_set_hash,
            canonical.state_root,
            canonical.genesis_timestamp,
        ]
    )


def derive_dag_seed(canonical: CanonicalInputs) -> str:
    return h(
        [
            "synergy-dag-topology-art-v2",
            canonical.genesis_hash,
            canonical.validator_set_hash,
            canonical.network_magic_bytes,
        ]
    )


def palette(art_seed: str) -> dict[str, Any]:
    order = ["lime_posy", "cyan_sxcp", "blue_synq", "purple_aegis"]
    shift = bytes.fromhex(art_seed)[0] % len(order)
    energy_order = order[shift:] + order[:shift]
    return {
        "brand": BRAND,
        "energy_order": energy_order,
        "semantic": {
            "background": BRAND["background_base"],
            "surface": BRAND["background_primary"],
            "surface_raised": BRAND["background_secondary"],
            "core": BRAND["electric_mint"],
            "validator_primary": BRAND["cyan_sxcp"],
            "validator_secondary": BRAND["lime_posy"],
            "dag_subtle": BRAND["purple_aegis"],
            "quorum": BRAND["blue_synq"],
            "archival_accent": BRAND["gold"],
            "provenance": BRAND["text_muted"],
        },
    }


def polar(cx: float, cy: float, r: float, angle_deg: float) -> tuple[float, float]:
    angle = math.radians(angle_deg)
    return cx + r * math.cos(angle), cy + r * math.sin(angle)


def regular_points(cx: float, cy: float, r: float, count: int, rotation: float) -> list[tuple[float, float]]:
    return [polar(cx, cy, r, rotation + i * (360 / count)) for i in range(count)]


def point_string(points: list[tuple[float, float]]) -> str:
    return " ".join(f"{fmt(x)},{fmt(y)}" for x, y in points)


def path_from_points(points: list[tuple[float, float]], close: bool = True) -> str:
    if not points:
        return ""
    head = f"M {fmt(points[0][0])} {fmt(points[0][1])}"
    tail = " ".join(f"L {fmt(x)} {fmt(y)}" for x, y in points[1:])
    return f"{head} {tail}{' Z' if close else ''}"


def short_hash(value: str) -> str:
    return f"{value[:8]}...{value[-6:]}"


def short_address(value: str) -> str:
    return f"{value[:10]}...{value[-7:]}"


def derive_validators(canonical: CanonicalInputs, art_seed: str) -> list[ValidatorArt]:
    count = len(canonical.validators)
    seed = bytes.fromhex(art_seed)
    rotation = -90 + ((canonical.chain_id % count) * (360 / count)) + (seed[3] % 9) - 4
    radius = 1180 + (seed[4] % 46)
    colors = [BRAND["lime_posy"], BRAND["cyan_sxcp"], BRAND["blue_synq"], BRAND["purple_aegis"], BRAND["electric_mint"]]
    validators: list[ValidatorArt] = []
    for index, validator in enumerate(canonical.validators, start=1):
        address = str(validator.get("validator_address") or validator.get("address") or "")
        consensus_key = str(validator.get("consensus_public_key") or "")
        validator_id_hash = str(validator.get("validator_id_hash") or "")
        fingerprint = h(["synergy-validator-art-v2", address, consensus_key, validator_id_hash])[:8]
        key_fingerprint = h(["synergy-validator-consensus-key-v2", consensus_key])[:10]
        angle = rotation + (index - 1) * (360 / count)
        x, y = polar(2048, 2048, radius, angle)
        validators.append(
            ValidatorArt(
                index=index,
                validator_id=str(validator.get("validator_id") or f"validator-{index}"),
                moniker=str(validator.get("moniker") or f"Synergy Genesis Validator {index}"),
                validator_address=address,
                validator_address_short=short_address(address),
                consensus_public_key=consensus_key,
                validator_id_hash=validator_id_hash,
                validator_art_fingerprint=fingerprint,
                consensus_key_fingerprint=key_fingerprint,
                x=x,
                y=y,
                angle=angle,
                color=colors[(index - 1) % len(colors)],
            )
        )
    return validators


def derive_geometry(art_seed: str) -> dict[str, Any]:
    seed = bytes.fromhex(art_seed)
    return {
        "ring_radii": [430, 690, 940, 1390],
        "minimal_ring_radii": [470, 760, 1040, 1320],
        "ring_rotation": seed[6] % 360,
        "tick_count": 36 + (seed[7] % 13),
        "core_rotation": seed[8] % 360,
        "facet_count": 5 + (seed[9] % 3),
        "internal_dag_line_count": 2 + (seed[10] % 2),
        "validator_radius": 94 + (seed[11] % 9),
        "ring_opacity": 0.38,
        "dag_opacity": 0.24,
        "quorum_opacity": 1.0,
        "glow_strength": 0.42,
    }


def derive_edges(validators: list[ValidatorArt], dag_seed: str) -> list[dict[str, Any]]:
    edges: list[dict[str, Any]] = []
    count = len(validators)
    for index in range(count):
        edges.append(
            {
                "from": validators[index].validator_id,
                "to": validators[(index + 1) % count].validator_id,
                "from_index": index,
                "to_index": (index + 1) % count,
                "role": "quorum_perimeter",
                "weight": "ceremonial",
            }
        )
    candidates: list[tuple[str, int, int]] = []
    for i in range(count):
        for j in range(i + 1, count):
            if (j - i) in (1, count - 1):
                continue
            score = h(["synergy-dag-edge-art-v2", dag_seed, validators[i].validator_address, validators[j].validator_address])
            candidates.append((score, i, j))
    for score, i, j in sorted(candidates)[:3]:
        edges.append(
            {
                "from": validators[i].validator_id,
                "to": validators[j].validator_id,
                "from_index": i,
                "to_index": j,
                "role": "dag_chord",
                "weight": score[:8],
            }
        )
    return edges


def svg_header(width: int, height: int, view_w: int, view_h: int, metadata: str, kind: str) -> list[str]:
    return [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {view_w} {view_h}" role="img" aria-label="Synergy Testnet genesis {kind}">',
        f"<metadata>{esc(metadata)}</metadata>",
        "<defs>",
        "<style><![CDATA[text{font-family:Sora,Rajdhani,Segoe UI,Arial,sans-serif} .mono{font-family:SFMono-Regular,Consolas,Menlo,monospace}]]></style>",
        '<radialGradient id="bg-radial" cx="50%" cy="45%" r="72%"><stop offset="0%" stop-color="#111622"/><stop offset="50%" stop-color="#05070d"/><stop offset="100%" stop-color="#030206"/></radialGradient>',
        '<linearGradient id="energy-gradient" x1="8%" y1="12%" x2="92%" y2="88%"><stop offset="0%" stop-color="#00ff66"/><stop offset="32%" stop-color="#00ced1"/><stop offset="66%" stop-color="#0060ff"/><stop offset="100%" stop-color="#7d00ff"/></linearGradient>',
        '<linearGradient id="core-gradient" x1="25%" y1="10%" x2="80%" y2="90%"><stop offset="0%" stop-color="#ffffff"/><stop offset="38%" stop-color="#00ffd4"/><stop offset="72%" stop-color="#00ced1"/><stop offset="100%" stop-color="#7d00ff"/></linearGradient>',
        '<linearGradient id="gold-magenta" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" stop-color="#ffd700"/><stop offset="100%" stop-color="#ff00e5"/></linearGradient>',
        '<filter id="core-glow" x="-35%" y="-35%" width="170%" height="170%"><feGaussianBlur stdDeviation="16" result="blur"/><feColorMatrix in="blur" type="matrix" values="0 0 0 0 0 0 0 0 0 1 0 0 0 0 0.83 0 0 0 .42 0"/><feMerge><feMergeNode/><feMergeNode in="SourceGraphic"/></feMerge></filter>',
        '<filter id="line-glow" x="-20%" y="-20%" width="140%" height="140%"><feGaussianBlur stdDeviation="5" result="blur"/><feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge></filter>',
        "</defs>",
        '<rect width="100%" height="100%" fill="url(#bg-radial)"/>',
    ]


def engraving_header(width: int, height: int, view_w: int, view_h: int, metadata: str) -> list[str]:
    return [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {view_w} {view_h}" role="img" aria-label="Synergy Testnet genesis engraving sigil">',
        f"<metadata>{esc(metadata)}</metadata>",
        f'<rect width="100%" height="100%" fill="{BRAND["background_base"]}"/>',
    ]


def draw_grid(width: int, height: int, step: int = 160) -> list[str]:
    lines = [f'<g opacity="0.18" stroke="{BRAND["background_tertiary"]}" stroke-width="1">']
    for x in range(step, width, step):
        lines.append(f'<line x1="{x}" y1="0" x2="{x}" y2="{height}"/>')
    for y in range(step, height, step):
        lines.append(f'<line x1="0" y1="{y}" x2="{width}" y2="{y}"/>')
    lines.append("</g>")
    return lines


def text(x: float, y: float, content: str, size: int, fill: str, anchor: str = "middle", weight: int = 500, cls: str = "", opacity: float = 1.0, spacing: str = "0") -> str:
    cls_attr = f' class="{cls}"' if cls else ""
    return (
        f'<text{cls_attr} x="{fmt(x)}" y="{fmt(y)}" text-anchor="{anchor}" font-size="{size}" '
        f'font-weight="{weight}" letter-spacing="{spacing}" fill="{fill}" opacity="{fmt(opacity)}">{esc(content)}</text>'
    )


def draw_motif(
    validators: list[ValidatorArt],
    edges: list[dict[str, Any]],
    geometry: dict[str, Any],
    *,
    cx: float = 2048,
    cy: float = 2048,
    scale: float = 1.0,
    labels: bool = False,
    minimal: bool = False,
    animated: bool = False,
) -> list[str]:
    def tx(x: float) -> float:
        return cx + (x - 2048) * scale

    def ty(y: float) -> float:
        return cy + (y - 2048) * scale

    def tr(r: float) -> float:
        return r * scale

    out: list[str] = []
    ring_radii = geometry["minimal_ring_radii"] if minimal else geometry["ring_radii"]
    pulse = ' class="pulse-ring"' if animated else ""
    out.append('<g id="synergy-genesis-motif">')
    out.append(f'<g opacity="{fmt(geometry["ring_opacity"])}" fill="none">')
    ring_colors = [BRAND["lime_posy"], BRAND["cyan_sxcp"], BRAND["blue_synq"], BRAND["purple_aegis"]]
    for index, radius in enumerate(ring_radii):
        dash = "18 30" if index % 2 else "2 24"
        out.append(
            f'<circle{pulse} cx="{fmt(cx)}" cy="{fmt(cy)}" r="{fmt(tr(radius))}" stroke="{ring_colors[index % 4]}" '
            f'stroke-width="{fmt(max(2, 7 * scale))}" stroke-dasharray="{dash}" transform="rotate({fmt(geometry["ring_rotation"] + index * 17)} {fmt(cx)} {fmt(cy)})"/>'
        )
    out.append("</g>")

    ticks = geometry["tick_count"] if not minimal else max(20, geometry["tick_count"] // 2)
    out.append(f'<g opacity="0.38" stroke="{BRAND["gold"]}" stroke-width="{fmt(max(2, 5 * scale))}" stroke-linecap="round">')
    for i in range(ticks):
        if i % 3 == 1:
            continue
        angle = geometry["ring_rotation"] + i * (360 / ticks)
        x1, y1 = polar(cx, cy, tr(1500), angle)
        x2, y2 = polar(cx, cy, tr(1530 if i % 5 else 1580), angle)
        out.append(f'<line x1="{fmt(x1)}" y1="{fmt(y1)}" x2="{fmt(x2)}" y2="{fmt(y2)}"/>')
    out.append("</g>")

    validator_points = [(tx(v.x), ty(v.y)) for v in validators]
    perimeter_path = path_from_points(validator_points, True)
    dash_anim = ' class="energy-path"' if animated else ""
    out.append(f'<path d="{perimeter_path}" fill="{BRAND["background_primary"]}" opacity="0.16" stroke="{BRAND["cyan_sxcp"]}" stroke-width="{fmt(2 * scale)}"/>')
    out.append(f'<g stroke-linecap="round" stroke-linejoin="round" fill="none" opacity="{fmt(geometry["quorum_opacity"])}">')
    for index, point in enumerate(validator_points):
        next_point = validator_points[(index + 1) % len(validator_points)]
        color = ring_colors[index % len(ring_colors)]
        segment = f'M {fmt(point[0])} {fmt(point[1])} L {fmt(next_point[0])} {fmt(next_point[1])}'
        out.append(f'<path d="{segment}" stroke="{color}" stroke-width="{fmt(54 * scale)}" fill="none"/>')
        out.append(f'<path d="{segment}" stroke="{BRAND["electric_mint"]}" stroke-width="{fmt(10 * scale)}" fill="none" opacity="0.5"/>')
    out.append("</g>")
    if animated:
        out.append(f'<path{dash_anim} d="{perimeter_path}" fill="none" stroke="{BRAND["electric_mint"]}" stroke-width="{fmt(10 * scale)}" stroke-linejoin="round" opacity="0.82"/>')

    out.append(f'<g stroke-linecap="round" fill="none" opacity="{fmt(geometry["dag_opacity"])}">')
    for edge in edges:
        if edge["role"] != "dag_chord":
            continue
        a = validators[edge["from_index"]]
        b = validators[edge["to_index"]]
        mx, my = (tx(a.x) + tx(b.x)) / 2, (ty(a.y) + ty(b.y)) / 2
        cx_curve = cx + (mx - cx) * 0.62
        cy_curve = cy + (my - cy) * 0.62
        out.append(
            f'<path d="M {fmt(tx(a.x))} {fmt(ty(a.y))} Q {fmt(cx_curve)} {fmt(cy_curve)} {fmt(tx(b.x))} {fmt(ty(b.y))}" '
            f'stroke="{BRAND["cyan_sxcp"]}" stroke-width="{fmt(8 * scale)}"/>'
        )
    out.append("</g>")

    facets = geometry["facet_count"]
    out.append(f'<g opacity="0.22" stroke="{BRAND["purple_aegis"]}" stroke-width="{fmt(3 * scale)}" fill="none">')
    for i in range(facets):
        angle = geometry["core_rotation"] + i * (360 / facets)
        a = polar(cx, cy, tr(255), angle)
        b = polar(cx, cy, tr(520), angle + 42)
        out.append(f'<line x1="{fmt(a[0])}" y1="{fmt(a[1])}" x2="{fmt(b[0])}" y2="{fmt(b[1])}"/>')
    out.append("</g>")

    core_rotation = geometry["core_rotation"]
    penta = point_string(regular_points(cx, cy, tr(310), 5, core_rotation - 90))
    hexagon = point_string(regular_points(cx, cy, tr(222), 6, core_rotation + 30))
    triangle_a = point_string(regular_points(cx, cy, tr(180), 3, core_rotation + 90))
    triangle_b = point_string(regular_points(cx, cy, tr(180), 3, core_rotation - 90))
    diamond = point_string(regular_points(cx, cy, tr(118), 4, core_rotation + 45))
    aura = ' class="core-aura"' if animated else ""
    out.append(f'<g id="genesis-core" filter="url(#core-glow)">')
    out.append(f'<polygon{aura} points="{penta}" fill="{BRAND["background_secondary"]}" stroke="url(#energy-gradient)" stroke-width="{fmt(13 * scale)}" opacity="0.94"/>')
    out.append(f'<polygon points="{hexagon}" fill="none" stroke="{BRAND["electric_mint"]}" stroke-width="{fmt(8 * scale)}" opacity="0.82"/>')
    out.append(f'<polygon points="{triangle_a}" fill="{BRAND["electric_mint"]}" opacity="0.18" stroke="{BRAND["text_bright"]}" stroke-width="{fmt(3 * scale)}"/>')
    out.append(f'<polygon points="{triangle_b}" fill="{BRAND["purple_aegis"]}" opacity="0.2" stroke="{BRAND["cyan_sxcp"]}" stroke-width="{fmt(3 * scale)}"/>')
    out.append(f'<polygon points="{diamond}" fill="url(#core-gradient)" stroke="{BRAND["text_bright"]}" stroke-width="{fmt(4 * scale)}"/>')
    out.append(f'<circle cx="{fmt(cx)}" cy="{fmt(cy)}" r="{fmt(28 * scale)}" fill="{BRAND["text_bright"]}"/>')
    out.append("</g>")

    node_radius = geometry["validator_radius"] * scale
    out.append("<g id=\"genesis-validators\">")
    for validator in validators:
        x, y = tx(validator.x), ty(validator.y)
        out.append(f'<g id="validator-{validator.index}-node">')
        out.append(f'<circle cx="{fmt(x)}" cy="{fmt(y)}" r="{fmt(node_radius + 24 * scale)}" fill="{BRAND["background_base"]}" stroke="{validator.color}" stroke-width="{fmt(8 * scale)}" opacity="0.98"/>')
        out.append(f'<circle cx="{fmt(x)}" cy="{fmt(y)}" r="{fmt(node_radius)}" fill="{BRAND["background_tertiary"]}" stroke="url(#energy-gradient)" stroke-width="{fmt(5 * scale)}"/>')
        out.append(f'<polygon points="{point_string(regular_points(x, y, node_radius * 0.56, 5, validator.angle + 18))}" fill="{validator.color}" opacity="0.34"/>')
        out.append(f'<circle cx="{fmt(x)}" cy="{fmt(y)}" r="{fmt(node_radius * 0.18)}" fill="{BRAND["gold"]}"/>')
        if labels and not minimal:
            lx, ly = polar(x, y, node_radius + 132 * scale, validator.angle)
            out.append(text(lx, ly, f"V{validator.index} / {validator.validator_art_fingerprint}", int(54 * scale), BRAND["text_secondary"], weight=700, opacity=0.88, cls="mono"))
        out.append("</g>")
    out.append("</g>")
    if minimal:
        out.append(text(cx, cy + tr(1540), "1264", int(132 * scale), BRAND["text_primary"], weight=800, opacity=0.72))
    out.append("</g>")
    return out


def render_minimal(canonical: CanonicalInputs, validators: list[ValidatorArt], edges: list[dict[str, Any]], geometry: dict[str, Any], art_seed: str, dag_seed: str) -> str:
    out = svg_header(2048, 2048, 4096, 4096, metadata_payload(canonical, art_seed, dag_seed, "minimal sigil"), "minimal sigil")
    out += draw_motif(validators, edges, geometry, minimal=True)
    out.append("</svg>")
    return "\n".join(out) + "\n"


def render_sigil(canonical: CanonicalInputs, validators: list[ValidatorArt], edges: list[dict[str, Any]], geometry: dict[str, Any], art_seed: str, dag_seed: str) -> str:
    out = svg_header(4096, 4096, 4096, 4096, metadata_payload(canonical, art_seed, dag_seed, "full sigil"), "full sigil")
    out += draw_grid(4096, 4096, 192)
    out += draw_motif(validators, edges, geometry, labels=False)
    out.append(text(2048, 440, "SYNERGY TESTNET", 132, BRAND["text_bright"], weight=800))
    out.append(text(2048, 570, "CHAIN 1264   /   MAGIC e312fa40   /   POST-QUANTUM DAG CONSENSUS", 56, BRAND["text_secondary"], weight=650))
    out.append(text(2048, 3620, f"GENESIS HASH {GENESIS_SHORT}", 70, BRAND["text_primary"], weight=700, cls="mono"))
    out.append(text(2048, 3820, f"FULL GENESIS HASH {canonical.genesis_hash}", 34, BRAND["text_muted"], weight=400, cls="mono", opacity=0.7))
    out.append("</svg>")
    return "\n".join(out) + "\n"


def render_animated(canonical: CanonicalInputs, validators: list[ValidatorArt], edges: list[dict[str, Any]], geometry: dict[str, Any], art_seed: str, dag_seed: str) -> str:
    out = svg_header(2048, 2048, 4096, 4096, metadata_payload(canonical, art_seed, dag_seed, "animated sigil"), "animated sigil")
    out.insert(
        out.index("</defs>"),
        "<style><![CDATA[@keyframes pulseRing{0%,100%{opacity:.18;stroke-width:5}50%{opacity:.38;stroke-width:9}}@keyframes energyTrace{to{stroke-dashoffset:-360}}@keyframes coreBreath{0%,100%{opacity:.88}50%{opacity:1}}.pulse-ring{animation:pulseRing 7s ease-in-out infinite}.energy-path{stroke-dasharray:96 34;animation:energyTrace 12s linear infinite}.core-aura{animation:coreBreath 5s ease-in-out infinite}text{font-family:Sora,Rajdhani,Segoe UI,Arial,sans-serif}.mono{font-family:SFMono-Regular,Consolas,Menlo,monospace}]]></style>",
    )
    out += draw_motif(validators, edges, geometry, minimal=True, animated=True)
    out.append(text(2048, 3650, "SYNERGY GENESIS", 88, BRAND["text_primary"], weight=800, opacity=0.72))
    out.append("</svg>")
    return "\n".join(out) + "\n"


def render_engraving(canonical: CanonicalInputs, validators: list[ValidatorArt], edges: list[dict[str, Any]], geometry: dict[str, Any], art_seed: str, dag_seed: str) -> str:
    out = engraving_header(2048, 2048, 4096, 4096, metadata_payload(canonical, art_seed, dag_seed, "monochrome engraving"))
    ink = BRAND["text_primary"]
    accent = BRAND["electric_mint"]
    out.append(f'<g fill="none" stroke="{ink}" stroke-linecap="round" stroke-linejoin="round">')
    for radius in [520, 800, 1110, 1420]:
        out.append(f'<circle cx="2048" cy="2048" r="{radius}" stroke-width="7" opacity="0.72"/>')
    perimeter = path_from_points([(v.x, v.y) for v in validators], True)
    out.append(f'<path d="{perimeter}" stroke="{accent}" stroke-width="22"/>')
    for edge in edges:
        if edge["role"] == "dag_chord":
            a = validators[edge["from_index"]]
            b = validators[edge["to_index"]]
            out.append(f'<line x1="{fmt(a.x)}" y1="{fmt(a.y)}" x2="{fmt(b.x)}" y2="{fmt(b.y)}" stroke="{ink}" stroke-width="6" opacity="0.55"/>')
    out.append(f'<polygon points="{point_string(regular_points(2048, 2048, 320, 5, geometry["core_rotation"] - 90))}" stroke="{accent}" stroke-width="18"/>')
    out.append(f'<polygon points="{point_string(regular_points(2048, 2048, 210, 6, geometry["core_rotation"] + 30))}" stroke="{ink}" stroke-width="10"/>')
    out.append(f'<polygon points="{point_string(regular_points(2048, 2048, 120, 4, geometry["core_rotation"] + 45))}" stroke="{accent}" stroke-width="12"/>')
    for validator in validators:
        out.append(f'<circle cx="{fmt(validator.x)}" cy="{fmt(validator.y)}" r="112" stroke="{accent}" stroke-width="14"/>')
        out.append(f'<circle cx="{fmt(validator.x)}" cy="{fmt(validator.y)}" r="36" stroke="{ink}" stroke-width="10"/>')
    out.append("</g>")
    out.append(text(2048, 3635, "SYNERGY TESTNET / CHAIN 1264", 72, ink, weight=800))
    out.append("</svg>")
    return "\n".join(out) + "\n"


def render_poster(canonical: CanonicalInputs, validators: list[ValidatorArt], edges: list[dict[str, Any]], geometry: dict[str, Any], art_seed: str, dag_seed: str) -> str:
    out = svg_header(5400, 7200, 5400, 7200, metadata_payload(canonical, art_seed, dag_seed, "poster"), "poster")
    out += draw_grid(5400, 7200, 240)
    out += draw_motif(validators, edges, geometry, cx=2700, cy=3100, scale=1.18, labels=True)
    out.append(text(2700, 650, "SYNERGY TESTNET", 218, BRAND["text_bright"], weight=850))
    out.append(text(2700, 850, "DETERMINISTIC GENESIS ARTIFACT", 88, BRAND["text_secondary"], weight=700))
    out.append(text(2700, 5450, "POST-QUANTUM DAG CONSENSUS", 98, BRAND["electric_mint"], weight=800))
    out.append(text(2700, 5625, "CHAIN 1264   /   MAGIC e312fa40   /   FIVE GENESIS VALIDATORS", 70, BRAND["text_primary"], weight=650))
    out.append(text(2700, 5875, f"GENESIS HASH {GENESIS_SHORT}", 74, BRAND["text_secondary"], weight=700, cls="mono"))
    out.append(text(2700, 6800, f"FULL GENESIS HASH {canonical.genesis_hash}", 42, BRAND["text_muted"], weight=400, cls="mono", opacity=0.72))
    out.append(text(2700, 6905, f"ART SEED {art_seed}", 38, BRAND["text_muted"], weight=400, cls="mono", opacity=0.56))
    out.append("</svg>")
    return "\n".join(out) + "\n"


def render_certificate(canonical: CanonicalInputs, validators: list[ValidatorArt], edges: list[dict[str, Any]], geometry: dict[str, Any], art_seed: str, dag_seed: str) -> str:
    out = svg_header(3300, 2550, 3300, 2550, metadata_payload(canonical, art_seed, dag_seed, "certificate"), "certificate")
    out.append(f'<rect x="130" y="130" width="3040" height="2290" rx="0" fill="none" stroke="url(#energy-gradient)" stroke-width="7"/>')
    out.append(f'<rect x="180" y="180" width="2940" height="2190" rx="0" fill="none" stroke="{BRAND["gold"]}" stroke-width="2" opacity="0.72"/>')
    out += draw_motif(validators, edges, geometry, cx=1650, cy=1040, scale=0.47, minimal=True)
    out.append(text(1650, 360, "SYNERGY TESTNET", 120, BRAND["text_bright"], weight=850))
    out.append(text(1650, 530, "GENESIS CERTIFICATE", 70, BRAND["text_secondary"], weight=700))
    out.append(text(1650, 1765, "CHAIN 1264 / MAGIC e312fa40 / POST-QUANTUM DAG CONSENSUS", 46, BRAND["electric_mint"], weight=700))
    out.append(text(1650, 1905, f"GENESIS HASH {GENESIS_SHORT}", 46, BRAND["text_primary"], weight=700, cls="mono"))
    out.append(text(1650, 2165, canonical.genesis_hash, 30, BRAND["text_muted"], weight=400, cls="mono", opacity=0.68))
    out.append("</svg>")
    return "\n".join(out) + "\n"


def render_plaque(canonical: CanonicalInputs, validator: ValidatorArt, validators: list[ValidatorArt], edges: list[dict[str, Any]], geometry: dict[str, Any], art_seed: str, dag_seed: str) -> str:
    out = svg_header(3600, 2400, 3600, 2400, metadata_payload(canonical, art_seed, dag_seed, f"validator {validator.index} plaque"), "validator plaque")
    out.append(f'<rect x="92" y="92" width="3416" height="2216" fill="{BRAND["background_primary"]}" stroke="url(#energy-gradient)" stroke-width="5"/>')
    out.append(f'<rect x="140" y="140" width="3320" height="2120" fill="none" stroke="{BRAND["gold"]}" stroke-width="2" opacity="0.56"/>')
    out += draw_motif(validators, edges, geometry, cx=920, cy=1120, scale=0.38, minimal=True)
    out.append(text(2180, 470, validator.moniker.upper(), 84, BRAND["text_bright"], anchor="start", weight=850))
    out.append(text(2180, 610, "GENESIS VALIDATOR PLAQUE", 46, BRAND["text_secondary"], anchor="start", weight=700))
    fields = [
        ("VALIDATOR ADDRESS", validator.validator_address),
        ("VALIDATOR FINGERPRINT", validator.validator_art_fingerprint),
        ("CONSENSUS KEY", validator.consensus_key_fingerprint),
        ("CHAIN", "1264"),
        ("MAGIC", canonical.network_magic_bytes),
        ("GENESIS HASH", GENESIS_SHORT),
    ]
    y = 850
    for label, value in fields:
        out.append(text(2180, y, label, 34, BRAND["text_muted"], anchor="start", weight=750))
        out.append(text(2180, y + 70, value, 46, BRAND["text_primary"], anchor="start", weight=650, cls="mono"))
        y += 210
    out.append(text(2180, 2140, "POST-QUANTUM DAG CONSENSUS / SYNERGY TESTNET", 34, BRAND["electric_mint"], anchor="start", weight=700))
    out.append("</svg>")
    return "\n".join(out) + "\n"


def render_png(svg_path: Path, png_path: Path, width: int, height: int) -> None:
    magick = shutil.which("magick")
    if not magick:
        fail("ImageMagick 'magick' is required for deterministic PNG export")
    source = svg_path.read_text(encoding="utf-8")
    raster_source = re.sub(r'font-family="[^"]+"', "", source)
    raster_source = re.sub(r"font-family:[^;}]+;?", "", raster_source)
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".svg", delete=False) as handle:
        handle.write(raster_source)
        temp_svg = Path(handle.name)
    font = Path("/System/Library/Fonts/Supplemental/Arial.ttf")
    command = [
        magick,
        "-background",
        "none",
    ]
    if font.exists():
        command += ["-font", str(font)]
    command += [
        "-density",
        "96",
        str(temp_svg),
        "-resize",
        f"{width}x{height}!",
        "-strip",
        "-define",
        "png:exclude-chunk=time,date",
        f"PNG32:{png_path}",
    ]
    try:
        subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    finally:
        temp_svg.unlink(missing_ok=True)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def blake3_file(path: Path) -> str:
    digest = blake3()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_entry(path: Path, base: Path) -> dict[str, Any]:
    return {
        "path": path.relative_to(base).as_posix(),
        "bytes": path.stat().st_size,
        "sha256": sha256_file(path),
        "blake3": blake3_file(path),
    }


def styleguide(canonical: CanonicalInputs, art_seed: str, dag_seed: str, validators: list[ValidatorArt], geometry: dict[str, Any], files: list[str]) -> dict[str, Any]:
    return {
        "generator_version": GENERATOR_VERSION,
        "creation_mode": "deterministic",
        "palette": palette(art_seed),
        "typography_assumptions": {
            "svg_font_family": FONT_STACK,
            "external_fonts_required": False,
            "hierarchy": ["SYNERGY TESTNET", "CHAIN 1264 / MAGIC e312fa40", "GENESIS HASH fingerprint", "full provenance hash"],
        },
        "svg_dimensions": {
            "minimal_sigil": {"width": 2048, "height": 2048, "viewBox": "0 0 4096 4096"},
            "full_sigil": {"width": 4096, "height": 4096, "viewBox": "0 0 4096 4096"},
            "poster": {"width": 5400, "height": 7200, "print_inches": "18x24 at 300 DPI"},
            "validator_plaque": {"width": 3600, "height": 2400},
            "certificate": {"width": 3300, "height": 2550},
        },
        "layout_grid": {"base_unit": 160, "square_artboard_center": [2048, 2048], "poster_center": [2700, 3100]},
        "ring_radii": geometry["ring_radii"],
        "minimal_ring_radii": geometry["minimal_ring_radii"],
        "validator_node_sizes": {"outer_radius": geometry["validator_radius"] + 24, "inner_radius": geometry["validator_radius"], "core_dot_ratio": 0.18},
        "line_opacity_ranges": {"quorum_perimeter": [0.95, 1.0], "dag_chord": [0.2, 0.26], "rings": [0.34, 0.42], "facets": [0.18, 0.26]},
        "glow_strengths": {"core": geometry["glow_strength"], "line": 0.28, "engraving": 0},
        "deterministic_seed_values": {"art_seed": art_seed, "dag_topology_seed": dag_seed},
        "validator_fingerprints": {v.validator_id: v.validator_art_fingerprint for v in validators},
        "artifact_filenames": files,
        "canonical_identity": {
            "genesis_hash": canonical.genesis_hash,
            "network_magic_bytes": canonical.network_magic_bytes,
            "chain_id": canonical.chain_id,
            "validator_set_hash": canonical.validator_set_hash,
            "state_root": canonical.state_root,
        },
    }


def manifest(
    canonical: CanonicalInputs,
    art_seed: str,
    dag_seed: str,
    validators: list[ValidatorArt],
    edges: list[dict[str, Any]],
    files: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "generator_version": GENERATOR_VERSION,
        "creation_mode": "deterministic",
        "genesis_hash": canonical.genesis_hash,
        "network_magic_bytes": canonical.network_magic_bytes,
        "chain_id": canonical.chain_id,
        "validator_set_hash": canonical.validator_set_hash,
        "state_root": canonical.state_root,
        "genesis_timestamp": canonical.genesis_timestamp,
        "art_seed": art_seed,
        "dag_topology_seed": dag_seed,
        "seed_derivations": {
            "art_seed": 'blake3("synergy-genesis-art-v2" || chain_id || genesis_hash || network_magic_bytes || validator_set_hash || state_root || genesis_timestamp)',
            "dag_topology_seed": 'blake3("synergy-dag-topology-art-v2" || genesis_hash || validator_set_hash || network_magic_bytes)',
            "validator_art_fingerprint": 'first_8_hex(blake3("synergy-validator-art-v2" || validator_address || consensus_public_key || validator_id_hash))',
        },
        "palette": palette(art_seed),
        "validators": [
            {
                "index": v.index,
                "validator_id": v.validator_id,
                "moniker": v.moniker,
                "validator_address": v.validator_address,
                "validator_address_short": v.validator_address_short,
                "validator_art_fingerprint": v.validator_art_fingerprint,
                "consensus_key_fingerprint": v.consensus_key_fingerprint,
                "position": {"x": round(v.x, 3), "y": round(v.y, 3), "angle": round(v.angle, 3)},
            }
            for v in validators
        ],
        "dag_edges": edges,
        "topology_metadata": canonical.topology_metadata,
        "files": files,
        "manifest_self_hash_excluded": True,
    }


def assert_no_secret_tokens(paths: list[Path]) -> None:
    forbidden = [
        "private_key",
        "seed_phrase",
        "mnemonic",
        "secret_key",
        "begin private key",
        "/users/",
        "file://",
    ]
    for path in paths:
        if path.suffix.lower() == ".png":
            payload = path.read_bytes().lower()
            for token in forbidden:
                if token.encode("utf-8") in payload:
                    fail(f"forbidden token {token!r} found in {path.name}")
            continue
        lower = path.read_text(encoding="utf-8").lower()
        for token in forbidden:
            if token in lower:
                fail(f"forbidden token {token!r} found in {path.name}")


def copy_artifacts(paths: list[Path], destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    for path in paths:
        shutil.copy2(path, destination / path.name)


def generate(args: argparse.Namespace) -> dict[str, Any]:
    genesis = read_json(Path(args.genesis))
    identifiers = read_json(Path(args.network_identifiers))
    canonical = extract_canonical(genesis, identifiers)
    art_seed = derive_art_seed(canonical)
    dag_seed = derive_dag_seed(canonical)
    geometry = derive_geometry(art_seed)
    validators = derive_validators(canonical, art_seed)
    edges = derive_edges(validators, dag_seed)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    svg_payloads = {
        ARTIFACTS["minimal_svg"]: render_minimal(canonical, validators, edges, geometry, art_seed, dag_seed),
        ARTIFACTS["sigil_svg"]: render_sigil(canonical, validators, edges, geometry, art_seed, dag_seed),
        ARTIFACTS["poster_svg"]: render_poster(canonical, validators, edges, geometry, art_seed, dag_seed),
        ARTIFACTS["engraving_svg"]: render_engraving(canonical, validators, edges, geometry, art_seed, dag_seed),
        ARTIFACTS["animated_svg"]: render_animated(canonical, validators, edges, geometry, art_seed, dag_seed),
        ARTIFACTS["certificate_svg"]: render_certificate(canonical, validators, edges, geometry, art_seed, dag_seed),
    }
    for validator in validators:
        svg_payloads[f"synergy-testnet-validator-{validator.index}-plaque.svg"] = render_plaque(
            canonical, validator, validators, edges, geometry, art_seed, dag_seed
        )

    generated_paths: list[Path] = []
    for name in sorted(svg_payloads):
        path = out_dir / name
        write_text(path, svg_payloads[name])
        generated_paths.append(path)

    if not args.skip_png:
        png_specs = [
            (ARTIFACTS["minimal_svg"], ARTIFACTS["minimal_png"], args.minimal_png_size, args.minimal_png_size),
            (ARTIFACTS["sigil_svg"], ARTIFACTS["sigil_png"], args.png_size, args.png_size),
            (ARTIFACTS["poster_svg"], ARTIFACTS["poster_png"], args.poster_png_width, args.poster_png_height),
            (ARTIFACTS["engraving_svg"], ARTIFACTS["engraving_png"], args.minimal_png_size, args.minimal_png_size),
            (ARTIFACTS["certificate_svg"], ARTIFACTS["certificate_png"], args.certificate_png_width, args.certificate_png_height),
        ]
        for validator in validators:
            png_specs.append(
                (
                    f"synergy-testnet-validator-{validator.index}-plaque.svg",
                    f"synergy-testnet-validator-{validator.index}-plaque.png",
                    args.plaque_png_width,
                    args.plaque_png_height,
                )
            )
        for svg_name, png_name, width, height in png_specs:
            png_path = out_dir / png_name
            render_png(out_dir / svg_name, png_path, int(width), int(height))
            generated_paths.append(png_path)

    artifact_names = sorted(path.name for path in generated_paths)
    style_path = out_dir / ARTIFACTS["styleguide"]
    write_json(style_path, styleguide(canonical, art_seed, dag_seed, validators, geometry, artifact_names))
    generated_paths.append(style_path)

    hash_entries = [file_entry(path, out_dir) for path in sorted(generated_paths, key=lambda p: p.name)]
    manifest_path = out_dir / ARTIFACTS["manifest"]
    manifest_payload = manifest(canonical, art_seed, dag_seed, validators, edges, hash_entries)
    write_json(manifest_path, manifest_payload)
    generated_paths.append(manifest_path)

    assert_no_secret_tokens(generated_paths)
    if args.copy_to:
        copy_artifacts(generated_paths, Path(args.copy_to))
    return manifest_payload


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Render deterministic Synergy Testnet genesis artwork")
    parser.add_argument("--genesis", required=True, help="Path to genesis.testnet.json")
    parser.add_argument("--network-identifiers", required=True, help="Path to network-identifiers.testnet.json")
    parser.add_argument("--out", required=True, help="Output artwork directory")
    parser.add_argument("--copy-to", help="Optional second directory to receive generated artifacts")
    parser.add_argument("--png-size", type=int, default=4096, help="Full sigil PNG square size")
    parser.add_argument("--minimal-png-size", type=int, default=2048, help="Minimal and engraving PNG square size")
    parser.add_argument("--poster-png-width", type=int, default=5400, help="Poster PNG width")
    parser.add_argument("--poster-png-height", type=int, default=7200, help="Poster PNG height")
    parser.add_argument("--plaque-png-width", type=int, default=3600, help="Validator plaque PNG width")
    parser.add_argument("--plaque-png-height", type=int, default=2400, help="Validator plaque PNG height")
    parser.add_argument("--certificate-png-width", type=int, default=3300, help="Certificate PNG width")
    parser.add_argument("--certificate-png-height", type=int, default=2550, help="Certificate PNG height")
    parser.add_argument("--skip-png", action="store_true", help="Generate only SVG and JSON artifacts")
    return parser.parse_args()


def main() -> None:
    os.environ.setdefault("LC_ALL", "C")
    manifest_payload = generate(parse_args())
    print(json.dumps({"art_seed": manifest_payload["art_seed"], "dag_topology_seed": manifest_payload["dag_topology_seed"]}, sort_keys=True))


if __name__ == "__main__":
    main()
