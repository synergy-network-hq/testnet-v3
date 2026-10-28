#!/usr/bin/env python3
"""Deterministic analysis for Synergy Aegis benchmark raw CSV samples."""

from __future__ import annotations

import argparse
import csv
import hashlib
import html
import json
import math
import random
import statistics
from collections import defaultdict
from pathlib import Path


GROUP_FIELDS = (
    "classification",
    "environment_id",
    "source_commit",
    "suite",
    "layer",
    "algorithm",
    "operation",
    "payload_profile",
    "message_bytes",
)


def percentile(values: list[float], probability: float) -> float:
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    rank = (len(ordered) - 1) * probability
    lower = math.floor(rank)
    upper = math.ceil(rank)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (rank - lower)


def bootstrap_median_ci(values: list[float], seed: int, resamples: int = 2_000) -> tuple[float, float]:
    generator = random.Random(seed)
    sample_count = len(values)
    medians = [
        statistics.median(generator.choices(values, k=sample_count))
        for _ in range(resamples)
    ]
    return percentile(medians, 0.025), percentile(medians, 0.975)


def mad_outlier_count(values: list[float]) -> int:
    median = statistics.median(values)
    deviations = [abs(value - median) for value in values]
    mad = statistics.median(deviations)
    if mad == 0:
        return sum(value != median for value in values)
    return sum(0.6745 * abs(value - median) / mad > 3.5 for value in values)


def optional_nonzero_max(group: list[dict[str, str]], field: str) -> int | None:
    values = [int(row.get(field) or 0) for row in group]
    nonzero = [value for value in values if value != 0]
    return max(nonzero) if nonzero else None


def optional_nonzero_signature_stats(
    group: list[dict[str, str]],
) -> tuple[int | None, float | None, int | None]:
    values = [int(row.get("signature_bytes") or 0) for row in group]
    nonzero = [value for value in values if value != 0]
    if not nonzero:
        return None, None, None
    return min(nonzero), statistics.median(nonzero), max(nonzero)


def load_rows(paths: list[Path]) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    rows: list[dict[str, str]] = []
    provenance: list[dict[str, str]] = []
    for path in paths:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        with path.open(newline="", encoding="utf-8") as handle:
            file_rows = list(csv.DictReader(handle))
        rows.extend(file_rows)
        provenance.append({"path": str(path), "sha256": digest, "rows": str(len(file_rows))})
    return rows, provenance


def summarize(rows: list[dict[str, str]]) -> list[dict[str, object]]:
    groups: dict[tuple[str, ...], list[dict[str, str]]] = defaultdict(list)
    for row in rows:
        groups[tuple(row[field] for field in GROUP_FIELDS)].append(row)
    summaries: list[dict[str, object]] = []
    for key in sorted(groups):
        group = groups[key]
        wall_ns = [float(row["wall_ns"]) for row in group]
        cpu_ns = [float(row["cpu_ns"]) for row in group]
        median_ns = statistics.median(wall_ns)
        seed_material = "\x1f".join(key).encode("utf-8")
        seed = int.from_bytes(hashlib.sha256(seed_material).digest()[:8], "big")
        ci_low, ci_high = bootstrap_median_ci(wall_ns, seed)
        mean_ns = statistics.fmean(wall_ns)
        stdev_ns = statistics.stdev(wall_ns) if len(wall_ns) > 1 else 0.0
        total_work_units = sum(int(row.get("work_units") or 1) for row in group)
        total_wall_ns = sum(wall_ns)
        total_cpu_ns = sum(cpu_ns)
        signature_min, signature_median, signature_max = optional_nonzero_signature_stats(group)
        summary: dict[str, object] = dict(zip(GROUP_FIELDS, key, strict=True))
        summary.update(
            n=len(group),
            valid_n=sum(row["valid"].lower() == "true" for row in group),
            valid_fraction=sum(row["valid"].lower() == "true" for row in group) / len(group),
            mean_wall_ns=mean_ns,
            median_wall_ns=median_ns,
            stdev_wall_ns=stdev_ns,
            cv_wall=stdev_ns / mean_ns if mean_ns else 0.0,
            min_wall_ns=min(wall_ns),
            p50_wall_ns=percentile(wall_ns, 0.50),
            p90_wall_ns=percentile(wall_ns, 0.90),
            p95_wall_ns=percentile(wall_ns, 0.95),
            p99_wall_ns=percentile(wall_ns, 0.99),
            max_wall_ns=max(wall_ns),
            median_ci95_low_ns=ci_low,
            median_ci95_high_ns=ci_high,
            mean_cpu_ns=statistics.fmean(cpu_ns),
            experiment=str(key[3]),
            environment=str(key[1]),
            workload=str(key[7]),
            sample_count=len(group),
            mean_us=mean_ns / 1_000,
            median_us=median_ns / 1_000,
            stddev_us=stdev_ns / 1_000,
            p90_us=percentile(wall_ns, 0.90) / 1_000,
            p95_us=percentile(wall_ns, 0.95) / 1_000,
            p99_us=percentile(wall_ns, 0.99) / 1_000,
            total_work_units=total_work_units,
            throughput_ops_per_second=(total_work_units * 1_000_000_000.0 / total_wall_ns) if total_wall_ns else 0.0,
            ops_per_sec=(total_work_units * 1_000_000_000.0 / total_wall_ns) if total_wall_ns else 0.0,
            cpu_percent=(total_cpu_ns / total_wall_ns * 100.0) if total_wall_ns else None,
            mad_outlier_count=mad_outlier_count(wall_ns),
            outlier_policy="retained_all_samples",
            max_rss_bytes=max(int(row["max_rss_bytes"]) for row in group),
            memory_mb=max(int(row["max_rss_bytes"]) for row in group) / 1_000_000,
            network_bytes=None,
            throughput_tps=None,
            result_type=str(key[0]),
            public_key_bytes=optional_nonzero_max(group, "public_key_bytes"),
            private_key_bytes=optional_nonzero_max(group, "private_key_bytes"),
            signature_bytes_min=signature_min,
            signature_bytes_median=signature_median,
            signature_bytes_max=signature_max,
            ciphertext_bytes=optional_nonzero_max(group, "ciphertext_bytes"),
            shared_secret_bytes=optional_nonzero_max(group, "shared_secret_bytes"),
            unsigned_serialized_bytes=optional_nonzero_max(group, "unsigned_serialized_bytes"),
            serialized_bytes=optional_nonzero_max(group, "serialized_bytes"),
            authentication_bytes=optional_nonzero_max(group, "authentication_bytes"),
            item_count=optional_nonzero_max(group, "item_count"),
            results=";".join(sorted({row["result"] for row in group})),
        )
        summaries.append(summary)
    return summaries


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    if not rows:
        raise ValueError(f"refusing to write empty table: {path}")
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def write_size_table(path: Path, rows: list[dict[str, str]]) -> None:
    size_rows: dict[str, dict[str, int | str]] = {}
    for row in rows:
        if row["suite"] != "primitive" or row["valid"].lower() != "true":
            continue
        algorithm = row["algorithm"]
        current = size_rows.setdefault(
            algorithm,
            {
                "algorithm": algorithm,
                "public_key_bytes": 0,
                "private_key_bytes": 0,
                "signature_bytes_min": 0,
                "signature_bytes_max": 0,
                "ciphertext_bytes": 0,
                "shared_secret_bytes": 0,
            },
        )
        for field in ("public_key_bytes", "private_key_bytes", "ciphertext_bytes", "shared_secret_bytes"):
            current[field] = max(int(current[field]), int(row[field]))
        signature_size = int(row["signature_bytes"])
        if signature_size:
            current["signature_bytes_min"] = (
                signature_size
                if not current["signature_bytes_min"]
                else min(int(current["signature_bytes_min"]), signature_size)
            )
            current["signature_bytes_max"] = max(int(current["signature_bytes_max"]), signature_size)
    ordered_rows: list[dict[str, object]] = []
    for key in sorted(size_rows):
        normalized: dict[str, object] = dict(size_rows[key])
        for field in (
            "public_key_bytes",
            "private_key_bytes",
            "signature_bytes_min",
            "signature_bytes_max",
            "ciphertext_bytes",
            "shared_secret_bytes",
        ):
            if normalized[field] == 0:
                normalized[field] = None
        ordered_rows.append(normalized)
    if ordered_rows:
        write_csv(path, ordered_rows)
        return
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "algorithm",
                "public_key_bytes",
                "private_key_bytes",
                "signature_bytes_min",
                "signature_bytes_max",
                "ciphertext_bytes",
                "shared_secret_bytes",
            ],
        )
        writer.writeheader()


def svg_text(x: float, y: float, value: str, *, size: int = 12, anchor: str = "middle", rotate: int = 0) -> str:
    transform = f' transform="rotate({rotate} {x:.1f} {y:.1f})"' if rotate else ""
    return f'<text x="{x:.1f}" y="{y:.1f}" font-size="{size}" text-anchor="{anchor}"{transform}>{html.escape(value)}</text>'


def write_log_bar_svg(path: Path, title: str, ylabel: str, labels: list[str], values: list[float], colors: list[str]) -> None:
    width, height = 1_200, 650
    left, right, top, bottom = 110, 35, 70, 190
    plot_width, plot_height = width - left - right, height - top - bottom
    positive = [value for value in values if value > 0]
    low = math.floor(math.log10(min(positive))) if positive else 0
    high = math.ceil(math.log10(max(positive))) if positive else 1
    if high == low:
        high += 1
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="white"/>',
        '<g font-family="-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif" fill="#1d2733">',
        svg_text(width / 2, 35, title, size=18),
    ]
    for exponent in range(low, high + 1):
        y = top + plot_height * (high - exponent) / (high - low)
        parts.append(f'<line x1="{left}" y1="{y:.1f}" x2="{width-right}" y2="{y:.1f}" stroke="#d9e0e6" stroke-width="1"/>')
        parts.append(svg_text(left - 12, y + 4, f"10^{exponent}", size=11, anchor="end"))
    slot = plot_width / max(len(labels), 1)
    bar_width = max(4.0, slot * 0.72)
    for index, (label, value, color) in enumerate(zip(labels, values, colors, strict=True)):
        x = left + slot * index + (slot - bar_width) / 2
        scaled = (math.log10(max(value, 10**low)) - low) / (high - low)
        bar_height = max(1.0, scaled * plot_height)
        y = top + plot_height - bar_height
        parts.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_width:.1f}" height="{bar_height:.1f}" fill="{color}"/>')
        parts.append(svg_text(x + bar_width / 2, top + plot_height + 18, label.replace("\n", " / "), size=9, anchor="end", rotate=-38))
    parts.extend(
        [
            f'<line x1="{left}" y1="{top}" x2="{left}" y2="{top+plot_height}" stroke="#1d2733"/>',
            f'<line x1="{left}" y1="{top+plot_height}" x2="{width-right}" y2="{top+plot_height}" stroke="#1d2733"/>',
            svg_text(25, top + plot_height / 2, ylabel, size=12, rotate=-90),
            '</g></svg>',
        ]
    )
    path.write_text("\n".join(parts) + "\n", encoding="utf-8")


def write_log_line_svg(
    path: Path,
    title: str,
    series: dict[str, list[tuple[int, float]]],
    *,
    xlabel: str = "Message bytes (log2 scale)",
    ylabel: str = "Median latency (microseconds, log scale)",
) -> None:
    width, height = 1_100, 650
    left, right, top, bottom = 105, 245, 65, 85
    plot_width, plot_height = width - left - right, height - top - bottom
    points = [point for values in series.values() for point in values]
    x_values = [math.log2(point[0]) for point in points]
    y_values = [math.log10(point[1]) for point in points if point[1] > 0]
    x_low, x_high = min(x_values), max(x_values)
    if x_low == x_high:
        x_low -= 0.5
        x_high += 0.5
    y_low, y_high = math.floor(min(y_values)), math.ceil(max(y_values))
    if y_low == y_high:
        y_high += 1
    palette = ["#355C7D", "#C06C84", "#6C5B7B", "#F67280", "#2A9D8F", "#E9C46A"]
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="white"/>',
        '<g font-family="-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif" fill="#1d2733">',
        svg_text(width / 2, 33, title, size=18),
    ]
    for exponent in range(y_low, y_high + 1):
        y = top + plot_height * (y_high - exponent) / (y_high - y_low)
        parts.append(f'<line x1="{left}" y1="{y:.1f}" x2="{left+plot_width}" y2="{y:.1f}" stroke="#d9e0e6"/>')
        parts.append(svg_text(left - 10, y + 4, f"10^{exponent}", size=11, anchor="end"))
    for raw_x in sorted({point[0] for point in points}):
        x_power = math.log2(raw_x)
        x = left + plot_width * (x_power - x_low) / (x_high - x_low)
        parts.append(f'<line x1="{x:.1f}" y1="{top}" x2="{x:.1f}" y2="{top+plot_height}" stroke="#eef1f4"/>')
        parts.append(svg_text(x, top + plot_height + 20, str(raw_x), size=10))
    for index, (name, values) in enumerate(sorted(series.items())):
        color = palette[index % len(palette)]
        values = sorted(values)
        coordinates = []
        for raw_x, raw_y in values:
            x = left + plot_width * (math.log2(raw_x) - x_low) / (x_high - x_low)
            y = top + plot_height * (y_high - math.log10(raw_y)) / (y_high - y_low)
            coordinates.append((x, y))
        parts.append(f'<polyline points="{" ".join(f"{x:.1f},{y:.1f}" for x, y in coordinates)}" fill="none" stroke="{color}" stroke-width="2"/>')
        for x, y in coordinates:
            parts.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3" fill="{color}"/>')
        legend_y = top + 20 + index * 24
        parts.append(f'<line x1="{left+plot_width+25}" y1="{legend_y-4}" x2="{left+plot_width+55}" y2="{legend_y-4}" stroke="{color}" stroke-width="3"/>')
        parts.append(svg_text(left + plot_width + 62, legend_y, name, size=10, anchor="start"))
    parts.extend(
        [
            svg_text(left + plot_width / 2, height - 20, xlabel, size=12),
            svg_text(24, top + plot_height / 2, ylabel, size=12, rotate=-90),
            '</g></svg>',
        ]
    )
    path.write_text("\n".join(parts) + "\n", encoding="utf-8")


def make_plots(
    summaries: list[dict[str, object]],
    rows: list[dict[str, str]],
    output_dir: Path,
) -> list[str]:
    plot_paths: list[str] = []
    primitive = [
        row
        for row in summaries
        if row["classification"] == "MEASURED"
        and row["suite"] == "primitive"
        and row["layer"] == "runtime_pqc_manager"
        and row["payload_profile"] == "transaction512"
        and row["operation"] in {"sign", "verify_valid"}
    ]
    if primitive:
        path = output_dir / "primitive-sign-verify-512B.svg"
        write_log_bar_svg(
            path,
            "Runtime PQCManager signature latency, 512-byte payload",
            "Median latency (microseconds, log scale)",
            [f"{row['algorithm']}\n{row['operation']}" for row in primitive],
            [float(row["median_wall_ns"]) / 1_000 for row in primitive],
            [
                "#355C7D" if row["operation"] == "sign" else "#C06C84"
                for row in primitive
            ],
        )
        plot_paths.append(str(path))

    layered_signature = [
        row
        for row in summaries
        if row["payload_profile"] == "transaction512"
        and (
            (
                row["layer"]
                in {"underlying_primitive_direct", "runtime_pqc_manager"}
                and row["operation"] in {"sign", "verify_valid"}
            )
            or (
                row["suite"] == "aegis"
                and row["layer"] == "aegis_domain_wrapper_transaction"
                and row["operation"] in {"sign_domain", "verify_cache_miss"}
            )
        )
    ]
    if layered_signature:
        layer_names = {
            "underlying_primitive_direct": "direct",
            "runtime_pqc_manager": "manager",
            "aegis_domain_wrapper_transaction": "Aegis",
        }
        path = output_dir / "signature-layer-comparison-512B.svg"
        write_log_bar_svg(
            path,
            "Signature cost by implementation layer, 512-byte payload",
            "Median latency (microseconds, log scale)",
            [
                f"{row['algorithm']}\n{layer_names[str(row['layer'])]} {row['operation']}"
                for row in layered_signature
            ],
            [float(row["median_wall_ns"]) / 1_000 for row in layered_signature],
            [
                {
                    "underlying_primitive_direct": "#2A9D8F",
                    "runtime_pqc_manager": "#355C7D",
                    "aegis_domain_wrapper_transaction": "#C06C84",
                }[str(row["layer"])]
                for row in layered_signature
            ],
        )
        plot_paths.append(str(path))

    aegis = [
        row
        for row in summaries
        if row["classification"] == "MEASURED"
        and row["suite"] == "aegis"
        and row["payload_profile"] == "transaction512"
        and row["operation"] in {"verify_cache_miss", "verify_cache_hit"}
    ]
    if aegis:
        path = output_dir / "aegis-cache-miss-vs-hit-512B.svg"
        write_log_bar_svg(
            path,
            "Aegis policy/domain verification: cache miss vs exact replay",
            "Median latency (microseconds, log scale)",
            [
                f"{row['algorithm']}\n{str(row['operation']).replace('verify_', '')}"
                for row in aegis
            ],
            [float(row["median_wall_ns"]) / 1_000 for row in aegis],
            [
                "#6C5B7B"
                if row["operation"] == "verify_cache_miss"
                else "#99B898"
                for row in aegis
            ],
        )
        plot_paths.append(str(path))

    scaling: dict[str, list[tuple[int, float]]] = defaultdict(list)
    for row in summaries:
        if row["suite"] == "primitive" and row["operation"] == "verify_valid":
            scaling[str(row["algorithm"])].append(
                (int(row["message_bytes"]), float(row["median_wall_ns"]) / 1_000)
            )
    if scaling:
        path = output_dir / "verification-message-scaling.svg"
        write_log_line_svg(path, "Primitive verification scaling by payload size", scaling)
        plot_paths.append(str(path))

    transaction_components = [
        row
        for row in summaries
        if row["suite"] == "protocol"
        and row["payload_profile"] == "transaction512"
        and (
            str(row["layer"]).endswith("_component")
            or row["operation"]
            in {
                "validate_for_admission",
                "verify_submission_envelope",
                "validate_carrier",
            }
        )
    ]
    if transaction_components:
        path = output_dir / "transaction-component-latency-512B.svg"
        write_log_bar_svg(
            path,
            "Transaction component latency, 512-byte payload",
            "Median latency (microseconds, log scale)",
            [
                f"{row['layer']}\n{row['operation']}"
                for row in transaction_components
            ],
            [
                float(row["median_wall_ns"]) / 1_000
                for row in transaction_components
            ],
            [
                "#355C7D" if "public_rpc" in str(row["layer"]) else "#C06C84"
                for row in transaction_components
            ],
        )
        plot_paths.append(str(path))

    transaction_size_series: dict[str, list[tuple[int, float]]] = defaultdict(list)
    for row in summaries:
        if (
            row["suite"] == "protocol"
            and row["layer"] == "public_rpc_transaction"
            and row["operation"] == "build_hash_sign_serialize"
        ):
            if row["unsigned_serialized_bytes"] is not None:
                transaction_size_series["legacy unsigned JSON"].append(
                    (int(row["message_bytes"]), float(row["unsigned_serialized_bytes"]))
                )
            if row["serialized_bytes"] is not None:
                transaction_size_series["legacy signed JSON"].append(
                    (int(row["message_bytes"]), float(row["serialized_bytes"]))
                )
        if (
            row["suite"] == "protocol"
            and row["layer"] == "aegis_legacy_carrier_component"
            and row["operation"] == "serialize_carrier"
            and row["serialized_bytes"] is not None
        ):
            transaction_size_series["Aegis legacy carrier JSON"].append(
                (int(row["message_bytes"]), float(row["serialized_bytes"]))
            )
    if transaction_size_series:
        path = output_dir / "transaction-byte-overhead.svg"
        write_log_line_svg(
            path,
            "Transaction serialization size by payload",
            transaction_size_series,
            xlabel="Application payload bytes (log2 scale)",
            ylabel="Serialized bytes (log scale)",
        )
        plot_paths.append(str(path))

    block_rows = [
        row
        for row in summaries
        if row["layer"] == "coordinated_block_authentication"
        and row["operation"] == "build_sign_serialize_block_package"
        and row["item_count"] is not None
    ]
    if block_rows:
        block_series: dict[str, list[tuple[int, float]]] = defaultdict(list)
        for row in block_rows:
            item_count = int(row["item_count"])
            for field, label in (
                ("serialized_bytes", "full NetworkMessage frame"),
                ("unsigned_serialized_bytes", "unsigned structural bytes"),
                ("authentication_bytes", "authentication bytes"),
            ):
                value = row[field]
                if value is not None:
                    block_series[label].append((item_count, float(value)))
        if block_series:
            path = output_dir / "coordinated-block-wire-scaling.svg"
            write_log_line_svg(
                path,
                "Coordinated committed-package wire scaling",
                block_series,
                xlabel="Signed Aegis transactions per block (log2 scale)",
                ylabel="Bytes (log scale)",
            )
            plot_paths.append(str(path))

    network_frame_rows = [
        row
        for row in summaries
        if row["layer"] == "coordinated_p2p_frame"
        and str(row["operation"]).startswith("serialize_")
        and row["item_count"] is not None
        and row["serialized_bytes"] is not None
    ]
    if network_frame_rows:
        network_frame_series: dict[str, list[tuple[int, float]]] = defaultdict(list)
        for row in network_frame_rows:
            message_kind = (
                str(row["operation"])
                .removeprefix("serialize_")
                .removesuffix("_network_frame")
            )
            network_frame_series[f"{message_kind} frame"].append(
                (int(row["item_count"]), float(row["serialized_bytes"]))
            )
        path = output_dir / "coordinated-network-message-scaling.svg"
        write_log_line_svg(
            path,
            "Coordinated consensus network-message scaling",
            network_frame_series,
            xlabel="Signed Aegis transactions per block (log2 scale)",
            ylabel="Exact framed JSON bytes (log scale)",
        )
        plot_paths.append(str(path))

    load_rows = [
        row
        for row in summaries
        if row["suite"] == "load"
        and row["operation"] == "concurrent_verify_burst"
        and row["item_count"] is not None
        and float(row["throughput_ops_per_second"]) > 0
    ]
    if load_rows:
        load_series: dict[str, list[tuple[int, float]]] = defaultdict(list)
        for row in load_rows:
            worker_label = str(row["payload_profile"]).split("_concurrency", 1)[0]
            load_series[worker_label].append(
                (int(row["item_count"]), float(row["throughput_ops_per_second"]))
            )
        path = output_dir / "controlled-load-throughput.svg"
        write_log_line_svg(
            path,
            "Controlled local Aegis verification throughput",
            load_series,
            xlabel="Concurrent verification attempts (log2 scale)",
            ylabel="Accepted verifications per second (log scale)",
        )
        plot_paths.append(str(path))

        tail_latency_series: dict[str, list[tuple[int, float]]] = defaultdict(list)
        cpu_throughput_series: dict[str, list[tuple[int, float]]] = defaultdict(list)
        for row in load_rows:
            worker_label = str(row["payload_profile"]).split("_concurrency", 1)[0]
            concurrency = int(row["item_count"])
            tail_latency_series[f"{worker_label} p95"].append(
                (concurrency, float(row["p95_wall_ns"]) / 1_000_000)
            )
            tail_latency_series[f"{worker_label} p99"].append(
                (concurrency, float(row["p99_wall_ns"]) / 1_000_000)
            )
            if row["cpu_percent"] is not None and float(row["cpu_percent"]) > 0:
                cpu_throughput_series[worker_label].append(
                    (
                        max(1, int(float(row["throughput_ops_per_second"]))),
                        float(row["cpu_percent"]),
                    )
                )
        path = output_dir / "controlled-load-tail-latency.svg"
        write_log_line_svg(
            path,
            "Controlled verification burst tail latency",
            tail_latency_series,
            xlabel="Concurrent verification attempts (log2 scale)",
            ylabel="Burst wall latency (milliseconds, log scale)",
        )
        plot_paths.append(str(path))
        if cpu_throughput_series:
            path = output_dir / "controlled-load-cpu-vs-throughput.svg"
            write_log_line_svg(
                path,
                "Benchmark-process CPU time versus verification throughput",
                cpu_throughput_series,
                xlabel="Accepted verifications per second (log2 scale)",
                ylabel="Process CPU time / wall time (percent, log scale)",
            )
            plot_paths.append(str(path))

    cold_rows = [row for row in summaries if row["suite"] == "cold_start"]
    if cold_rows:
        path = output_dir / "cold-start-latency.svg"
        write_log_bar_svg(
            path,
            "Fresh-process Aegis initialization and first operations",
            "Median latency (microseconds, log scale)",
            [str(row["operation"]) for row in cold_rows],
            [float(row["median_wall_ns"]) / 1_000 for row in cold_rows],
            ["#6C5B7B" for _ in cold_rows],
        )
        plot_paths.append(str(path))

    size_labels: list[str] = []
    size_values: list[float] = []
    size_colors: list[str] = []
    size_fields = (
        ("public_key_bytes", "public key", "#355C7D"),
        ("private_key_bytes", "private key", "#6C5B7B"),
        ("signature_bytes", "signature", "#C06C84"),
        ("ciphertext_bytes", "ciphertext", "#2A9D8F"),
    )
    seen: dict[tuple[str, str], int] = {}
    for row in rows:
        if row["suite"] != "primitive" or row["valid"].lower() != "true":
            continue
        for field, _label, _color in size_fields:
            value = int(row[field])
            if value:
                key = (row["algorithm"], field)
                seen[key] = max(seen.get(key, 0), value)
    for (algorithm, field), value in sorted(seen.items()):
        label, color = next(
            (label, color)
            for candidate, label, color in size_fields
            if candidate == field
        )
        size_labels.append(f"{algorithm}\n{label}")
        size_values.append(float(value))
        size_colors.append(color)
    if size_labels:
        path = output_dir / "cryptographic-object-sizes.svg"
        write_log_bar_svg(
            path,
            "Observed cryptographic object sizes",
            "Bytes (log scale)",
            size_labels,
            size_values,
            size_colors,
        )
        plot_paths.append(str(path))
    return plot_paths


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", action="append", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)

    rows, provenance = load_rows(args.input)
    if not rows:
        raise SystemExit("no raw samples found")
    summaries = summarize(rows)
    write_csv(args.output_dir / "summary.csv", summaries)
    (args.output_dir / "summary.json").write_text(
        json.dumps({"classification": "DERIVED", "groups": summaries}, indent=2) + "\n",
        encoding="utf-8",
    )
    write_size_table(args.output_dir / "object-sizes.csv", rows)
    plots = make_plots(summaries, rows, args.output_dir)
    failure_rows = [row for row in rows if row["valid"].lower() != "true"]
    metadata = {
        "classification": "DERIVED",
        "raw_sample_count": len(rows),
        "summary_group_count": len(summaries),
        "failed_safety_sample_count": len(failure_rows),
        "failed_safety_results": sorted({row["result"] for row in failure_rows}),
        "bootstrap_resamples": 2_000,
        "bootstrap_confidence": 0.95,
        "bootstrap_statistic": "median",
        "bootstrap_seed": "sha256 of grouping key",
        "percentile_method": "linear interpolation at (n-1)*p",
        "outlier_policy": "MAD flags reported; all samples retained",
        "inputs": provenance,
        "plots": plots,
    }
    (args.output_dir / "analysis.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
