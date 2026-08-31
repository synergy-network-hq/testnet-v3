#!/usr/bin/env python3
"""Generate publication derivations that must remain separate from measurements."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import statistics
from collections import defaultdict
from pathlib import Path

from analyze import percentile, write_log_line_svg


LOAD_PROFILE = re.compile(r"workers(?P<workers>\d+)_concurrency(?P<concurrency>\d+)")
RESULT_COUNTS = re.compile(
    r"accepted=(?P<accepted>\d+);saturated=(?P<saturated>\d+);unexpected=(?P<unexpected>\d+)"
)
VALIDATOR_COUNTS = (4, 6, 7, 10, 16, 25, 50)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--primary-run", type=Path, required=True)
    parser.add_argument("--load-run", type=Path, action="append", default=[])
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args()


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    if not rows:
        raise ValueError(f"refusing to write empty derived table: {path}")
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def raw_files(run: Path, pattern: str = "*.csv") -> list[Path]:
    files = sorted((run / "raw").glob(pattern))
    if not files:
        raise FileNotFoundError(f"no raw inputs matched {run / 'raw' / pattern}")
    return files


def load_run_rows(load_runs: list[Path]) -> tuple[list[dict[str, object]], list[Path]]:
    output: list[dict[str, object]] = []
    inputs: list[Path] = []
    for run in load_runs:
        for path in raw_files(run, "*load-workers*.csv"):
            inputs.append(path)
            grouped: dict[tuple[int, int, str], list[dict[str, str]]] = defaultdict(list)
            for row in read_csv(path):
                profile = LOAD_PROFILE.fullmatch(row["payload_profile"])
                if profile is None:
                    raise ValueError(f"unexpected load profile {row['payload_profile']!r}")
                grouped[
                    (
                        int(profile.group("workers")),
                        int(profile.group("concurrency")),
                        row["environment_id"],
                    )
                ].append(row)
            for (workers, concurrency, environment_id), rows in sorted(grouped.items()):
                wall_ms = [int(row["wall_ns"]) / 1_000_000 for row in rows]
                throughput = [
                    int(row["work_units"]) * 1_000_000_000 / int(row["wall_ns"])
                    for row in rows
                ]
                accepted: list[int] = []
                saturated: list[int] = []
                unexpected: list[int] = []
                for row in rows:
                    result = RESULT_COUNTS.fullmatch(row["result"])
                    if result is None:
                        raise ValueError(f"unexpected load result {row['result']!r}")
                    accepted.append(int(result.group("accepted")))
                    saturated.append(int(result.group("saturated")))
                    unexpected.append(int(result.group("unexpected")))
                output.append(
                    {
                        "classification": "MEASURED",
                        "run_directory": run.name,
                        "environment_id": environment_id,
                        "source_commit": rows[0]["source_commit"],
                        "workers": workers,
                        "offered_concurrency": concurrency,
                        "n": len(rows),
                        "median_burst_wall_ms": statistics.median(wall_ms),
                        "p95_burst_wall_ms": percentile(wall_ms, 0.95),
                        "p99_burst_wall_ms": percentile(wall_ms, 0.99),
                        "median_accepted_verifications": statistics.median(accepted),
                        "median_saturated_verifications": statistics.median(saturated),
                        "median_verification_ops_per_second": statistics.median(throughput),
                        "p95_verification_ops_per_second": percentile(throughput, 0.95),
                        "saturation_fraction": sum(saturated) / (len(rows) * concurrency),
                        "unexpected_error_fraction": sum(unexpected) / (len(rows) * concurrency),
                        "throughput_tps": None,
                        "notes": "controlled local unique-signature verification bursts; not transaction or chain throughput",
                    }
                )
    return output, inputs


def load_variability_rows(run_rows: list[dict[str, object]]) -> list[dict[str, object]]:
    grouped: dict[tuple[int, int], list[dict[str, object]]] = defaultdict(list)
    for row in run_rows:
        grouped[(int(row["workers"]), int(row["offered_concurrency"]))].append(row)
    output: list[dict[str, object]] = []
    for (workers, concurrency), rows in sorted(grouped.items()):
        medians = [float(row["median_verification_ops_per_second"]) for row in rows]
        output.append(
            {
                "classification": "DERIVED",
                "workers": workers,
                "offered_concurrency": concurrency,
                "independent_runs": len(rows),
                "samples_per_run": ";".join(str(row["n"]) for row in rows),
                "median_of_run_medians_ops_per_second": statistics.median(medians),
                "min_run_median_ops_per_second": min(medians),
                "max_run_median_ops_per_second": max(medians),
                "run_median_cv": (
                    statistics.stdev(medians) / statistics.fmean(medians)
                    if len(medians) > 1 and statistics.fmean(medians)
                    else None
                ),
                "throughput_tps": None,
                "notes": "run-level variation of controlled crypto-pool throughput; saturation is backpressure, not committed TPS",
            }
        )
    return output


def latency_summary(rows: list[dict[str, str]]) -> dict[str, object]:
    wall_ns = [int(row["wall_ns"]) for row in rows]
    total_work = sum(int(row["work_units"]) for row in rows)
    total_wall = sum(wall_ns)
    return {
        "n": len(rows),
        "mean_us": statistics.fmean(wall_ns) / 1_000,
        "median_us": statistics.median(wall_ns) / 1_000,
        "p95_us": percentile(wall_ns, 0.95) / 1_000,
        "p99_us": percentile(wall_ns, 0.99) / 1_000,
        "ops_per_second": total_work * 1_000_000_000 / total_wall,
    }


def publication_table_rows(
    primary_run: Path,
) -> tuple[dict[str, list[dict[str, object]]], list[Path]]:
    primitive_path = raw_files(primary_run, "*primitive.csv")[0]
    aegis_path = raw_files(primary_run, "*aegis.csv")[0]
    protocol_path = raw_files(primary_run, "*protocol.csv")[0]
    primitive = read_csv(primitive_path)
    aegis = read_csv(aegis_path)
    protocol = read_csv(protocol_path)

    sizes: list[dict[str, object]] = []
    for algorithm in sorted({row["algorithm"] for row in primitive}):
        rows = [
            row
            for row in primitive
            if row["algorithm"] == algorithm and row["valid"] == "true"
        ]
        values = {
            field: [int(row[field]) for row in rows if int(row[field]) > 0]
            for field in (
                "public_key_bytes",
                "private_key_bytes",
                "signature_bytes",
                "ciphertext_bytes",
                "shared_secret_bytes",
            )
        }
        sizes.append(
            {
                "classification": "MEASURED",
                "algorithm": algorithm,
                "public_key_bytes": max(values["public_key_bytes"], default=None),
                "private_key_bytes": max(values["private_key_bytes"], default=None),
                "signature_bytes_min": min(values["signature_bytes"], default=None),
                "signature_bytes_max": max(values["signature_bytes"], default=None),
                "ciphertext_bytes": max(values["ciphertext_bytes"], default=None),
                "shared_secret_bytes": max(values["shared_secret_bytes"], default=None),
                "source_commit": rows[0]["source_commit"],
            }
        )

    primitive_latency: list[dict[str, object]] = []
    grouped_primitive: dict[tuple[str, str, str], list[dict[str, str]]] = defaultdict(list)
    for row in primitive:
        if row["layer"] != "runtime_pqc_manager" or row["suite"] != "primitive":
            continue
        include = row["operation"] == "keygen" or (
            row["payload_profile"] == "transaction512"
            and row["operation"] in {"sign", "verify_valid"}
        ) or (
            row["payload_profile"] == "kem"
            and row["operation"] in {"encapsulate", "decapsulate"}
        )
        if include:
            grouped_primitive[
                (row["algorithm"], row["operation"], row["payload_profile"])
            ].append(row)
    for (algorithm, operation, workload), rows in sorted(grouped_primitive.items()):
        primitive_latency.append(
            {
                "classification": "MEASURED",
                "algorithm": algorithm,
                "operation": operation,
                "workload": workload,
                **latency_summary(rows),
                "source_commit": rows[0]["source_commit"],
            }
        )

    production_latency: list[dict[str, object]] = []
    selected_aegis = [
        row
        for row in aegis
        if row["layer"] == "aegis_domain_wrapper_transaction"
        and row["algorithm"] == "ML-DSA-65"
        and row["payload_profile"] == "transaction512"
        and row["operation"] in {"sign_domain", "verify_cache_miss", "verify_cache_hit"}
    ]
    selected_protocol = [
        row
        for row in protocol
        if row["payload_profile"] == "transaction512"
        and (row["layer"], row["operation"])
        in {
            ("public_rpc_transaction", "build_hash_sign_serialize"),
            ("public_rpc_transaction", "validate_for_admission"),
            ("aegis_typed_transaction", "build_sign_verify_admit_carrier"),
            ("aegis_typed_transaction", "verify_submission_envelope"),
            ("aegis_legacy_carrier", "validate_carrier"),
        }
    ]
    grouped_production: dict[tuple[str, str, str], list[dict[str, str]]] = defaultdict(list)
    for row in [*selected_aegis, *selected_protocol]:
        grouped_production[(row["layer"], row["algorithm"], row["operation"])].append(row)
    for (layer, algorithm, operation), rows in sorted(grouped_production.items()):
        production_latency.append(
            {
                "classification": "MEASURED",
                "protocol_object": layer,
                "algorithm": algorithm,
                "operation": operation,
                **latency_summary(rows),
                "source_commit": rows[0]["source_commit"],
                "notes": rows[0]["notes"],
            }
        )

    transaction_overhead: list[dict[str, object]] = []
    legacy_groups: dict[str, list[dict[str, str]]] = defaultdict(list)
    envelope_groups: dict[str, list[dict[str, str]]] = defaultdict(list)
    carrier_groups: dict[str, list[dict[str, str]]] = defaultdict(list)
    for row in protocol:
        if row["layer"] == "public_rpc_transaction" and row["operation"] == "build_hash_sign_serialize":
            legacy_groups[row["payload_profile"]].append(row)
        elif row["layer"] == "aegis_submission_envelope_component" and row["operation"] == "serialize_submission_envelope":
            envelope_groups[row["payload_profile"]].append(row)
        elif row["layer"] == "aegis_legacy_carrier_component" and row["operation"] == "serialize_carrier":
            carrier_groups[row["payload_profile"]].append(row)
    for profile, rows in sorted(legacy_groups.items(), key=lambda item: int(item[1][0]["message_bytes"])):
        unsigned = statistics.median(int(row["unsigned_serialized_bytes"]) for row in rows)
        signed = statistics.median(int(row["serialized_bytes"]) for row in rows)
        envelope = statistics.median(
            int(row["serialized_bytes"]) for row in envelope_groups[profile]
        )
        carrier = statistics.median(
            int(row["serialized_bytes"]) for row in carrier_groups[profile]
        )
        transaction_overhead.append(
            {
                "classification": "DERIVED_FROM_MEASURED_BYTES",
                "payload_profile": profile,
                "payload_bytes": int(rows[0]["message_bytes"]),
                "legacy_unsigned_json_bytes_median": unsigned,
                "legacy_signed_json_bytes_median": signed,
                "aegis_submission_envelope_json_bytes_median": envelope,
                "aegis_legacy_carrier_json_bytes_median": carrier,
                "carrier_overhead_vs_unsigned_percent": (carrier - unsigned) / unsigned * 100,
                "carrier_overhead_vs_signed_percent": (carrier - signed) / signed * 100,
                "n": len(rows),
                "source_commit": rows[0]["source_commit"],
            }
        )

    guard_results: dict[int, str] = {}
    for row in protocol:
        if row["layer"] == "coordinated_p2p_frame_guard":
            guard_results[int(row["item_count"])] = row["result"]
    block_groups: dict[int, list[dict[str, str]]] = defaultdict(list)
    for row in protocol:
        if (
            row["layer"] == "coordinated_block_authentication"
            and row["operation"] == "build_sign_serialize_block_package"
        ):
            block_groups[int(row["item_count"])].append(row)
    block_overhead: list[dict[str, object]] = []
    for count, rows in sorted(block_groups.items()):
        frame_values = [int(row["serialized_bytes"]) for row in rows]
        auth_values = [int(row["authentication_bytes"]) for row in rows]
        frame_median = statistics.median(frame_values)
        auth_median = statistics.median(auth_values)
        block_overhead.append(
            {
                "classification": "MEASURED",
                "transactions_per_block": count,
                "frame_bytes_median": frame_median,
                "frame_bytes_min": min(frame_values),
                "frame_bytes_max": max(frame_values),
                "authentication_delta_bytes_median": auth_median,
                "authentication_percent": auth_median / frame_median * 100,
                "frame_guard_result": guard_results[count],
                "n": len(rows),
                "source_commit": rows[0]["source_commit"],
            }
        )
    return (
        {
            "cryptographic-artifact-sizes.csv": sizes,
            "primitive-latency.csv": primitive_latency,
            "aegis-production-latency.csv": production_latency,
            "transaction-overhead.csv": transaction_overhead,
            "block-overhead.csv": block_overhead,
        },
        [primitive_path, aegis_path, protocol_path],
    )


def frame_statistics(protocol_rows: list[dict[str, str]]) -> dict[int, dict[str, dict[str, float]]]:
    accepted_counts = {
        int(row["item_count"])
        for row in protocol_rows
        if row["layer"] == "coordinated_p2p_frame_guard"
        and row["result"] == "accepted_within_8mib_limit"
    }
    grouped: dict[tuple[int, str], list[dict[str, str]]] = defaultdict(list)
    for row in protocol_rows:
        if row["layer"] != "coordinated_p2p_frame":
            continue
        transaction_count = int(row["item_count"])
        if transaction_count not in accepted_counts:
            continue
        kind = row["operation"].removeprefix("serialize_").removesuffix("_network_frame")
        grouped[(transaction_count, kind)].append(row)
    output: dict[int, dict[str, dict[str, float]]] = defaultdict(dict)
    for (transaction_count, kind), rows in grouped.items():
        output[transaction_count][kind] = {
            "frame_bytes": statistics.median(int(row["serialized_bytes"]) for row in rows),
            "authentication_bytes": statistics.median(
                int(row["authentication_bytes"]) for row in rows
            ),
            "n": len(rows),
        }
    return dict(output)


def validator_scaling_rows(
    primary_run: Path,
) -> tuple[list[dict[str, object]], list[Path], dict[str, object]]:
    protocol_path = raw_files(primary_run, "*protocol.csv")[0]
    aegis_path = raw_files(primary_run, "*aegis.csv")[0]
    protocol_rows = read_csv(protocol_path)
    aegis_rows = read_csv(aegis_path)
    frames = frame_statistics(protocol_rows)
    transaction_aegis = [
        row
        for row in aegis_rows
        if row["layer"] == "aegis_domain_wrapper_transaction"
        and row["algorithm"] == "ML-DSA-65"
        and row["payload_profile"] == "transaction512"
    ]
    miss_ns = statistics.median(
        int(row["wall_ns"])
        for row in transaction_aegis
        if row["operation"] == "verify_cache_miss"
    )
    hit_ns = statistics.median(
        int(row["wall_ns"])
        for row in transaction_aegis
        if row["operation"] == "verify_cache_hit"
    )
    output: list[dict[str, object]] = []
    for transaction_count, message_sizes in sorted(frames.items()):
        if set(message_sizes) != {"assignment", "proposal", "committed"}:
            raise ValueError(f"incomplete coordinated frame set for {transaction_count} transactions")
        for validator_count in VALIDATOR_COUNTS:
            consensus_verify_calls = 5 * validator_count + 2
            transaction_verify_calls = (validator_count + 1) * transaction_count
            primitive_misses = (
                3 * validator_count - 1 + validator_count * transaction_count
            )
            cache_hits = 2 * validator_count + 3 + transaction_count
            assignment = message_sizes["assignment"]
            proposal = message_sizes["proposal"]
            committed = message_sizes["committed"]
            total_frame_bytes = (
                (validator_count - 1) * assignment["frame_bytes"]
                + proposal["frame_bytes"]
                + (validator_count - 1) * committed["frame_bytes"]
            )
            total_authentication_bytes = (
                (validator_count - 1) * assignment["authentication_bytes"]
                + proposal["authentication_bytes"]
                + (validator_count - 1) * committed["authentication_bytes"]
            )
            output.append(
                {
                    "classification": "DERIVED",
                    "validator_count": validator_count,
                    "validator_count_context": (
                        "current_six-validator_configuration; aggregate remains derived"
                        if validator_count == 6
                        else "hypothetical validator count"
                    ),
                    "transactions_per_block": transaction_count,
                    "measured_frame_samples_per_kind": int(assignment["n"]),
                    "network_transmissions_per_successful_block": 2 * validator_count - 1,
                    "consensus_signatures_created_per_block": 3,
                    "consensus_aegis_verify_calls": consensus_verify_calls,
                    "transaction_aegis_verify_calls": transaction_verify_calls,
                    "total_aegis_verify_calls": consensus_verify_calls + transaction_verify_calls,
                    "modeled_primitive_cache_misses": primitive_misses,
                    "modeled_positive_cache_hits": cache_hits,
                    "aggregate_exact_frame_bytes": total_frame_bytes,
                    "aggregate_authentication_delta_bytes": total_authentication_bytes,
                    "modeled_aegis_verify_wall_ms": (
                        primitive_misses * miss_ns + cache_hits * hit_ns
                    )
                    / 1_000_000,
                    "block_latency_ms": None,
                    "finality_latency_ms": None,
                    "cpu_percent": None,
                    "formulas": "tx=2N-1;consensus_verify=5N+2;transaction_verify=(N+1)T;miss=3N-1+NT;hit=2N+3+T",
                    "notes": "steady successful round, all N validators connected, no retry/rebroadcast/cache eviction; modeled time uses measured generic 512-byte Aegis ML-DSA-65 cache-miss/hit medians and is not measured consensus latency",
                }
            )
    metadata = {
        "classification": "DERIVED",
        "source_commit": protocol_rows[0]["source_commit"],
        "configured_validator_count": 6,
        "measured_aegis_cache_miss_median_ns": miss_ns,
        "measured_aegis_cache_hit_median_ns": hit_ns,
        "formulas": {
            "network_transmissions": "2*N-1",
            "consensus_signatures_created": "3",
            "consensus_aegis_verify_calls": "5*N+2",
            "transaction_aegis_verify_calls": "(N+1)*T",
            "primitive_cache_misses": "3*N-1+N*T",
            "positive_cache_hits": "2*N+3+T",
            "aggregate_frame_bytes": "(N-1)*assignment_frame+proposal_frame+(N-1)*committed_frame",
        },
        "assumptions": [
            "one successful coordinated_round_robin_v1 block without timeout, retry, replay, or sync traffic",
            "the coordinator has N-1 connected remote validator peers",
            "the assigned producer receives the committed package after proposing",
            "the shared positive-result cache retains the exact assignment, block, commit, and transaction signatures",
            "frame-byte inputs are medians of exact locally serialized production NetworkMessage values",
            "modeled verification wall time is not block, round, CPU, or finality latency",
        ],
    }
    return output, [protocol_path, aegis_path], metadata


def main() -> None:
    args = parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    load_runs = [args.primary_run, *args.load_run]
    measured_load, load_inputs = load_run_rows(load_runs)
    variability = load_variability_rows(measured_load)
    validator_rows, validator_inputs, derivation = validator_scaling_rows(args.primary_run)
    publication_tables, publication_inputs = publication_table_rows(args.primary_run)
    write_csv(args.output_dir / "load-independent-runs.csv", measured_load)
    write_csv(args.output_dir / "load-run-variability.csv", variability)
    write_csv(args.output_dir / "validator-scaling.csv", validator_rows)
    for filename, rows in publication_tables.items():
        write_csv(args.output_dir / filename, rows)

    transaction_counts = sorted({int(row["transactions_per_block"]) for row in validator_rows})
    selected_counts = [count for count in (1, 10, 100, 233) if count in transaction_counts]
    verify_series: dict[str, list[tuple[int, float]]] = defaultdict(list)
    bytes_series: dict[str, list[tuple[int, float]]] = defaultdict(list)
    for row in validator_rows:
        transaction_count = int(row["transactions_per_block"])
        if transaction_count not in selected_counts:
            continue
        verify_series[f"T={transaction_count}"].append(
            (int(row["validator_count"]), float(row["total_aegis_verify_calls"]))
        )
        bytes_series[f"T={transaction_count}"].append(
            (
                int(row["validator_count"]),
                float(row["aggregate_authentication_delta_bytes"]),
            )
        )
    write_log_line_svg(
        args.output_dir / "validator-count-vs-authentication-verifications.svg",
        "Derived Aegis verification calls per successful block",
        verify_series,
        xlabel="Validator count N (log2 scale)",
        ylabel="Aegis verification calls (log scale)",
    )
    write_log_line_svg(
        args.output_dir / "validator-count-vs-authentication-bytes.svg",
        "Derived aggregate authentication bytes per successful block",
        bytes_series,
        xlabel="Validator count N (log2 scale)",
        ylabel="Authentication-delta bytes (log scale)",
    )
    # Bind every raw file consumed by the consolidated analyzer, not only the
    # narrower subset used to construct report-specific tables and models.
    all_inputs = sorted(set(raw_files(args.primary_run) + load_inputs))
    derivation["inputs"] = [
        {"path": str(path), "sha256": digest(path), "rows": len(read_csv(path))}
        for path in all_inputs
    ]
    derivation["publication_raw_row_count"] = sum(
        int(item["rows"]) for item in derivation["inputs"]
    )
    (args.output_dir / "derivation.json").write_text(
        json.dumps(derivation, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
