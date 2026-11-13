#!/usr/bin/env python3
"""Analyze Synergy consensus timing trace JSONL files."""

from __future__ import annotations

import argparse
import json
import math
import statistics
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


MAJOR_SEGMENTS = [
    "block_wall_interval_ms",
    "block_timestamp_interval_ms",
    "proposal_build_duration_ms",
    "proposal_sent_after_build_ms",
    "proposal_to_vote_request_receive_ms",
    "vote_validation_duration_ms",
    "pqc_sign_duration_ms",
    "pqc_verify_duration_ms",
    "vote_response_elapsed_since_request_ms",
    "vote_response_received_by_proposer_ms",
    "qc_threshold_from_proposal_sent_ms",
    "qc_threshold_from_first_vote_ms",
    "qc_threshold_elapsed_ms",
    "commit_duration_ms",
    "post_commit_to_next_proposal_eligibility_ms",
    "proposer_gap_after_previous_commit_ms",
    "proposer_gap_after_previous_eligibility_ms",
]


def percentile(values: list[float], quantile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    rank = (len(ordered) - 1) * quantile
    low = math.floor(rank)
    high = math.ceil(rank)
    if low == high:
        return ordered[int(rank)]
    return ordered[low] + (ordered[high] - ordered[low]) * (rank - low)


def distribution(values: list[float]) -> dict[str, Any]:
    clean = [float(value) for value in values if value is not None]
    if not clean:
        return {"count": 0, "min": None, "max": None, "avg": None, "p50": None, "p90": None, "p95": None, "p99": None}
    return {
        "count": len(clean),
        "min": min(clean),
        "max": max(clean),
        "avg": statistics.fmean(clean),
        "p50": percentile(clean, 0.50),
        "p90": percentile(clean, 0.90),
        "p95": percentile(clean, 0.95),
        "p99": percentile(clean, 0.99),
    }


def read_events(paths: list[Path]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for path in paths:
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, 1):
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    event = json.loads(stripped)
                except json.JSONDecodeError as error:
                    raise SystemExit(f"{path}:{line_number}: invalid JSON: {error}") from error
                event["_trace_file"] = str(path)
                event["_line_number"] = line_number
                event["event_type"] = event.get("event_type") or event.get("event")
                events.append(event)
    return events


def event_time(event: dict[str, Any] | None) -> float | None:
    if event is None:
        return None
    value = event.get("wall_time_ms")
    if isinstance(value, (int, float)):
        return float(value)
    return None


def height_key(event: dict[str, Any]) -> tuple[int, str] | None:
    height = event.get("height")
    block_hash = event.get("block_hash")
    if isinstance(height, int) and isinstance(block_hash, str) and block_hash:
        return height, block_hash
    return None


def first_event(events: list[dict[str, Any]], event_type: str) -> dict[str, Any] | None:
    candidates = [event for event in events if event.get("event_type") == event_type and event_time(event) is not None]
    if not candidates:
        return None
    return min(candidates, key=lambda event: event_time(event) or 0)


def last_event(events: list[dict[str, Any]], event_type: str) -> dict[str, Any] | None:
    candidates = [event for event in events if event.get("event_type") == event_type and event_time(event) is not None]
    if not candidates:
        return None
    return max(candidates, key=lambda event: event_time(event) or 0)


def duration_between(start: dict[str, Any] | None, end: dict[str, Any] | None) -> float | None:
    if not start or not end:
        return None
    start_time = event_time(start)
    end_time = event_time(end)
    if start_time is None or end_time is None:
        return None
    return end_time - start_time


def build_block_summaries(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_block: dict[tuple[int, str], list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        key = height_key(event)
        if key:
            by_block[key].append(event)

    summaries: list[dict[str, Any]] = []
    for (height, block_hash), block_events in sorted(by_block.items()):
        proposal_start = first_event(block_events, "proposal_build_start")
        proposal_built = first_event(block_events, "proposal_built")
        proposal_sent = first_event(block_events, "proposal_sent") or first_event(block_events, "vote_request_sent")
        first_vote_request = first_event(block_events, "vote_request_received")
        first_vote_response = first_event(block_events, "vote_response_received_by_proposer")
        qc_threshold = first_event(block_events, "qc_threshold_reached")
        commit_start = first_event(block_events, "block_commit_start")
        commit_end = first_event(block_events, "block_commit_end") or first_event(block_events, "block_committed_timing")
        committed_timing = first_event(block_events, "block_committed_timing")

        vote_validation = [
            event.get("duration_ms")
            for event in block_events
            if event.get("event_type") == "vote_validation_end" and isinstance(event.get("duration_ms"), (int, float))
        ]
        pqc_sign = [
            event.get("duration_ms")
            for event in block_events
            if event.get("event_type") == "pqc_vote_sign_end" and isinstance(event.get("duration_ms"), (int, float))
        ]
        pqc_verify = [
            event.get("duration_ms")
            for event in block_events
            if event.get("event_type") == "pqc_vote_verify_end" and isinstance(event.get("duration_ms"), (int, float))
        ]
        vote_response_elapsed = [
            event.get("elapsed_since_request_ms")
            for event in block_events
            if event.get("event_type") == "vote_response_sent"
            and isinstance(event.get("elapsed_since_request_ms"), (int, float))
        ]
        vote_response_received_times = [
            event_time(event)
            for event in block_events
            if event.get("event_type") == "vote_response_received_by_proposer" and event_time(event) is not None
        ]

        block_commit_time = None
        next_eligibility = None
        if committed_timing:
            block_commit_time = committed_timing.get("block_commit_time_ms")
            next_eligibility = committed_timing.get("next_proposal_eligibility_time_ms")

        proposal_build_duration = (
            (proposal_built or {}).get("duration_ms")
            if isinstance((proposal_built or {}).get("duration_ms"), (int, float))
            else duration_between(proposal_start, proposal_built)
        )
        proposal_start_wall_time = event_time(proposal_start)
        if proposal_start_wall_time is None and proposal_built and isinstance(proposal_build_duration, (int, float)):
            built_time = event_time(proposal_built)
            if built_time is not None:
                proposal_start_wall_time = built_time - proposal_build_duration

        summary = {
            "height": height,
            "block_hash": block_hash,
            "proposer": (proposal_start or proposal_built or proposal_sent or {}).get("chosen_proposer")
            or (proposal_start or proposal_built or proposal_sent or {}).get("proposer"),
            "block_timestamp": (proposal_built or commit_end or {}).get("block_timestamp"),
            "proposal_start_wall_time_ms": proposal_start_wall_time,
            "proposal_build_duration_ms": proposal_build_duration,
            "proposal_sent_after_build_ms": duration_between(proposal_built, proposal_sent),
            "proposal_to_vote_request_receive_ms": duration_between(proposal_sent, first_vote_request),
            "vote_validation_duration_ms": max(vote_validation) if vote_validation else None,
            "pqc_sign_duration_ms": max(pqc_sign) if pqc_sign else None,
            "pqc_verify_duration_ms": max(pqc_verify) if pqc_verify else None,
            "vote_response_elapsed_since_request_ms": max(vote_response_elapsed) if vote_response_elapsed else None,
            "vote_response_received_by_proposer_ms": (
                max(vote_response_received_times) - event_time(proposal_sent)
                if vote_response_received_times and proposal_sent and event_time(proposal_sent) is not None
                else None
            ),
            "qc_threshold_from_proposal_sent_ms": duration_between(proposal_sent, qc_threshold),
            "qc_threshold_from_first_vote_ms": duration_between(first_vote_response, qc_threshold),
            "qc_threshold_elapsed_ms": (qc_threshold or {}).get("elapsed_ms"),
            "commit_duration_ms": (commit_end or {}).get("commit_duration_ms")
            if isinstance((commit_end or {}).get("commit_duration_ms"), (int, float))
            else duration_between(commit_start, commit_end),
            "post_commit_to_next_proposal_eligibility_ms": (
                next_eligibility - block_commit_time
                if isinstance(next_eligibility, (int, float)) and isinstance(block_commit_time, (int, float))
                else None
            ),
            "commit_wall_time_ms": event_time(commit_end),
            "next_proposal_eligibility_time_ms": next_eligibility,
            "rounds": sorted({event.get("round") for event in block_events if isinstance(event.get("round"), int)}),
            "local_view_rounds": sorted({event.get("local_view_round") for event in block_events if isinstance(event.get("local_view_round"), int)}),
            "peer_counts": [
                event.get("network_peer_count")
                for event in block_events
                if isinstance(event.get("network_peer_count"), int)
            ],
            "rejected_reasons": [
                event.get("reason")
                for event in block_events
                if event.get("event_type") == "rejected_proposal" and event.get("reason")
            ],
            "same_height_supersede_events": sum(
                1
                for event in block_events
                if event.get("event_type") == "rejected_proposal"
                and event.get("fail_closed_same_height_supersede") is True
            ),
            "stale_transient_lock_recovery_events": sum(
                1 for event in block_events if event.get("event_type") == "stale_transient_lock_recovery"
            ),
            "event_count": len(block_events),
        }
        summaries.append(summary)

    committed = [summary for summary in summaries if summary.get("commit_wall_time_ms") is not None]
    committed.sort(key=lambda item: (item["commit_wall_time_ms"], item["height"]))
    previous = None
    for summary in committed:
        if previous:
            summary["block_wall_interval_ms"] = summary["commit_wall_time_ms"] - previous["commit_wall_time_ms"]
            if isinstance(summary.get("block_timestamp"), int) and isinstance(previous.get("block_timestamp"), int):
                summary["block_timestamp_interval_ms"] = (summary["block_timestamp"] - previous["block_timestamp"]) * 1000
            if isinstance(previous.get("next_proposal_eligibility_time_ms"), (int, float)):
                proposal_start_wall_time = summary.get("proposal_start_wall_time_ms")
                if isinstance(proposal_start_wall_time, (int, float)):
                    summary["proposer_gap_after_previous_eligibility_ms"] = (
                        proposal_start_wall_time - previous["next_proposal_eligibility_time_ms"]
                    )
            proposal_start_wall_time = summary.get("proposal_start_wall_time_ms")
            if isinstance(proposal_start_wall_time, (int, float)):
                summary["proposer_gap_after_previous_commit_ms"] = (
                    proposal_start_wall_time - previous["commit_wall_time_ms"]
                )
        previous = summary
    return summaries


def classify(summary: dict[str, Any]) -> tuple[str, str, str]:
    distributions = summary["event_latency_distributions"]
    block_p95 = distributions.get("block_timestamp_interval_ms", {}).get("p95")
    wall_p95 = distributions.get("block_wall_interval_ms", {}).get("p95")
    vote_p90 = distributions.get("qc_threshold_elapsed_ms", {}).get("p90") or 0
    vote_from_proposal_p90 = distributions.get("qc_threshold_from_proposal_sent_ms", {}).get("p90") or 0
    post_commit_p90 = distributions.get("post_commit_to_next_proposal_eligibility_ms", {}).get("p90") or 0
    proposer_gap_p90 = distributions.get("proposer_gap_after_previous_commit_ms", {}).get("p90") or 0
    proposer_gap_after_eligibility_p95 = distributions.get("proposer_gap_after_previous_eligibility_ms", {}).get("p95") or 0
    p2p_p90 = distributions.get("proposal_to_vote_request_receive_ms", {}).get("p90") or 0
    pqc_sign_p95 = distributions.get("pqc_sign_duration_ms", {}).get("p95") or 0
    pqc_verify_p95 = distributions.get("pqc_verify_duration_ms", {}).get("p95") or 0

    has_slow_cadence = (block_p95 is not None and block_p95 > 4000) or (
        block_p95 is None and wall_p95 is not None and wall_p95 > 4000
    )
    if summary["stale_transient_lock_recovery_count"] > 0:
        return (
            "transient_lock_reconciliation_delay",
            "medium",
            "stale transient lock recovery events were present in the trace",
        )
    if summary["same_height_supersede_count"] > 0:
        return (
            "view_rotation_or_timeout_anchor",
            "medium",
            "fail-closed same-height supersede events were present in the trace",
        )
    if summary["view_round_churn_count"] > max(1, summary["committed_block_count"] // 10):
        return (
            "view_rotation_or_timeout_anchor",
            "medium",
            "above-baseline round/view churn was present across committed blocks",
        )
    if has_slow_cadence and max(pqc_sign_p95, pqc_verify_p95) > 1000:
        return (
            "pqc_sign_verify_cost",
            "medium",
            "slow cadence coincides with high PQC sign/verify p95 duration",
        )
    if has_slow_cadence and p2p_p90 > 500:
        return (
            "p2p_delivery_delay",
            "medium",
            "slow cadence coincides with high proposal-to-vote-request delivery latency",
        )
    if has_slow_cadence and max(vote_p90, vote_from_proposal_p90) > 1000:
        return (
            "vote_collection_delay",
            "medium",
            "slow cadence coincides with high QC threshold or vote collection latency",
        )
    if has_slow_cadence and proposer_gap_after_eligibility_p95 > 1000:
        return (
            "scheduler_or_slot_eligibility_gap",
            "medium",
            "slow cadence coincides with proposer gaps after the next proposal was already eligible",
        )
    if has_slow_cadence and max(post_commit_p90, proposer_gap_p90) > 1000:
        return (
            "proposer_post_commit_wait",
            "medium",
            "slow cadence coincides with post-commit eligibility/proposer gap latency",
        )
    if not has_slow_cadence and max(post_commit_p90, proposer_gap_p90) > 1000:
        return (
            "scheduler_or_slot_eligibility_gap",
            "low",
            "cadence did not exceed 4s locally, but proposer gap timing is the largest recurring delay",
        )
    if not has_slow_cadence:
        return (
            "inconclusive",
            "low",
            "local trace did not reproduce slow cadence and no dominant internal delay crossed the classifier threshold",
        )
    return (
        "inconclusive",
        "low",
        "slow cadence was observed but no single measured span clearly dominates",
    )


def summarize(events: list[dict[str, Any]]) -> dict[str, Any]:
    block_summaries = build_block_summaries(events)
    committed = [summary for summary in block_summaries if summary.get("commit_wall_time_ms") is not None]
    event_counts = Counter(event.get("event_type", "unknown") for event in events)
    rejected_reasons = Counter()
    for event in events:
        if event.get("event_type") == "rejected_proposal":
            rejected_reasons[str(event.get("reason", "unknown"))] += 1

    segment_values = {
        segment: [
            summary[segment]
            for summary in block_summaries
            if isinstance(summary.get(segment), (int, float))
        ]
        for segment in MAJOR_SEGMENTS
    }
    distributions = {segment: distribution(values) for segment, values in segment_values.items()}
    top_slowest = sorted(
        committed,
        key=lambda item: item.get("block_timestamp_interval_ms")
        if isinstance(item.get("block_timestamp_interval_ms"), (int, float))
        else item.get("block_wall_interval_ms", -1),
        reverse=True,
    )[:10]

    summary = {
        "trace_files": sorted({event["_trace_file"] for event in events}),
        "event_count": len(events),
        "event_counts": dict(sorted(event_counts.items())),
        "first_wall_time_ms": min((event_time(event) for event in events if event_time(event) is not None), default=None),
        "last_wall_time_ms": max((event_time(event) for event in events if event_time(event) is not None), default=None),
        "committed_block_count": len(committed),
        "min_committed_height": min((item["height"] for item in committed), default=None),
        "max_committed_height": max((item["height"] for item in committed), default=None),
        "event_latency_distributions": distributions,
        "top_slowest_blocks": top_slowest,
        "rejected_proposal_count": sum(rejected_reasons.values()),
        "rejected_reasons": dict(rejected_reasons),
        "stale_transient_lock_recovery_count": sum(
            1 for event in events if event.get("event_type") == "stale_transient_lock_recovery"
        ),
        "same_height_supersede_count": sum(
            1
            for event in events
            if event.get("event_type") == "rejected_proposal"
            and event.get("fail_closed_same_height_supersede") is True
        ),
        "view_round_churn_count": sum(
            1
            for item in committed
            if any(round_number and round_number > 1 for round_number in item.get("rounds", []))
            or any(round_number and round_number > 0 for round_number in item.get("local_view_rounds", []))
        ),
        "block_summaries": block_summaries,
    }
    delay_class, confidence, reason = classify(summary)
    summary["delay_classification"] = {
        "class": delay_class,
        "confidence": confidence,
        "reason": reason,
    }
    return summary


def fmt_ms(value: Any) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, (int, float)):
        return f"{value:.1f}"
    return str(value)


def print_table(summary: dict[str, Any]) -> None:
    print("Consensus Timing Trace Summary")
    print(f"events={summary['event_count']} committed_blocks={summary['committed_block_count']} "
          f"height_range={summary['min_committed_height']}..{summary['max_committed_height']}")
    classification = summary["delay_classification"]
    print(f"classification={classification['class']} confidence={classification['confidence']}")
    print(f"reason={classification['reason']}")
    print()
    print("Major Segment Distributions (ms)")
    print(f"{'segment':44} {'count':>6} {'p50':>10} {'p90':>10} {'p95':>10} {'p99':>10} {'max':>10}")
    for segment in MAJOR_SEGMENTS:
        dist = summary["event_latency_distributions"][segment]
        print(
            f"{segment:44} {dist['count']:6} {fmt_ms(dist['p50']):>10} {fmt_ms(dist['p90']):>10} "
            f"{fmt_ms(dist['p95']):>10} {fmt_ms(dist['p99']):>10} {fmt_ms(dist['max']):>10}"
        )
    print()
    print("Top Slowest Blocks")
    print(f"{'height':>8} {'hash':12} {'ts_interval':>12} {'wall_interval':>13} {'qc_elapsed':>11} {'post_commit':>12} {'proposer_gap':>12}")
    for item in summary["top_slowest_blocks"]:
        print(
            f"{item['height']:8} {item['block_hash'][:12]} "
            f"{fmt_ms(item.get('block_timestamp_interval_ms')):>12} "
            f"{fmt_ms(item.get('block_wall_interval_ms')):>13} "
            f"{fmt_ms(item.get('qc_threshold_elapsed_ms')):>11} "
            f"{fmt_ms(item.get('post_commit_to_next_proposal_eligibility_ms')):>12} "
            f"{fmt_ms(item.get('proposer_gap_after_previous_commit_ms')):>12}"
        )
    print()
    print("Event Counts")
    for event_type, count in summary["event_counts"].items():
        print(f"{event_type}: {count}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("traces", nargs="+", type=Path, help="Trace JSONL file(s)")
    parser.add_argument("--summary-json", type=Path, help="Write summary JSON to this path")
    parser.add_argument("--table", type=Path, help="Write human-readable table to this path")
    args = parser.parse_args()

    events = read_events(args.traces)
    summary = summarize(events)

    if args.summary_json:
        args.summary_json.parent.mkdir(parents=True, exist_ok=True)
        args.summary_json.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    if args.table:
        args.table.parent.mkdir(parents=True, exist_ok=True)
        with args.table.open("w", encoding="utf-8") as handle:
            original = sys.stdout
            sys.stdout = handle
            try:
                print_table(summary)
            finally:
                sys.stdout = original
    else:
        print_table(summary)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
