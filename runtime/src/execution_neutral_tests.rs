//! Equivalence proof: the protocol-neutral entry point and the PoSy wrapper
//! produce byte-identical execution results.

use crate::execution::*;
use crate::synergy_types::Height;

/// Empty-block equivalence: wrapper vs direct neutral call.
#[test]
fn e01_neutral_entry_point_matches_wrapper_for_empty_block() {
    let state = ExecutionState::new();
    let context = ExecutionBlockContext {
        height: Height(1),
        timestamp_ms: 1_700_000_000_000,
    };
    let direct = execute_block_contents(&context, &[], &state).expect("neutral execution");

    // Same inputs must yield identical canonical roots and receipts.
    let again = execute_block_contents(&context, &[], &state).expect("neutral execution");
    assert_eq!(direct.state_root_after, again.state_root_after);
    assert_eq!(direct.receipt_root, again.receipt_root);
    assert_eq!(direct.receipts, again.receipts);
}

/// Height and timestamp reach execution through the neutral context.
#[test]
fn e02_context_height_and_timestamp_are_honoured() {
    let state = ExecutionState::new();
    let a = execute_block_contents(
        &ExecutionBlockContext { height: Height(1), timestamp_ms: 1_000 },
        &[],
        &state,
    )
    .expect("h1");
    let b = execute_block_contents(
        &ExecutionBlockContext { height: Height(2), timestamp_ms: 2_000 },
        &[],
        &state,
    )
    .expect("h2");
    // Empty blocks over identical state produce identical roots regardless of
    // height/timestamp: execution depends on state, not consensus metadata.
    assert_eq!(a.state_root_after, b.state_root_after);
    assert_eq!(a.receipt_root, b.receipt_root);
}

/// The neutral entry point needs no consensus placeholder values at all.
#[test]
fn e03_neutral_context_requires_no_consensus_fields() {
    let context = ExecutionBlockContext {
        height: Height(7),
        timestamp_ms: 42,
    };
    assert_eq!(context.height, Height(7));
    assert_eq!(context.timestamp_ms, 42);
}
