use std::sync::Mutex;

use synergy_state::{StateDiff, WorldState};
use synergy_synq::{
    DeterministicContext, SynqArtifact, SynqExecutor, SynqHost, SynqTraceEvent, SynqTraceSink,
    SynqVm,
};
use synergy_transaction::SignedTransaction;

use super::{SynqRuntime, TransactionDispatch, TransactionExecutionContext};

pub trait SynqHostFactory {
    type Host: SynqHost;

    fn prepare(&self, state: &WorldState) -> Result<Self::Host, String>;
    fn finish(&self, host: Self::Host) -> Result<StateDiff, String>;
}

/// Narrow deterministic bridge from transaction execution into the canonical
/// SynQ VM/host contracts. A concrete VM and state host must be injected.
pub struct SynqRuntimeAdapter<V, F, T> {
    vm: V,
    hosts: F,
    trace: Mutex<T>,
}

impl<V, F, T> SynqRuntimeAdapter<V, F, T> {
    pub fn new(vm: V, hosts: F, trace: T) -> Self {
        Self {
            vm,
            hosts,
            trace: Mutex::new(trace),
        }
    }
}

impl<V, F, T> SynqRuntime for SynqRuntimeAdapter<V, F, T>
where
    V: SynqVm,
    F: SynqHostFactory,
    T: SynqTraceSink,
{
    type Error = String;

    fn execute_synq(
        &self,
        artifact: &[u8],
        input: &[u8],
        transaction: &SignedTransaction,
        context: TransactionExecutionContext<'_>,
        state: &WorldState,
    ) -> Result<TransactionDispatch, Self::Error> {
        let artifact = SynqArtifact::new(artifact.to_vec()).map_err(|error| error.to_string())?;
        let transaction_id = transaction.id().map_err(|error| error.to_string())?;
        let mut host = self.hosts.prepare(state)?;
        let deterministic_context = DeterministicContext {
            block_height: context.block_height,
            transaction_index: context.transaction_index,
        };
        if let Ok(mut trace) = self.trace.lock() {
            trace.record(SynqTraceEvent::ExecutionStarted {
                artifact_hash: artifact.code_hash.clone(),
                block_height: context.block_height,
                transaction_index: context.transaction_index,
                gas_limit: transaction.unsigned.fee_limit.gas_limit,
            });
        }
        let receipt = SynqExecutor::execute(
            &artifact,
            transaction_id,
            deterministic_context,
            input,
            transaction.unsigned.fee_limit.gas_limit,
            &self.vm,
            &mut host,
        )
        .map_err(|error| {
            if let Ok(mut trace) = self.trace.lock() {
                trace.record(SynqTraceEvent::ExecutionRejected {
                    reason: error.to_string(),
                });
            }
            error.to_string()
        })?;
        let state_diff = self.hosts.finish(host)?;
        state_diff
            .validate()
            .map_err(|error| format!("{error:?}"))?;
        if let Ok(mut trace) = self.trace.lock() {
            trace.record(SynqTraceEvent::ExecutionFinished {
                gas_used: receipt.gas_used,
                events: receipt.events,
            });
        }
        Ok(TransactionDispatch {
            state_diff,
            gas_used: receipt.gas_used,
        })
    }
}
