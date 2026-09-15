use crate::{
    DeterministicExecutionInput, DeterministicStateTransition, ExecutionError, ExecutionOutcome,
};

/// Applies only ETDAG-established protected order. It cannot vote, certify, or finalize.
#[derive(Debug, Default)]
pub struct DeterministicExecutor;

impl DeterministicExecutor {
    pub fn execute<T: DeterministicStateTransition>(
        &self,
        input: &DeterministicExecutionInput,
        transition: &T,
        state: &mut T::State,
    ) -> Result<ExecutionOutcome, ExecutionError<T::Error>>
    where
        T::State: Clone,
    {
        input.validate().map_err(ExecutionError::Input)?;
        // A proposal is speculative until the entire ordered input succeeds.
        // Match the frozen runtime's execute_block clone-and-return behavior:
        // never expose a partially applied state after a failed transition.
        let mut working = state.clone();
        let mut applied_envelope_ids = Vec::with_capacity(input.ordered_reveals.len());
        for reveal in &input.ordered_reveals {
            transition
                .apply(&mut working, reveal)
                .map_err(ExecutionError::Transition)?;
            applied_envelope_ids.push(reveal.envelope_id.clone());
        }
        let state_root = transition.state_root(&working);
        if state_root.trim().is_empty() {
            return Err(ExecutionError::EmptyStateRoot);
        }
        *state = working;
        Ok(ExecutionOutcome {
            target_height: input.context.target_height,
            applied_envelope_ids,
            state_root,
        })
    }

    pub fn may_determine_finality(&self) -> bool {
        false
    }
}
