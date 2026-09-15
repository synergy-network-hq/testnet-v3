use crate::AuthorizedReveal;

/// State/VM adapter that owns transition semantics. The executor owns ordering.
pub trait DeterministicStateTransition {
    type State;
    type Error;

    fn apply(&self, state: &mut Self::State, reveal: &AuthorizedReveal) -> Result<(), Self::Error>;

    fn state_root(&self, state: &Self::State) -> String;
}
