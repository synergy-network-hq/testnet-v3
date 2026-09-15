/// Internal execution messages are never accepted from public transaction
/// ingress. This marker keeps the transport boundary explicit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InternalIngress;

impl InternalIngress {
    pub const fn may_determine_finality(self) -> bool {
        false
    }
}
