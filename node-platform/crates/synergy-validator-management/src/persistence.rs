/// Atomic durable boundary for the complete validator-management state.
///
/// Implementations must refuse replacement when the current bytes differ from
/// `expected`; lifecycle transitions and idempotency records then become one
/// production commit.
pub trait ValidatorManagementStore {
    fn load(&self) -> Result<Option<Vec<u8>>, String>;

    fn compare_and_swap(
        &mut self,
        expected: Option<&[u8]>,
        replacement: &[u8],
    ) -> Result<(), String>;
}
