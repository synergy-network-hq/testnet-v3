use synergy_admin_api::operations::AdminOperation;

pub fn operation(action: &str, key_id: &str) -> Result<AdminOperation, String> {
    super::identity::operation(action, key_id)
}
