pub trait NetbirdManagementApi {
    fn revoke_peer(&mut self, peer_id: &str) -> Result<(), String>;
    fn rotate_setup_key(&mut self, enrollment_id: &str) -> Result<String, String>;
    fn peer_is_authorized(&self, peer_id: &str) -> Result<bool, String>;
}
