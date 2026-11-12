#[derive(Debug)]
pub struct OneTimeEnrollmentKey(Option<String>);
impl OneTimeEnrollmentKey {
    pub fn new(value: String) -> Result<Self, String> {
        if value.is_empty() {
            Err("empty enrollment material".into())
        } else {
            Ok(Self(Some(value)))
        }
    }
    pub fn take(&mut self) -> Result<String, String> {
        self.0
            .take()
            .ok_or_else(|| "enrollment material already consumed".into())
    }
}
impl Drop for OneTimeEnrollmentKey {
    fn drop(&mut self) {
        if let Some(value) = self.0.as_mut() {
            value.clear()
        }
    }
}
