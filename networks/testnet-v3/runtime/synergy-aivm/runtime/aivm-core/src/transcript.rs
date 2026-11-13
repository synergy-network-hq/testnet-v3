pub struct Transcript {
    pub job_id: String,
    pub model_id: String,
    pub status: String,
}

impl Transcript {
    pub fn new(job_id: &str, model_id: &str) -> Self {
        Transcript {
            job_id: job_id.to_string(),
            model_id: model_id.to_string(),
            status: "initialized".to_string(),
        }
    }

    pub fn update_status(&mut self, status: &str) {
        self.status = status.to_string();
    }
}
