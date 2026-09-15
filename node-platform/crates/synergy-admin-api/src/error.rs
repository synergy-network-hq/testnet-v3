impl crate::AdminError {
    pub fn forbidden(message: impl Into<String>) -> Self {
        Self {
            code: "forbidden".into(),
            message: message.into(),
            retryable: false,
        }
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        Self {
            code: "conflict".into(),
            message: message.into(),
            retryable: false,
        }
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self {
            code: "internal".into(),
            message: message.into(),
            retryable: true,
        }
    }
}
