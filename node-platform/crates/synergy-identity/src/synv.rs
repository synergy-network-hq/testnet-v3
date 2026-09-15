pub(crate) fn valid_synv(value: &str) -> bool {
    value.len() >= 12
        && value.starts_with("synv1")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}
