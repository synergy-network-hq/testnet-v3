use crate::NodeIdError;

const SUFFIX: &str = ".node";
const MIN_LABEL_LENGTH: usize = 3;
const MAX_LABEL_LENGTH: usize = 63;

/// Returns the canonical lowercase representation of a Synergy NodeID.
///
/// # Errors
/// Returns NodeIdError when the input is not a valid single-label .node name.
pub fn normalize_node_id(value: &str) -> Result<String, NodeIdError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(NodeIdError::Empty);
    }
    if !trimmed.is_ascii() {
        return Err(NodeIdError::InvalidCharacter);
    }
    let normalized = trimmed.to_ascii_lowercase();
    let label = normalized
        .strip_suffix(SUFFIX)
        .ok_or(NodeIdError::InvalidSuffix)?;
    if !(MIN_LABEL_LENGTH..=MAX_LABEL_LENGTH).contains(&label.len()) {
        return Err(NodeIdError::InvalidLabelLength);
    }
    if label.starts_with('-') || label.ends_with('-') {
        return Err(NodeIdError::InvalidHyphen);
    }
    if !label
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(NodeIdError::InvalidCharacter);
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_nested_or_non_node_names() {
        assert_eq!(
            normalize_node_id("east.atlas.node"),
            Err(NodeIdError::InvalidCharacter)
        );
    }

    #[test]
    fn refuses_boundary_hyphens() {
        assert_eq!(
            normalize_node_id("-atlas.node"),
            Err(NodeIdError::InvalidHyphen)
        );
    }
}
