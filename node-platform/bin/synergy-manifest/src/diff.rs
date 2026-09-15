use serde::Serialize;
use serde_json::Value;

use crate::sign::SignedManifest;

const MAX_DIFFERENCES: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ManifestDifference {
    pub field: String,
    pub left: String,
    pub right: String,
}

pub fn diff(
    left: &SignedManifest,
    right: &SignedManifest,
) -> Result<Vec<ManifestDifference>, String> {
    left.unsigned.validate()?;
    right.unsigned.validate()?;
    let left = serde_json::to_value(&left.unsigned)
        .map_err(|error| format!("encode left manifest: {error}"))?;
    let right = serde_json::to_value(&right.unsigned)
        .map_err(|error| format!("encode right manifest: {error}"))?;
    let mut differences = Vec::new();
    compare("$", &left, &right, &mut differences);
    Ok(differences)
}

fn compare(path: &str, left: &Value, right: &Value, differences: &mut Vec<ManifestDifference>) {
    if differences.len() >= MAX_DIFFERENCES || left == right {
        return;
    }
    match (left, right) {
        (Value::Object(left), Value::Object(right)) => {
            let keys = left
                .keys()
                .chain(right.keys())
                .collect::<std::collections::BTreeSet<_>>();
            for key in keys {
                let child = format!("{path}.{key}");
                compare(
                    &child,
                    left.get(key).unwrap_or(&Value::Null),
                    right.get(key).unwrap_or(&Value::Null),
                    differences,
                );
                if differences.len() >= MAX_DIFFERENCES {
                    break;
                }
            }
        }
        (Value::Array(left), Value::Array(right)) => {
            for index in 0..left.len().max(right.len()) {
                let child = format!("{path}[{index}]");
                compare(
                    &child,
                    left.get(index).unwrap_or(&Value::Null),
                    right.get(index).unwrap_or(&Value::Null),
                    differences,
                );
                if differences.len() >= MAX_DIFFERENCES {
                    break;
                }
            }
        }
        _ => differences.push(ManifestDifference {
            field: path.into(),
            left: render(left),
            right: render(right),
        }),
    }
}

fn render(value: &Value) -> String {
    let encoded = serde_json::to_string(value).unwrap_or_else(|_| "<unavailable>".into());
    const LIMIT: usize = 512;
    if encoded.len() <= LIMIT {
        return encoded;
    }
    let mut boundary = LIMIT;
    while !encoded.is_char_boundary(boundary) {
        boundary -= 1;
    }
    format!("{}...", &encoded[..boundary])
}
