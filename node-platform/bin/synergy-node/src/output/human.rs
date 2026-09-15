use serde_json::Value;

pub fn render(value: &Value) -> String {
    match value {
        Value::Object(fields) => fields
            .iter()
            .map(|(key, value)| format!("{key}: {}", scalar(value)))
            .collect::<Vec<_>>()
            .join("\n"),
        _ => scalar(value),
    }
}

fn scalar(value: &Value) -> String {
    match value {
        Value::Null => "-".into(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::String(value) => value.clone(),
        Value::Array(values) => values.iter().map(scalar).collect::<Vec<_>>().join(", "),
        Value::Object(_) => serde_json::to_string(value).unwrap_or_else(|_| "<unavailable>".into()),
    }
}
