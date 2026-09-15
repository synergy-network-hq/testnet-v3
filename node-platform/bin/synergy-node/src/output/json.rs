use serde::Serialize;

pub fn render(value: &impl Serialize) -> Result<String, String> {
    serde_json::to_string_pretty(value).map_err(|error| format!("serialize JSON output: {error}"))
}
