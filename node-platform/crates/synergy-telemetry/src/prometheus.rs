use crate::TelemetrySnapshot;

pub fn encode_prometheus(snapshot: &TelemetrySnapshot, max_bytes: usize) -> Result<String, String> {
    if max_bytes == 0 {
        return Err("Prometheus output limit must be nonzero".into());
    }
    let mut output = String::new();
    for (name, value) in &snapshot.counters {
        let line = format!("synergy_{name} {value}\n");
        if output.len().saturating_add(line.len()) > max_bytes {
            return Err("Prometheus output exceeds configured limit".into());
        }
        output.push_str(&line);
    }
    Ok(output)
}
