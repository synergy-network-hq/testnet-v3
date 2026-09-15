//! Canonical P2P transport endpoint parsing.

/// Parses a supported bootstrap or discovery endpoint into canonical
/// \`host:port\` / \`[ipv6]:port\` form. Identity prefixes, paths, queries, and
/// fragments are transport decoration and intentionally excluded.
pub fn parse_dial_address(endpoint: &str) -> Option<String> {
    let raw = endpoint.trim();
    if raw.is_empty() {
        return None;
    }
    let raw = raw
        .strip_prefix("snr://")
        .or_else(|| raw.strip_prefix("enode://"))
        .unwrap_or(raw);
    let raw = raw.rsplit_once('@').map(|(_, right)| right).unwrap_or(raw);
    let raw = raw.split('/').next().unwrap_or(raw);
    let raw = raw.split('?').next().unwrap_or(raw);
    let raw = raw.split('#').next().unwrap_or(raw);
    normalize_dial_target(raw.trim())
}

fn normalize_dial_target(dial: &str) -> Option<String> {
    let dial = dial.trim();
    if dial.is_empty() {
        return None;
    }
    if let Some(stripped) = dial.strip_prefix('[') {
        let (host, port) = stripped.rsplit_once("]:")?;
        return normalize_host_port(host, port);
    }
    let (host, port) = dial.rsplit_once(':')?;
    normalize_host_port(host, port)
}

fn normalize_host_port(host: &str, port: &str) -> Option<String> {
    let host = host
        .trim()
        .trim_matches('[')
        .trim_matches(']')
        .trim_end_matches('.');
    let port = port.trim().parse::<u16>().ok()?;
    if port == 0 || host.is_empty() || !is_plausible_dial_host(host) {
        return None;
    }
    match host.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V6(_)) => Some(format!("[{host}]:{port}")),
        Ok(std::net::IpAddr::V4(_)) => Some(format!("{host}:{port}")),
        Err(_) if host.contains(':') => None,
        Err(_) => Some(format!("{host}:{port}")),
    }
}

fn is_plausible_dial_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") || host.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    host.contains('.')
        && host.chars().all(|character| {
            character.is_ascii_alphanumeric() || character == '-' || character == '.'
        })
}

#[cfg(test)]
mod tests {
    use super::parse_dial_address;
    #[test]
    fn strips_identity_and_normalizes_ipv6() {
        assert_eq!(
            parse_dial_address("snr://peer@74.208.227.23:5620"),
            Some("74.208.227.23:5620".to_string())
        );
        assert_eq!(
            parse_dial_address("enode://peer@[2a02:1812:172a:e900:1497:71dc:d720:e28e]:5620/path"),
            Some("[2a02:1812:172a:e900:1497:71dc:d720:e28e]:5620".to_string())
        );
    }
    #[test]
    fn rejects_non_dialable_host_and_zero_port() {
        assert_eq!(parse_dial_address("snr://peer@test:5620"), None);
        assert_eq!(parse_dial_address("127.0.0.1:0"), None);
    }
}
