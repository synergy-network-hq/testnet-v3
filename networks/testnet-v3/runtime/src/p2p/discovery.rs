//! Authenticated bootstrap-discovery inputs.
//!
//! This module owns DNS/dnsaddr resolution only. It produces untrusted dial
//! candidates; `networking` remains responsible for applying local role scope,
//! identity-bound transport policy, and authenticated-peer admission before a
//! candidate can become a connection.

use crate::{debug, warn};
use hickory_resolver::config::ResolverConfig;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::RData;
use hickory_resolver::{Resolver, TokioResolver};
use std::collections::HashSet;
use tokio::runtime::{Builder as TokioRuntimeBuilder, Runtime as TokioRuntime};

const MAX_DNSADDR_REFERENCE_DEPTH: usize = 4;

struct BootstrapDnsResolver {
    resolver: TokioResolver,
    runtime: TokioRuntime,
}

/// Resolve configured dnsaddr TXT records into canonical TCP dial candidates.
/// DNS responses are discovery hints, never identity or membership evidence.
pub(crate) fn resolve_dns_bootstrap_targets(record_names: &[String]) -> Vec<String> {
    if record_names.is_empty() {
        return Vec::new();
    }

    let resolver = match build_dns_resolver() {
        Ok(resolver) => resolver,
        Err(error) => {
            warn!("p2p", "Failed to initialize DNS resolver for bootstrap discovery", "error" => error);
            return Vec::new();
        }
    };

    let mut visited = HashSet::<String>::new();
    let mut targets = HashSet::<String>::new();
    for record_name in record_names {
        collect_dnsaddr_record_targets(&resolver, record_name, 0, &mut visited, &mut targets);
    }

    let mut ordered = targets.into_iter().collect::<Vec<_>>();
    ordered.sort();
    ordered
}

fn build_dns_resolver() -> Result<BootstrapDnsResolver, String> {
    let runtime = TokioRuntimeBuilder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| error.to_string())?;
    let resolver = TokioResolver::builder_tokio()
        .and_then(|builder| builder.build())
        .or_else(|_| {
            Resolver::builder_with_config(
                ResolverConfig::default(),
                TokioRuntimeProvider::default(),
            )
            .build()
        })
        .map_err(|error| error.to_string())?;
    Ok(BootstrapDnsResolver { resolver, runtime })
}

fn collect_dnsaddr_record_targets(
    resolver: &BootstrapDnsResolver,
    record_name: &str,
    depth: usize,
    visited: &mut HashSet<String>,
    targets: &mut HashSet<String>,
) {
    let record_name = record_name.trim();
    if record_name.is_empty() || depth > MAX_DNSADDR_REFERENCE_DEPTH {
        return;
    }

    let canonical = record_name.trim_end_matches('.').to_string();
    if !visited.insert(canonical.clone()) {
        return;
    }

    match resolver
        .runtime
        .block_on(resolver.resolver.txt_lookup(canonical.clone()))
    {
        Ok(records) => {
            for record in records.answers() {
                let RData::TXT(txt_record) = &record.data else {
                    continue;
                };
                for txt in &txt_record.txt_data {
                    let Ok(value) = std::str::from_utf8(txt) else {
                        continue;
                    };
                    collect_dnsaddr_txt_target(resolver, value, depth, visited, targets);
                }
            }
        }
        Err(error) => {
            debug!(
                "p2p",
                "Bootstrap DNS TXT lookup failed",
                "record" => canonical,
                "error" => error.to_string()
            );
        }
    }
}

fn collect_dnsaddr_txt_target(
    resolver: &BootstrapDnsResolver,
    value: &str,
    depth: usize,
    visited: &mut HashSet<String>,
    targets: &mut HashSet<String>,
) {
    let value = value
        .trim()
        .trim_matches('"')
        .strip_prefix("dnsaddr=")
        .unwrap_or(value.trim())
        .trim();
    if value.is_empty() {
        return;
    }

    if let Some(next_record) = parse_dnsaddr_reference_record(value) {
        collect_dnsaddr_record_targets(resolver, &next_record, depth + 1, visited, targets);
    } else if let Some(dial) = parse_dnsaddr_multiaddr_to_dial_address(value) {
        targets.insert(dial);
    }
}

fn parse_dnsaddr_reference_record(value: &str) -> Option<String> {
    let referenced = value.strip_prefix("/dnsaddr/")?;
    let referenced = referenced.split('/').next()?.trim().trim_end_matches('.');
    (!referenced.is_empty()).then(|| format!("_dnsaddr.{referenced}"))
}

/// Parse the TCP subset of a dnsaddr multiaddr. UDP and malformed records are
/// deliberately rejected because the current P2P transport is TCP-only.
pub(crate) fn parse_dnsaddr_multiaddr_to_dial_address(value: &str) -> Option<String> {
    let segments = value
        .split('/')
        .filter(|segment| !segment.trim().is_empty())
        .collect::<Vec<_>>();
    let mut host = None;
    let mut port = None;
    let mut transport = None;
    let mut index = 0usize;
    while index + 1 < segments.len() {
        let key = segments[index];
        let value = segments[index + 1];
        match key {
            "dns" | "dns4" | "dns6" | "ip4" | "ip6" if host.is_none() => {
                host = Some(value.to_string());
            }
            "tcp" => {
                if let Ok(parsed) = value.parse::<u16>() {
                    port = Some(parsed);
                    transport = Some("tcp");
                }
            }
            "udp" => transport = Some("udp"),
            _ => {}
        }
        index += 2;
    }
    match (host, port, transport) {
        (Some(host), Some(port), Some("tcp")) => Some(format!("{host}:{port}")),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::parse_dnsaddr_multiaddr_to_dial_address;

    #[test]
    fn accepts_only_tcp_dnsaddr_multiaddrs() {
        assert_eq!(
            parse_dnsaddr_multiaddr_to_dial_address("/dns4/boot.synergy-network.io/tcp/5622"),
            Some("boot.synergy-network.io:5622".to_string())
        );
        assert_eq!(
            parse_dnsaddr_multiaddr_to_dial_address("/ip4/10.69.10.2/tcp/5622"),
            Some("10.69.10.2:5622".to_string())
        );
        assert_eq!(
            parse_dnsaddr_multiaddr_to_dial_address("/dns4/boot.synergy-network.io/udp/5622"),
            None
        );
        assert_eq!(
            parse_dnsaddr_multiaddr_to_dial_address("/dns4/boot.synergy-network.io/tcp/not-a-port"),
            None
        );
    }
}
