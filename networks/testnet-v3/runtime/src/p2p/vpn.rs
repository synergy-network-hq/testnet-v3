//! Validator VPN transport policy.
//!
//! A validator identity is authorized by the genesis-bound membership and
//! validator lifecycle. This module only resolves and validates the private
//! network route used to reach that already-authorized identity; possession of
//! a VPN address never grants consensus authority.

use crate::config::NodeConfig;
use crate::p2p::transport::parse_dial_address;
use crate::p2p::validator_transport_registry::validator_transport_for;

const VALIDATOR_P2P_PORT: u16 = 5622;

pub(super) fn normalize_validator_address_target(value: &str) -> Option<String> {
    let value = value.trim();
    if value.starts_with("synv1")
        && !value.contains(':')
        && value.len() >= 12
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric())
    {
        Some(value.to_string())
    } else {
        None
    }
}

pub(super) fn validator_vpn_transport_for_target(
    config: &NodeConfig,
    validator_address: &str,
) -> Option<String> {
    let qualification_mode = chain1266_private_qualification_mode();
    let validator_address = normalize_validator_address_target(validator_address)?;

    // Production routes are identity-bound entries from the verified provider
    // registry. A release-time topology file is not a transport authority and
    // cannot silently repair an incomplete signed registry.
    if !qualification_mode {
        if let Some(dial_address) = validator_transport_for(&validator_address) {
            let dial_address = parse_dial_address(&dial_address)?;
            return is_validator_vpn_dial_address(&dial_address).then_some(dial_address);
        }

        // Test fixtures model the historical qualification overlay without
        // weakening production registry admission.
        if !cfg!(test) {
            return None;
        }
    }

    configured_validator_vpn_transport_for_target(config, &validator_address, qualification_mode)
}

pub(super) fn validator_vpn_transport_for_target_with_static_fallback(
    config: &NodeConfig,
    validator_address: &str,
    allow_static_fallback: bool,
) -> Option<String> {
    let qualification_mode = chain1266_private_qualification_mode();
    let validator_address = normalize_validator_address_target(validator_address)?;

    // This explicit helper exists only for qualification and unit-test
    // callers. Production discovery must use validator_vpn_transport_for_target
    // above, which never falls back to static installer routes.
    if !qualification_mode {
        if let Some(dial_address) = validator_transport_for(&validator_address) {
            let dial_address = parse_dial_address(&dial_address)?;
            if is_validator_vpn_dial_address(&dial_address) {
                return Some(dial_address);
            }
        }
    }
    if !allow_static_fallback {
        return None;
    }
    configured_validator_vpn_transport_for_target(config, &validator_address, qualification_mode)
}

pub(super) fn configured_validator_vpn_transport_for_target(
    config: &NodeConfig,
    validator_address: &str,
    require_private_qualification_overlay: bool,
) -> Option<String> {
    config
        .network
        .validator_vpn_transports
        .iter()
        .find_map(|transport| {
            let configured_validator =
                normalize_validator_address_target(&transport.validator_address)?;
            if configured_validator != validator_address {
                return None;
            }
            let dial_address = parse_dial_address(&transport.dial_address)?;
            let approved = if require_private_qualification_overlay {
                is_private_qualification_innernet_dial_address(&dial_address, 10)
            } else {
                is_validator_vpn_dial_address(&dial_address)
            };
            approved.then_some(dial_address)
        })
}

pub(super) fn chain1266_private_qualification_mode() -> bool {
    std::env::var(crate::desired_state::CHAIN1266_QUALIFICATION_MODE_ENV).as_deref() == Ok("1")
}

pub(super) fn is_validator_vpn_dial_address(value: &str) -> bool {
    is_canonical_netbird_validator_dial_address(value)
}

pub(super) fn is_current_validator_vpn_dial_address(value: &str) -> bool {
    is_validator_vpn_dial_address(value)
        || (chain1266_private_qualification_mode()
            && is_private_qualification_innernet_dial_address(value, 10))
}

pub(super) fn is_canonical_netbird_validator_dial_address(value: &str) -> bool {
    // NetBird assigns validator routes dynamically from 10.69.0.0/16. Do not
    // treat historical subnets or a route itself as authorization evidence.
    is_innernet_dial_address_in_subnet(value, 69)
        || (cfg!(test) && is_innernet_dial_address(value, 70, 10))
}

pub(super) fn is_private_qualification_innernet_dial_address(value: &str, third_octet: u8) -> bool {
    is_innernet_dial_address(value, 126, third_octet)
}

pub(super) fn is_validator_vpn_relayer_dial_address(value: &str) -> bool {
    is_innernet_dial_address(value, 69, 1)
        || (cfg!(test) && is_innernet_dial_address(value, 70, 20))
}

pub(super) fn is_current_validator_vpn_relayer_dial_address(value: &str) -> bool {
    is_validator_vpn_relayer_dial_address(value)
        || (chain1266_private_qualification_mode()
            && is_private_qualification_innernet_dial_address(value, 20))
}

/// Inbound TCP peers use an ephemeral source port. The authenticated relayer
/// role still has to originate from a canonical validator-VPN host range.
pub(super) fn is_validator_vpn_relayer_source_host(value: &str) -> bool {
    let Some((octets, _port)) = parse_validator_vpn_endpoint(value) else {
        return false;
    };
    (octets[0] == 10 && octets[1] == 69 && octets[2] == 1 && (1..=254).contains(&octets[3]))
        || (cfg!(test)
            && octets[0] == 10
            && octets[1] == 70
            && octets[2] == 20
            && (1..=254).contains(&octets[3]))
}

fn is_innernet_dial_address(value: &str, second_octet: u8, third_octet: u8) -> bool {
    let Some((octets, port)) = parse_validator_vpn_endpoint(value) else {
        return false;
    };
    port == VALIDATOR_P2P_PORT
        && octets[0] == 10
        && octets[1] == second_octet
        && octets[2] == third_octet
        && (1..=254).contains(&octets[3])
}

fn is_innernet_dial_address_in_subnet(value: &str, second_octet: u8) -> bool {
    let Some((octets, port)) = parse_validator_vpn_endpoint(value) else {
        return false;
    };
    port == VALIDATOR_P2P_PORT
        && octets[0] == 10
        && octets[1] == second_octet
        && (1..=254).contains(&octets[3])
}

fn parse_validator_vpn_endpoint(value: &str) -> Option<([u8; 4], u16)> {
    let normalized = parse_dial_address(value)?;
    let (host, port) = normalized.rsplit_once(':')?;
    let port = port.parse::<u16>().ok()?;
    let octets = host
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .parse::<std::net::Ipv4Addr>()
        .ok()?
        .octets();
    Some((octets, port))
}

#[cfg(test)]
mod tests {
    use super::{
        is_canonical_netbird_validator_dial_address, is_validator_vpn_relayer_dial_address,
    };

    #[test]
    fn accepts_assigned_netbird_routes_but_not_host_or_port_lookalikes() {
        assert!(is_canonical_netbird_validator_dial_address(
            "10.69.132.92:5622"
        ));
        assert!(!is_canonical_netbird_validator_dial_address(
            "10.70.132.92:5622"
        ));
        assert!(!is_canonical_netbird_validator_dial_address(
            "10.69.132.0:5622"
        ));
        assert!(!is_canonical_netbird_validator_dial_address(
            "10.69.132.92:5623"
        ));
        assert!(is_validator_vpn_relayer_dial_address("10.69.1.42:5622"));
    }
}
