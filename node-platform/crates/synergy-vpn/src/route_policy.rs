pub const VALIDATOR_P2P_PORT: u16 = 5622;

/// Validates an endpoint whose identity, scope and exact address have already
/// been authorized by a verified transport snapshot. Overlay allocation is
/// supplied by that signed snapshot, not a historical installation's subnet.
/// This shape check does not authenticate a route or grant membership.
pub fn validate_authenticated_route(identity: &str, dial: &str) -> Result<String, VpnRouteError> {
    normalize_validator_address(identity).ok_or(VpnRouteError::InvalidIdentity)?;
    let address = dial
        .parse::<std::net::SocketAddrV4>()
        .map_err(|_| VpnRouteError::InvalidRoute)?;
    if address.port() != VALIDATOR_P2P_PORT || address.to_string() != dial {
        return Err(VpnRouteError::InvalidRoute);
    }
    if !address.ip().is_private() {
        return Err(VpnRouteError::WrongScope);
    }
    Ok(dial.to_owned())
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverlayScope {
    Validator,
    Sentry,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VpnRouteError {
    InvalidIdentity,
    InvalidRoute,
    WrongScope,
}

/// Validates an already-authorized identity's transport route. Callers must
/// obtain eligibility and active PoSy membership from their proper owners.
#[derive(Debug, Clone, Copy)]
pub struct VpnRoutePolicy {
    scope: OverlayScope,
}
impl VpnRoutePolicy {
    pub fn new(scope: OverlayScope) -> Self {
        Self { scope }
    }
    pub fn validate(&self, identity: &str, dial: &str) -> Result<String, VpnRouteError> {
        normalize_validator_address(identity).ok_or(VpnRouteError::InvalidIdentity)?;
        let (host, port) = dial.rsplit_once(':').ok_or(VpnRouteError::InvalidRoute)?;
        if port.parse::<u16>().ok() != Some(VALIDATOR_P2P_PORT)
            || port != VALIDATOR_P2P_PORT.to_string()
        {
            return Err(VpnRouteError::InvalidRoute);
        }
        let subnet = match self.scope {
            OverlayScope::Validator => "10.69.10.",
            OverlayScope::Sentry => "10.69.1.",
        };
        let suffix = host.strip_prefix(subnet).ok_or(VpnRouteError::WrongScope)?;
        if suffix.is_empty() || (suffix.len() > 1 && suffix.starts_with('0')) {
            return Err(VpnRouteError::InvalidRoute);
        }
        let octet = suffix
            .parse::<u8>()
            .map_err(|_| VpnRouteError::InvalidRoute)?;
        if octet == 0 {
            return Err(VpnRouteError::InvalidRoute);
        }
        Ok(dial.to_owned())
    }
}
/// Accepts the exact canonical validator-address shape used by the signed
/// Testnet-v3 transport registry; it is not membership authorization.
pub fn normalize_validator_address(value: &str) -> Option<String> {
    if synergy_address::address_kind(value) == synergy_address::AddressKind::Validator {
        return Some(value.to_string());
    }
    // Frozen authority identifiers remain accepted only as transport-registry
    // identity labels; canonical account/address validation is owned by
    // synergy-address and is enforced at transaction admission.
    ((8..=128).contains(&value.len())
        && value.starts_with("synv1")
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()))
    .then(|| value.to_string())
}
#[cfg(test)]
mod tests {
    use super::*;
    const ID: &str = "synv11lrh6jcxaejkj4zv994j7qwn2rk6u3ar4emn";
    #[test]
    fn authenticated_routes_use_signed_allocation_not_historical_subnet() {
        for dial in [
            "10.69.106.160:5622",
            "10.69.11.219:5622",
            "10.69.56.215:5622",
            "10.69.184.171:5622",
            "10.69.140.27:5622",
            "172.20.1.2:5622",
            "192.168.12.3:5622",
        ] {
            assert_eq!(validate_authenticated_route(ID, dial), Ok(dial.into()));
        }
        for dial in [
            "8.8.8.8:5622",
            "127.0.0.1:5622",
            "0.0.0.0:5622",
            "169.254.1.2:5622",
            "224.0.0.1:5622",
        ] {
            assert_eq!(
                validate_authenticated_route(ID, dial),
                Err(VpnRouteError::WrongScope)
            );
        }
        for dial in [
            "10.69.11.219:5623",
            "10.69.011.219:5622",
            "10.69.11.219:05622",
            "snr://peer@10.69.11.219:5622",
            "validator.local:5622",
        ] {
            assert_eq!(
                validate_authenticated_route(ID, dial),
                Err(VpnRouteError::InvalidRoute)
            );
        }
        assert_eq!(
            validate_authenticated_route("invalid", "10.69.11.219:5622"),
            Err(VpnRouteError::InvalidIdentity)
        );
    }
    #[test]
    fn validates_exact_frozen_validator_transport_shape() {
        let p = VpnRoutePolicy::new(OverlayScope::Validator);
        assert_eq!(
            p.validate(ID, "10.69.10.92:5622"),
            Ok("10.69.10.92:5622".into())
        );
        assert_eq!(
            p.validate(ID, "10.69.11.92:5622"),
            Err(VpnRouteError::WrongScope)
        );
        assert_eq!(
            p.validate(ID, "10.69.10.92:5623"),
            Err(VpnRouteError::InvalidRoute)
        );
        assert_eq!(
            p.validate(ID, "10.69.10.092:5622"),
            Err(VpnRouteError::InvalidRoute)
        );
        assert_eq!(
            p.validate(ID, "snr://peer@10.69.10.92:5622"),
            Err(VpnRouteError::WrongScope)
        );
        assert_eq!(
            p.validate("SYNV1validator0001", "10.69.10.92:5622"),
            Err(VpnRouteError::InvalidIdentity)
        );
    }
    #[test]
    fn sentry_scope_is_narrower_and_does_not_grant_authority() {
        let p = VpnRoutePolicy::new(OverlayScope::Sentry);
        assert!(p.validate(ID, "10.69.1.42:5622").is_ok());
        assert_eq!(
            p.validate(ID, "10.69.2.42:5622"),
            Err(VpnRouteError::WrongScope)
        );
    }
}
