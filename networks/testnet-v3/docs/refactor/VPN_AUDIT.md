# VPN audit

Validator VPN handling is currently embedded in `p2p/networking.rs`, including `network.validator_vpn_transports`, NetBird-range qualification, relayer checks, and route resolution. This proves the VPN is currently transport plumbing but also shows it is coupled to P2P behavior.

Target state is a dedicated VPN/transport-registry subsystem: authorization proof produces an enrollment request; NetBird allocation and lease material produce authenticated transport routes; P2P consumes a route lease without treating VPN membership as consensus authority. Existing connected validators must continue during enrollment-control outage.
