use crate::crypto::aegis_pqvm::SYNERGY_P2P_HANDSHAKE_V1;
use crate::synergy_types::Hash;
use std::net::IpAddr;

pub fn generate_pq_peer_address(aegis_pq_public_key_bytes: &[u8], ip: IpAddr, port: u16) -> String {
    let node_id = Hash::from_domain_bytes(SYNERGY_P2P_HANDSHAKE_V1, aegis_pq_public_key_bytes);
    format!("pqnode://{}@{}:{}", node_id.to_hex(), ip, port)
}

pub fn generate_enode(_ip: IpAddr, _port: u16) -> String {
    panic!("classical enode identities are disabled; use Aegis PQC peer identity bindings")
}
