use synergy_network::transport::{require_native_session_profile, NativeSessionProfileError};

#[test]
fn production_library_has_no_implicit_session_profile() {
    assert_eq!(
        require_native_session_profile(),
        Err(NativeSessionProfileError::UnapprovedPostQuantumSessionProfile)
    );
}

fn guarded(source: &str, declaration: &str, guard: &str) {
    let body = source
        .split_once(declaration)
        .expect("entrypoint exists")
        .1
        .split_once('{')
        .unwrap()
        .1
        .trim_start();
    let body = body
        .strip_prefix("let configuration = load(config_path).map_err(StartError::Configuration)?;")
        .unwrap_or(body)
        .trim_start();
    assert!(
        body.starts_with("#[cfg(not(test))]"),
        "only offline unit fixtures may bypass production gate"
    );
    assert!(
        body.lines().take(6).collect::<String>().contains(guard),
        "guard precedes network or lifecycle effects"
    );
}
#[test]
fn production_start_registration_and_both_socket_directions_are_guarded() {
    let session = include_str!("../../../bin/synergy-node/src/services/network_session.rs");
    for entry in ["pub fn run_inbound(", "pub fn run_outbound("] {
        guarded(session, entry, "require_native_session_profile()");
    }
    let network = include_str!("../../../bin/synergy-node/src/services/network.rs");
    for entry in ["pub fn registration(", "fn start(&mut self, cancellation:"] {
        guarded(network, entry, "require_native_session_profile()");
    }
    let startup = include_str!("../../../bin/synergy-node/src/commands/start.rs")
        .split_once("pub fn start_with_services(")
        .unwrap()
        .1
        .split_once("#[cfg(feature = \"qualification-timing\")]")
        .unwrap()
        .0;
    let secure = startup
        .find("apqe_transport::verify_runtime(&configuration)")
        .unwrap();
    let fallback = startup.find("#[cfg(not(test))]").unwrap();
    let enforced = startup
        .find("require_native_post_quantum_transport()")
        .unwrap();
    let identity = startup
        .find("selected_network::verify(&configuration)")
        .unwrap();
    assert!(startup.contains("if configuration.apqe_transport.is_some()"));
    assert!(secure < fallback && fallback < enforced && enforced < identity);
    let challenge = session
        .split_once("fn challenge()")
        .unwrap()
        .1
        .split_once("fn local_offer(")
        .unwrap()
        .0;
    assert!(challenge.contains("AegisProtectedPrimitives"));
    assert!(!challenge.contains("/dev/urandom"));
}
