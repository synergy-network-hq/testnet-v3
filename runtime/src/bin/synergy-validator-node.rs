use synergy_testnet::{config::load_node_config, role_profiles::NodeRole};

fn main() {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.as_slice() == ["release-binding"] {
        print!(
            "{}",
            include_str!("../../../launch/TESTNET_V3_RUNTIME_BINDING.json")
        );
        return;
    }
    // This is intentionally narrower than `preflight-release`: it proves that
    // a generated public configuration is accepted by the runtime's actual
    // TOML parser and consensus invariants without opening custody material,
    // loading Genesis/desired state, creating storage, or starting networking.
    if let [command, flag, path] = args.as_slice() {
        if command == "validate-config" && flag == "--config" {
            let config = load_node_config(Some(path)).unwrap_or_else(|error| {
                eprintln!("synergy-validator-node validate-config: {error}");
                std::process::exit(1);
            });
            if config.identity.role != "validator"
                || config.role.compiled_profile != NodeRole::Validator.profile().compiled_profile
                || config.identity.node_id.trim().is_empty()
            {
                eprintln!(
                    "synergy-validator-node validate-config: configuration is not a bound validator profile"
                );
                std::process::exit(1);
            }
            println!(
                "CHAIN1266_VALIDATOR_CONFIG_PARSED validator_id={} chain_id={} network_id={} protocol={} mode={}",
                config.identity.node_id,
                config.blockchain.chain_id,
                config.network.network_id,
                config.consensus.algorithm,
                config.consensus.mode,
            );
            return;
        }
    }
    synergy_testnet::role_runtime::run(
        "synergy-validator-node",
        Some(NodeRole::Validator.profile()),
    );
}
