# Current Canonical Node Platform File Tree

> Generated from the actual canonical remote checkout on synergy-val4. This is an implementation tree, not the target-state checklist.

~~~~text
node-platform/
|-- Cargo.lock
|-- Cargo.toml
|-- benches/
|   |-- block_validation.rs
|   |-- certificate_validation.rs
|   |-- etdag_encryption.rs
|   |-- etdag_ordering.rs
|   |-- etdag_reveal.rs
|   |-- etdag_validation.rs
|   |-- p2p.rs
|   |-- posy_vote_processing.rs
|   |-- signature_verification.rs
|   |-- state_transition.rs
|   +-- storage.rs
|-- bin/
|   |-- synergy-db/
|   |   |-- Cargo.toml
|   |   +-- src/
|   |       |-- export.rs
|   |       |-- inspect.rs
|   |       |-- main.rs
|   |       |-- migrate.rs
|   |       |-- repair.rs
|   |       +-- verify.rs
|   |-- synergy-genesis/
|   |   |-- Cargo.toml
|   |   +-- src/
|   |       |-- builder.rs
|   |       |-- etdag.rs
|   |       |-- main.rs
|   |       |-- network.rs
|   |       |-- signing.rs
|   |       |-- validator_set.rs
|   |       +-- verify.rs
|   |-- synergy-keytool/
|   |   |-- Cargo.toml
|   |   +-- src/
|   |       |-- aegis_keys.rs
|   |       |-- consensus_keys.rs
|   |       |-- etdag_keys.rs
|   |       |-- inspect.rs
|   |       |-- main.rs
|   |       |-- node_identity.rs
|   |       +-- rotation.rs
|   |-- synergy-manifest/
|   |   |-- Cargo.toml
|   |   +-- src/
|   |       |-- build.rs
|   |       |-- diff.rs
|   |       |-- inspect.rs
|   |       |-- main.rs
|   |       |-- sign.rs
|   |       +-- verify.rs
|   +-- synergy-node/
|       |-- Cargo.toml
|       +-- src/
|           |-- admin_client.rs
|           |-- cli.rs
|           |-- commands/
|           |   |-- ai.rs
|           |   |-- config.rs
|           |   |-- cross_chain.rs
|           |   |-- database.rs
|           |   |-- doctor.rs
|           |   |-- etdag.rs
|           |   |-- health.rs
|           |   |-- identity.rs
|           |   |-- init.rs
|           |   |-- join.rs
|           |   |-- keys.rs
|           |   |-- leave.rs
|           |   |-- manifest.rs
|           |   |-- mod.rs
|           |   |-- peers.rs
|           |   |-- posy.rs
|           |   |-- readiness.rs
|           |   |-- restart.rs
|           |   |-- role.rs
|           |   |-- sentry.rs
|           |   |-- snapshot.rs
|           |   |-- start.rs
|           |   |-- status.rs
|           |   |-- stop.rs
|           |   |-- sync.rs
|           |   |-- telemetry.rs
|           |   |-- upgrade.rs
|           |   |-- validator.rs
|           |   |-- version.rs
|           |   +-- vpn.rs
|           |-- main.rs
|           +-- output/
|               |-- human.rs
|               |-- json.rs
|               +-- mod.rs
|-- config/
|   |-- example/
|   |   |-- ai-compute.toml
|   |   |-- archive.toml
|   |   |-- cross_chain.toml
|   |   |-- indexer.toml
|   |   |-- observer.toml
|   |   |-- rpc-gateway.toml
|   |   |-- sentry.toml
|   |   +-- validator.toml
|   |-- limits.toml
|   |-- logging.toml
|   +-- telemetry.toml
|-- crates/
|   |-- synergy-admin-api/
|   |   |-- Cargo.toml
|   |   +-- src/
|   |       |-- audit.rs
|   |       |-- auth.rs
|   |       |-- authorization.rs
|   |       |-- client.rs
|   |       |-- error.rs
|   |       |-- events/
|   |       |   |-- backpressure.rs
|   |       |   |-- event.rs
|   |       |   |-- mod.rs
|   |       |   +-- stream.rs
|   |       |-- lib.rs
|   |       |-- operations/
|   |       |   |-- ai.rs
|   |       |   |-- config.rs
|   |       |   |-- cross_chain.rs
|   |       |   |-- etdag.rs
|   |       |   |-- identity.rs
|   |       |   |-- lifecycle.rs
|   |       |   |-- mod.rs
|   |       |   |-- peers.rs
|   |       |   |-- posy.rs
|   |       |   |-- sentry.rs
|   |       |   |-- storage.rs
|   |       |   |-- sync.rs
|   |       |   |-- telemetry.rs
|   |       |   |-- upgrade.rs
|   |       |   |-- validator.rs
|   |       |   +-- vpn.rs
|   |       |-- protocol.rs
|   |       +-- server.rs
|   |-- synergy-aegis/
|   |   |-- Cargo.toml
|   |   +-- src/
|   |       |-- attestation.rs
|   |       |-- audit.rs
|   |       |-- key_lifecycle.rs
|   |       |-- kms_bridge.rs
|   |       |-- lib.rs
|   |       |-- policy.rs
|   |       |-- signer.rs
|   |       +-- verifier.rs
|   |-- synergy-ai/
|   |   |-- Cargo.toml
|   |   +-- src/
|   |       |-- assurance/
|   |       |   |-- evaluation.rs
|   |       |   |-- independence.rs
|   |       |   |-- mod.rs
|   |       |   |-- reputation.rs
|   |       |   +-- verification.rs
|   |       |-- capability.rs
|   |       |-- compute/
|   |       |   |-- agent.rs
|   |       |   |-- inference.rs
|   |       |   |-- mod.rs
|   |       |   +-- training.rs
|   |       |-- coordination/
|   |       |   |-- federated.rs
|   |       |   |-- mod.rs
|   |       |   |-- routing.rs
|   |       |   +-- scheduler.rs
|   |       |-- data/
|   |       |   |-- dataset_provenance.rs
|   |       |   |-- mod.rs
|   |       |   |-- model_repository.rs
|   |       |   +-- vector_memory.rs
|   |       |-- job.rs
|   |       |-- lib.rs
|   |       |-- metrics.rs
|   |       |-- policy.rs
|   |       |-- provider.rs
|   |       +-- receipt.rs
|   |-- synergy-aivm/
|   |   |-- Cargo.toml
|   |   +-- src/
|   |       |-- lib.rs
|   |       |-- metrics.rs
|   |       |-- resources.rs
|   |       |-- runtime.rs
|   |       |-- sandbox.rs
|   |       +-- validation.rs
|   |-- synergy-block/
|   |   |-- Cargo.toml
|   |   +-- src/
|   |       |-- block.rs
|   |       |-- body.rs
|   |       |-- builder.rs
|   |       |-- commitment.rs
|   |       |-- encoding.rs
|   |       |-- header.rs
|   |       |-- lib.rs
|   |       +-- validation.rs
|   |-- synergy-config/
|   |   |-- Cargo.toml
|   |   +-- src/
|   |       |-- consensus.rs
|   |       |-- etdag.rs
|   |       |-- lib.rs
|   |       |-- loader.rs
|   |       |-- network.rs
|   |       |-- node.rs
|   |       |-- p2p.rs
|   |       |-- role.rs
|   |       |-- rpc.rs
|   |       |-- storage.rs
|   |       |-- telemetry.rs
|   |       |-- validation.rs
|   |       +-- vpn.rs
|   |-- synergy-crypto/
|   |   |-- Cargo.toml
|   |   +-- src/
|   |       |-- constant_time.rs
|   |       |-- domain.rs
|   |       |-- encoding.rs
|   |       |-- hash.rs
|   |       |-- kem/
|   |       |   |-- ml_kem.rs
|   |       |   +-- mod.rs
|   |       |-- key_provider/
|   |       |   |-- filesystem.rs
|   |       |   |-- hsm.rs
|   |       |   |-- mod.rs
|   |       |   |-- provider.rs
|   |       |   |-- remote.rs
|   |       |   +-- tpm.rs
|   |       |-- lib.rs
|   |       |-- random.rs
|   |       |-- signatures/
|   |       |   |-- fn_dsa.rs
|   |       |   |-- ml_dsa.rs
|   |       |   |-- mod.rs
|   |       |   |-- sphincs.rs
|   |       |   +-- verifier.rs
|   |       +-- symmetric/
|   |           |-- aes_gcm.rs
|   |           +-- mod.rs
|   |-- synergy-data-availability/
|   |   |-- Cargo.toml
|   |   +-- src/
|   |       |-- audit.rs
|   |       |-- lib.rs
|   |       |-- proof.rs
|   |       |-- retention.rs
|   |       |-- serve.rs
|   |       |-- shard.rs
|   |       +-- store.rs
|   |-- synergy-etdag/
|   |   |-- Cargo.toml
|   |   +-- src/
|   |       |-- admission/
|   |       |   |-- certificate.rs
|   |       |   |-- context.rs
|   |       |   |-- mod.rs
|   |       |   |-- nonce_window.rs
|   |       |   |-- policy.rs
|   |       |   |-- request.rs
|   |       |   |-- resource_limits.rs
|   |       |   |-- target_height.rs
|   |       |   |-- validator.rs
|   |       |   +-- verifier.rs
|   |       |-- availability/
|   |       |   |-- certificate.rs
|   |       |   |-- collector.rs
|   |       |   |-- mod.rs
|   |       |   |-- recovery.rs
|   |       |   |-- verifier.rs
|   |       |   +-- vote.rs
|   |       |-- certificates/
|   |       |   |-- availability.rs
|   |       |   |-- batch_finality.rs
|   |       |   |-- batch_timeout.rs
|   |       |   |-- batch_validate.rs
|   |       |   |-- canonical.rs
|   |       |   |-- mod.rs
|   |       |   |-- ordering.rs
|   |       |   |-- target_admission.rs
|   |       |   +-- verifier.rs
|   |       |-- crypto/
|   |       |   |-- aead.rs
|   |       |   |-- envelope.rs
|   |       |   |-- kem.rs
|   |       |   |-- key_registry.rs
|   |       |   |-- key_rotation.rs
|   |       |   |-- mod.rs
|   |       |   |-- nonce.rs
|   |       |   |-- padding.rs
|   |       |   +-- verifier.rs
|   |       |-- dag/
|   |       |   |-- cut.rs
|   |       |   |-- dependency.rs
|   |       |   |-- deterministic_order.rs
|   |       |   |-- graph.rs
|   |       |   |-- insertion.rs
|   |       |   |-- mod.rs
|   |       |   |-- parents.rs
|   |       |   |-- traversal.rs
|   |       |   |-- validation.rs
|   |       |   |-- vertex.rs
|   |       |   +-- vertex_id.rs
|   |       |-- digest.rs
|   |       |-- domains.rs
|   |       |-- errors.rs
|   |       |-- execution/
|   |       |   |-- batch_validation.rs
|   |       |   |-- deterministic_batch.rs
|   |       |   |-- execution_adapter.rs
|   |       |   |-- execution_input.rs
|   |       |   |-- mod.rs
|   |       |   +-- transaction_validation.rs
|   |       |-- governance/
|   |       |   |-- activation.rs
|   |       |   |-- fee_schedule.rs
|   |       |   |-- key_registry.rs
|   |       |   |-- manifest.rs
|   |       |   |-- mod.rs
|   |       |   |-- parameters.rs
|   |       |   +-- verifier.rs
|   |       |-- ingress/
|   |       |   |-- admission_queue.rs
|   |       |   |-- envelope_validation.rs
|   |       |   |-- mod.rs
|   |       |   |-- protected_transaction.rs
|   |       |   |-- rate_limit.rs
|   |       |   |-- receipt.rs
|   |       |   |-- replay_protection.rs
|   |       |   |-- sender_validation.rs
|   |       |   +-- service.rs
|   |       |-- lib.rs
|   |       |-- metrics.rs
|   |       |-- network/
|   |       |   |-- adapter.rs
|   |       |   |-- gossip.rs
|   |       |   |-- handler.rs
|   |       |   |-- messages.rs
|   |       |   |-- mod.rs
|   |       |   +-- retransmission.rs
|   |       |-- ordering/
|   |       |   |-- batch.rs
|   |       |   |-- cut_marker.rs
|   |       |   |-- mod.rs
|   |       |   |-- order_key.rs
|   |       |   |-- order_root.rs
|   |       |   |-- proof.rs
|   |       |   |-- protected_cut.rs
|   |       |   |-- seed.rs
|   |       |   +-- verifier.rs
|   |       |-- parameters.rs
|   |       |-- persistence/
|   |       |   |-- admission_store.rs
|   |       |   |-- certificate_store.rs
|   |       |   |-- graph_store.rs
|   |       |   |-- mod.rs
|   |       |   |-- protected_input_store.rs
|   |       |   |-- recovery.rs
|   |       |   |-- reveal_store.rs
|   |       |   +-- safety_journal.rs
|   |       |-- profile.rs
|   |       |-- recovery/
|   |       |   |-- missing_artifacts.rs
|   |       |   |-- mod.rs
|   |       |   |-- reconcile.rs
|   |       |   |-- replay.rs
|   |       |   +-- startup.rs
|   |       +-- reveal/
|   |           |-- authorization.rs
|   |           |-- decrypt.rs
|   |           |-- decrypt_share.rs
|   |           |-- gate.rs
|   |           |-- mod.rs
|   |           |-- share_collector.rs
|   |           |-- transcript.rs
|   |           +-- verifier.rs
|   |-- synergy-etdag-client/
|   |   |-- Cargo.toml
|   |   +-- src/
|   |       |-- encrypt.rs
|   |       |-- envelope.rs
|   |       |-- ingress_keys.rs
|   |       |-- lib.rs
|   |       |-- padding.rs
|   |       |-- receipt.rs
|   |       |-- submit.rs
|   |       +-- target_context.rs
|   |-- synergy-execution/
|   |   |-- Cargo.toml
|   |   +-- src/
|   |       |-- context.rs
|   |       |-- dispatcher/
|   |       |   |-- governance.rs
|   |       |   |-- mod.rs
|   |       |   |-- native.rs
|   |       |   |-- sxcp.rs
|   |       |   |-- synq.rs
|   |       |   +-- system.rs
|   |       |-- executor.rs
|   |       |-- fees.rs
|   |       |-- lib.rs
|   |       |-- receipts.rs
|   |       |-- rollback.rs
|   |       |-- scheduler.rs
|   |       |-- transition.rs
|   |       +-- validation.rs
|   |-- synergy-governance/
|   |   |-- Cargo.toml
|   |   +-- src/
|   |       |-- activation.rs
|   |       |-- audit.rs
|   |       |-- authorization.rs
|   |       |-- constitution.rs
|   |       |-- emergency.rs
|   |       |-- lib.rs
|   |       |-- proposal.rs
|   |       +-- vote.rs
|   |-- synergy-health/
|   |   |-- Cargo.toml
|   |   +-- src/
|   |       |-- checks.rs
|   |       |-- dependency.rs
|   |       |-- lib.rs
|   |       |-- liveness.rs
|   |       |-- readiness.rs
|   |       |-- stall.rs
|   |       +-- status.rs
|   |-- synergy-identity/
|   |   |-- Cargo.toml
|   |   +-- src/
|   |       |-- duplicate_guard.rs
|   |       |-- key_binding.rs
|   |       |-- lib.rs
|   |       |-- node_id.rs
|   |       |-- proof_of_possession.rs
|   |       |-- public_identity.rs
|   |       |-- rotation.rs
|   |       |-- store.rs
|   |       +-- synv.rs
|   |-- synergy-manifest/
|   |   |-- Cargo.toml
|   |   +-- src/
|   |       |-- chain_identity.rs
|   |       |-- consensus_binding.rs
|   |       |-- etdag_binding.rs
|   |       |-- genesis_binding.rs
|   |       |-- hash.rs
|   |       |-- lib.rs
|   |       |-- network_manifest.rs
|   |       |-- protocol_versions.rs
|   |       |-- release_binding.rs
|   |       |-- role_binding.rs
|   |       |-- signature.rs
|   |       |-- transport_binding.rs
|   |       +-- verifier.rs
|   |-- synergy-network/
|   |   |-- Cargo.toml
|   |   +-- src/
|   |       |-- discovery/
|   |       |   |-- bootseed.rs
|   |       |   |-- cache.rs
|   |       |   |-- dns.rs
|   |       |   |-- mod.rs
|   |       |   |-- peer_exchange.rs
|   |       |   |-- seed_set.rs
|   |       |   |-- transport_registry.rs
|   |       |   +-- verifier.rs
|   |       |-- handshake/
|   |       |   |-- chain.rs
|   |       |   |-- challenge.rs
|   |       |   |-- compatibility.rs
|   |       |   |-- identity.rs
|   |       |   |-- mod.rs
|   |       |   |-- policy.rs
|   |       |   |-- protocol.rs
|   |       |   |-- rejection.rs
|   |       |   |-- role.rs
|   |       |   |-- signing.rs
|   |       |   +-- verifier.rs
|   |       |-- lib.rs
|   |       |-- metrics.rs
|   |       |-- peer/
|   |       |   |-- admission.rs
|   |       |   |-- backoff.rs
|   |       |   |-- ban.rs
|   |       |   |-- connection_limits.rs
|   |       |   |-- duplicate.rs
|   |       |   |-- health.rs
|   |       |   |-- manager.rs
|   |       |   |-- mod.rs
|   |       |   |-- peer.rs
|   |       |   |-- persistence.rs
|   |       |   |-- quarantine.rs
|   |       |   |-- score.rs
|   |       |   |-- session.rs
|   |       |   +-- state.rs
|   |       |-- protocol/
|   |       |   |-- codec.rs
|   |       |   |-- compatibility.rs
|   |       |   |-- envelope.rs
|   |       |   |-- framing.rs
|   |       |   |-- id.rs
|   |       |   |-- mod.rs
|   |       |   |-- registry.rs
|   |       |   |-- size_limits.rs
|   |       |   +-- version.rs
|   |       |-- router/
|   |       |   |-- backpressure.rs
|   |       |   |-- handler.rs
|   |       |   |-- mailbox.rs
|   |       |   |-- mod.rs
|   |       |   |-- queue.rs
|   |       |   |-- retransmit.rs
|   |       |   +-- router.rs
|   |       |-- sentry/
|   |       |   |-- failover.rs
|   |       |   |-- filter.rs
|   |       |   |-- forwarder.rs
|   |       |   |-- metrics.rs
|   |       |   |-- mod.rs
|   |       |   |-- policy.rs
|   |       |   |-- public_peers.rs
|   |       |   +-- validator_link.rs
|   |       +-- transport/
|   |           |-- address.rs
|   |           |-- connection.rs
|   |           |-- dialer.rs
|   |           |-- limits.rs
|   |           |-- listener.rs
|   |           |-- mod.rs
|   |           |-- tcp.rs
|   |           |-- timeout.rs
|   |           +-- transport.rs
|   |-- synergy-node-core/
|   |   |-- Cargo.toml
|   |   +-- src/
|   |       |-- context.rs
|   |       |-- error.rs
|   |       |-- lib.rs
|   |       |-- lifecycle/
|   |       |   |-- bootstrap.rs
|   |       |   |-- degraded.rs
|   |       |   |-- draining.rs
|   |       |   |-- mod.rs
|   |       |   |-- preflight.rs
|   |       |   |-- ready.rs
|   |       |   |-- shutdown.rs
|   |       |   |-- startup.rs
|   |       |   |-- state.rs
|   |       |   +-- synchronized.rs
|   |       |-- node.rs
|   |       |-- readiness/
|   |       |   |-- checks.rs
|   |       |   |-- consensus.rs
|   |       |   |-- etdag.rs
|   |       |   |-- gate.rs
|   |       |   |-- mod.rs
|   |       |   |-- networking.rs
|   |       |   |-- storage.rs
|   |       |   |-- sync.rs
|   |       |   +-- vpn.rs
|   |       +-- supervisor/
|   |           |-- cancellation.rs
|   |           |-- dependency_graph.rs
|   |           |-- mod.rs
|   |           |-- restart_policy.rs
|   |           |-- service.rs
|   |           |-- shutdown.rs
|   |           +-- supervisor.rs
|   |-- synergy-p2p-protocols/
|   |   |-- Cargo.toml
|   |   +-- src/
|   |       |-- block_sync.rs
|   |       |-- errors.rs
|   |       |-- etdag.rs
|   |       |-- lib.rs
|   |       |-- observer.rs
|   |       |-- peer_exchange.rs
|   |       |-- posy.rs
|   |       |-- snapshot.rs
|   |       |-- state_sync.rs
|   |       |-- status.rs
|   |       |-- sxcp.rs
|   |       +-- transaction.rs
|   |-- synergy-posy/
|   |   |-- Cargo.toml
|   |   +-- src/
|   |       |-- clustering/
|   |       |   |-- assignment.rs
|   |       |   |-- cluster.rs
|   |       |   |-- membership.rs
|   |       |   |-- mod.rs
|   |       |   |-- schedule.rs
|   |       |   +-- verification.rs
|   |       |-- domains.rs
|   |       |-- engine/
|   |       |   |-- driver.rs
|   |       |   |-- events.rs
|   |       |   |-- height.rs
|   |       |   |-- mod.rs
|   |       |   |-- round.rs
|   |       |   |-- state_machine.rs
|   |       |   |-- timers.rs
|   |       |   +-- transition.rs
|   |       |-- errors.rs
|   |       |-- finality/
|   |       |   |-- certificate.rs
|   |       |   |-- commit.rs
|   |       |   |-- finality.rs
|   |       |   |-- mod.rs
|   |       |   |-- observer.rs
|   |       |   +-- verifier.rs
|   |       |-- lib.rs
|   |       |-- membership/
|   |       |   |-- activation.rs
|   |       |   |-- authority.rs
|   |       |   |-- deactivation.rs
|   |       |   |-- epoch.rs
|   |       |   |-- expulsion.rs
|   |       |   |-- jailing.rs
|   |       |   |-- mod.rs
|   |       |   |-- registration.rs
|   |       |   |-- registry.rs
|   |       |   |-- shadow.rs
|   |       |   |-- slashing.rs
|   |       |   |-- transition.rs
|   |       |   +-- validator.rs
|   |       |-- metrics.rs
|   |       |-- network/
|   |       |   |-- adapter.rs
|   |       |   |-- envelope.rs
|   |       |   |-- inbound.rs
|   |       |   |-- mod.rs
|   |       |   |-- outbound.rs
|   |       |   +-- retransmission.rs
|   |       |-- parameters.rs
|   |       |-- persistence/
|   |       |   |-- certificate_store.rs
|   |       |   |-- finality_store.rs
|   |       |   |-- fsync.rs
|   |       |   |-- mod.rs
|   |       |   |-- prepared_state.rs
|   |       |   |-- proposal_store.rs
|   |       |   |-- safety_journal.rs
|   |       |   |-- signing_authority.rs
|   |       |   +-- vote_store.rs
|   |       |-- proposal/
|   |       |   |-- builder.rs
|   |       |   |-- mod.rs
|   |       |   |-- proposal.rs
|   |       |   |-- recovery.rs
|   |       |   |-- selection.rs
|   |       |   +-- validation.rs
|   |       |-- protocol.rs
|   |       |-- quorum/
|   |       |   |-- builder.rs
|   |       |   |-- certificate.rs
|   |       |   |-- compatible_merge.rs
|   |       |   |-- mod.rs
|   |       |   |-- policy.rs
|   |       |   +-- verifier.rs
|   |       |-- recovery/
|   |       |   |-- mod.rs
|   |       |   |-- peer_recovery.rs
|   |       |   |-- prepared_state.rs
|   |       |   |-- reconciliation.rs
|   |       |   |-- replay.rs
|   |       |   +-- startup.rs
|   |       |-- timeout/
|   |       |   |-- certificate.rs
|   |       |   |-- mod.rs
|   |       |   |-- recovery.rs
|   |       |   |-- round_change.rs
|   |       |   +-- timeout.rs
|   |       |-- version.rs
|   |       +-- voting/
|   |           |-- collection.rs
|   |           |-- duplicate_guard.rs
|   |           |-- mod.rs
|   |           |-- phase.rs
|   |           |-- validation.rs
|   |           +-- vote.rs
|   |-- synergy-protocol-types/
|   |   |-- Cargo.toml
|   |   +-- src/
|   |       |-- block.rs
|   |       |-- certificate.rs
|   |       |-- chain.rs
|   |       |-- cluster.rs
|   |       |-- epoch.rs
|   |       |-- hash.rs
|   |       |-- height.rs
|   |       |-- lib.rs
|   |       |-- role.rs
|   |       |-- serialization.rs
|   |       |-- transaction.rs
|   |       +-- validator.rs
|   |-- synergy-roles/
|   |   |-- Cargo.toml
|   |   +-- src/
|   |       |-- authority_plane.rs
|   |       |-- capability.rs
|   |       |-- lib.rs
|   |       |-- ports.rs
|   |       |-- profile.rs
|   |       |-- registry.rs
|   |       |-- role.rs
|   |       |-- service_graph.rs
|   |       +-- validation.rs
|   |-- synergy-rpc/
|   |   |-- Cargo.toml
|   |   +-- src/
|   |       |-- auth.rs
|   |       |-- health.rs
|   |       |-- lib.rs
|   |       |-- methods/
|   |       |   |-- account.rs
|   |       |   |-- block.rs
|   |       |   |-- chain.rs
|   |       |   |-- etdag.rs
|   |       |   |-- mod.rs
|   |       |   |-- node.rs
|   |       |   |-- peers.rs
|   |       |   |-- posy.rs
|   |       |   |-- sync.rs
|   |       |   |-- system.rs
|   |       |   |-- transaction.rs
|   |       |   +-- validator.rs
|   |       |-- middleware/
|   |       |   |-- limits.rs
|   |       |   |-- metrics.rs
|   |       |   |-- mod.rs
|   |       |   +-- request_id.rs
|   |       |-- rate_limit.rs
|   |       +-- server.rs
|   |-- synergy-snapshot/
|   |   |-- Cargo.toml
|   |   +-- src/
|   |       |-- builder.rs
|   |       |-- chunk.rs
|   |       |-- lib.rs
|   |       |-- manifest.rs
|   |       |-- restore.rs
|   |       |-- retention.rs
|   |       |-- signer.rs
|   |       |-- uploader.rs
|   |       +-- verifier.rs
|   |-- synergy-state/
|   |   |-- Cargo.toml
|   |   +-- src/
|   |       |-- account.rs
|   |       |-- diff.rs
|   |       |-- lib.rs
|   |       |-- overlay.rs
|   |       |-- proof.rs
|   |       |-- pruning.rs
|   |       |-- root.rs
|   |       |-- state.rs
|   |       +-- transition.rs
|   |-- synergy-storage/
|   |   |-- Cargo.toml
|   |   +-- src/
|   |       |-- column/
|   |       |   |-- blocks.rs
|   |       |   |-- consensus.rs
|   |       |   |-- etdag.rs
|   |       |   |-- metadata.rs
|   |       |   |-- mod.rs
|   |       |   |-- peers.rs
|   |       |   +-- state.rs
|   |       |-- database.rs
|   |       |-- disk_guard.rs
|   |       |-- fsync.rs
|   |       |-- integrity.rs
|   |       |-- lib.rs
|   |       |-- migration.rs
|   |       |-- pruning.rs
|   |       |-- recovery.rs
|   |       |-- transaction.rs
|   |       +-- wal.rs
|   |-- synergy-sxcp/
|   |   |-- Cargo.toml
|   |   +-- src/
|   |       |-- adapters/
|   |       |   |-- bitcoin.rs
|   |       |   |-- ethereum.rs
|   |       |   |-- mod.rs
|   |       |   +-- solana.rs
|   |       |-- capability.rs
|   |       |-- finality.rs
|   |       |-- independence.rs
|   |       |-- lib.rs
|   |       |-- proof.rs
|   |       |-- protocol.rs
|   |       |-- receipt.rs
|   |       |-- relay.rs
|   |       |-- vault.rs
|   |       +-- verifier.rs
|   |-- synergy-sync/
|   |   |-- Cargo.toml
|   |   +-- src/
|   |       |-- block/
|   |       |   |-- importer.rs
|   |       |   |-- mod.rs
|   |       |   |-- requester.rs
|   |       |   |-- responder.rs
|   |       |   |-- retry.rs
|   |       |   |-- scheduler.rs
|   |       |   +-- verifier.rs
|   |       |-- head/
|   |       |   |-- candidate.rs
|   |       |   |-- collector.rs
|   |       |   |-- mod.rs
|   |       |   |-- quorum_view.rs
|   |       |   |-- selection.rs
|   |       |   +-- verifier.rs
|   |       |-- lib.rs
|   |       |-- manager.rs
|   |       |-- metrics.rs
|   |       |-- persistence.rs
|   |       |-- readiness.rs
|   |       |-- sources/
|   |       |   |-- archive.rs
|   |       |   |-- failover.rs
|   |       |   |-- mod.rs
|   |       |   |-- peer.rs
|   |       |   |-- scoring.rs
|   |       |   +-- snapshot.rs
|   |       |-- state/
|   |       |   |-- checkpoint.rs
|   |       |   |-- chunk.rs
|   |       |   |-- downloader.rs
|   |       |   |-- importer.rs
|   |       |   |-- manifest.rs
|   |       |   |-- mod.rs
|   |       |   |-- resume.rs
|   |       |   +-- verifier.rs
|   |       +-- status.rs
|   |-- synergy-synq/
|   |   |-- Cargo.toml
|   |   +-- src/
|   |       |-- bytecode.rs
|   |       |-- determinism.rs
|   |       |-- executor.rs
|   |       |-- gas.rs
|   |       |-- host.rs
|   |       |-- lib.rs
|   |       |-- storage.rs
|   |       |-- tracing.rs
|   |       |-- verifier.rs
|   |       +-- vm.rs
|   |-- synergy-telemetry/
|   |   |-- Cargo.toml
|   |   +-- src/
|   |       |-- ai.rs
|   |       |-- alerts.rs
|   |       |-- consensus.rs
|   |       |-- cross_chain.rs
|   |       |-- etdag.rs
|   |       |-- health.rs
|   |       |-- lib.rs
|   |       |-- metrics.rs
|   |       |-- p2p.rs
|   |       |-- prometheus.rs
|   |       |-- readiness.rs
|   |       |-- registry.rs
|   |       |-- sentry.rs
|   |       |-- storage.rs
|   |       |-- structured_log.rs
|   |       |-- sync.rs
|   |       |-- tracing.rs
|   |       +-- vpn.rs
|   |-- synergy-transaction/
|   |   |-- Cargo.toml
|   |   +-- src/
|   |       |-- fee.rs
|   |       |-- id.rs
|   |       |-- lib.rs
|   |       |-- nonce.rs
|   |       |-- receipt.rs
|   |       |-- signature.rs
|   |       |-- system_transaction.rs
|   |       |-- transaction.rs
|   |       +-- validation.rs
|   |-- synergy-transport-registry/
|   |   |-- Cargo.toml
|   |   +-- src/
|   |       |-- binding.rs
|   |       |-- cache.rs
|   |       |-- generation.rs
|   |       |-- lease.rs
|   |       |-- lib.rs
|   |       |-- reconciliation.rs
|   |       |-- registry.rs
|   |       |-- revocation.rs
|   |       |-- signer.rs
|   |       +-- verifier.rs
|   |-- synergy-tx-ingress/
|   |   |-- Cargo.toml
|   |   +-- src/
|   |       |-- admission.rs
|   |       |-- governance.rs
|   |       |-- internal.rs
|   |       |-- lib.rs
|   |       |-- metrics.rs
|   |       |-- protected.rs
|   |       |-- router.rs
|   |       +-- system.rs
|   |-- synergy-uma/
|   |   |-- Cargo.toml
|   |   +-- src/
|   |       |-- adapters/
|   |       |   |-- bitcoin.rs
|   |       |   |-- ethereum.rs
|   |       |   |-- mod.rs
|   |       |   +-- solana.rs
|   |       |-- address.rs
|   |       |-- coordinator.rs
|   |       |-- lib.rs
|   |       |-- mapping.rs
|   |       |-- registry.rs
|   |       +-- verifier.rs
|   |-- synergy-validator-management/
|   |   |-- Cargo.toml
|   |   +-- src/
|   |       |-- activation.rs
|   |       |-- expulsion.rs
|   |       |-- health.rs
|   |       |-- jailing.rs
|   |       |-- lib.rs
|   |       |-- migration.rs
|   |       |-- onboarding.rs
|   |       |-- registry.rs
|   |       |-- removal.rs
|   |       |-- shadow.rs
|   |       +-- slashing.rs
|   |-- synergy-version/
|   |   |-- Cargo.toml
|   |   +-- src/
|   |       |-- activation.rs
|   |       |-- compatibility.rs
|   |       |-- config.rs
|   |       |-- database.rs
|   |       |-- lib.rs
|   |       |-- protocol.rs
|   |       +-- release.rs
|   |-- synergy-vpn/
|   |   |-- Cargo.toml
|   |   +-- src/
|   |       |-- client.rs
|   |       |-- enrollment/
|   |       |   |-- authorization.rs
|   |       |   |-- challenge.rs
|   |       |   |-- mod.rs
|   |       |   |-- proof.rs
|   |       |   |-- request.rs
|   |       |   |-- response.rs
|   |       |   |-- resume.rs
|   |       |   +-- revoke.rs
|   |       |-- lease_verifier.rs
|   |       |-- lib.rs
|   |       |-- metrics.rs
|   |       |-- netbird/
|   |       |   |-- api.rs
|   |       |   |-- daemon.rs
|   |       |   |-- mod.rs
|   |       |   |-- profile.rs
|   |       |   +-- status.rs
|   |       |-- overlay_scope.rs
|   |       |-- peer_binding.rs
|   |       |-- readiness.rs
|   |       |-- route_policy.rs
|   |       |-- sentry_binding.rs
|   |       |-- state.rs
|   |       +-- transport_lease.rs
|   +-- synergy-ws/
|       |-- Cargo.toml
|       +-- src/
|           |-- blocks.rs
|           |-- finality.rs
|           |-- lib.rs
|           |-- node.rs
|           |-- server.rs
|           |-- subscriptions.rs
|           +-- transactions.rs
|-- fuzz/
|   |-- Cargo.toml
|   +-- fuzz_targets/
|       |-- block.rs
|       |-- etdag_certificate.rs
|       |-- etdag_envelope.rs
|       |-- etdag_reveal.rs
|       |-- etdag_vertex.rs
|       |-- handshake.rs
|       |-- network_manifest.rs
|       |-- p2p_frame.rs
|       |-- posy_certificate.rs
|       |-- posy_vote.rs
|       |-- snapshot_manifest.rs
|       +-- transaction.rs
|-- networks/
|   |-- devnet/
|   |   |-- bootseeds.json
|   |   |-- etdag/
|   |   |   |-- activation.json
|   |   |   |-- fee-schedule.json
|   |   |   |-- ingress-key-registry.json
|   |   |   +-- parameters.json
|   |   |-- genesis.json
|   |   |-- network-manifest.json
|   |   |-- protocol-versions.json
|   |   +-- roles.json
|   |-- mainnet/
|   |   |-- bootseeds.json
|   |   |-- etdag/
|   |   |   |-- activation.json
|   |   |   |-- fee-schedule.json
|   |   |   |-- ingress-key-registry.json
|   |   |   +-- parameters.json
|   |   |-- genesis.json
|   |   |-- network-manifest.json
|   |   |-- protocol-versions.json
|   |   +-- roles.json
|   +-- testnet/
|       |-- bootseeds.json
|       |-- etdag/
|       |   |-- activation.json
|       |   |-- fee-schedule.json
|       |   |-- ingress-key-registry.json
|       |   +-- parameters.json
|       |-- genesis.json
|       |-- network-manifest.json
|       |-- protocol-versions.json
|       +-- roles.json
|-- packaging/
|   |-- deb/
|   |   |-- control
|   |   |-- postinst
|   |   |-- postrm
|   |   +-- prerm
|   |-- install/
|   |   |-- install.sh
|   |   |-- uninstall.sh
|   |   |-- upgrade.sh
|   |   +-- verify-release.sh
|   |-- rpm/
|   |   +-- synergy-node.spec
|   |-- systemd/
|   |   |-- hardening.conf
|   |   |-- synergy-node.env
|   |   |-- synergy-node.service
|   |   +-- synergy-vpn-enrollment.service
|   +-- tarball/
|       +-- build-release.sh
|-- proto/
|   |-- admin/
|   |   |-- events.proto
|   |   |-- health.proto
|   |   |-- management.proto
|   |   +-- vpn.proto
|   |-- etdag/
|   |   |-- availability.proto
|   |   |-- certificates.proto
|   |   |-- ingress.proto
|   |   |-- ordering.proto
|   |   |-- recovery.proto
|   |   |-- reveal.proto
|   |   +-- vertex.proto
|   |-- p2p/
|   |   |-- discovery.proto
|   |   |-- errors.proto
|   |   |-- handshake.proto
|   |   |-- peer_exchange.proto
|   |   +-- status.proto
|   |-- posy/
|   |   |-- finality.proto
|   |   |-- proposal.proto
|   |   |-- quorum_certificate.proto
|   |   |-- timeout.proto
|   |   +-- vote.proto
|   +-- sync/
|       |-- blocks.proto
|       |-- checkpoint.proto
|       |-- snapshot.proto
|       +-- state.proto
|-- roles/
|   |-- aegis_cryptography.toml
|   |-- ai_assurance.toml
|   |-- ai_compute.toml
|   |-- ai_coordination.toml
|   |-- ai_data.toml
|   |-- archive.toml
|   |-- bootseed.toml
|   |-- consensus_audit.toml
|   |-- cross_chain.toml
|   |-- data_availability.toml
|   |-- indexer.toml
|   |-- infrastructure/
|   |   |-- snapshot_source.toml
|   |   +-- transport_registry.toml
|   |-- network_analytics.toml
|   |-- observer_light.toml
|   |-- oracle.toml
|   |-- rpc_gateway.toml
|   |-- sentry.toml
|   |-- synq_execution.toml
|   |-- uma_coordinator.toml
|   |-- validator.toml
|   +-- witness.toml
|-- schemas/
|   |-- bootseed-record.schema.json
|   |-- etdag-fee-schedule.schema.json
|   |-- etdag-ingress-keys.schema.json
|   |-- etdag-parameters.schema.json
|   |-- genesis.schema.json
|   |-- network-manifest.schema.json
|   |-- node-config.schema.json
|   |-- role-profile.schema.json
|   |-- snapshot-manifest.schema.json
|   |-- transport-lease.schema.json
|   +-- validator-membership.schema.json
|-- services/
|   |-- bootseed-registry/
|   |   |-- Cargo.toml
|   |   +-- src/
|   |       |-- expiry.rs
|   |       |-- main.rs
|   |       |-- metrics.rs
|   |       |-- records.rs
|   |       |-- registry.rs
|   |       |-- signing.rs
|   |       +-- verification.rs
|   |-- snapshot-publisher/
|   |   |-- Cargo.toml
|   |   +-- src/
|   |       |-- main.rs
|   |       |-- manifest.rs
|   |       |-- metrics.rs
|   |       |-- publisher.rs
|   |       |-- retention.rs
|   |       |-- signer.rs
|   |       +-- storage.rs
|   +-- vpn-enrollment-broker/
|       |-- Cargo.toml
|       +-- src/
|           |-- audit.rs
|           |-- authorization.rs
|           |-- chain_verifier.rs
|           |-- challenge.rs
|           |-- main.rs
|           |-- metrics.rs
|           |-- one_time_key.rs
|           |-- peer_binding.rs
|           |-- providers/
|           |   |-- mod.rs
|           |   +-- netbird.rs
|           |-- reconciliation.rs
|           |-- revocation.rs
|           |-- server.rs
|           +-- transport_lease.rs
|-- simulation/
|   |-- Cargo.toml
|   +-- src/
|       |-- byzantine.rs
|       |-- cluster.rs
|       |-- crash.rs
|       |-- disk_failure.rs
|       |-- fault.rs
|       |-- invariant.rs
|       |-- latency.rs
|       |-- main.rs
|       |-- packet_loss.rs
|       |-- partition.rs
|       |-- report.rs
|       |-- sentry.rs
|       |-- validator.rs
|       |-- virtual_clock.rs
|       +-- virtual_network.rs
|-- tests/
|   |-- adverse_network/
|   |   |-- bandwidth.rs
|   |   |-- connection_churn.rs
|   |   |-- jitter.rs
|   |   |-- latency.rs
|   |   +-- packet_loss.rs
|   |-- consensus/
|   |   |-- compatible_certificates.rs
|   |   |-- conflicting_certificates.rs
|   |   |-- delayed_vote.rs
|   |   |-- dropped_vote.rs
|   |   |-- duplicate_vote.rs
|   |   |-- finality_safety.rs
|   |   |-- membership_epoch_transition.rs
|   |   |-- normal_progress.rs
|   |   |-- partial_broadcast_restart.rs
|   |   |-- proposer_failure.rs
|   |   |-- reordered_vote.rs
|   |   |-- restart_after_persist.rs
|   |   |-- restart_after_send.rs
|   |   |-- restart_before_persist.rs
|   |   |-- shadow_activation.rs
|   |   +-- timeout_recovery.rs
|   |-- etdag/
|   |   |-- availability_certificate.rs
|   |   |-- batch_execution.rs
|   |   |-- dag_dependencies.rs
|   |   |-- decrypt_shares.rs
|   |   |-- deterministic_ordering.rs
|   |   |-- encryption.rs
|   |   |-- invalid_reveal.rs
|   |   |-- malformed_ciphertext.rs
|   |   |-- nonce_window.rs
|   |   |-- protected_cut.rs
|   |   |-- resource_exhaustion.rs
|   |   |-- restart_recovery.rs
|   |   |-- reveal_gate.rs
|   |   +-- target_admission.rs
|   |-- fixtures/
|   |   |-- certificates/
|   |   |-- corrupted/
|   |   |-- etdag/
|   |   |-- genesis/
|   |   |-- manifests/
|   |   |-- snapshots/
|   |   +-- validator_sets/
|   |-- integration/
|   |   |-- admin_api.rs
|   |   |-- ai_capability_roles.rs
|   |   |-- block_sync.rs
|   |   |-- cli_parity.rs
|   |   |-- control_panel_parity.rs
|   |   |-- cross_chain_independence.rs
|   |   |-- etdag_ingress.rs
|   |   |-- etdag_reveal.rs
|   |   |-- peer_authentication.rs
|   |   |-- peer_discovery.rs
|   |   |-- role_isolation.rs
|   |   |-- sentry_failover.rs
|   |   |-- sentry_perimeter.rs
|   |   |-- shutdown.rs
|   |   |-- snapshot_restore.rs
|   |   |-- startup.rs
|   |   |-- state_sync.rs
|   |   |-- validator_join.rs
|   |   |-- validator_remove.rs
|   |   |-- validator_restart.rs
|   |   +-- vpn_enrollment.rs
|   |-- networking/
|   |   |-- backpressure.rs
|   |   |-- bootseed_failure.rs
|   |   |-- duplicate_connection.rs
|   |   |-- frame_limits.rs
|   |   |-- handshake_timeout.rs
|   |   |-- malicious_peer.rs
|   |   |-- peer_churn.rs
|   |   |-- protocol_mismatch.rs
|   |   |-- sentry_acl.rs
|   |   |-- sentry_filtering.rs
|   |   |-- sentry_redundancy.rs
|   |   +-- stale_peer.rs
|   |-- partitions/
|   |   |-- asymmetric_partition.rs
|   |   |-- half_split.rs
|   |   |-- heal_and_resume.rs
|   |   |-- isolated_validator.rs
|   |   +-- minority_partition.rs
|   |-- roles/
|   |   |-- aegis_cryptography.rs
|   |   |-- ai_assurance.rs
|   |   |-- ai_compute.rs
|   |   |-- ai_coordination.rs
|   |   |-- ai_data.rs
|   |   |-- archive.rs
|   |   |-- capability_isolation.rs
|   |   |-- consensus_audit.rs
|   |   |-- cross_chain.rs
|   |   |-- data_availability.rs
|   |   |-- indexer.rs
|   |   |-- network_analytics.rs
|   |   |-- observer_light.rs
|   |   |-- oracle.rs
|   |   |-- rpc_gateway.rs
|   |   |-- sentry.rs
|   |   |-- synq_execution.rs
|   |   |-- uma_coordinator.rs
|   |   |-- validator.rs
|   |   +-- witness.rs
|   |-- sync/
|   |   |-- corrupt_block.rs
|   |   |-- corrupt_snapshot.rs
|   |   |-- dishonest_head.rs
|   |   |-- interrupted_snapshot.rs
|   |   |-- missing_blocks.rs
|   |   |-- multi_source_failover.rs
|   |   +-- source_failure.rs
|   |-- unit/
|   |   |-- etdag/
|   |   |-- execution/
|   |   |-- management/
|   |   |-- p2p/
|   |   |-- posy/
|   |   |-- storage/
|   |   |-- sync/
|   |   +-- vpn/
|   |-- upgrade/
|   |   |-- activation_height.rs
|   |   |-- database_migration.rs
|   |   |-- incompatible_version.rs
|   |   |-- mixed_versions.rs
|   |   |-- pre_activation.rs
|   |   +-- rollback.rs
|   +-- vpn/
|       |-- broker_restart.rs
|       |-- ip_change.rs
|       |-- key_rotation.rs
|       |-- management_outage.rs
|       |-- mass_restart.rs
|       |-- reused_enrollment_key.rs
|       |-- sentry_enrollment.rs
|       |-- sentry_scope.rs
|       |-- simultaneous_join.rs
|       |-- stale_transport_lease.rs
|       |-- unauthorized_join.rs
|       |-- validator_revocation.rs
|       +-- zero_touch_join.rs
+-- tools/
    |-- bootstrap/
    |   |-- clean-host.sh
    |   |-- install-node.sh
    |   +-- verify-host.sh
    |-- network/
    |   |-- latency-test.rs
    |   |-- partition-test.rs
    |   |-- peer-probe.rs
    |   +-- protocol-probe.rs
    |-- release/
    |   |-- build.sh
    |   |-- checksum.sh
    |   |-- publish.sh
    |   |-- sign.sh
    |   +-- verify.sh
    |-- storage/
    |   |-- corrupt-test-db.rs
    |   |-- inspect-wal.rs
    |   +-- verify-db.rs
    +-- validator/
        |-- generate-identity.sh
        |-- readiness-report.sh
        |-- test-peers.sh
        |-- test-vpn.sh
        +-- verify-membership.sh
~~~~

**Count:** 216 directories, 1143 files.
