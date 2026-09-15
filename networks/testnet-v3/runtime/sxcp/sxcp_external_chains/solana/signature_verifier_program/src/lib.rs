use anchor_lang::prelude::*;

declare_id!("SXCPVeri111111111111111111111111111111111");

/// signature_verifier_program validates aggregated witness signatures produced
/// by the SXCP relayer network. A real implementation would link to a
/// post‑quantum crypto library compiled to BPF. Here we simply emit an
/// event to demonstrate invocation.
#[program]
pub mod signature_verifier_program {
    use super::*;

    pub fn verify(ctx: Context<Verify>, event_hash: [u8; 32], _signature: Vec<u8>, signers: Vec<Pubkey>) -> Result<()> {
        emit!(AttestationVerified { event_hash, signers });
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Verify<'info> {
    pub caller: Signer<'info>,
}

#[event]
pub struct AttestationVerified {
    pub event_hash: [u8; 32],
    pub signers: Vec<Pubkey>,
}