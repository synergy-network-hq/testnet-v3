use anchor_lang::prelude::*;

declare_id!("SXCPStPr1111111111111111111111111111111");

/// state_proof_validator_program validates Merkle proofs for cross‑chain events
/// on Solana. Since Solana typically does not use Merkle trees for logs,
/// this module is mostly a placeholder demonstrating how to call a verifier
/// from Anchor. The verify instruction accepts a leaf and proof and
/// recomputes a root for comparison to a stored value.
#[program]
pub mod state_proof_validator_program {
    use super::*;
    pub fn set_root(ctx: Context<SetRoot>, new_root: [u8; 32]) -> Result<()> {
        ctx.accounts.root_storage.root = new_root;
        Ok(())
    }
    pub fn verify(ctx: Context<Verify>, leaf: [u8; 32], proof: Vec<[u8; 32]>) -> Result<bool> {
        let mut computed = leaf;
        for sibling in proof.iter() {
            computed = if computed <= *sibling {
                hash_pair(computed, *sibling)
            } else {
                hash_pair(*sibling, computed)
            };
        }
        let valid = computed == ctx.accounts.root_storage.root;
        Ok(valid)
    }
}

#[account]
pub struct RootStorage {
    pub root: [u8; 32],
}

#[derive(Accounts)]
pub struct SetRoot<'info> {
    #[account(mut, signer)]
    pub admin: AccountInfo<'info>,
    #[account(mut)]
    pub root_storage: Account<'info, RootStorage>,
}

#[derive(Accounts)]
pub struct Verify<'info> {
    pub root_storage: Account<'info, RootStorage>,
}

fn hash_pair(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    use anchor_lang::solana_program::hash::{hashv, Hash};
    let result: Hash = hashv(&[&left, &right]);
    result.to_bytes()
}