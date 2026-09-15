use anchor_lang::prelude::*;

declare_id!("SXCPWitn111111111111111111111111111111111");

/// witness_registry_program stores and manages authorised relayers for SXCP on
/// Solana. It tracks whether a relayer is active, their stake and
/// reputation score. This simplified version omits stake transfer logic and
/// does not perform cryptographic checks.
#[program]
pub mod witness_registry_program {
    use super::*;

    pub fn add_relayer(ctx: Context<AddRelayer>, relayer: Pubkey) -> Result<()> {
        let registry = &mut ctx.accounts.registry;
        registry.relayers.push(RelayerInfo { relayer, active: true, reputation: 0, stake: 0 });
        Ok(())
    }

    pub fn remove_relayer(ctx: Context<RemoveRelayer>, index: u32) -> Result<()> {
        let registry = &mut ctx.accounts.registry;
        require!((index as usize) < registry.relayers.len(), CustomError::IndexOutOfBounds);
        registry.relayers.remove(index as usize);
        Ok(())
    }

    pub fn update_reputation(ctx: Context<UpdateReputation>, index: u32, delta: i64) -> Result<()> {
        let registry = &mut ctx.accounts.registry;
        require!((index as usize) < registry.relayers.len(), CustomError::IndexOutOfBounds);
        let info = &mut registry.relayers[index as usize];
        if delta >= 0 {
            info.reputation = info.reputation.saturating_add(delta as u64);
        } else {
            let d = (-delta) as u64;
            if info.reputation > d { info.reputation -= d; } else { info.reputation = 0; }
        }
        Ok(())
    }
}

#[account]
pub struct Registry {
    pub relayers: Vec<RelayerInfo>,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct RelayerInfo {
    pub relayer: Pubkey,
    pub active: bool,
    pub reputation: u64,
    pub stake: u64,
}

#[derive(Accounts)]
pub struct AddRelayer<'info> {
    #[account(mut, signer)]
    pub admin: AccountInfo<'info>,
    #[account(mut)]
    pub registry: Account<'info, Registry>,
}

#[derive(Accounts)]
pub struct RemoveRelayer<'info> {
    #[account(mut, signer)]
    pub admin: AccountInfo<'info>,
    #[account(mut)]
    pub registry: Account<'info, Registry>,
}

#[derive(Accounts)]
pub struct UpdateReputation<'info> {
    #[account(mut, signer)]
    pub admin: AccountInfo<'info>,
    #[account(mut)]
    pub registry: Account<'info, Registry>,
}

#[error_code]
pub enum CustomError {
    #[msg("Index out of bounds")]
    IndexOutOfBounds,
}