use anchor_lang::prelude::*;

declare_id!("SXCPFinl1111111111111111111111111111111");

/// finality_checker_program determines whether a transaction on Solana is
/// considered final. On Solana finality is generally achieved after a certain
/// number of confirmations or based on epoch boundaries. This simplified
/// implementation stores a confirmation threshold and compares it against
/// the difference between the current slot and the slot of the target event.
#[program]
pub mod finality_checker_program {
    use super::*;
    pub fn initialize(ctx: Context<Initialize>, threshold: u64) -> Result<()> {
        let state = &mut ctx.accounts.state;
        state.confirmations = threshold;
        Ok(())
    }
    pub fn set_threshold(ctx: Context<SetThreshold>, threshold: u64) -> Result<()> {
        let state = &mut ctx.accounts.state;
        require!(ctx.accounts.admin.key() == state.admin, CustomError::NotAdmin);
        state.confirmations = threshold;
        Ok(())
    }
    pub fn is_final(ctx: Context<IsFinal>, event_slot: u64) -> Result<bool> {
        let state = &ctx.accounts.state;
        let current_slot = Clock::get()?.slot;
        let diff = current_slot.saturating_sub(event_slot);
        let valid = diff >= state.confirmations;
        Ok(valid)
    }
}

#[account]
pub struct FinalityState {
    pub admin: Pubkey,
    pub confirmations: u64,
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = admin, space = 8 + 32 + 8)]
    pub state: Account<'info, FinalityState>,
    #[account(mut, signer)]
    pub admin: AccountInfo<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SetThreshold<'info> {
    #[account(mut)]
    pub state: Account<'info, FinalityState>,
    #[account(signer)]
    pub admin: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct IsFinal<'info> {
    pub state: Account<'info, FinalityState>,
}

#[error_code]
pub enum CustomError {
    #[msg("Caller is not admin")] NotAdmin,
}