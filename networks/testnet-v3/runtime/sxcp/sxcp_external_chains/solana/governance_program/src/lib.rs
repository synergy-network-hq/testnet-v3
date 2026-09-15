use anchor_lang::prelude::*;

declare_id!("SXCPGovr11111111111111111111111111111111");

/// governance_program exposes parameter changes and emergency pause for SXCP
/// programs on Solana. For demonstration, it stores a deposit limit and a
/// paused flag which can be toggled by an admin. In practice this module
/// would coordinate upgrades and parameter changes across multiple on‑chain
/// programs.
#[program]
pub mod governance_program {
    use super::*;
    pub fn initialize(ctx: Context<Initialize>, deposit_limit: u64) -> Result<()> {
        let cfg = &mut ctx.accounts.config;
        cfg.admin = *ctx.accounts.admin.key;
        cfg.paused = false;
        cfg.deposit_limit = deposit_limit;
        Ok(())
    }
    pub fn set_deposit_limit(ctx: Context<SetDepositLimit>, new_limit: u64) -> Result<()> {
        let cfg = &mut ctx.accounts.config;
        require!(cfg.admin == *ctx.accounts.admin.key, CustomError::NotAdmin);
        cfg.deposit_limit = new_limit;
        Ok(())
    }
    pub fn pause(ctx: Context<Pause>) -> Result<()> {
        let cfg = &mut ctx.accounts.config;
        require!(cfg.admin == *ctx.accounts.admin.key, CustomError::NotAdmin);
        cfg.paused = true;
        Ok(())
    }
    pub fn unpause(ctx: Context<Pause>) -> Result<()> {
        let cfg = &mut ctx.accounts.config;
        require!(cfg.admin == *ctx.accounts.admin.key, CustomError::NotAdmin);
        cfg.paused = false;
        Ok(())
    }
}

#[account]
pub struct Config {
    pub admin: Pubkey,
    pub paused: bool,
    pub deposit_limit: u64,
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = admin, space = 8 + 32 + 1 + 8)]
    pub config: Account<'info, Config>,
    #[account(mut, signer)]
    pub admin: AccountInfo<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SetDepositLimit<'info> {
    #[account(mut)]
    pub config: Account<'info, Config>,
    #[account(signer)]
    pub admin: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct Pause<'info> {
    #[account(mut)]
    pub config: Account<'info, Config>,
    #[account(signer)]
    pub admin: AccountInfo<'info>,
}

#[error_code]
pub enum CustomError {
    #[msg("Caller is not admin")] NotAdmin,
}