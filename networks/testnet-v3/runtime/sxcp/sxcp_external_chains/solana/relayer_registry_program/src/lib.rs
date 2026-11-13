use anchor_lang::prelude::*;

declare_id!("SXCPRelr1111111111111111111111111111111");

/// relayer_registry_program tracks stake balances of relayers on Solana. It
/// allows relayers to deposit lamports as stake and later withdraw them.
/// Rewards distribution is left to the compensation pool. Stake amounts are
/// stored in a PDA account keyed by the relayer’s public key.
#[program]
pub mod relayer_registry_program {
    use super::*;
    pub fn deposit_stake(ctx: Context<DepositStake>, amount: u64) -> Result<()> {
        let stake_account = &mut ctx.accounts.stake_account;
        stake_account.relayer = *ctx.accounts.relayer.key;
        stake_account.amount = stake_account.amount.saturating_add(amount);
        let ix = anchor_lang::solana_program::system_instruction::transfer(
            ctx.accounts.relayer.key,
            ctx.accounts.pda.key,
            amount,
        );
        anchor_lang::solana_program::program::invoke(
            &ix,
            &[ctx.accounts.relayer.to_account_info(), ctx.accounts.pda.to_account_info()],
        )?;
        Ok(())
    }
    pub fn withdraw_stake(ctx: Context<WithdrawStake>, amount: u64) -> Result<()> {
        let stake_account = &mut ctx.accounts.stake_account;
        require!(stake_account.amount >= amount, CustomError::InsufficientStake);
        stake_account.amount = stake_account.amount.saturating_sub(amount);
        **ctx.accounts.pda.to_account_info().try_borrow_mut_lamports()? -= amount;
        **ctx.accounts.relayer.to_account_info().try_borrow_mut_lamports()? += amount;
        Ok(())
    }
}

#[account]
pub struct StakeAccount {
    pub relayer: Pubkey,
    pub amount: u64,
}

#[derive(Accounts)]
pub struct DepositStake<'info> {
    #[account(mut, signer)]
    pub relayer: AccountInfo<'info>,
    #[account(mut)]
    pub stake_account: Account<'info, StakeAccount>,
    #[account(mut)]
    /// CHECK: PDA that holds the lamports
    pub pda: AccountInfo<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct WithdrawStake<'info> {
    #[account(mut, signer)]
    pub relayer: AccountInfo<'info>,
    #[account(mut)]
    pub stake_account: Account<'info, StakeAccount>,
    #[account(mut)]
    /// CHECK: PDA that holds the lamports
    pub pda: AccountInfo<'info>,
    pub system_program: Program<'info, System>,
}

#[error_code]
pub enum CustomError {
    #[msg("Insufficient stake")] InsufficientStake,
}