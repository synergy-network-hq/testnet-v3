use anchor_lang::prelude::*;

declare_id!("SXCPComp1111111111111111111111111111111");

/// comp_pool_program collects fees on Solana and distributes them to relayers.
/// Because Anchor does not support arbitrary lamport loops easily, this
/// simplified version credits all fees to a single admin account. In a real
/// implementation you would track stakers and perform fair division.
#[program]
pub mod comp_pool_program {
    use super::*;
    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        pool.admin = *ctx.accounts.admin.key;
        pool.collected = 0;
        Ok(())
    }
    pub fn deposit_fee(ctx: Context<DepositFee>, amount: u64) -> Result<()> {
        // transfer lamports from payer to pool account
        let ix = anchor_lang::solana_program::system_instruction::transfer(
            ctx.accounts.payer.key,
            ctx.accounts.pool_account.key,
            amount,
        );
        anchor_lang::solana_program::program::invoke(
            &ix,
            &[ctx.accounts.payer.to_account_info(), ctx.accounts.pool_account.to_account_info()],
        )?;
        ctx.accounts.pool.collected += amount;
        Ok(())
    }
    pub fn distribute(ctx: Context<Distribute>) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        require!(pool.collected > 0, CustomError::NoFees);
        // in this example we send all collected fees to admin
        let amount = pool.collected;
        pool.collected = 0;
        **ctx.accounts.pool_account.to_account_info().try_borrow_mut_lamports()? -= amount;
        **ctx.accounts.admin.try_borrow_mut_lamports()? += amount;
        Ok(())
    }
}

#[account]
pub struct CompPool {
    pub admin: Pubkey,
    pub collected: u64,
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(init, payer = admin, space = 8 + 32 + 8)]
    pub pool: Account<'info, CompPool>,
    #[account(mut, signer)]
    pub admin: AccountInfo<'info>,
    pub system_program: Program<'info, System>,
    #[account(mut)]
    pub pool_account: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct DepositFee<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(mut)]
    pub pool: Account<'info, CompPool>,
    #[account(mut)]
    pub pool_account: AccountInfo<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Distribute<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,
    #[account(mut)]
    pub pool: Account<'info, CompPool>,
    #[account(mut)]
    pub pool_account: AccountInfo<'info>,
}

#[error_code]
pub enum CustomError {
    #[msg("No fees available for distribution")] NoFees,
}