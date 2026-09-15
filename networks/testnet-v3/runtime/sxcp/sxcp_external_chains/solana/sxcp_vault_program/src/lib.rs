use anchor_lang::prelude::*;

// Placeholder program ID. Replace with the actual ID upon deployment.
declare_id!("SXCPVaul1111111111111111111111111111111111");

/// The sxcp_vault_program implements a chain‑side vault for the Synergy
/// Cross‑Chain Protocol on Solana. It handles deposits under hash‑time locks
/// and releases funds based on secrets or witness attestations. This file is
/// intentionally simple and omits token transfers; it demonstrates how to
/// structure Anchor programs for SXCP.

#[program]
pub mod sxcp_vault_program {
    use super::*;

    /// Lock lamports under a hash‑time lock. The depositor sends lamports to
    /// the program and specifies a hash of the secret and a timeout. The
    /// deposit is recorded on chain and relayers monitor the Deposit event.
    pub fn deposit(ctx: Context<Deposit>, hash_lock: [u8; 32], timeout: i64) -> Result<()> {
        let deposit = &mut ctx.accounts.deposit_record;
        require!(timeout > Clock::get()?.unix_timestamp, CustomError::InvalidTimeout);
        deposit.depositor = ctx.accounts.depositor.key();
        deposit.amount = ctx.accounts.system_program.lamports().checked_sub(ctx.accounts.depositor.lamports()).unwrap_or(0);
        deposit.hash_lock = hash_lock;
        deposit.timeout = timeout;
        deposit.claimed = false;
        Ok(())
    }

    /// Claim the deposit by revealing the preimage of the hash lock. Funds are
    /// transferred to the claimer. In a real implementation this would involve
    /// token program instructions.
    pub fn claim(ctx: Context<Claim>, _deposit_id: [u8; 32], _preimage: [u8; 32]) -> Result<()> {
        let _deposit = &mut ctx.accounts.deposit_record;
        // Verify preimage matches hash_lock and transfer lamports.
        Ok(())
    }

    /// Refund the deposit after the timeout expires. Only the original
    /// depositor can trigger a refund.
    pub fn refund(ctx: Context<Refund>, _deposit_id: [u8; 32]) -> Result<()> {
        let _deposit = &mut ctx.accounts.deposit_record;
        // Check timeout and return lamports to depositor.
        Ok(())
    }
}

/// Stores a pending deposit for atomic swap mode.
#[account]
pub struct DepositRecord {
    pub depositor: Pubkey,
    pub amount: u64,
    pub hash_lock: [u8; 32],
    pub timeout: i64,
    pub claimed: bool,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut, signer)]
    pub depositor: AccountInfo<'info>,
    #[account(init, payer = depositor, space = 8 + 32 + 8 + 32 + 8 + 1)]
    pub deposit_record: Account<'info, DepositRecord>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Claim<'info> {
    #[account(mut, has_one = depositor)]
    pub deposit_record: Account<'info, DepositRecord>,
    pub depositor: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct Refund<'info> {
    #[account(mut, has_one = depositor)]
    pub deposit_record: Account<'info, DepositRecord>,
    pub depositor: AccountInfo<'info>,
}

#[error_code]
pub enum CustomError {
    #[msg("Timeout must be in the future")]
    InvalidTimeout,
}