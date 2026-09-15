use anchor_lang::prelude::*;

declare_id!("SXCPLgrr1111111111111111111111111111111");

/// audit_logger_program emits audit events for SXCP operations. On Solana,
/// events are logged via the Anchor `emit!` macro. A history account is
/// optionally maintained to allow on‑chain queries, though in many cases
/// off‑chain indexers are preferable.
#[program]
pub mod audit_logger_program {
    use super::*;
    pub fn record(ctx: Context<Record>, event_hash: [u8; 32], action: String) -> Result<()> {
        let entry = LogEntry {
            actor: *ctx.accounts.actor.key,
            event_hash,
            action: action.clone(),
            timestamp: Clock::get()?.unix_timestamp,
        };
        // append to the history account
        ctx.accounts.history.entries.push(entry.clone());
        emit!(AuditEvent { actor: *ctx.accounts.actor.key, event_hash, action });
        Ok(())
    }
}

#[account]
pub struct History {
    pub entries: Vec<LogEntry>,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct LogEntry {
    pub actor: Pubkey,
    pub event_hash: [u8; 32],
    pub action: String,
    pub timestamp: i64,
}

#[derive(Accounts)]
pub struct Record<'info> {
    #[account(mut, signer)]
    pub actor: AccountInfo<'info>,
    #[account(mut)]
    pub history: Account<'info, History>,
    pub system_program: Program<'info, System>,
}

#[event]
pub struct AuditEvent {
    pub actor: Pubkey,
    pub event_hash: [u8; 32],
    pub action: String,
}