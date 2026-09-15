import Database from 'better-sqlite3';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export class RelayerStore {
  constructor(dbPath) {
    this.dbPath = dbPath;
    this.db = null;
    this.logger = console;
  }

  initialize() {
    // Ensure directory exists
    const dir = path.dirname(this.dbPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    this.db = new Database(this.dbPath);
    this.db.pragma('journal_mode = WAL');
    this.db.pragma('synchronous = NORMAL');

    this.createTables();
    this.logger.info(`[Store] Initialized SQLite database at ${this.dbPath}`);
  }

  createTables() {
    // Processed events: track which IntentCommitted events have been seen
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS processed_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        chain_id INTEGER NOT NULL,
        tx_hash TEXT NOT NULL,
        event_index INTEGER NOT NULL,
        intent_id BLOB NOT NULL,
        sender ADDRESS NOT NULL,
        nonce INTEGER NOT NULL,
        intent_hash BLOB NOT NULL,
        block_number INTEGER NOT NULL,
        processed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(chain_id, tx_hash, event_index)
      )
    `);

    // Bundles: track attestation bundles
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS bundles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        bundle_id BLOB UNIQUE NOT NULL,
        source_chain_id INTEGER NOT NULL,
        dest_chain_id INTEGER NOT NULL,
        intent_id BLOB NOT NULL,
        bundle_hash BLOB NOT NULL,
        status TEXT NOT NULL DEFAULT 'pending',
        pqc_algorithm TEXT NOT NULL,
        signature_count INTEGER DEFAULT 0,
        threshold INTEGER NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        submitted_at DATETIME,
        finalized_at DATETIME
      )
    `);

    // Retry state: exponential backoff tracking
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS retry_state (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        bundle_id BLOB UNIQUE NOT NULL,
        retry_count INTEGER DEFAULT 0,
        last_attempt DATETIME,
        next_retry DATETIME,
        last_error TEXT,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Replay cache: prevent duplicate processing
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS replay_cache (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        chain_id INTEGER NOT NULL,
        block_number INTEGER NOT NULL,
        tx_hash TEXT NOT NULL,
        event_sig TEXT NOT NULL,
        cached_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(chain_id, block_number, tx_hash, event_sig)
      )
    `);

    // Checkpoints: track last processed block per chain
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS checkpoints (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        chain_id INTEGER UNIQUE NOT NULL,
        last_block_number INTEGER DEFAULT 0,
        last_finalized_block INTEGER DEFAULT 0,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Create indices for performance
    this.db.exec(`
      CREATE INDEX IF NOT EXISTS idx_processed_events_chain_block
        ON processed_events(chain_id, block_number);
      CREATE INDEX IF NOT EXISTS idx_bundles_status
        ON bundles(status);
      CREATE INDEX IF NOT EXISTS idx_bundles_created_at
        ON bundles(created_at);
      CREATE INDEX IF NOT EXISTS idx_retry_state_next_retry
        ON retry_state(next_retry);
    `);
  }

  // Checkpoint management
  getCheckpoint(chainId) {
    const stmt = this.db.prepare(
      'SELECT last_block_number, last_finalized_block FROM checkpoints WHERE chain_id = ?'
    );
    const result = stmt.get(chainId);
    return result || { last_block_number: 0, last_finalized_block: 0 };
  }

  setCheckpoint(chainId, blockNumber, finalizedBlock = null) {
    const stmt = this.db.prepare(`
      INSERT INTO checkpoints (chain_id, last_block_number, last_finalized_block, updated_at)
      VALUES (?, ?, ?, CURRENT_TIMESTAMP)
      ON CONFLICT(chain_id) DO UPDATE SET
        last_block_number = excluded.last_block_number,
        last_finalized_block = COALESCE(excluded.last_finalized_block, last_finalized_block)
    `);
    stmt.run(chainId, blockNumber, finalizedBlock);
  }

  // Event processing
  recordProcessedEvent(event) {
    const stmt = this.db.prepare(`
      INSERT INTO processed_events
      (chain_id, tx_hash, event_index, intent_id, sender, nonce, intent_hash, block_number)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);

    try {
      stmt.run(
        event.chainId,
        event.txHash,
        event.eventIndex || 0,
        Buffer.from(event.intentId.slice(2), 'hex'),
        event.sender,
        event.nonce,
        Buffer.from(event.intentHash.slice(2), 'hex'),
        event.blockNumber
      );
      return true;
    } catch (error) {
      if (error.message.includes('UNIQUE constraint failed')) {
        return false; // Already processed
      }
      throw error;
    }
  }

  isEventProcessed(chainId, txHash, eventIndex = 0) {
    const stmt = this.db.prepare(
      'SELECT id FROM processed_events WHERE chain_id = ? AND tx_hash = ? AND event_index = ?'
    );
    return stmt.get(chainId, txHash, eventIndex) !== undefined;
  }

  // Bundle management
  createBundle(bundleId, sourceChainId, destChainId, intentId, bundleHash, pqcAlgorithm, threshold) {
    const stmt = this.db.prepare(`
      INSERT INTO bundles
      (bundle_id, source_chain_id, dest_chain_id, intent_id, bundle_hash, pqc_algorithm, threshold)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      Buffer.from(bundleId.slice(2), 'hex'),
      sourceChainId,
      destChainId,
      Buffer.from(intentId.slice(2), 'hex'),
      Buffer.from(bundleHash.slice(2), 'hex'),
      pqcAlgorithm,
      threshold
    );
  }

  getBundle(bundleId) {
    const stmt = this.db.prepare(`
      SELECT id, bundle_id, source_chain_id, dest_chain_id, intent_id,
             bundle_hash, status, pqc_algorithm, signature_count, threshold,
             created_at, submitted_at, finalized_at
      FROM bundles WHERE bundle_id = ?
    `);

    const result = stmt.get(Buffer.from(bundleId.slice(2), 'hex'));
    if (!result) return null;

    return {
      id: result.id,
      bundleId: '0x' + result.bundle_id.toString('hex'),
      sourceChainId: result.source_chain_id,
      destChainId: result.dest_chain_id,
      intentId: '0x' + result.intent_id.toString('hex'),
      bundleHash: '0x' + result.bundle_hash.toString('hex'),
      status: result.status,
      pqcAlgorithm: result.pqc_algorithm,
      signatureCount: result.signature_count,
      threshold: result.threshold,
      createdAt: result.created_at,
      submittedAt: result.submitted_at,
      finalizedAt: result.finalized_at,
    };
  }

  updateBundleStatus(bundleId, status, submitted = false, finalized = false) {
    const stmt = this.db.prepare(`
      UPDATE bundles
      SET status = ?,
          submitted_at = CASE WHEN ? THEN CURRENT_TIMESTAMP ELSE submitted_at END,
          finalized_at = CASE WHEN ? THEN CURRENT_TIMESTAMP ELSE finalized_at END
      WHERE bundle_id = ?
    `);

    stmt.run(status, submitted ? 1 : 0, finalized ? 1 : 0, Buffer.from(bundleId.slice(2), 'hex'));
  }

  incrementBundleSignatures(bundleId) {
    const stmt = this.db.prepare(
      'UPDATE bundles SET signature_count = signature_count + 1 WHERE bundle_id = ?'
    );
    stmt.run(Buffer.from(bundleId.slice(2), 'hex'));
  }

  getPendingBundles(limit = 100) {
    const stmt = this.db.prepare(`
      SELECT bundle_id, source_chain_id, dest_chain_id, intent_id,
             bundle_hash, pqc_algorithm, signature_count, threshold
      FROM bundles
      WHERE status = 'pending'
      ORDER BY created_at ASC
      LIMIT ?
    `);

    const results = stmt.all(limit);
    return results.map(r => ({
      bundleId: '0x' + r.bundle_id.toString('hex'),
      sourceChainId: r.source_chain_id,
      destChainId: r.dest_chain_id,
      intentId: '0x' + r.intent_id.toString('hex'),
      bundleHash: '0x' + r.bundle_hash.toString('hex'),
      pqcAlgorithm: r.pqc_algorithm,
      signatureCount: r.signature_count,
      threshold: r.threshold,
    }));
  }

  // Retry state management
  getRetryState(bundleId) {
    const stmt = this.db.prepare(
      'SELECT retry_count, last_attempt, next_retry, last_error FROM retry_state WHERE bundle_id = ?'
    );
    const result = stmt.get(Buffer.from(bundleId.slice(2), 'hex'));
    return result || { retry_count: 0, last_attempt: null, next_retry: null, last_error: null };
  }

  recordRetry(bundleId, error, backoffSeconds) {
    const nextRetry = new Date(Date.now() + backoffSeconds * 1000);
    const stmt = this.db.prepare(`
      INSERT INTO retry_state (bundle_id, retry_count, last_attempt, next_retry, last_error, updated_at)
      VALUES (?, 1, CURRENT_TIMESTAMP, ?, ?, CURRENT_TIMESTAMP)
      ON CONFLICT(bundle_id) DO UPDATE SET
        retry_count = retry_count + 1,
        last_attempt = CURRENT_TIMESTAMP,
        next_retry = excluded.next_retry,
        last_error = excluded.last_error,
        updated_at = CURRENT_TIMESTAMP
    `);

    stmt.run(
      Buffer.from(bundleId.slice(2), 'hex'),
      nextRetry.toISOString(),
      error
    );
  }

  clearRetryState(bundleId) {
    const stmt = this.db.prepare('DELETE FROM retry_state WHERE bundle_id = ?');
    stmt.run(Buffer.from(bundleId.slice(2), 'hex'));
  }

  // Replay cache
  addToReplayCache(chainId, blockNumber, txHash, eventSig) {
    const stmt = this.db.prepare(`
      INSERT INTO replay_cache (chain_id, block_number, tx_hash, event_sig)
      VALUES (?, ?, ?, ?)
    `);

    try {
      stmt.run(chainId, blockNumber, txHash, eventSig);
    } catch (error) {
      if (!error.message.includes('UNIQUE constraint failed')) {
        throw error;
      }
    }
  }

  isInReplayCache(chainId, blockNumber, txHash, eventSig) {
    const stmt = this.db.prepare(
      'SELECT id FROM replay_cache WHERE chain_id = ? AND block_number = ? AND tx_hash = ? AND event_sig = ?'
    );
    return stmt.get(chainId, blockNumber, txHash, eventSig) !== undefined;
  }

  // Cleanup old cache entries
  pruneReplayCache(daysOld = 7) {
    const stmt = this.db.prepare(`
      DELETE FROM replay_cache
      WHERE cached_at < datetime('now', '-' || ? || ' days')
    `);
    const changes = stmt.run(daysOld).changes;
    this.logger.info(`[Store] Pruned ${changes} old replay cache entries`);
  }

  close() {
    if (this.db) {
      this.db.close();
      this.logger.info('[Store] Database connection closed');
    }
  }
}
