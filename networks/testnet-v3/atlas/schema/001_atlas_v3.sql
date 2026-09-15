BEGIN;

CREATE TABLE atlas_network (
  singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
  chain_id BIGINT NOT NULL CHECK (chain_id = 1266),
  chain_incarnation BIGINT NOT NULL CHECK (chain_incarnation = 4),
  network_id TEXT NOT NULL CHECK (network_id = 'synergy-testnet-v3'),
  genesis_hash TEXT NOT NULL CHECK (genesis_hash ~ '^[0-9a-f]{64}$'),
  network_magic TEXT NOT NULL CHECK (network_magic ~ '^[0-9a-f]{8}$'),
  rpc_url TEXT NOT NULL,
  api_url TEXT NOT NULL,
  websocket_url TEXT NOT NULL,
  manifest_sha256 TEXT NOT NULL CHECK (manifest_sha256 ~ '^[0-9a-f]{64}$'),
  configured_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE blocks (
  chain_id BIGINT NOT NULL DEFAULT 1266 CHECK (chain_id = 1266),
  chain_incarnation BIGINT NOT NULL DEFAULT 4 CHECK (chain_incarnation = 4),
  network_id TEXT NOT NULL DEFAULT 'synergy-testnet-v3' CHECK (network_id = 'synergy-testnet-v3'),
  height BIGINT NOT NULL CHECK (height >= 0),
  hash TEXT NOT NULL,
  parent_hash TEXT,
  proposer_address TEXT,
  block_timestamp TIMESTAMPTZ,
  finalized BOOLEAN NOT NULL DEFAULT FALSE,
  transaction_count INTEGER NOT NULL DEFAULT 0 CHECK (transaction_count >= 0),
  payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  PRIMARY KEY (network_id, hash),
  UNIQUE (network_id, height)
);

CREATE TABLE transactions (
  chain_id BIGINT NOT NULL DEFAULT 1266 CHECK (chain_id = 1266),
  chain_incarnation BIGINT NOT NULL DEFAULT 4 CHECK (chain_incarnation = 4),
  network_id TEXT NOT NULL DEFAULT 'synergy-testnet-v3' CHECK (network_id = 'synergy-testnet-v3'),
  hash TEXT NOT NULL,
  block_hash TEXT,
  block_height BIGINT,
  sender_address TEXT,
  receiver_address TEXT,
  amount_base_units NUMERIC(78, 0),
  fee_base_units NUMERIC(78, 0),
  status TEXT NOT NULL DEFAULT 'pending',
  transaction_timestamp TIMESTAMPTZ,
  payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  PRIMARY KEY (network_id, hash),
  FOREIGN KEY (network_id, block_hash) REFERENCES blocks (network_id, hash) DEFERRABLE INITIALLY DEFERRED
);

CREATE TABLE accounts (
  chain_id BIGINT NOT NULL DEFAULT 1266 CHECK (chain_id = 1266),
  chain_incarnation BIGINT NOT NULL DEFAULT 4 CHECK (chain_incarnation = 4),
  network_id TEXT NOT NULL DEFAULT 'synergy-testnet-v3' CHECK (network_id = 'synergy-testnet-v3'),
  address TEXT NOT NULL,
  balance_base_units NUMERIC(78, 0) NOT NULL DEFAULT 0,
  staked_base_units NUMERIC(78, 0) NOT NULL DEFAULT 0,
  account_type TEXT,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (network_id, address)
);

CREATE TABLE tokens (
  chain_id BIGINT NOT NULL DEFAULT 1266 CHECK (chain_id = 1266),
  chain_incarnation BIGINT NOT NULL DEFAULT 4 CHECK (chain_incarnation = 4),
  network_id TEXT NOT NULL DEFAULT 'synergy-testnet-v3' CHECK (network_id = 'synergy-testnet-v3'),
  token_id TEXT NOT NULL,
  symbol TEXT NOT NULL,
  name TEXT NOT NULL,
  decimals INTEGER CHECK (decimals BETWEEN 0 AND 255),
  total_supply NUMERIC(78, 0),
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  PRIMARY KEY (network_id, token_id)
);

CREATE TABLE token_holders (
  chain_incarnation BIGINT NOT NULL DEFAULT 4 CHECK (chain_incarnation = 4),
  network_id TEXT NOT NULL DEFAULT 'synergy-testnet-v3' CHECK (network_id = 'synergy-testnet-v3'),
  token_id TEXT NOT NULL,
  account_address TEXT NOT NULL,
  balance_base_units NUMERIC(78, 0) NOT NULL,
  PRIMARY KEY (network_id, token_id, account_address),
  FOREIGN KEY (network_id, token_id) REFERENCES tokens (network_id, token_id) ON DELETE CASCADE
);

CREATE TABLE contracts (
  chain_id BIGINT NOT NULL DEFAULT 1266 CHECK (chain_id = 1266),
  chain_incarnation BIGINT NOT NULL DEFAULT 4 CHECK (chain_incarnation = 4),
  network_id TEXT NOT NULL DEFAULT 'synergy-testnet-v3' CHECK (network_id = 'synergy-testnet-v3'),
  address TEXT NOT NULL,
  name TEXT,
  contract_type TEXT,
  bytecode_hash TEXT,
  abi JSONB,
  deployment_block_hash TEXT,
  deployment_height BIGINT,
  creator_address TEXT,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  PRIMARY KEY (network_id, address)
);

CREATE TABLE validators (
  chain_id BIGINT NOT NULL DEFAULT 1266 CHECK (chain_id = 1266),
  chain_incarnation BIGINT NOT NULL DEFAULT 4 CHECK (chain_incarnation = 4),
  network_id TEXT NOT NULL DEFAULT 'synergy-testnet-v3' CHECK (network_id = 'synergy-testnet-v3'),
  address TEXT NOT NULL,
  validator_id TEXT,
  reward_address TEXT,
  status TEXT NOT NULL DEFAULT 'unknown',
  voting_power NUMERIC(78, 0),
  self_stake NUMERIC(78, 0),
  posy_score NUMERIC,
  cluster_id TEXT,
  metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
  PRIMARY KEY (network_id, address)
);

CREATE TABLE internal_transfers (
  chain_incarnation BIGINT NOT NULL DEFAULT 4 CHECK (chain_incarnation = 4),
  network_id TEXT NOT NULL DEFAULT 'synergy-testnet-v3' CHECK (network_id = 'synergy-testnet-v3'),
  transaction_hash TEXT NOT NULL,
  transfer_index INTEGER NOT NULL CHECK (transfer_index >= 0),
  sender_address TEXT,
  receiver_address TEXT,
  amount_base_units NUMERIC(78, 0) NOT NULL,
  PRIMARY KEY (network_id, transaction_hash, transfer_index),
  FOREIGN KEY (network_id, transaction_hash) REFERENCES transactions (network_id, hash) ON DELETE CASCADE
);

CREATE TABLE approvals (
  chain_incarnation BIGINT NOT NULL DEFAULT 4 CHECK (chain_incarnation = 4),
  network_id TEXT NOT NULL DEFAULT 'synergy-testnet-v3' CHECK (network_id = 'synergy-testnet-v3'),
  transaction_hash TEXT NOT NULL,
  approval_index INTEGER NOT NULL CHECK (approval_index >= 0),
  owner_address TEXT NOT NULL,
  spender_address TEXT NOT NULL,
  token_id TEXT,
  amount_base_units NUMERIC(78, 0),
  PRIMARY KEY (network_id, transaction_hash, approval_index),
  FOREIGN KEY (network_id, transaction_hash) REFERENCES transactions (network_id, hash) ON DELETE CASCADE
);

CREATE TABLE activity_records (
  chain_incarnation BIGINT NOT NULL DEFAULT 4 CHECK (chain_incarnation = 4),
  network_id TEXT NOT NULL DEFAULT 'synergy-testnet-v3' CHECK (network_id = 'synergy-testnet-v3'),
  activity_id TEXT NOT NULL,
  account_address TEXT,
  transaction_hash TEXT,
  activity_type TEXT NOT NULL,
  occurred_at TIMESTAMPTZ,
  payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  PRIMARY KEY (network_id, activity_id)
);

CREATE TABLE fee_collections (
  chain_incarnation BIGINT NOT NULL DEFAULT 4 CHECK (chain_incarnation = 4),
  network_id TEXT NOT NULL DEFAULT 'synergy-testnet-v3' CHECK (network_id = 'synergy-testnet-v3'),
  transaction_hash TEXT NOT NULL,
  collector_address TEXT NOT NULL,
  amount_base_units NUMERIC(78, 0) NOT NULL,
  block_height BIGINT,
  PRIMARY KEY (network_id, transaction_hash),
  FOREIGN KEY (network_id, transaction_hash) REFERENCES transactions (network_id, hash) ON DELETE CASCADE
);

CREATE TABLE reward_distributions (
  chain_incarnation BIGINT NOT NULL DEFAULT 4 CHECK (chain_incarnation = 4),
  network_id TEXT NOT NULL DEFAULT 'synergy-testnet-v3' CHECK (network_id = 'synergy-testnet-v3'),
  distribution_id TEXT NOT NULL,
  validator_address TEXT,
  reward_address TEXT,
  amount_base_units NUMERIC(78, 0) NOT NULL,
  epoch BIGINT,
  block_height BIGINT,
  payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  PRIMARY KEY (network_id, distribution_id)
);

CREATE TABLE etdag_vertices (
  chain_incarnation BIGINT NOT NULL DEFAULT 4 CHECK (chain_incarnation = 4),
  network_id TEXT NOT NULL DEFAULT 'synergy-testnet-v3' CHECK (network_id = 'synergy-testnet-v3'),
  vertex_hash TEXT NOT NULL,
  block_hash TEXT,
  proposer_address TEXT,
  availability_certificate TEXT,
  status TEXT NOT NULL DEFAULT 'unknown',
  created_at TIMESTAMPTZ,
  payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  PRIMARY KEY (network_id, vertex_hash)
);

CREATE TABLE etdag_edges (
  chain_incarnation BIGINT NOT NULL DEFAULT 4 CHECK (chain_incarnation = 4),
  network_id TEXT NOT NULL DEFAULT 'synergy-testnet-v3' CHECK (network_id = 'synergy-testnet-v3'),
  child_vertex_hash TEXT NOT NULL,
  parent_vertex_hash TEXT NOT NULL,
  PRIMARY KEY (network_id, child_vertex_hash, parent_vertex_hash),
  FOREIGN KEY (network_id, child_vertex_hash) REFERENCES etdag_vertices (network_id, vertex_hash) ON DELETE CASCADE,
  FOREIGN KEY (network_id, parent_vertex_hash) REFERENCES etdag_vertices (network_id, vertex_hash) ON DELETE CASCADE
);

CREATE TABLE chart_points (
  chain_incarnation BIGINT NOT NULL DEFAULT 4 CHECK (chain_incarnation = 4),
  network_id TEXT NOT NULL DEFAULT 'synergy-testnet-v3' CHECK (network_id = 'synergy-testnet-v3'),
  series TEXT NOT NULL,
  bucket_start TIMESTAMPTZ NOT NULL,
  value NUMERIC NOT NULL,
  PRIMARY KEY (network_id, series, bucket_start)
);

CREATE TABLE aggregate_metrics (
  chain_incarnation BIGINT NOT NULL DEFAULT 4 CHECK (chain_incarnation = 4),
  network_id TEXT NOT NULL DEFAULT 'synergy-testnet-v3' CHECK (network_id = 'synergy-testnet-v3'),
  metric_name TEXT NOT NULL,
  metric_value JSONB NOT NULL,
  computed_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (network_id, metric_name)
);

CREATE TABLE indexer_state (
  singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
  chain_id BIGINT NOT NULL DEFAULT 1266 CHECK (chain_id = 1266),
  chain_incarnation BIGINT NOT NULL DEFAULT 4 CHECK (chain_incarnation = 4),
  network_id TEXT NOT NULL DEFAULT 'synergy-testnet-v3' CHECK (network_id = 'synergy-testnet-v3'),
  indexed_height BIGINT NOT NULL DEFAULT -1 CHECK (indexed_height >= -1),
  indexed_block_hash TEXT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE indexer_checkpoints (
  chain_incarnation BIGINT NOT NULL DEFAULT 4 CHECK (chain_incarnation = 4),
  network_id TEXT NOT NULL DEFAULT 'synergy-testnet-v3' CHECK (network_id = 'synergy-testnet-v3'),
  height BIGINT NOT NULL CHECK (height >= 0),
  block_hash TEXT NOT NULL,
  state_root TEXT,
  checkpointed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (network_id, height)
);

CREATE INDEX transactions_by_block ON transactions (network_id, block_height DESC);
CREATE INDEX transactions_by_sender ON transactions (network_id, sender_address, transaction_timestamp DESC);
CREATE INDEX transactions_by_receiver ON transactions (network_id, receiver_address, transaction_timestamp DESC);
CREATE INDEX activity_by_account ON activity_records (network_id, account_address, occurred_at DESC);
CREATE INDEX chart_points_by_series ON chart_points (network_id, series, bucket_start DESC);

COMMIT;
