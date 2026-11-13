import { ethers } from 'ethers';
import EventEmitter from 'events';

const INTENT_COMMITTED_EVENT = 'IntentCommitted(bytes32,address,uint256,bytes32,uint256,uint256)';
const POLL_INTERVAL_MS = 12000; // 12 seconds
const CONFIRMATION_BLOCKS = 12;

export class SourceChainWatcher extends EventEmitter {
  constructor(chainId, wsUrl, rpcUrl, store, config = {}) {
    super();
    this.chainId = chainId;
    this.wsUrl = wsUrl;
    this.rpcUrl = rpcUrl;
    this.store = store;
    this.config = {
      pollIntervalMs: config.pollIntervalMs || POLL_INTERVAL_MS,
      confirmationBlocks: config.confirmationBlocks || CONFIRMATION_BLOCKS,
      ...config,
    };

    this.wsProvider = null;
    this.rpcProvider = null;
    this.contract = null;
    this.contractAddress = null;
    this.currentBlock = 0;
    this.lastPolledBlock = 0;
    this.pollingTimer = null;
    this.isPolling = false;
    this.wsConnected = false;

    this.logger = console;
  }

  async initialize(contractAddress) {
    this.contractAddress = contractAddress;

    // Create providers
    this.rpcProvider = new ethers.JsonRpcProvider(this.rpcUrl);

    // Try WebSocket first
    try {
      this.wsProvider = new ethers.WebSocketEventProvider(this.wsUrl);
      this.wsProvider.on('error', () => {
        this.logger.warn(`[Watcher:${this.chainId}] WebSocket disconnected, falling back to polling`);
        this.wsConnected = false;
        this.startPolling();
      });
      this.wsProvider.on('network', () => {
        this.wsConnected = true;
        this.logger.info(`[Watcher:${this.chainId}] WebSocket reconnected`);
        this.stopPolling();
      });
    } catch (error) {
      this.logger.warn(`[Watcher:${this.chainId}] WebSocket unavailable, using polling: ${error.message}`);
      this.startPolling();
    }

    // Create contract interface for event filtering
    const abi = [
      'event IntentCommitted(bytes32 indexed intentId, address indexed sender, uint256 nonce, bytes32 intentHash, uint256 indexed blockNumber, uint256 timestamp)',
    ];
    const iface = new ethers.Interface(abi);
    this.eventTopic = iface.getEventTopic('IntentCommitted');

    // Get current block
    const network = await this.rpcProvider.getNetwork();
    this.currentBlock = await this.rpcProvider.getBlockNumber();
    this.lastPolledBlock = this.currentBlock - 1;

    // Restore checkpoint
    const checkpoint = this.store.getCheckpoint(this.chainId);
    if (checkpoint.last_block_number > 0) {
      this.lastPolledBlock = checkpoint.last_block_number;
      this.logger.info(`[Watcher:${this.chainId}] Restored checkpoint at block ${this.lastPolledBlock}`);
    }

    this.logger.info(`[Watcher:${this.chainId}] Initialized on chain ${this.chainId} at block ${this.currentBlock}`);

    // Setup event listeners with WebSocket (will fall back to polling)
    if (this.wsProvider && this.wsConnected) {
      this.setupWebSocketListeners();
    } else {
      this.startPolling();
    }
  }

  setupWebSocketListeners() {
    const filter = {
      address: this.contractAddress,
      topics: [this.eventTopic],
    };

    this.wsProvider.on(filter, (log) => {
      this.processLog(log);
    });

    this.logger.info(`[Watcher:${this.chainId}] WebSocket listeners configured`);
  }

  async processLog(log) {
    try {
      const abi = [
        'event IntentCommitted(bytes32 indexed intentId, address indexed sender, uint256 nonce, bytes32 intentHash, uint256 indexed blockNumber, uint256 timestamp)',
      ];
      const iface = new ethers.Interface(abi);
      const parsed = iface.parseLog(log);

      if (!parsed) return;

      const event = {
        chainId: this.chainId,
        txHash: log.transactionHash,
        eventIndex: log.logIndex,
        intentId: parsed.args[0],
        sender: parsed.args[1],
        nonce: parsed.args[2],
        intentHash: parsed.args[3],
        blockNumber: parsed.args[4],
        timestamp: parsed.args[5],
        blockTime: (await this.rpcProvider.getBlock(log.blockNumber))?.timestamp || Math.floor(Date.now() / 1000),
      };

      // Check replay cache
      if (this.store.isInReplayCache(this.chainId, log.blockNumber, log.transactionHash, this.eventTopic)) {
        return;
      }

      // Record in store
      const isNew = this.store.recordProcessedEvent(event);
      if (!isNew) {
        return;
      }

      this.store.addToReplayCache(this.chainId, log.blockNumber, log.transactionHash, this.eventTopic);

      this.logger.info(`[Watcher:${this.chainId}] IntentCommitted: ${event.intentId} from ${event.sender} (nonce: ${event.nonce})`);

      // Emit for coordinator
      this.emit('IntentCommitted', event);

      // Update checkpoint
      if (log.blockNumber > this.lastPolledBlock) {
        this.lastPolledBlock = log.blockNumber;
        this.store.setCheckpoint(this.chainId, this.lastPolledBlock);
      }
    } catch (error) {
      this.logger.error(`[Watcher:${this.chainId}] Error processing log: ${error.message}`);
    }
  }

  startPolling() {
    if (this.isPolling) return;

    this.isPolling = true;
    this.logger.info(`[Watcher:${this.chainId}] Started polling for events`);

    const poll = async () => {
      try {
        const currentBlock = await this.rpcProvider.getBlockNumber();
        const toBlock = Math.max(this.lastPolledBlock, currentBlock - this.config.confirmationBlocks);

        if (toBlock > this.lastPolledBlock) {
          const logs = await this.rpcProvider.getLogs({
            address: this.contractAddress,
            topics: [this.eventTopic],
            fromBlock: this.lastPolledBlock + 1,
            toBlock,
          });

          for (const log of logs) {
            await this.processLog(log);
          }

          this.lastPolledBlock = toBlock;
          this.store.setCheckpoint(this.chainId, this.lastPolledBlock);
        }
      } catch (error) {
        this.logger.error(`[Watcher:${this.chainId}] Polling error: ${error.message}`);
      }

      if (this.isPolling) {
        this.pollingTimer = setTimeout(poll, this.config.pollIntervalMs);
      }
    };

    this.pollingTimer = setTimeout(poll, 100); // Start immediately
  }

  stopPolling() {
    if (!this.isPolling) return;

    this.isPolling = false;
    if (this.pollingTimer) {
      clearTimeout(this.pollingTimer);
      this.pollingTimer = null;
    }

    this.logger.info(`[Watcher:${this.chainId}] Stopped polling`);
  }

  getLastProcessedBlock() {
    return this.lastPolledBlock;
  }

  async close() {
    this.stopPolling();
    if (this.wsProvider) {
      this.wsProvider.removeAllListeners();
    }
    this.logger.info(`[Watcher:${this.chainId}] Closed`);
  }
}
