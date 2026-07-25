const EMPTY_ACCOUNT_SNAPSHOT = Object.freeze({
  address: undefined,
  chainId: undefined,
  isConnected: false,
});

export function normalizeAccountSnapshot(account) {
  return account && typeof account === "object" ? account : EMPTY_ACCOUNT_SNAPSHOT;
}
