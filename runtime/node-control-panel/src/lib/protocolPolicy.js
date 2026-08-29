export function epochForBlockHeight(blockHeight, epochLength = 1000) {
  const height = Number(blockHeight);
  const length = Number(epochLength);
  if (!Number.isFinite(height) || !Number.isFinite(length) || length <= 0) return null;
  const normalizedHeight = Math.max(0, Math.trunc(height));
  const normalizedLength = Math.trunc(length);
  if (normalizedLength <= 0) return null;
  return normalizedHeight === 0
    ? 0
    : Math.floor((normalizedHeight - 1) / normalizedLength);
}

export function epochWindowForBlockHeight(blockHeight, epochLength = 1000) {
  const height = Number(blockHeight);
  const length = Number(epochLength);
  const epoch = epochForBlockHeight(height, length);
  if (epoch === null) return null;
  const normalizedHeight = Math.max(0, Math.trunc(height));
  const normalizedLength = Math.trunc(length);
  const startHeight = (epoch * normalizedLength) + 1;
  const endHeight = (epoch + 1) * normalizedLength;
  const observedBlocks = normalizedHeight === 0
    ? 0
    : normalizedHeight - startHeight + 1;
  return {
    epoch,
    startHeight,
    endHeight,
    progress: Math.min(100, Math.max(0, (observedBlocks / normalizedLength) * 100)),
    remaining: Math.max(0, endHeight - normalizedHeight),
  };
}

export function validatorClusterQuorumThreshold(totalValidators) {
  const count = Number(totalValidators);
  if (!Number.isFinite(count) || count <= 0) return 0;
  const normalizedCount = Math.trunc(count);
  if (normalizedCount <= 0) return 0;
  // Smallest q satisfying 3*q > 2*n.
  return normalizedCount - Math.floor((normalizedCount - 1) / 3);
}

export function validatorClusterCount(totalValidators) {
  const count = Number(totalValidators);
  if (!Number.isFinite(count) || count <= 0) return 0;
  const normalizedCount = Math.trunc(count);
  if (normalizedCount < 10) return 1;
  if (normalizedCount < 21) return 2;
  return Math.floor(normalizedCount / 7);
}

export function validatorLargestClusterSize(totalValidators) {
  const count = Number(totalValidators);
  if (!Number.isFinite(count) || count <= 0) return 0;
  const normalizedCount = Math.trunc(count);
  const clusterCount = validatorClusterCount(normalizedCount);
  return clusterCount === 0 ? 0 : Math.ceil(normalizedCount / clusterCount);
}

export function validatorNetworkClusterQuorumThreshold(totalValidators) {
  return validatorClusterQuorumThreshold(validatorLargestClusterSize(totalValidators));
}
