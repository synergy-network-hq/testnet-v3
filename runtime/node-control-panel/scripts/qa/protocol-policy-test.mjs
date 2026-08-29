import assert from 'node:assert/strict';
import test from 'node:test';
import {
  epochForBlockHeight,
  epochWindowForBlockHeight,
  validatorClusterCount,
  validatorClusterQuorumThreshold,
  validatorLargestClusterSize,
  validatorNetworkClusterQuorumThreshold,
} from '../../src/lib/protocolPolicy.js';

test('epochs use one-based 1000-block boundaries', () => {
  for (const [height, expectedEpoch] of [
    [0, 0],
    [1, 0],
    [1000, 0],
    [1001, 1],
    [2000, 1],
    [2001, 2],
  ]) {
    assert.equal(epochForBlockHeight(height), expectedEpoch, `height ${height}`);
  }
});

test('epoch windows preserve inclusive block ranges', () => {
  assert.deepEqual(epochWindowForBlockHeight(0), {
    epoch: 0,
    startHeight: 1,
    endHeight: 1000,
    progress: 0,
    remaining: 1000,
  });
  assert.deepEqual(epochWindowForBlockHeight(1000), {
    epoch: 0,
    startHeight: 1,
    endHeight: 1000,
    progress: 100,
    remaining: 0,
  });
  assert.deepEqual(epochWindowForBlockHeight(1001), {
    epoch: 1,
    startHeight: 1001,
    endHeight: 2000,
    progress: 0.1,
    remaining: 999,
  });
});

test('cluster quorum matches canonical five, six, and seven member policy', () => {
  assert.equal(validatorClusterQuorumThreshold(0), 0);
  assert.equal(validatorClusterQuorumThreshold(0.5), 0);
  assert.equal(validatorClusterQuorumThreshold(5), 4);
  assert.equal(validatorClusterQuorumThreshold(6), 5);
  assert.equal(validatorClusterQuorumThreshold(7), 5);
});

test('network quorum is derived from balanced cluster size, not total validators', () => {
  for (const [validators, clusters, largestCluster, quorum] of [
    [0, 0, 0, 0],
    [6, 1, 6, 5],
    [9, 1, 9, 7],
    [10, 2, 5, 4],
    [15, 2, 8, 6],
    [20, 2, 10, 7],
    [21, 3, 7, 5],
    [27, 3, 9, 7],
    [28, 4, 7, 5],
    [29, 4, 8, 6],
    [35, 5, 7, 5],
  ]) {
    assert.equal(validatorClusterCount(validators), clusters, `${validators} cluster count`);
    assert.equal(
      validatorLargestClusterSize(validators),
      largestCluster,
      `${validators} largest cluster`,
    );
    assert.equal(
      validatorNetworkClusterQuorumThreshold(validators),
      quorum,
      `${validators} network cluster quorum`,
    );
  }
});
