const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { setupOnboardingIpc } = require('../../electron/ipc/onboarding-ipc.cjs');

async function main() {
  const handlers = new Map();
  const userDataPath = fs.mkdtempSync(path.join(os.tmpdir(), 'synergy-bond-stake-'));
  const commands = [];
  try {
    setupOnboardingIpc(
      { handle: (channel, handler) => handlers.set(channel, handler) },
      {
        invokeControlService: async (command, args) => {
          commands.push({ command, args });
          assert.ok(['testnet_set_validator_owner', 'testnet_record_validator_funding'].includes(command));
          return { status: 'ok' };
        },
        userDataPath,
      },
    );
    const bondStake = handlers.get('onboarding:bond-stake');
    assert.equal(typeof bondStake, 'function');
    const response = await bondStake({}, {
      nodeId: 'validator-1',
      walletAddress: 'syn1operator',
      validatorAddress: 'synv1validator',
      amountNwei: '50001000000000',
    });

    assert.equal(response.ok, true);
    const envelope = response.walletRequest.envelope;
    const payload = JSON.parse(envelope.data.slice('token_transfer:'.length));
    assert.equal(payload.amount, 50001000000000);
    assert.equal(payload.to, 'synv1validator');
    assert.equal(envelope.value, '1');
    assert.equal(envelope.tokenAmountNwei, '50001000000000');
    assert.equal(envelope.gasLimit, '100000');
    assert.equal(envelope.metadata.amountSnrg, 50001);
    assert.equal(envelope.metadata.amountNwei, '50001000000000');
    assert.equal(envelope.metadata.bondAmountSnrg, 50000);
    assert.equal(envelope.metadata.feeReserveSnrg, 1);

    const recordValidatorFunding = handlers.get('onboarding:record-validator-funding');
    assert.equal(typeof recordValidatorFunding, 'function');
    const recordResponse = await recordValidatorFunding({}, {
      nodeId: 'validator-1',
      txHash: '0x0123456789abcdef',
      amountSnrg: 50001,
    });
    assert.equal(recordResponse.ok, true);
    assert.deepEqual(commands.at(-1), {
      command: 'testnet_record_validator_funding',
      args: {
        input: {
          nodeId: 'validator-1',
          txHash: '0x0123456789abcdef',
          amountSnrg: 50001,
        },
      },
    });
    const invalidAmount = await recordValidatorFunding({}, {
      nodeId: 'validator-1',
      txHash: '0x0123456789abcdef',
      amountSnrg: 'not-a-number',
    });
    assert.equal(invalidAmount.ok, false);
    assert.equal(invalidAmount.code, 'STAKE_AMOUNT_INVALID');

    const exactBondOnly = await recordValidatorFunding({}, {
      nodeId: 'validator-1',
      txHash: '0x0123456789abcdef',
      amountSnrg: 50000,
    });
    assert.equal(exactBondOnly.ok, false);
    assert.equal(exactBondOnly.code, 'STAKE_AMOUNT_INVALID');
  } finally {
    fs.rmSync(userDataPath, { recursive: true, force: true });
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
