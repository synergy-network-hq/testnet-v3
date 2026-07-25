import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';

const source = await readFile(new URL('../../src/services/validatorEligibilityService.js', import.meta.url), 'utf8');
const testableSource = source.replace(
  "import { invokeOnboarding } from '../lib/desktopClient';",
  `const invokeOnboarding = async (action, input) => {
    globalThis.__onboardingCalls = [...(globalThis.__onboardingCalls || []), { action, input }];
    if (action === 'verifyValidatorEligibility') return globalThis.__eligibilityPayload;
    if (action === 'bondStake') return globalThis.__bondStakeResponse || {};
    if (action === 'recordValidatorFunding') return {};
    throw new Error('Unexpected onboarding action in test: ' + action);
  };`,
);
const {
  ELIGIBILITY_STATUSES,
  VALIDATOR_FUNDING_SENDER_MINIMUM_SNRG,
  validatorEligibilityService,
} = await import(
  `data:text/javascript,${encodeURIComponent(testableSource)}`,
);

test('exact 50,000 SNRG funding is not ready to bond', async () => {
  globalThis.__eligibilityPayload = {
    snrgBalance: 50_000,
    activeStakeAmount: 0,
    validatorFundingAmount: 50_000,
    fundingReadyToBond: true,
    eligibilityStatus: ELIGIBILITY_STATUSES.stakeReadyToBond,
  };

  const eligibility = await validatorEligibilityService.verifyValidatorEligibility('syn1operator', {
    nodeId: 'validator-1',
    validatorAddress: 'synv1validator',
  });

  assert.equal(eligibility.requiredStake, 50_000);
  assert.equal(eligibility.validatorFundingAmount, 50_000);
  assert.equal(eligibility.fundingReadyToBond, false);
  assert.notEqual(eligibility.eligibilityStatus, ELIGIBILITY_STATUSES.stakeReadyToBond);
  assert.equal(eligibility.eligible, false);
});

test('owner wallet must also cover the dynamically estimated funding transaction fee', async () => {
  globalThis.__onboardingCalls = [];
  globalThis.__bondStakeResponse = {};
  globalThis.fetch = async (_url, options) => {
    const request = JSON.parse(options.body);
    const resultByMethod = {
      synergy_getAccountNonce: 6,
      synergy_estimateGas: {
        gas: 64120,
        maxFee: '15064420000',
      },
      synergy_getTokenBalance: 50_001_000_000_000,
    };
    return {
      ok: true,
      json: async () => ({ jsonrpc: '2.0', id: request.id, result: resultByMethod[request.method] }),
    };
  };

  let walletRequested = false;
  await assert.rejects(
    validatorEligibilityService.stakeRequiredAmount({
      walletAddress: 'synw1operator',
      validatorAddress: 'synv1validator',
      nodeId: 'validator-1',
      requestWalletAction: async () => {
        walletRequested = true;
        return {};
      },
    }),
    /owner wallet needs at least 50,016\.06442 SNRG/i,
  );

  assert.equal(walletRequested, false);
  assert.ok(VALIDATOR_FUNDING_SENDER_MINIMUM_SNRG > 50_016);
});

test('50,001 SNRG funding is ready while the 50,000 SNRG bond remains unconfirmed', async () => {
  globalThis.__eligibilityPayload = {
    snrgBalance: 50_001,
    activeStakeAmount: 0,
    validatorFundingAmount: 50_001,
    fundingReadyToBond: false,
  };

  const eligibility = await validatorEligibilityService.verifyValidatorEligibility('syn1operator', {
    nodeId: 'validator-1',
    validatorAddress: 'synv1validator',
  });

  assert.equal(eligibility.requiredStake, 50_000);
  assert.equal(eligibility.fundingReadyToBond, true);
  assert.equal(eligibility.eligibilityStatus, ELIGIBILITY_STATUSES.stakeReadyToBond);
  assert.equal(eligibility.eligible, false);
});
