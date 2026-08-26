import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const fixtureUrl = new URL('../../control-service/fixtures/validator-operations/five-validator-observations.json', import.meta.url);
const serviceUrl = new URL('../../src/services/validatorOperationsService.js', import.meta.url);
const panelUrl = new URL('../../src/components/control-panel/ValidatorOperationsPanel.jsx', import.meta.url);

test('five-validator operations fixture carries the complete expedited evidence surface', async () => {
  const fixture = JSON.parse(await readFile(fixtureUrl, 'utf8'));
  assert.deepEqual(fixture.validator_ids, ['validator-02', 'validator-03', 'validator-04', 'validator-05', 'validator-06']);
  assert.equal(fixture.base_observation.schema_version, 'synergy.validator-operations.v1');
  for (const field of ['discovery', 'release', 'service', 'peers', 'chain', 'posy', 'protected_pipeline', 'resources', 'preflight']) {
    assert.ok(fixture.base_observation[field], `missing ${field}`);
  }
  assert.equal(fixture.base_observation.release.binary_sha256.length, 64);
  assert.equal(fixture.base_observation.protected_pipeline.source, 'NORMAL_ETDAG_STEADY_STATE');
  assert.equal(fixture.base_observation.preflight.length, 18);
});

test('renderer service exposes only typed operations commands and all three lifecycle actions', async () => {
  const [service, panel] = await Promise.all([readFile(serviceUrl, 'utf8'), readFile(panelUrl, 'utf8')]);
  for (const command of [
    'validator.operations.cluster.status', 'validator.operations.node.status',
    'validator.operations.preflight', 'validator.operations.logs',
    'validator.operations.lifecycle.control', 'validator.operations.snapshot.capture',
  ]) assert.match(service, new RegExp(command.replaceAll('.', '\\.')));
  assert.match(panel, /\['START', 'STOP', 'RESTART'\]/);
  assert.match(panel, /never a consensus authority/i);
  assert.doesNotMatch(service, /shell|terminal|exec|spawn/i);
});
