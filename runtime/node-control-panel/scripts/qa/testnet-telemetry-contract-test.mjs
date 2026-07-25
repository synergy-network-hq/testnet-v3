import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';

const providerSource = readFileSync(
  new URL('../../src/components/control-panel/ControlPanelProvider.jsx', import.meta.url),
  'utf8',
);
const backendSource = readFileSync(
  new URL('../../control-service/src/testnet.rs', import.meta.url),
  'utf8',
);

test('live status exposes optional resource fields and samples the matched workspace process', () => {
  assert.match(backendSource, /pub cpu_percent: Option<f64>,/);
  assert.match(backendSource, /pub memory_percent: Option<f64>,/);
  assert.match(backendSource, /pub memory_mb: Option<f64>,/);
  assert.match(backendSource, /pub disk_percent: Option<f64>,/);
  assert.match(backendSource, /process_matches_workspace\(process, workspace_directory\)/);
  assert.match(backendSource, /filesystem_disk_percent\(workspace_directory\)/);
});

test('provider history preserves unavailable resource values as null', () => {
  assert.match(providerSource, /function finiteTelemetryNumber\(value\)/);
  assert.match(providerSource, /cpuPercent: finiteTelemetryNumber\(entry\?\.cpu_percent\)/);
  assert.match(providerSource, /memoryPercent: finiteTelemetryNumber\(entry\?\.memory_percent\)/);
  assert.match(providerSource, /memoryMb: finiteTelemetryNumber\(entry\?\.memory_mb\)/);
  assert.match(providerSource, /diskPercent: finiteTelemetryNumber\(entry\?\.disk_percent\)/);
  assert.doesNotMatch(providerSource, /cpuPercent: Number\(entry\?\.cpu_percent\) \|\| 0/);
  assert.doesNotMatch(providerSource, /memoryPercent: Number\(entry\?\.memory_percent\) \|\| 0/);
  assert.doesNotMatch(providerSource, /memoryMb: Number\(entry\?\.memory_mb\) \|\| 0/);
  assert.doesNotMatch(providerSource, /diskPercent: Number\(entry\?\.disk_percent\) \|\| 0/);
});
