import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const read = (relativePath) => fs.readFileSync(path.join(root, relativePath), 'utf8');
const jsx = read('src/components/control-panel-v18/ControlPanelV18.jsx');
const css = read('src/styles/controlPanelV18.css');

test('monitoring and performance use operational SVG visualizations', () => {
  for (const required of [
    'function OperationalLineChart',
    'v18-operational-chart__grid',
    'v18-operational-chart__axis-labels',
    'v18-operational-chart__direct-label',
    'function PerformanceScoreDonut',
    'function UsageGauge',
    'Reward history',
  ]) {
    assert.ok(jsx.includes(required), `ControlPanelV18.jsx missing ${required}`);
  }

  assert.doesNotMatch(jsx, /v18-chart["'`]/, 'placeholder bar chart markup must be removed');
  assert.doesNotMatch(jsx, /v18-donut is-performance/, 'performance must not use the old CSS donut');
  assert.doesNotMatch(css, /\.v18-chart span/, 'placeholder bar chart styles must be removed');
  assert.match(css, /\.v18-score-donut__value[\s\S]*stroke: currentColor;/, 'score donut must use an SVG stroke');
  assert.match(css, /\.v18-operational-chart__line[\s\S]*stroke: var\(--chart-tone\);/, 'operational chart must use a direct SVG line');
});

test('readiness is fetched explicitly and exposes truthful request states', () => {
  assert.match(jsx, /invoke\('testnet_get_node_readiness', \{ nodeId: selectedNodeId \}\)/);
  assert.match(jsx, /const \[readinessState, setReadinessState\]/);
  assert.match(jsx, /Refreshing readiness checks/);
  assert.match(jsx, /Readiness request failed/);
  assert.match(jsx, /Last checked/);
});

test('null telemetry values remain unavailable and create line gaps', () => {
  assert.match(jsx, /function finiteChartValue\(value\)/);
  assert.match(jsx, /value == null \|\| value === ''/);
  assert.match(jsx, /point\.value == null \? null/);
  assert.match(jsx, /const segments = \[\]/);
  assert.match(jsx, /No CPU history was returned/);
  assert.match(jsx, /No memory history was returned/);
  assert.match(jsx, /No chain-height history was returned/);
  assert.match(jsx, /scoreAvailable \? formatPercent\(scoreBreakdown\.total, 2\) : 'Unavailable'/);
  assert.match(jsx, /No participation inputs were returned for an earnings breakdown/);
});

test('self-bond preflight failures remain visible after funding is confirmed', () => {
  assert.match(jsx, /const bondAttempted = Boolean\(eligibility\.bondTxHash\)/);
  assert.match(jsx, /const bondFailureMessage = String\(eligibility\.errorMessage \|\| ''\)\.trim\(\)/);
  assert.match(jsx, /bondAttempted && bondFailureMessage \? 'Self-Bond Requires Attention'/);
  assert.match(jsx, /bondAttempted && bondFailureMessage\s*\?\s*bondFailureMessage/);
  assert.match(jsx, /bondTxStatus: outcomeUnknown \? 'submission-unknown' : 'failed'/);
});
