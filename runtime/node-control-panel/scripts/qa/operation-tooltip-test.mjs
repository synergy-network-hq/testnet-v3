import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';

const operationsSource = readFileSync(
  new URL('../../src/components/control-panel-v18/ControlPanelV18.jsx', import.meta.url),
  'utf8',
);
const operationsCss = readFileSync(
  new URL('../../src/styles/controlPanelV18.css', import.meta.url),
  'utf8',
);

function sourceSection(source, startMarker, endMarker) {
  const start = source.indexOf(startMarker);
  const end = source.indexOf(endMarker, start + startMarker.length);
  assert.ok(start >= 0, `Missing source marker: ${startMarker}`);
  assert.ok(end > start, `Missing source end marker: ${endMarker}`);
  return source.slice(start, end);
}

test('operation tooltips are delayed and accessible on hover and focus', () => {
  const tooltipSource = sourceSection(operationsSource, 'function OperationTooltip', 'function terminalTime');

  assert.match(operationsSource, /const OPERATION_TOOLTIP_DELAY_MS = 450;/);
  assert.match(tooltipSource, /window\.setTimeout\(\(\) => setVisible\(true\), OPERATION_TOOLTIP_DELAY_MS\)/);
  assert.match(tooltipSource, /onMouseEnter=\{showTooltip\}/);
  assert.match(tooltipSource, /onMouseLeave=\{hideTooltip\}/);
  assert.match(tooltipSource, /onFocus=\{showTooltip\}/);
  assert.match(tooltipSource, /onBlur=\{hideTooltip\}/);
  assert.match(tooltipSource, /role="tooltip"/);
  assert.match(tooltipSource, /aria-describedby=\{visible \? tooltipId : undefined\}/);
  assert.match(tooltipSource, /cloneElement\(children, \{ 'aria-describedby': visible \? tooltipId : undefined \}\)/);
  assert.match(operationsCss, /\.v18-operation-tooltip-trigger:focus-visible/);
  assert.match(operationsCss, /\.v18-operation-tooltip \{/);
});

test('category and action tooltip content is plain and availability-aware', () => {
  const operationsPageSource = sourceSection(operationsSource, 'function OperationsPage', 'function ValidatorPeers');

  assert.match(operationsSource, /tooltip: availableOperationTooltip\(category\.tooltip \|\| category\.description\)/);
  assert.match(operationsSource, /tooltip: availableOperationTooltip\(action\.tooltip \|\| action\.description\)/);
  assert.match(operationsPageSource, /const tooltipMessage = availability\.available/);
  assert.match(operationsPageSource, /`Unavailable: \$\{availability\.message\}`/);
  assert.match(operationsPageSource, /aria-label=\{`\$\{operation\.label\}\. \$\{tooltipMessage\}`\}/);
  assert.match(operationsPageSource, /<OperationTooltip key=\{category\.id\} message=\{category\.tooltip \|\| category\.detail\}>/);
  assert.match(operationsPageSource, /<OperationTooltip[\s\S]*message=\{tooltipMessage\}[\s\S]*disabled=\{!availability\.available\}/);
  assert.doesNotMatch(operationsPageSource, /title=\{operation\.tooltip \|\| operation\.detail\}/);
  assert.doesNotMatch(operationsPageSource, /title=\{category\.tooltip \|\| category\.detail\}/);
});

test('unavailable operation controls are disabled and cannot dispatch', () => {
  const operationsPageSource = sourceSection(operationsSource, 'function OperationsPage', 'function ValidatorPeers');
  const requestStart = operationsPageSource.indexOf('const requestOperation');
  const requestEnd = operationsPageSource.indexOf('\n\n  useEffect', requestStart);
  const requestSource = operationsPageSource.slice(requestStart, requestEnd);

  assert.match(operationsPageSource, /disabled=\{!availability\.available\}/);
  assert.match(operationsPageSource, /className=\{cls\('v18-operation-row',[\s\S]*!availability\.available && 'is-unavailable'\)/);
  assert.match(requestSource, /if \(!availability\.available\) \{/);
  assert.ok(
    requestSource.indexOf('if (!availability.available)') < requestSource.indexOf('runAction('),
    'Unavailable operations must be rejected before runAction dispatch.',
  );
  assert.match(operationsCss, /\.v18-operation-row\.is-unavailable,[\s\S]*cursor: not-allowed;/);
});

console.log('Operation tooltip QA passed: delayed hover/focus help, availability-aware copy, and disabled no-dispatch contract.');
