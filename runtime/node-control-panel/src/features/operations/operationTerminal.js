const STREAM_KEYS = Object.freeze(['stdout', 'stderr']);
const NESTED_OUTPUT_KEYS = Object.freeze(['data', 'details', 'output', 'payload', 'report', 'result']);

function textValue(value) {
  return typeof value === 'string' ? value : String(value ?? '');
}

function normalizeLines(value) {
  return textValue(value)
    .replace(/\r\n/g, '\n')
    .replace(/\r/g, '\n')
    .split('\n')
    .map((line) => line.trimEnd())
    .join('\r\n');
}

function operationCommand(operation = {}) {
  return textValue(operation.displayCommand || operation.command || operation.label || operation.actionId)
    .trim();
}

export function createOperationTerminalEvent({
  operation = {},
  phase,
  status = '',
  stream = '',
  text = '',
  detail = '',
} = {}) {
  return {
    operationId: textValue(operation.id || operation.actionId).trim(),
    label: textValue(operation.label || operation.actionId).trim(),
    command: operationCommand(operation),
    serviceCommand: textValue(operation.serviceCommand).trim(),
    phase,
    status,
    stream,
    text: textValue(text),
    detail: textValue(detail),
  };
}

export function formatOperationTerminalEvent(event = {}) {
  const command = textValue(event.command).trim();
  const label = textValue(event.label || command || 'Operation').trim();

  if (event.phase === 'start') {
    const commandLine = command ? `\r\n[operation] Command: ${command}` : '';
    const serviceLine = event.serviceCommand
      ? `\r\n[operation] Local service: ${event.serviceCommand}`
      : '';
    return `\r\n[operation] Starting ${label}${commandLine}${serviceLine}\r\n[operation] Output below is from the installed Control Panel service on this machine.\r\n`;
  }

  if (event.phase === 'output' && textValue(event.text)) {
    const stream = event.stream === 'stderr' ? 'stderr' : 'stdout';
    return `[${stream}]\r\n${normalizeLines(event.text)}\r\n`;
  }

  if (event.phase === 'complete') {
    const status = event.status === 'success' ? 'OK' : 'FAIL';
    return `${status} ${label}: ${textValue(event.detail || 'Operation completed.').trim()}\r\n`;
  }

  return '';
}

export function extractOperationOutput(result) {
  const output = [];
  const visited = new Set();

  function visit(value, allowNested = true) {
    if (!value || typeof value !== 'object' || visited.has(value)) return;
    visited.add(value);

    STREAM_KEYS.forEach((stream) => {
      const text = textValue(value[stream]);
      if (text.trim()) output.push({ stream, text });
    });

    if (!allowNested) return;
    NESTED_OUTPUT_KEYS.forEach((key) => visit(value[key], true));
  }

  visit(result);
  return output;
}
