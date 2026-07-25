import {
  createOperationTerminalEvent,
  extractOperationOutput,
  formatOperationTerminalEvent,
} from './operationTerminal.js';

function textValue(value) {
  return typeof value === 'string' ? value : String(value ?? '');
}

/**
 * Runs the typed service action only after the allowlisted PTY bridge has
 * accepted the catalog action ID. Service output is emitted once for the
 * Operations terminal to append to the same local PTY session.
 */
export async function executeOperationThroughPty({
  operation = {},
  terminalName,
  cwd,
  openTerminalSession,
  writeAllowlistedOperation,
  handler,
  appendTerminalOutput,
  completionDetail = () => 'Operation completed.',
} = {}) {
  if (typeof openTerminalSession !== 'function') {
    throw new Error('Operations require a local terminal session bridge.');
  }
  if (typeof writeAllowlistedOperation !== 'function') {
    throw new Error('Operations require an allowlisted PTY command bridge.');
  }
  if (typeof handler !== 'function') {
    throw new Error('Operations require a mapped service handler.');
  }
  if (typeof appendTerminalOutput !== 'function') {
    throw new Error('Operations require a persistent terminal output bridge.');
  }

  const actionId = textValue(operation.actionId || operation.id).trim();
  if (!actionId) throw new Error('Operations require an allowlisted action ID.');

  const terminalOperation = {
    ...operation,
    command: operation.displayCommand || `synergy ${operation.label}`,
    serviceCommand: operation.binding?.serviceCommand || null,
  };
  const session = await openTerminalSession({
    cwd: cwd || undefined,
    name: terminalName || 'Operations terminal:local',
    reuseExisting: true,
  });
  const sessionId = textValue(session?.sessionId).trim();
  if (!sessionId) throw new Error('The Operations terminal bridge opened a session without an id.');

  await appendTerminalOutput(sessionId, formatOperationTerminalEvent(createOperationTerminalEvent({
    operation: terminalOperation,
    phase: 'start',
  })));
  await writeAllowlistedOperation(sessionId, actionId);
  const appendEvent = async (event) => {
    const transcript = formatOperationTerminalEvent(event);
    if (transcript) await appendTerminalOutput(sessionId, transcript);
  };

  try {
    const result = await handler();
    for (const { stream, text } of extractOperationOutput(result)) {
      await appendEvent(createOperationTerminalEvent({
        operation: terminalOperation,
        phase: 'output',
        stream,
        text,
      }));
    }
    await appendEvent(createOperationTerminalEvent({
      operation: terminalOperation,
      phase: 'complete',
      status: 'success',
      detail: completionDetail(result),
    }));
    return { result, terminalOperation, sessionId };
  } catch (error) {
    await appendEvent(createOperationTerminalEvent({
      operation: terminalOperation,
      phase: 'complete',
      status: 'failure',
      detail: error?.message || String(error || 'Operation failed.'),
    }));
    throw error;
  }
}
