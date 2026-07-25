function setupTerminalIpc(ipcMain, terminalManager) {
  const ownerId = (event) => event.sender.id;

  ipcMain.handle('desktop:open-terminal-session', (event, options = {}) =>
    terminalManager.openSession(options, ownerId(event)),
  );
  ipcMain.handle('desktop:write-terminal-input', (event, payload = {}) =>
    terminalManager.writeInput(payload.sessionId, payload.input, ownerId(event)),
  );
  ipcMain.handle('desktop:write-allowlisted-operation', (event, payload = {}) =>
    terminalManager.writeAllowlistedOperation(
      payload.sessionId,
      payload.actionId,
      ownerId(event),
    ),
  );
  ipcMain.handle('desktop:append-terminal-output', (event, payload = {}) =>
    terminalManager.appendOutput(payload.sessionId, payload.output, ownerId(event)),
  );
  ipcMain.handle('desktop:clear-terminal-output', (event, sessionId) =>
    terminalManager.clearSessionOutput(String(sessionId), ownerId(event)),
  );
  ipcMain.handle('desktop:resize-terminal', (event, payload = {}) =>
    terminalManager.resizeSession(payload.sessionId, payload.cols, payload.rows, ownerId(event)),
  );
  ipcMain.handle('desktop:interrupt-terminal-session', (event, sessionId) =>
    terminalManager.interruptSession(String(sessionId), ownerId(event)),
  );
  ipcMain.handle('desktop:close-terminal-session', (event, sessionId) =>
    terminalManager.closeSession(String(sessionId), ownerId(event)),
  );
  ipcMain.handle('desktop:get-terminal-session', (event, sessionId) =>
    terminalManager.getSessionState(String(sessionId), ownerId(event)),
  );
  ipcMain.handle('desktop:list-terminal-sessions', (event) =>
    terminalManager.listSessions(ownerId(event)),
  );
}

module.exports = {
  setupTerminalIpc,
};
