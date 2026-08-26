import { invoke } from '../lib/desktopClient';

export const getValidatorOperationsCluster = () => invoke('validator.operations.cluster.status');

export const getValidatorOperationsStatus = (nodeSlotId) => invoke(
  'validator.operations.node.status',
  { nodeSlotId },
);

export const getValidatorHostPreflight = (nodeSlotId) => invoke(
  'validator.operations.preflight',
  { nodeSlotId },
);

export const getValidatorStructuredLogs = (nodeSlotId, limit = 200) => invoke(
  'validator.operations.logs',
  { nodeSlotId, limit },
);

export const controlValidatorLifecycle = (nodeSlotId, action, reason) => invoke(
  'validator.operations.lifecycle.control',
  { nodeSlotId, request: { action, reason } },
);

export const captureValidatorDiagnosticSnapshot = (nodeSlotId) => invoke(
  'validator.operations.snapshot.capture',
  { nodeSlotId },
);
