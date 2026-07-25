const DEFAULT_COORDINATOR_URL_ENV = 'SYNERGY_COORDINATOR_API_URL';
const LEGACY_COORDINATOR_URL_ENV = 'SYNERGY_INNERNET_COORDINATOR_URL';
const PACKAGED_COORDINATOR_URL_ENV = 'SYNERGY_VALIDATOR_VPN_COORDINATOR_URL';

function coordinatorError(code, message, details = null) {
  const error = new Error(message);
  error.code = code;
  error.details = details;
  return error;
}

function stringValue(...values) {
  for (const value of values) {
    const normalized = String(value ?? '').trim();
    if (normalized) return normalized;
  }
  return null;
}

function assertCurrentAssignedIp(value, peerType = null) {
  const assignedIp = stringValue(value);
  const match = assignedIp?.match(/^10\.70\.(10|20)\.(\d{1,3})(?:\/32)?$/);
  const host = Number(match?.[2]);
  const subnet = match?.[1];
  const expectedSubnet = peerType === 'validator' ? '10' : peerType === 'relayer' ? '20' : subnet;
  if (!match || subnet !== expectedSubnet || !Number.isInteger(host) || host < 1 || host > 254) {
    throw coordinatorError(
      'ASSIGNED_IP_INVALID',
      'The coordinator returned an IP outside the current secure validator network.',
    );
  }
  return assignedIp;
}

function validatorIdentityFields(input = {}) {
  const identity = input.validatorIdentity || input.validator_identity || {};
  const eligibility = input.eligibility || {};
  const source = { ...eligibility, ...input, ...identity };
  const fields = {
    node_id: stringValue(source.nodeId, source.node_id),
    validator_address: stringValue(source.validatorAddress, source.validator_address),
    operator_address: stringValue(
      source.operatorAddress,
      source.operator_address,
      source.ownerWalletAddress,
      source.owner_wallet_address,
      source.walletAddress,
      source.wallet_address,
    ),
    stake_tx_hash: stringValue(source.stakeTxHash, source.stake_tx_hash),
  };
  return Object.fromEntries(Object.entries(fields).filter(([, value]) => value !== null));
}

function coordinatorBaseUrl() {
  const value = String(
    process.env[DEFAULT_COORDINATOR_URL_ENV]
      || process.env[LEGACY_COORDINATOR_URL_ENV]
      || process.env[PACKAGED_COORDINATOR_URL_ENV]
      || '',
  ).trim().replace(/\/$/, '');
  if (!value) {
    throw coordinatorError(
      'COORDINATOR_NOT_CONFIGURED',
      `Secure-network coordinator is not configured. Set ${DEFAULT_COORDINATOR_URL_ENV} in the desktop main-process environment.`,
    );
  }
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw coordinatorError('COORDINATOR_URL_INVALID', 'Secure-network coordinator URL is invalid.');
  }
  if (parsed.protocol !== 'https:' && parsed.hostname !== 'localhost') {
    throw coordinatorError('COORDINATOR_URL_INSECURE', 'Secure-network coordinator must use HTTPS.');
  }
  return parsed.toString().replace(/\/$/, '');
}

async function coordinatorRequest(pathname, options = {}) {
  const url = `${coordinatorBaseUrl()}${pathname}`;
  let response;
  try {
    response = await fetch(url, { ...options, signal: AbortSignal.timeout(15_000) });
  } catch (cause) {
    throw coordinatorError('COORDINATOR_UNREACHABLE', 'Could not reach the secure-network coordinator.', {
      reason: cause?.name || 'network_error',
    });
  }
  const payload = await response.json().catch(() => ({}));
  if (response.ok) return payload;

  const codeByStatus = {
    401: 'INVALID_OR_USED_TOKEN',
    403: 'COORDINATOR_FORBIDDEN',
    429: 'COORDINATOR_RATE_LIMITED',
  };
  throw coordinatorError(
    payload?.code || codeByStatus[response.status] || 'COORDINATOR_REJECTED',
    payload?.detail || payload?.error || 'The secure-network coordinator rejected the request.',
    {
      status: response.status,
      coordinatorError: payload?.error || null,
      detail: payload?.detail || null,
    },
  );
}

async function requestInvite({ onboardingToken, peerName, peerType, ...input } = {}) {
  const token = String(onboardingToken || '').trim();
  const name = String(peerName || '').trim();
  const type = String(peerType || '').trim();
  if (!token) throw coordinatorError('ONBOARDING_TOKEN_REQUIRED', 'Enter the secure-network onboarding token.');
  if (!name) throw coordinatorError('PEER_NAME_REQUIRED', 'A validator nickname is required before connecting the secure network.');
  if (!['validator', 'relayer'].includes(type)) {
    throw coordinatorError('PEER_TYPE_INVALID', 'Secure-network peer type must be validator or relayer.');
  }

  const payload = await coordinatorRequest('/v1/invite', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    body: JSON.stringify({
      auth: { type: 'onboarding_token', token },
      peer_name: name,
      peer_type: type,
      ...validatorIdentityFields(input),
    }),
  });
  const resumeExisting = payload?.resume_existing === true || payload?.resumeExisting === true;
  if (!resumeExisting && (!payload?.invite || typeof payload.invite !== 'string')) {
    throw coordinatorError('INVITE_MISSING', 'The coordinator did not return a secure-network invite.');
  }
  const assignedIp = payload.assigned_ip || payload.assignedIp || null;
  if (assignedIp) assertCurrentAssignedIp(assignedIp, type);
  return {
    invite: typeof payload.invite === 'string' ? payload.invite : null,
    resumeExisting,
    enrollmentId: payload.enrollment_id || payload.enrollmentId || null,
    assignedIp,
    expiresAt: payload.expires_at || payload.expiresAt || null,
    configurationVersion: payload.configuration_version || payload.configurationVersion || null,
    confirmationToken: payload.confirmation_token || payload.confirmationToken || null,
    interfaceName: payload.interface_name || payload.interfaceName || payload.innernet_interface || payload.innernetInterface || payload.interface || null,
    propagation: payload.propagation || null,
  };
}

async function confirmRedemption({
  enrollmentId,
  confirmationToken,
  interfaceName,
  assignedIp,
} = {}) {
  const id = stringValue(enrollmentId);
  const token = stringValue(confirmationToken);
  if (!id) throw coordinatorError('ENROLLMENT_ID_REQUIRED', 'The coordinator did not return an enrollment ID.');
  if (!token) throw coordinatorError('CONFIRMATION_TOKEN_REQUIRED', 'The coordinator did not return an Innernet confirmation token.');
  if (!stringValue(interfaceName)) throw coordinatorError('INTERFACE_REQUIRED', 'The redeemed Innernet interface was not identified.');
  if (!stringValue(assignedIp)) throw coordinatorError('ASSIGNED_IP_REQUIRED', 'The coordinator did not return an assigned Innernet IP.');
  assertCurrentAssignedIp(assignedIp);

  return coordinatorRequest('/v1/mesh/confirm', {
    method: 'POST',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      enrollment_id: id,
      confirmation_token: token,
      interface_name: interfaceName,
      assigned_ip: assignedIp,
      handshake_confirmed: true,
    }),
  });
}

async function getMeshStatus({ enrollmentId, confirmationToken } = {}) {
  const enrollment = stringValue(enrollmentId);
  const token = stringValue(confirmationToken);
  return coordinatorRequest('/v1/mesh/status', {
    headers: {
      Accept: 'application/json',
      ...(enrollment ? { 'X-Synergy-Innernet-Enrollment': enrollment } : {}),
      ...(token ? { 'X-Synergy-Innernet-Token': token } : {}),
    },
  });
}

async function getCoordinatorHealth() {
  const health = await coordinatorRequest('/health', {
    headers: { Accept: 'application/json' },
  });
  return {
    ...health,
    reachable: health?.status === 'ok',
  };
}

async function getMeshTransportSnapshot({ enrollmentId, confirmationToken } = {}) {
  const enrollment = stringValue(enrollmentId);
  const token = stringValue(confirmationToken);
  if (!enrollment || !token) {
    throw coordinatorError('CONFIRMATION_TOKEN_REQUIRED', 'A per-enrollment Innernet confirmation token is required to fetch validator transports.');
  }
  return coordinatorRequest('/v1/mesh/transports', {
    headers: {
      Accept: 'application/json',
      'X-Synergy-Innernet-Enrollment': enrollment,
      'X-Synergy-Innernet-Token': token,
    },
  });
}

async function refreshMeshTransportSnapshot({ receipt } = {}) {
  if (!receipt || typeof receipt !== 'object' || Array.isArray(receipt)) {
    throw coordinatorError(
      'MEMBERSHIP_RECEIPT_REQUIRED',
      'A confirmed Innernet membership receipt is required to refresh validator transports.',
    );
  }
  return coordinatorRequest('/v1/mesh/transports/refresh', {
    method: 'POST',
    headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
    body: JSON.stringify({ receipt }),
  });
}

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForMeshPropagation(enrollmentOrGeneration, { attempts = 20, intervalMs = 3_000 } = {}) {
  const enrollment = typeof enrollmentOrGeneration === 'object' && enrollmentOrGeneration !== null
    ? enrollmentOrGeneration
    : { configurationVersion: enrollmentOrGeneration };
  const expectedGeneration = Number(enrollment.configurationVersion ?? enrollment.configuration_version);
  const confirmationToken = stringValue(enrollment.confirmationToken, enrollment.confirmation_token);
  const enrollmentId = stringValue(enrollment.enrollmentId, enrollment.enrollment_id);
  if (!confirmationToken) {
    throw coordinatorError('CONFIRMATION_TOKEN_REQUIRED', 'A per-enrollment Innernet confirmation token is required to verify mesh status.');
  }
  if (!Number.isInteger(expectedGeneration) || expectedGeneration < 1) {
    throw coordinatorError('COORDINATOR_GENERATION_MISSING', 'The coordinator did not return a valid secure-network configuration version.');
  }
  for (let attempt = 0; attempt < attempts; attempt += 1) {
    const status = await getMeshStatus({ enrollmentId, confirmationToken });
    const statusEnrollmentId = stringValue(
      status?.enrollment_id,
      status?.enrollmentId,
      status?.enrollment?.enrollment_id,
      status?.enrollment?.enrollmentId,
    );
    if (enrollmentId && statusEnrollmentId && statusEnrollmentId !== enrollmentId) {
      throw coordinatorError('COORDINATOR_ENROLLMENT_MISMATCH', 'The coordinator returned mesh status for a different enrollment.');
    }
    const latestGeneration = Number(
      status?.latest_generation
        ?? status?.latestGeneration
        ?? status?.configuration_version
        ?? status?.configurationVersion,
    );
    const bootstrapComplete = status?.bootstrap_complete === true || status?.bootstrapComplete === true;
    if (bootstrapComplete && latestGeneration >= expectedGeneration) {
      return {
        ...status,
        status: 'confirmed',
        generation: expectedGeneration,
        configurationVersion: expectedGeneration,
        enrollmentId: enrollmentId || statusEnrollmentId,
        complete: true,
      };
    }
    if (Number.isInteger(latestGeneration) && latestGeneration > expectedGeneration) {
      throw coordinatorError('COORDINATOR_CONFIGURATION_SUPERSEDED', 'The secure-network configuration changed while enrollment was in progress. Retry to use the latest verified configuration.');
    }
    if (attempt + 1 < attempts) await wait(intervalMs);
  }
  throw coordinatorError('COORDINATOR_PROPAGATION_UNCONFIRMED', 'The coordinator has not confirmed secure-network propagation to every active validator. Setup remains blocked.');
}

module.exports = {
  confirmRedemption,
  getCoordinatorHealth,
  getMeshStatus,
  getMeshTransportSnapshot,
  refreshMeshTransportSnapshot,
  requestInvite,
  waitForMeshPropagation,
};
