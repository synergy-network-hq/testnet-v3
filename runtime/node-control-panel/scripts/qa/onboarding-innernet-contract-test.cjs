const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const {
  confirmRedemption,
  getMeshTransportSnapshot,
  requestInvite,
  refreshMeshTransportSnapshot,
  waitForMeshPropagation,
} = require('../../electron/onboarding/coordinator-client.cjs');
const {
  isExistingInterfaceConfigError,
  isResumableInnernetInstallError,
  hasExistingInterfaceConfig,
  parseDarwinMeshInspection,
  parseWireGuardDump,
  prepareRemoteInnernetClient,
  redeemInvite,
  renderInnernetLaunchdPlist,
  renderInnernetSystemdUnit,
  resolveInnernetClientBinary,
  resolveRemoteInnernetPlatform,
  waitForMeshHandshake,
} = require('../../electron/onboarding/innernet.cjs');
const { setupOnboardingIpc } = require('../../electron/ipc/onboarding-ipc.cjs');
const {
  RemoteExecutor,
  macosAuthorizationArguments,
  sudoRequiresInteractiveAuthorization,
  targetError,
} = require('../../electron/onboarding/targets.cjs');
const {
  PendingInviteStore,
  REDEEMED_INVITE_RECOVERY_GRACE_MS,
} = require('../../electron/onboarding/pending-invites.cjs');

function response(payload, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    async json() { return payload; },
  };
}

function writeExecutable(directory, name, source) {
  fs.mkdirSync(directory, { recursive: true });
  const filePath = path.join(directory, name);
  fs.writeFileSync(filePath, `#!/bin/sh\n${source}\n`, { mode: 0o700 });
  return filePath;
}

async function main() {
  const temporaryDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'synergy-innernet-contract-'));
  const originalEnvironment = {
    coordinatorUrl: process.env.SYNERGY_COORDINATOR_API_URL,
    path: process.env.PATH,
    innernetBinary: process.env.SYNERGY_INNERNET_CLIENT_BIN,
    handshakeTimeout: process.env.SYNERGY_INNERNET_HANDSHAKE_TIMEOUT_MS,
    nodeEnv: process.env.NODE_ENV,
    skipLaunchdPersistence: process.env.SYNERGY_NCP_TEST_SKIP_LAUNCHD_PERSISTENCE,
    skipSystemdPersistence: process.env.SYNERGY_NCP_TEST_SKIP_SYSTEMD_PERSISTENCE,
  };
  const calls = [];
  const progress = [];
  const now = Math.floor(Date.now() / 1000);
  const wgDump = `private\t51820\t0\npeer\tpsk\t198.51.100.10:51820\t10.70.10.1/32\t${now}\t1\t1\t0\n`;
  const wgDumpWithoutHandshake = 'private\t51820\t0\npeer\tpsk\t198.51.100.10:51820\t10.70.10.1/32\t0\t0\t0\t0\n';
  const signedMeshTransportSnapshot = {
    version: 1,
    network: 'synergy-innernet-membership-v1',
    migration_id: 'migration-7',
    configuration_version: 43,
    transports: [{ validator_address: 'synv1validator7', dial_address: '10.70.10.7:5622' }],
    signature: 'ed25519:refreshed-test',
  };

  try {
    process.env.SYNERGY_COORDINATOR_API_URL = 'https://localhost:47895';
    process.env.NODE_ENV = 'test';
    process.env.SYNERGY_NCP_TEST_SKIP_LAUNCHD_PERSISTENCE = 'true';
    process.env.SYNERGY_NCP_TEST_SKIP_SYSTEMD_PERSISTENCE = 'true';
    process.env.SYNERGY_INNERNET_HANDSHAKE_TIMEOUT_MS = '2000';
    const packagedResourceRoot = path.join(temporaryDirectory, 'packaged-resources');
    const packagedInnernetPath = writeExecutable(path.join(packagedResourceRoot, 'innernet'), 'innernet-linux-amd64', 'exit 0');
    assert.equal(
      await resolveInnernetClientBinary({ targetPlatform: 'linux-amd64', resourceRoot: packagedResourceRoot, packaged: true }),
      packagedInnernetPath,
    );
    await assert.rejects(
      resolveInnernetClientBinary({ targetPlatform: 'linux-arm64', resourceRoot: packagedResourceRoot, packaged: true }),
      (error) => error.code === 'INNERNET_CLIENT_NOT_BUNDLED',
    );

    const remoteInnernetSource = path.join(temporaryDirectory, 'innernet-linux-amd64-source');
    fs.writeFileSync(remoteInnernetSource, 'official-innernet-client-bytes', { mode: 0o700 });
    const remoteDigest = require('node:crypto').createHash('sha256').update(fs.readFileSync(remoteInnernetSource)).digest('hex');
    const remoteWrites = [];
    const remoteExecutor = {
      mode: 'remote',
      async run(command, args) {
        if (command === 'sh' && args[1] === 'printf %s "$HOME"') return { stdout: '/home/validator', stderr: '', code: 0 };
        if (command === 'mkdir') return { stdout: '', stderr: '', code: 0 };
        if (command === 'sh' && args[1].includes('if test -f')) return { stdout: remoteWrites.length ? `${remoteDigest}\n` : '', stderr: '', code: 0 };
        if (command === 'sh' && args[1].includes('sha256sum --')) return { stdout: `${remoteDigest}\n`, stderr: '', code: 0 };
        throw new Error(`Unexpected remote command: ${command} ${args.join(' ')}`);
      },
      async writeFile(filePath, content, mode) { remoteWrites.push({ filePath, content, mode }); },
    };
    const remoteClientPath = await prepareRemoteInnernetClient(remoteExecutor, remoteInnernetSource);
    assert.equal(remoteWrites.length, 1);
    assert.equal(remoteWrites[0].filePath, remoteClientPath);
    assert.equal(remoteWrites[0].mode, '0700');
    assert.deepEqual(remoteWrites[0].content, fs.readFileSync(remoteInnernetSource));

    const unsupportedRemoteExecutor = {
      async run(command, args) {
        if (command === 'uname' && args[0] === '-s') return { stdout: 'Linux\n' };
        if (command === 'uname' && args[0] === '-m') return { stdout: 'aarch64\n' };
        throw new Error(`Unexpected platform command: ${command} ${args.join(' ')}`);
      },
    };
    await assert.rejects(
      resolveRemoteInnernetPlatform(unsupportedRemoteExecutor),
      (error) => error.code === 'INNERNET_REMOTE_PLATFORM_UNSUPPORTED',
    );
    let remoteInviteWrites = 0;
    const unsupportedRedeemExecutor = {
      ...unsupportedRemoteExecutor,
      mode: 'remote',
      async writeFile() { remoteInviteWrites += 1; },
      async runElevated() { throw new Error('Remote elevation must not be attempted.'); },
    };
    await assert.rejects(
      redeemInvite(unsupportedRedeemExecutor, { invite: 'opaque', assignedIp: '10.70.10.7', interfaceName: 'innernet0' }),
      (error) => error.code === 'INNERNET_REMOTE_PLATFORM_UNSUPPORTED',
    );
    assert.equal(remoteInviteWrites, 0);

    const sudo = writeExecutable(temporaryDirectory, 'sudo', 'if [ "$1" = "-n" ]; then shift; fi\nif [ "$1" = "--" ]; then shift; fi\nexec "$@"');
    writeExecutable(temporaryDirectory, 'innernet', 'exit 0');
    writeExecutable(temporaryDirectory, 'wg', 'printf "%b" "private\\t51820\\t0\\npeer\\tpsk\\t198.51.100.10:51820\\t10.70.10.1/32\\t' + now + '\\t1\\t1\\t0\\n"');
    writeExecutable(temporaryDirectory, 'ip', 'printf "%b" "2: innernet0    inet 10.70.10.7/32 scope global innernet0\\n"');
    process.env.PATH = `${temporaryDirectory}:${originalEnvironment.path}`;
    process.env.SYNERGY_INNERNET_CLIENT_BIN = 'innernet';
    assert.ok(fs.existsSync(sudo));
    const authorizationArgs = macosAuthorizationArguments(
      '/Applications/Synergy Node Control Panel.app/Contents/Resources/innernet/innernet-darwin-arm64',
      ['install', '--default-name', "/tmp/invite with 'quote'"],
    );
    assert.deepEqual(authorizationArgs.slice(0, 6), [
      '-e', 'on run argv',
      '-e', 'do shell script (item 1 of argv) with administrator privileges',
      '-e', 'end run',
    ]);
    assert.match(authorizationArgs[6], /^export PATH='/);
    assert.match(authorizationArgs[6], /\/binaries\/innernet:\/usr\/bin:\/bin:\/usr\/sbin:\/sbin/);
    assert.match(authorizationArgs[6], /; exec '\/Applications\/Synergy Node Control Panel\.app\//);
    assert.match(authorizationArgs[6], /'"'"'quote'"'"''$/);
    assert.equal(sudoRequiresInteractiveAuthorization({ details: { stderr: 'sudo: a password is required' } }), true);
    assert.equal(sudoRequiresInteractiveAuthorization({ details: { stderr: 'innernet: invitation is invalid' } }), false);
    const remoteElevatedExecutor = new RemoteExecutor(
      { username: 'validator', host: 'validator.invalid', port: 22 },
      '/tmp/synergy-test-ssh.sock',
      '/tmp/synergy-test-known-hosts',
    );
    remoteElevatedExecutor.run = async () => {
      throw targetError('COMMAND_FAILED', 'Remote Innernet command failed.', {
        stderr: '[E] Config file for innernet interface sy-vpn already exists.',
      });
    };
    await assert.rejects(
      remoteElevatedExecutor.runElevated('innernet', ['install', '/tmp/invite']),
      (error) => error.code === 'COMMAND_FAILED'
        && isExistingInterfaceConfigError(error),
    );
    remoteElevatedExecutor.run = async () => {
      throw targetError('COMMAND_FAILED', 'Remote sudo authorization failed.', {
        stderr: 'sudo: a password is required',
      });
    };
    await assert.rejects(
      remoteElevatedExecutor.runElevated('innernet', ['up', 'sy-vpn']),
      (error) => error.code === 'REMOTE_SUDO_REQUIRED',
    );

    const encryptedInviteDirectory = path.join(temporaryDirectory, 'encrypted-invite-store');
    const fakeSafeStorage = {
      isEncryptionAvailable: () => true,
      encryptString: (value) => Buffer.from(Buffer.from(value, 'utf8').toString('base64'), 'utf8'),
      decryptString: (value) => Buffer.from(value.toString('utf8'), 'base64').toString('utf8'),
    };
    const pendingInviteStore = new PendingInviteStore(encryptedInviteDirectory, fakeSafeStorage);
    const persistedInvites = new Map([['local', {
      invite: 'opaque-persisted-invite',
      enrollmentId: 'persisted-enrollment',
      expiresAt: '2099-07-10T12:00:00Z',
    }]]);
    await pendingInviteStore.save(persistedInvites);
    assert.equal((await pendingInviteStore.load()).get('local').enrollmentId, 'persisted-enrollment');
    assert.equal(
      fs.readFileSync(path.join(encryptedInviteDirectory, 'onboarding', 'pending-innernet-invites.bin'), 'utf8').includes('opaque-persisted-invite'),
      false,
    );
    const recentlyExpiredInvite = {
      invite: 'recently-expired-redeemed-invite',
      enrollmentId: 'recoverable-enrollment',
      confirmationToken: 'recoverable-confirmation',
      expiresAt: new Date(Date.now() - 60 * 60 * 1_000).toISOString(),
    };
    const staleExpiredInvite = {
      ...recentlyExpiredInvite,
      invite: 'stale-expired-invite',
      enrollmentId: 'stale-enrollment',
      expiresAt: new Date(Date.now() - REDEEMED_INVITE_RECOVERY_GRACE_MS - 1_000).toISOString(),
    };
    await pendingInviteStore.save(new Map([
      ['recoverable', recentlyExpiredInvite],
      ['stale', staleExpiredInvite],
      ['malformed', { ...recentlyExpiredInvite, expiresAt: 'not-a-date' }],
    ]));
    const recoveredInvites = await pendingInviteStore.load();
    assert.equal(recoveredInvites.get('recoverable').enrollmentId, 'recoverable-enrollment');
    assert.equal(recoveredInvites.has('stale'), false);
    assert.equal(recoveredInvites.has('malformed'), false);

    global.fetch = async (url, options = {}) => {
      const parsed = new URL(url);
      const body = options.body ? JSON.parse(options.body) : null;
      calls.push({ path: parsed.pathname, method: options.method || 'GET', headers: options.headers || {}, body });
      if (parsed.pathname === '/v1/invite') {
        return response({
          invite: 'opaque-innernet-invite',
          enrollment_id: 'enrollment-7',
          confirmation_token: 'confirm-7',
          configuration_version: 42,
          interface_name: 'innernet0',
          assigned_ip: '10.70.10.7',
          expires_at: '2099-07-10T12:00:00Z',
        });
      }
      if (parsed.pathname === '/v1/mesh/confirm') {
        return response({ receipt: { id: 'receipt-7' }, propagation: { generation: 42 } });
      }
      if (parsed.pathname === '/v1/mesh/status') {
        return response({
          enrollment_id: 'enrollment-7',
          latest_generation: 42,
          bootstrap_complete: true,
        });
      }
      if (parsed.pathname === '/v1/mesh/transports') {
        return response({
          version: 1,
          network: 'synergy-innernet-membership-v1',
          migration_id: 'migration-7',
          configuration_version: 42,
          transports: [{ validator_address: 'synv1validator7', dial_address: '10.70.10.7:5622' }],
          signature: 'ed25519:test',
        });
      }
      if (parsed.pathname === '/v1/mesh/transports/refresh') return response(signedMeshTransportSnapshot);
      throw new Error(`Unexpected coordinator path: ${parsed.pathname}`);
    };

    const invite = await requestInvite({
      onboardingToken: 'one-time-token',
      peerName: 'validator-7',
      peerType: 'validator',
      nodeId: 'node-7',
      validatorAddress: 'synv1validator7',
      operatorAddress: 'syn1operator7',
    });
    assert.equal(invite.enrollmentId, 'enrollment-7');
    assert.equal(invite.confirmationToken, 'confirm-7');
    assert.deepEqual(calls[0].body, {
      auth: { type: 'onboarding_token', token: 'one-time-token' },
      peer_name: 'validator-7',
      peer_type: 'validator',
      node_id: 'node-7',
      validator_address: 'synv1validator7',
      operator_address: 'syn1operator7',
    });

    const successfulCoordinatorFetch = global.fetch;
    global.fetch = async () => response({
      invite: null,
      resume_existing: true,
      enrollment_id: 'recovered-enrollment-7',
      confirmation_token: 'recovered-confirm-7',
      configuration_version: 43,
      interface_name: 'sy-vpn',
      assigned_ip: '10.70.10.8',
      expires_at: '2099-07-10T12:00:00Z',
    });
    const recoveredInvite = await requestInvite({
      onboardingToken: 'same-one-time-token',
      peerName: 'validator-testnet-existing',
      peerType: 'validator',
      nodeId: 'existing-node',
      validatorAddress: 'synv1existing',
    });
    assert.equal(recoveredInvite.resumeExisting, true);
    assert.equal(recoveredInvite.invite, null);
    assert.equal(recoveredInvite.assignedIp, '10.70.10.8');
    global.fetch = successfulCoordinatorFetch;

    global.fetch = async () => response({
      invite: 'retired-range-invite',
      assigned_ip: '10.69.10.8',
    });
    await assert.rejects(
      requestInvite({
        onboardingToken: 'one-time-token',
        peerName: 'validator-retired-range',
        peerType: 'validator',
      }),
      (error) => error.code === 'ASSIGNED_IP_INVALID',
    );
    global.fetch = successfulCoordinatorFetch;

    global.fetch = async () => response({
      error: 'innernet_unavailable',
      detail: 'The assigned Innernet address is already in use.',
    }, 503);
    await assert.rejects(
      requestInvite({
        onboardingToken: 'one-time-token',
        peerName: 'validator-8',
        peerType: 'validator',
      }),
      (error) => error.code === 'COORDINATOR_REJECTED'
        && error.message === 'The assigned Innernet address is already in use.'
        && error.details?.coordinatorError === 'innernet_unavailable',
    );
    global.fetch = successfulCoordinatorFetch;

    await confirmRedemption({
      enrollmentId: invite.enrollmentId,
      confirmationToken: invite.confirmationToken,
      interfaceName: invite.interfaceName,
      assignedIp: invite.assignedIp,
    });
    assert.deepEqual(calls[1].body, {
      enrollment_id: 'enrollment-7',
      confirmation_token: 'confirm-7',
      interface_name: 'innernet0',
      assigned_ip: '10.70.10.7',
      handshake_confirmed: true,
    });
    await waitForMeshPropagation({
      enrollmentId: invite.enrollmentId,
      configurationVersion: invite.configurationVersion,
      confirmationToken: invite.confirmationToken,
    }, { attempts: 1, intervalMs: 0 });
    assert.deepEqual(calls[2].headers, {
      Accept: 'application/json',
      'X-Synergy-Innernet-Enrollment': 'enrollment-7',
      'X-Synergy-Innernet-Token': 'confirm-7',
    });
    await getMeshTransportSnapshot({
      enrollmentId: invite.enrollmentId,
      confirmationToken: invite.confirmationToken,
    });
    assert.deepEqual(calls[3].headers, {
      Accept: 'application/json',
      'X-Synergy-Innernet-Enrollment': 'enrollment-7',
      'X-Synergy-Innernet-Token': 'confirm-7',
    });
    const refreshedSnapshot = await refreshMeshTransportSnapshot({ receipt: { id: 'receipt-7' } });
    assert.deepEqual(refreshedSnapshot, signedMeshTransportSnapshot);
    assert.equal(calls[4].path, '/v1/mesh/transports/refresh');
    assert.equal(calls[4].method, 'POST');
    assert.deepEqual(calls[4].headers, {
      Accept: 'application/json',
      'Content-Type': 'application/json',
    });
    assert.deepEqual(calls[4].body, { receipt: { id: 'receipt-7' } });

    global.fetch = async () => response({
      error: 'mesh_refresh_rejected',
      detail: 'The signed mesh transport snapshot is no longer current.',
    }, 409);
    await assert.rejects(
      refreshMeshTransportSnapshot({ receipt: { id: 'receipt-7' } }),
      (error) => error.code === 'COORDINATOR_REJECTED'
        && error.message === 'The signed mesh transport snapshot is no longer current.'
        && error.details?.status === 409
        && error.details?.coordinatorError === 'mesh_refresh_rejected',
    );
    global.fetch = successfulCoordinatorFetch;

    const executorCalls = [];
    const executor = {
      mode: 'local',
      async runElevated(command, args) {
        executorCalls.push([command, args]);
        if (command === 'test') {
          const error = new Error('config not found');
          error.code = 'ELEVATED_COMMAND_FAILED';
          throw error;
        }
        if (command === 'innernet') return { stdout: '', stderr: '', code: 0 };
        if (command === 'wg' && args[0] === 'show' && args[1] === 'innernet0') return { stdout: wgDump, stderr: '', code: 0 };
        throw new Error(`Unexpected elevated command: ${command} ${args.join(' ')}`);
      },
      async run(command, args) {
        executorCalls.push([command, args]);
        if (command === 'test') {
          const error = new Error('not found');
          error.code = 'COMMAND_FAILED';
          throw error;
        }
        if (command === 'ip') return { stdout: '2: innernet0    inet 10.70.10.7/32 scope global innernet0\n', stderr: '', code: 0 };
        throw new Error(`Unexpected command: ${command} ${args.join(' ')}`);
      },
      async writeFile() {},
      async removeFile() {},
    };
    const mesh = await redeemInvite(executor, invite, (item) => progress.push(item));
    assert.equal(mesh.interfaceName, 'innernet0');
    assert.equal(mesh.assignedIp, '10.70.10.7');
    assert.equal(mesh.handshakeConfirmed, true);
    assert.equal(
      executorCalls.some(([command, args]) => command === 'innernet'
        && args[0] === 'install'
        && args[1] === '--default-name'
        && args[2] === '--delete-invite'
        && path.isAbsolute(args[3])),
      true,
    );
    assert.equal(executorCalls.some(([command, args]) => command === 'wg' && args.join(' ') === 'show interfaces'), true);
    const unit = renderInnernetSystemdUnit('/home/validator/.local/lib/synergy-ncp/innernet-test', 'sy-vpn');
    assert.match(unit, /^ExecStart=\/home\/validator\/\.local\/lib\/synergy-ncp\/innernet-test up sy-vpn$/m);
    assert.match(unit, /^Before=synergy-validator\.service synergy-testnet-relayer\.service$/m);
    assert.throws(
      () => renderInnernetSystemdUnit('innernet', 'sy-vpn'),
      (error) => error.code === 'INNERNET_CLIENT_PATH_INVALID',
    );
    const launchdPlist = renderInnernetLaunchdPlist(
      '/Applications/Synergy & Node Control Panel.app/Contents/Resources/innernet/innernet-darwin-arm64',
      'sy-vpn',
    );
    assert.match(launchdPlist, /<string>network\.synergy\.innernet<\/string>/);
    assert.match(launchdPlist, /<integer>30<\/integer>/);
    assert.match(launchdPlist, /Synergy &amp; Node Control Panel\.app/);
    assert.match(launchdPlist, /<string>up<\/string>\s*<string>sy-vpn<\/string>/);
    assert.throws(
      () => renderInnernetLaunchdPlist('innernet', 'sy-vpn'),
      (error) => error.code === 'INNERNET_CLIENT_PATH_INVALID',
    );

    const recoveredProgress = [];
    const recoveredExecutor = {
      mode: 'local',
      async runElevated(command, args) {
        if (command === 'test') {
          const error = new Error('config not found');
          error.code = 'ELEVATED_COMMAND_FAILED';
          throw error;
        }
        if (command === 'innernet') throw new Error('Innernet reported a post-registration failure.');
        if (command === 'wg' && args[0] === 'show' && args[1] === 'innernet0') return { stdout: wgDump, stderr: '', code: 0 };
        throw new Error(`Unexpected recovered elevated command: ${command} ${args.join(' ')}`);
      },
      async run(command, args) {
        if (command === 'test') {
          const error = new Error('not found');
          error.code = 'COMMAND_FAILED';
          throw error;
        }
        if (command === 'ip') return { stdout: '2: innernet0    inet 10.70.10.7/32 scope global innernet0\n', stderr: '', code: 0 };
        throw new Error(`Unexpected recovered command: ${command} ${args.join(' ')}`);
      },
      async writeFile() {},
      async removeFile() {},
    };
    const recoveredMesh = await redeemInvite(recoveredExecutor, invite, (item) => recoveredProgress.push(item));
    assert.equal(recoveredMesh.handshakeConfirmed, true);
    assert.equal(recoveredProgress.some((item) => item.step === 'innernet_client_recovered'), true);

    const resumeCalls = [];
    const resumeProgress = [];
    const existingConfigError = Object.assign(
      new Error('Administrator approval succeeded, but innernet-darwin-arm64 failed.'),
      { details: { stderr: '[E] Config file for innernet interface sy-vpn already exists.' } },
    );
    assert.equal(isExistingInterfaceConfigError(existingConfigError), true);
    assert.equal(isResumableInnernetInstallError(existingConfigError), true);
    const nestedExistingConfigError = Object.assign(
      new Error('Administrator approval succeeded, but innernet-darwin-arm64 failed.'),
      {
        details: {
          cause: {
            stdout: '7:75: execution error: [E] Config file for innernet interface sy-vpn already exists. (1)',
          },
        },
      },
    );
    assert.equal(isExistingInterfaceConfigError(nestedExistingConfigError), true);
    assert.equal(isResumableInnernetInstallError(nestedExistingConfigError), true);
    assert.equal(
      await hasExistingInterfaceConfig({
        async run(command, args) {
          assert.deepEqual([command, args], ['test', ['-f', '/etc/innernet/sy-vpn.conf']]);
          return { stdout: '', stderr: '', code: 0 };
        },
      }, 'sy-vpn'),
      true,
    );
    assert.equal(
      await hasExistingInterfaceConfig({
        async run() {
          const error = new Error('not found');
          error.code = 'COMMAND_FAILED';
          throw error;
        },
      }, 'sy-vpn'),
      false,
    );
    const elevatedConfigChecks = [];
    assert.equal(
      await hasExistingInterfaceConfig({
        mode: 'local',
        async run() {
          const error = new Error('not visible without administrator traversal');
          error.code = 'COMMAND_FAILED';
          throw error;
        },
        async runElevated(command, args) {
          elevatedConfigChecks.push([command, args]);
          return { stdout: '', stderr: '', code: 0 };
        },
      }, 'sy-vpn'),
      true,
    );
    assert.deepEqual(elevatedConfigChecks, [['test', ['-f', '/etc/innernet/sy-vpn.conf']]]);

    const proactiveResumeCalls = [];
    const proactiveResumeExecutor = {
      mode: 'local',
      async runElevated(command, args) {
        proactiveResumeCalls.push([command, args]);
        if (command === 'innernet' && args.join(' ') === 'up sy-vpn') return { stdout: '', stderr: '', code: 0 };
        if (command === 'wg' && args[0] === 'show' && args[1] === 'sy-vpn') return { stdout: wgDump, stderr: '', code: 0 };
        throw new Error(`Unexpected proactive recovery command: ${command} ${args.join(' ')}`);
      },
      async run(command, args) {
        if (command === 'test' && args.join(' ') === '-f /etc/innernet/sy-vpn.conf') return { stdout: '', stderr: '', code: 0 };
        if (command === 'ip') return { stdout: '2: sy-vpn    inet 10.70.10.7/32 scope global sy-vpn\n', stderr: '', code: 0 };
        throw new Error(`Unexpected proactive recovery command: ${command} ${args.join(' ')}`);
      },
      async writeFile() {
        throw new Error('Existing config recovery must not write or redeem an invite.');
      },
      async removeFile() {},
    };
    const proactivelyResumedMesh = await redeemInvite(
      proactiveResumeExecutor,
      { ...invite, interfaceName: 'sy-vpn', interface_name: 'sy-vpn' },
      () => {},
    );
    assert.equal(proactivelyResumedMesh.handshakeConfirmed, true);
    assert.equal(
      proactiveResumeCalls.some(([command, args]) => command === 'innernet' && args.join(' ') === 'up sy-vpn'),
      true,
    );
    assert.equal(
      proactiveResumeCalls.some(([command, args]) => command === 'innernet' && args[0] === 'install'),
      false,
    );
    assert.deepEqual(parseWireGuardDump('sy-vpn', wgDump).peers[0].allowedIps, ['10.70.10.1/32']);
    const darwinInspection = parseDarwinMeshInspection([
      'SYNERGY_MESH_STATUS=ready',
      'SYNERGY_MESH_DEVICE=utun8',
      `SYNERGY_MESH_DUMP_B64=${Buffer.from(wgDump).toString('base64')}`,
      `SYNERGY_MESH_ADDRS_B64=${Buffer.from('utun8: flags=8051<UP>\n\tinet 10.70.10.7 --> 10.70.10.7 netmask 0xffffffff\n').toString('base64')}`,
    ].join('\n'), 'sy-vpn', '10.70.10.7/32');
    assert.equal(darwinInspection.deviceInterfaceName, 'utun8');
    assert.equal(darwinInspection.handshakeConfirmed, true);
    assert.equal(darwinInspection.peersConnected, 1);

    let handshakeEstablished = false;
    const handshakeProbeCalls = [];
    const handshakeProbeExecutor = {
      mode: 'local',
      async runElevated(command, args) {
        handshakeProbeCalls.push([command, args]);
        if (command === 'test' && args.join(' ') === '-f /etc/innernet/sy-vpn.conf') return { stdout: '', stderr: '', code: 0 };
        if (command === 'innernet' && args.join(' ') === 'up sy-vpn') return { stdout: '', stderr: '', code: 0 };
        if (command === 'wg' && args.join(' ') === 'show interfaces') return { stdout: 'sy-vpn\n', stderr: '', code: 0 };
        if (command === 'wg' && args.join(' ') === 'show sy-vpn dump') {
          return { stdout: handshakeEstablished ? wgDump : wgDumpWithoutHandshake, stderr: '', code: 0 };
        }
        throw new Error(`Unexpected handshake-probe elevated command: ${command} ${args.join(' ')}`);
      },
      async run(command, args) {
        handshakeProbeCalls.push([command, args]);
        if (command === 'test' && args.join(' ') === '-f /etc/innernet/sy-vpn.conf') return { stdout: '', stderr: '', code: 0 };
        if (command === 'ip') return { stdout: '2: sy-vpn    inet 10.70.10.7/32 scope global sy-vpn\n', stderr: '', code: 0 };
        if (command === 'ping' && args.join(' ') === '-n -c 1 10.70.10.1') {
          handshakeEstablished = true;
          return { stdout: '', stderr: '', code: 0 };
        }
        throw new Error(`Unexpected handshake-probe command: ${command} ${args.join(' ')}`);
      },
      async writeFile() {
        throw new Error('Existing config handshake recovery must not redeem an invite.');
      },
      async removeFile() {},
    };
    const handshakeProbeMesh = await redeemInvite(
      handshakeProbeExecutor,
      { ...invite, interfaceName: 'sy-vpn', interface_name: 'sy-vpn' },
      () => {},
    );
    assert.equal(handshakeProbeMesh.handshakeConfirmed, true);
    assert.equal(
      handshakeProbeCalls.some(([command, args]) => command === 'ping' && args.join(' ') === '-n -c 1 10.70.10.1'),
      true,
    );

    const noHandshakeHealth = {
      ...parseWireGuardDump('sy-vpn', wgDumpWithoutHandshake),
      deviceInterfaceName: 'sy-vpn',
      assignedIp: '10.70.10.7',
      addresses: [{ ip: '10.70.10.7', cidr: '10.70.10.7/32' }],
      interfaceUp: true,
      peersConnected: 0,
      handshakeConfirmed: false,
    };
    const failedPingCalls = [];
    const failedPingExecutor = {
      mode: 'local',
      async runElevated(command, args) {
        failedPingCalls.push([command, args]);
        if (command === 'wg' && args.join(' ') === 'show interfaces') return { stdout: 'sy-vpn\n', stderr: '', code: 0 };
        if (command === 'wg' && args.join(' ') === 'show sy-vpn dump') {
          return { stdout: wgDumpWithoutHandshake, stderr: '', code: 0 };
        }
        throw new Error(`Unexpected failed-ping elevated command: ${command} ${args.join(' ')}`);
      },
      async run(command, args) {
        failedPingCalls.push([command, args]);
        if (command === 'ip') return { stdout: '2: sy-vpn    inet 10.70.10.7/32 scope global sy-vpn\n', stderr: '', code: 0 };
        if (command === 'ping') {
          const error = new Error('peer does not answer ICMP');
          error.code = 'COMMAND_FAILED';
          throw error;
        }
        throw new Error(`Unexpected failed-ping command: ${command} ${args.join(' ')}`);
      },
    };
    const failedPingHealth = await waitForMeshHandshake(
      failedPingExecutor,
      {
        interfaceName: 'sy-vpn',
        assignedIp: '10.70.10.7',
        initialHealth: noHandshakeHealth,
        timeoutMs: 10,
        pollIntervalMs: 1,
      },
    );
    assert.equal(failedPingHealth.handshakeConfirmed, false);
    assert.equal(
      failedPingCalls.some(([command, args]) => command === 'ping' && args.join(' ') === '-n -c 1 10.70.10.1'),
      true,
    );

    let repeatedProbeCount = 0;
    const repeatedProbeProgress = [];
    const repeatedProbeExecutor = {
      mode: 'local',
      async runElevated(command, args) {
        if (command === 'wg' && args.join(' ') === 'show interfaces') return { stdout: 'sy-vpn\n', stderr: '', code: 0 };
        if (command === 'wg' && args.join(' ') === 'show sy-vpn dump') {
          return { stdout: repeatedProbeCount >= 2 ? wgDump : wgDumpWithoutHandshake, stderr: '', code: 0 };
        }
        throw new Error(`Unexpected repeated-probe elevated command: ${command} ${args.join(' ')}`);
      },
      async run(command, args) {
        if (command === 'ip') return { stdout: '2: sy-vpn    inet 10.70.10.7/32 scope global sy-vpn\n', stderr: '', code: 0 };
        if (command === 'ping') {
          repeatedProbeCount += 1;
          return { stdout: '', stderr: '', code: 0 };
        }
        throw new Error(`Unexpected repeated-probe command: ${command} ${args.join(' ')}`);
      },
    };
    const repeatedProbeHealth = await waitForMeshHandshake(
      repeatedProbeExecutor,
      {
        interfaceName: 'sy-vpn',
        assignedIp: '10.70.10.7',
        initialHealth: noHandshakeHealth,
        emitProgress: (item) => repeatedProbeProgress.push(item),
        timeoutMs: 100,
        pollIntervalMs: 1,
        probeIntervalMs: 5,
      },
    );
    assert.equal(repeatedProbeHealth.handshakeConfirmed, true);
    assert.equal(repeatedProbeCount >= 2, true);
    assert.equal(
      repeatedProbeProgress.some((item) => item.step === 'handshake_waiting' && item.peersConfigured === 1),
      true,
    );

    let delayedInterfacePresent = false;
    let delayedHandshakeEstablished = false;
    const delayedInterfaceCalls = [];
    const delayedInterfaceExecutor = {
      mode: 'local',
      async runElevated(command, args) {
        delayedInterfaceCalls.push([command, args]);
        if (command === 'wg' && args.join(' ') === 'show interfaces') {
          if (!delayedInterfacePresent) {
            delayedInterfacePresent = true;
            return { stdout: '', stderr: '', code: 0 };
          }
          return { stdout: 'utun8\n', stderr: '', code: 0 };
        }
        if (command === 'wg' && args.join(' ') === 'show sy-vpn dump') {
          const error = new Error('logical Innernet name is not a Darwin interface');
          error.code = 'COMMAND_FAILED';
          throw error;
        }
        if (command === 'wg' && args.join(' ') === 'show utun8 dump') {
          return {
            stdout: delayedHandshakeEstablished ? wgDump : wgDumpWithoutHandshake,
            stderr: '',
            code: 0,
          };
        }
        throw new Error(`Unexpected delayed-interface elevated command: ${command} ${args.join(' ')}`);
      },
      async run(command, args) {
        delayedInterfaceCalls.push([command, args]);
        if (command === 'ip' && args[args.length - 1] === 'sy-vpn') {
          const error = new Error('logical Innernet name is not a Darwin interface');
          error.code = 'COMMAND_FAILED';
          throw error;
        }
        if (command === 'ifconfig' && args[0] === 'sy-vpn') {
          const error = new Error('logical Innernet name is not a Darwin interface');
          error.code = 'COMMAND_FAILED';
          throw error;
        }
        if (command === 'ip' && args[args.length - 1] === 'utun8') {
          return { stdout: '2: utun8    inet 10.70.10.7/32 scope global utun8\n', stderr: '', code: 0 };
        }
        if (command === 'ping' && args.join(' ') === '-n -c 1 10.70.10.1') {
          delayedHandshakeEstablished = true;
          return { stdout: '', stderr: '', code: 0 };
        }
        throw new Error(`Unexpected delayed-interface command: ${command} ${args.join(' ')}`);
      },
    };
    const delayedInterfaceHealth = await waitForMeshHandshake(
      delayedInterfaceExecutor,
      {
        interfaceName: 'sy-vpn',
        assignedIp: '10.70.10.7',
        timeoutMs: 500,
        pollIntervalMs: 1,
      },
    );
    assert.equal(delayedInterfaceHealth.handshakeConfirmed, true);
    assert.equal(delayedInterfaceHealth.deviceInterfaceName, 'utun8');
    assert.equal(
      delayedInterfaceCalls.some(([command, args]) => command === 'ping' && args.join(' ') === '-n -c 1 10.70.10.1'),
      true,
    );
    const explicitlyRecoveredMesh = await redeemInvite(
      proactiveResumeExecutor,
      {
        ...recoveredInvite,
        interfaceName: 'sy-vpn',
        interface_name: 'sy-vpn',
        assignedIp: '10.70.10.7',
      },
      () => {},
    );
    assert.equal(explicitlyRecoveredMesh.handshakeConfirmed, true);
    const recoveredWithoutConfigProbe = await redeemInvite(
      {
        ...proactiveResumeExecutor,
        async runElevated(command, args) {
          if (command === 'test') {
            const error = new Error('config not found');
            error.code = 'ELEVATED_COMMAND_FAILED';
            throw error;
          }
          return proactiveResumeExecutor.runElevated(command, args);
        },
        async run(command, args) {
          if (command === 'test') {
            const error = new Error('not found');
            error.code = 'COMMAND_FAILED';
            throw error;
          }
          return proactiveResumeExecutor.run(command, args);
        },
      },
      {
        ...recoveredInvite,
        interfaceName: 'sy-vpn',
        interface_name: 'sy-vpn',
        assignedIp: '10.70.10.7',
      },
    );
    assert.equal(recoveredWithoutConfigProbe.handshakeConfirmed, true);
    const resumeExecutor = {
      mode: 'local',
      async runElevated(command, args) {
        resumeCalls.push([command, args]);
        if (command === 'test') {
          const error = new Error('config not found');
          error.code = 'ELEVATED_COMMAND_FAILED';
          throw error;
        }
        if (command === 'innernet' && args[0] === 'install') throw existingConfigError;
        if (command === 'innernet' && args.join(' ') === 'up sy-vpn') return { stdout: '', stderr: '', code: 0 };
        if (command === 'wg' && args[0] === 'show' && args[1] === 'sy-vpn') return { stdout: wgDump, stderr: '', code: 0 };
        throw new Error(`Unexpected resume elevated command: ${command} ${args.join(' ')}`);
      },
      async run(command, args) {
        if (command === 'test') {
          const error = new Error('not found');
          error.code = 'COMMAND_FAILED';
          throw error;
        }
        if (command === 'ip') return { stdout: '2: sy-vpn    inet 10.70.10.7/32 scope global sy-vpn\n', stderr: '', code: 0 };
        throw new Error(`Unexpected resume command: ${command} ${args.join(' ')}`);
      },
      async writeFile() {},
      async removeFile() {},
    };
    const resumedMesh = await redeemInvite(
      resumeExecutor,
      { ...invite, interfaceName: 'sy-vpn', interface_name: 'sy-vpn' },
      (item) => resumeProgress.push(item),
    );
    assert.equal(resumedMesh.handshakeConfirmed, true);
    assert.equal(resumeCalls.some(([command, args]) => command === 'innernet' && args.join(' ') === 'up sy-vpn'), true);
    assert.equal(resumeProgress.some((item) => item.step === 'existing_innernet_config_started'), true);
    assert.equal(resumeProgress.some((item) => item.step === 'innernet_client_recovered'), true);

    const darwinUtunCalls = [];
    const darwinUtunExecutor = {
      ...resumeExecutor,
      async runElevated(command, args) {
        darwinUtunCalls.push([command, args]);
        if (command === 'test' && args.join(' ') === '-f /etc/innernet/sy-vpn.conf') return { stdout: '', stderr: '', code: 0 };
        if (command === 'innernet' && args[0] === 'install') throw existingConfigError;
        if (command === 'innernet' && args.join(' ') === 'up sy-vpn') return { stdout: '', stderr: '', code: 0 };
        if (command === 'wg' && args.join(' ') === 'show interfaces') return { stdout: 'utun8\n', stderr: '', code: 0 };
        if (command === 'wg' && args.join(' ') === 'show sy-vpn dump') {
          const error = new Error('logical Innernet name is not a Darwin interface');
          error.code = 'COMMAND_FAILED';
          throw error;
        }
        if (command === 'wg' && args.join(' ') === 'show utun8 dump') return { stdout: wgDump, stderr: '', code: 0 };
        throw new Error(`Unexpected Darwin utun elevated command: ${command} ${args.join(' ')}`);
      },
      async run(command, args) {
        if (command === 'test') {
          const error = new Error('not visible without administrator traversal');
          error.code = 'COMMAND_FAILED';
          throw error;
        }
        if (command === 'ip') {
          const error = new Error('ip is unavailable on macOS');
          error.code = 'COMMAND_UNAVAILABLE';
          throw error;
        }
        if (command === 'ifconfig' && args[0] === 'sy-vpn') {
          const error = new Error('interface does not exist');
          error.code = 'COMMAND_FAILED';
          throw error;
        }
        if (command === 'ifconfig' && args[0] === 'utun8') {
          return { stdout: 'utun8: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST>\n\tinet 10.70.10.7 --> 10.70.10.7 netmask 0xffffffff\n', stderr: '', code: 0 };
        }
        throw new Error(`Unexpected Darwin utun command: ${command} ${args.join(' ')}`);
      },
    };
    const darwinUtunMesh = await redeemInvite(
      darwinUtunExecutor,
      { ...invite, interfaceName: 'sy-vpn', interface_name: 'sy-vpn' },
      () => {},
    );
    assert.equal(darwinUtunMesh.interfaceName, 'sy-vpn');
    assert.equal(darwinUtunMesh.deviceInterfaceName, 'utun8');
    assert.equal(darwinUtunMesh.handshakeConfirmed, true);
    assert.equal(
      darwinUtunCalls.some(([command, args]) => command === 'wg' && args.join(' ') === 'show utun8 dump'),
      true,
    );
    assert.equal(
      darwinUtunCalls.some(([command, args]) => command === 'innernet' && args[0] === 'install'),
      false,
    );

    const darwinMissingInterfaceExecutor = {
      ...darwinUtunExecutor,
      async runElevated(command, args) {
        if (command === 'test' && args.join(' ') === '-f /etc/innernet/sy-vpn.conf') return { stdout: '', stderr: '', code: 0 };
        if (command === 'innernet' && args[0] === 'install') throw existingConfigError;
        if (command === 'innernet' && args.join(' ') === 'up sy-vpn') return { stdout: '', stderr: '', code: 0 };
        if (command === 'wg' && args.join(' ') === 'show interfaces') return { stdout: '', stderr: '', code: 0 };
        if (command === 'wg' && args.join(' ') === 'show sy-vpn dump') {
          const error = new Error('logical Innernet name is not a Darwin interface');
          error.code = 'COMMAND_FAILED';
          throw error;
        }
        throw new Error(`Unexpected missing-interface elevated command: ${command} ${args.join(' ')}`);
      },
    };
    await assert.rejects(
      () => redeemInvite(
        darwinMissingInterfaceExecutor,
        { ...invite, interfaceName: 'sy-vpn', interface_name: 'sy-vpn' },
        () => {},
      ),
      (error) => error.code === 'INTERFACE_FAILED'
        && !String(error.message).includes('Config file for innernet interface sy-vpn already exists'),
    );

    const duplicateIpError = Object.assign(
      new Error('Innernet server rejected the peer assignment (exit code Some(1)).'),
      {
        details: {
          stderr: 'Error: internal database error Caused by: 0: UNIQUE constraint failed: peers.ip 1: Error code 2067: A UNIQUE constraint failed.',
        },
      },
    );
    assert.equal(isExistingInterfaceConfigError(duplicateIpError), false);
    assert.equal(isResumableInnernetInstallError(duplicateIpError), true);
    const duplicateResumeCalls = [];
    const duplicateResumeExecutor = {
      ...resumeExecutor,
      async runElevated(command, args) {
        duplicateResumeCalls.push([command, args]);
        if (command === 'test') {
          const error = new Error('config not found');
          error.code = 'ELEVATED_COMMAND_FAILED';
          throw error;
        }
        if (command === 'innernet' && args[0] === 'install') throw duplicateIpError;
        if (command === 'innernet' && args.join(' ') === 'up sy-vpn') return { stdout: '', stderr: '', code: 0 };
        if (command === 'wg' && args[0] === 'show' && args[1] === 'sy-vpn') return { stdout: wgDump, stderr: '', code: 0 };
        throw new Error(`Unexpected duplicate-IP recovery command: ${command} ${args.join(' ')}`);
      },
    };
    const duplicateResumedMesh = await redeemInvite(
      duplicateResumeExecutor,
      { ...invite, interfaceName: 'sy-vpn', interface_name: 'sy-vpn' },
      () => {},
    );
    assert.equal(duplicateResumedMesh.handshakeConfirmed, true);
    assert.equal(
      duplicateResumeCalls.some(([command, args]) => command === 'innernet' && args.join(' ') === 'up sy-vpn'),
      true,
    );

    const failedExecutor = {
      ...recoveredExecutor,
      async runElevated(command, args) {
        if (command === 'test') {
          const error = new Error('config not found');
          error.code = 'ELEVATED_COMMAND_FAILED';
          throw error;
        }
        if (command === 'innernet') throw new Error('Innernet failed before registration.');
        if (command === 'wg') throw new Error('Interface is absent.');
        throw new Error(`Unexpected failed elevated command: ${command} ${args.join(' ')}`);
      },
    };
    await assert.rejects(
      redeemInvite(failedExecutor, invite),
      (error) => error.code === 'INVITE_REDEMPTION_FAILED',
    );

    const handlers = new Map();
    const controlCommands = [];
    setupOnboardingIpc(
      { handle: (channel, handler) => handlers.set(channel, handler) },
      {
        userDataPath: path.join(temporaryDirectory, 'user-data'),
        invokeControlService: async (command, args) => {
          controlCommands.push({ command, args });
          if (command === 'testnet_reuse_innernet_enrollment') return { status: 'not_enrolled' };
          if (command !== 'testnet_record_innernet_enrollment') throw new Error(`Unexpected control command: ${command}`);
          return { recorded: true };
        },
      },
    );
    const ipcResponse = await handlers.get('onboarding:connect-secure-network')({ sender: { send() {} } }, {
      targetId: 'local',
      nodeId: 'node-7',
      peerName: 'validator-7',
      peerType: 'validator',
      onboardingToken: 'one-time-token',
      validatorAddress: 'synv1validator7',
      operatorAddress: 'syn1operator7',
    });
    assert.equal(ipcResponse.ok, true);
    assert.equal(controlCommands.length, 2);
    assert.equal(controlCommands[0].command, 'testnet_reuse_innernet_enrollment');
    assert.equal(controlCommands[1].command, 'testnet_record_innernet_enrollment');
    assert.deepEqual(controlCommands[1].args.input.coordinatorReceipt, { id: 'receipt-7' });
    assert.deepEqual(controlCommands[1].args.input.innernetTransportSnapshot.transports, [
      { validator_address: 'synv1validator7', dial_address: '10.70.10.7:5622' },
    ]);
    assert.equal(controlCommands[1].args.input.localInterfaceEvidence.interfaceName, 'innernet0');
    assert.equal(controlCommands[1].args.input.localInterfaceEvidence.assignedIp, '10.70.10.7');
    assert.equal(progress.some((item) => item.step === 'handshake_confirmed'), true);

    const retryHandlers = new Map();
    let retryRedemptions = 0;
    const inviteCallsBeforeRetry = calls.filter((call) => call.path === '/v1/invite').length;
    setupOnboardingIpc(
      { handle: (channel, handler) => retryHandlers.set(channel, handler) },
      {
        userDataPath: path.join(temporaryDirectory, 'retry-user-data'),
        invokeControlService: async () => ({ recorded: true }),
        redeemInviteFn: async () => {
          retryRedemptions += 1;
          if (retryRedemptions === 1) throw new Error('Simulated local authorization failure.');
          return {
            interfaceName: 'innernet0',
            assignedIp: '10.70.10.7',
            addresses: [{ ip: '10.70.10.7', cidr: '10.70.10.7/32' }],
            handshakeConfirmed: true,
            peersConnected: 1,
            peers: [{ name: 'Peer 1', lastHandshakeSecondsAgo: 0 }],
          };
        },
      },
    );
    const retryInput = {
      targetId: 'local',
      nodeId: 'node-7',
      peerName: 'validator-7',
      peerType: 'validator',
      onboardingToken: 'one-time-token',
      validatorAddress: 'synv1validator7',
      operatorAddress: 'syn1operator7',
    };
    const firstRetry = await retryHandlers.get('onboarding:connect-secure-network')({ sender: { send() {} } }, retryInput);
    const secondRetry = await retryHandlers.get('onboarding:connect-secure-network')({ sender: { send() {} } }, retryInput);
    assert.equal(firstRetry.ok, false);
    assert.equal(secondRetry.ok, true);
    assert.equal(retryRedemptions, 2);
    assert.equal(
      calls.filter((call) => call.path === '/v1/invite').length - inviteCallsBeforeRetry,
      1,
      'A local redemption retry must reuse the pending coordinator invite.',
    );

    const expiredRecoveryHandlers = new Map();
    const inviteCallsBeforeExpiredRecovery = calls.filter((call) => call.path === '/v1/invite').length;
    setupOnboardingIpc(
      { handle: (channel, handler) => expiredRecoveryHandlers.set(channel, handler) },
      {
        userDataPath: path.join(temporaryDirectory, 'expired-recovery-user-data'),
        invokeControlService: async () => ({ recorded: true }),
        pendingInviteStore: {
          async load() {
            return new Map([['local', {
              ...invite,
              expiresAt: new Date(Date.now() - 60 * 60 * 1_000).toISOString(),
            }]]);
          },
          async save() {},
        },
        redeemInviteFn: async () => ({
          interfaceName: 'innernet0',
          assignedIp: '10.70.10.7',
          addresses: [{ ip: '10.70.10.7', cidr: '10.70.10.7/32' }],
          handshakeConfirmed: true,
          peersConnected: 1,
          peers: [{ name: 'Peer 1', lastHandshakeSecondsAgo: 0 }],
        }),
      },
    );
    const expiredRecovery = await expiredRecoveryHandlers.get('onboarding:connect-secure-network')(
      { sender: { send() {} } },
      retryInput,
    );
    assert.equal(expiredRecovery.ok, true);
    assert.equal(
      calls.filter((call) => call.path === '/v1/invite').length,
      inviteCallsBeforeExpiredRecovery,
      'An expired but redeemed pending invite must be confirmed instead of replaced.',
    );

    const staleRecoveryHandlers = new Map();
    const inviteCallsBeforeStaleRecovery = calls.filter((call) => call.path === '/v1/invite').length;
    setupOnboardingIpc(
      { handle: (channel, handler) => staleRecoveryHandlers.set(channel, handler) },
      {
        userDataPath: path.join(temporaryDirectory, 'stale-recovery-user-data'),
        invokeControlService: async () => ({ recorded: true }),
        pendingInviteStore: {
          async load() {
            return new Map([['local', {
              ...invite,
              expiresAt: new Date(Date.now() - REDEEMED_INVITE_RECOVERY_GRACE_MS - 1_000).toISOString(),
            }]]);
          },
          async save() {},
        },
        redeemInviteFn: async () => ({
          interfaceName: 'innernet0',
          assignedIp: '10.70.10.7',
          addresses: [{ ip: '10.70.10.7', cidr: '10.70.10.7/32' }],
          handshakeConfirmed: true,
          peersConnected: 1,
          peers: [{ name: 'Peer 1', lastHandshakeSecondsAgo: 0 }],
        }),
      },
    );
    const staleRecovery = await staleRecoveryHandlers.get('onboarding:connect-secure-network')(
      { sender: { send() {} } },
      retryInput,
    );
    assert.equal(staleRecovery.ok, true);
    assert.equal(
      calls.filter((call) => call.path === '/v1/invite').length,
      inviteCallsBeforeStaleRecovery + 1,
      'An in-memory invite beyond the bounded recovery window must be replaced.',
    );

    const ipcSource = fs.readFileSync(path.join(__dirname, '../../electron/ipc/onboarding-ipc.cjs'), 'utf8');
    assert.equal(ipcSource.includes('testnet_enroll_validator_vpn'), false);
    assert.equal(ipcSource.includes('validator-vpn-enroll'), false);
    console.log('Innernet onboarding contract QA passed');
  } finally {
    if (originalEnvironment.coordinatorUrl === undefined) delete process.env.SYNERGY_COORDINATOR_API_URL;
    else process.env.SYNERGY_COORDINATOR_API_URL = originalEnvironment.coordinatorUrl;
    if (originalEnvironment.path === undefined) delete process.env.PATH;
    else process.env.PATH = originalEnvironment.path;
    if (originalEnvironment.innernetBinary === undefined) delete process.env.SYNERGY_INNERNET_CLIENT_BIN;
    else process.env.SYNERGY_INNERNET_CLIENT_BIN = originalEnvironment.innernetBinary;
    if (originalEnvironment.handshakeTimeout === undefined) delete process.env.SYNERGY_INNERNET_HANDSHAKE_TIMEOUT_MS;
    else process.env.SYNERGY_INNERNET_HANDSHAKE_TIMEOUT_MS = originalEnvironment.handshakeTimeout;
    if (originalEnvironment.nodeEnv === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = originalEnvironment.nodeEnv;
    if (originalEnvironment.skipLaunchdPersistence === undefined) delete process.env.SYNERGY_NCP_TEST_SKIP_LAUNCHD_PERSISTENCE;
    else process.env.SYNERGY_NCP_TEST_SKIP_LAUNCHD_PERSISTENCE = originalEnvironment.skipLaunchdPersistence;
    if (originalEnvironment.skipSystemdPersistence === undefined) delete process.env.SYNERGY_NCP_TEST_SKIP_SYSTEMD_PERSISTENCE;
    else process.env.SYNERGY_NCP_TEST_SKIP_SYSTEMD_PERSISTENCE = originalEnvironment.skipSystemdPersistence;
    fs.rmSync(temporaryDirectory, { recursive: true, force: true });
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
