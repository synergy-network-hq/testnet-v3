const crypto = require('crypto');
const fs = require('fs/promises');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');
const { safeStorage } = require('electron');

function targetError(code, message, details = null) {
  const error = new Error(message);
  error.code = code;
  error.details = details;
  return error;
}

function shellQuote(value) {
  return `'${String(value).replace(/'/g, "'\\\"'\\\"'")}'`;
}

function authorizationShellQuote(value) {
  return `'${String(value).replace(/'/g, "'\"'\"'")}'`;
}

function elevatedExecutableSearchPath() {
  const resourceDirectory = process.resourcesPath
    ? path.join(process.resourcesPath, 'innernet')
    : path.resolve(__dirname, '..', '..', 'binaries', 'innernet');
  return [resourceDirectory, '/usr/bin', '/bin', '/usr/sbin', '/sbin'].join(':');
}

function macosAuthorizationArguments(command, args = [], executablePath = elevatedExecutableSearchPath()) {
  const invocation = [command, ...args].map(authorizationShellQuote).join(' ');
  const commandLine = `export PATH=${authorizationShellQuote(executablePath)}; exec ${invocation}`;
  return [
    '-e', 'on run argv',
    '-e', 'do shell script (item 1 of argv) with administrator privileges',
    '-e', 'end run',
    commandLine,
  ];
}

function boundedCommandFailure(error) {
  const raw = String(error?.details?.stderr || error?.message || '').replace(/[\u0000-\u001f\u007f]+/g, ' ').trim();
  return raw.slice(-1_000);
}

function sudoRequiresInteractiveAuthorization(error) {
  const failure = boundedCommandFailure(error);
  return /(?:a password is required|no tty present|a terminal is required)/i.test(failure);
}

function run(command, args, { env, input, onStdout, onStderr, timeoutMs = 30_000 } = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      env: { ...process.env, ...env },
      stdio: [input === undefined ? 'ignore' : 'pipe', 'pipe', 'pipe'],
      windowsHide: true,
    });
    let stdout = '';
    let stderr = '';
    const append = (current, chunk) => `${current}${chunk}`.slice(-16_384);
    child.stdout.on('data', (chunk) => {
      stdout = append(stdout, chunk);
      onStdout?.(chunk.toString());
    });
    child.stderr.on('data', (chunk) => {
      stderr = append(stderr, chunk);
      onStderr?.(chunk.toString());
    });
    const timeout = setTimeout(() => child.kill('SIGTERM'), timeoutMs);
    if (input !== undefined) child.stdin.end(input);
    child.once('error', (cause) => {
      clearTimeout(timeout);
      reject(targetError('COMMAND_UNAVAILABLE', 'Required secure-network command is not available.', { command, cause: cause?.code || cause?.name }));
    });
    child.once('close', (code) => {
      clearTimeout(timeout);
      resolve({ code: Number(code || 0), stdout, stderr });
    });
  });
}

async function withTemporaryAskpass(password, callback) {
  if (typeof password !== 'string' || password.length === 0) {
    throw targetError('SSH_TEMPORARY_PASSWORD_REQUIRED', 'Enter the one-time SSH password to install the managed connection key.');
  }
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'synergy-ncp-askpass-'));
  const scriptPath = path.join(directory, 'askpass.sh');
  try {
    await fs.writeFile(scriptPath, '#!/bin/sh\nprintf \'%s\\n\' "$SYNERGY_NCP_SSH_PASSWORD"\n', { mode: 0o700 });
    return await callback({
      SSH_ASKPASS: scriptPath,
      SSH_ASKPASS_REQUIRE: 'force',
      DISPLAY: process.env.DISPLAY || 'synergy-ncp',
      SYNERGY_NCP_SSH_PASSWORD: password,
    });
  } finally {
    await fs.rm(directory, { recursive: true, force: true });
  }
}

async function bootstrapManagedKeyWithTemporaryPassword(target, controlDirectory, publicKey, password) {
  const knownHostsPath = path.join(controlDirectory, 'known_hosts');
  await fs.mkdir(path.dirname(knownHostsPath), { recursive: true, mode: 0o700 });
  const remoteCommand = [
    'set -eu',
    'install -d -m 700 "$HOME/.ssh"',
    'touch "$HOME/.ssh/authorized_keys"',
    'chmod 600 "$HOME/.ssh/authorized_keys"',
    'IFS= read -r key',
    'grep -qxF "$key" "$HOME/.ssh/authorized_keys" || printf "%s\\n" "$key" >> "$HOME/.ssh/authorized_keys"',
  ].join('; ');
  await withTemporaryAskpass(password, (env) => runSuccessful('ssh', [
    '-p', String(target.port),
    '-o', 'BatchMode=no',
    '-o', 'NumberOfPasswordPrompts=1',
    '-o', 'PreferredAuthentications=password,keyboard-interactive',
    '-o', 'PubkeyAuthentication=no',
    '-o', 'StrictHostKeyChecking=accept-new',
    '-o', `UserKnownHostsFile=${knownHostsPath}`,
    '-o', 'ConnectTimeout=15',
    `${target.username}@${target.host}`,
    `sh -lc ${shellQuote(remoteCommand)}`,
  ], { env, input: `${publicKey}\n`, timeoutMs: 45_000 }));
}

async function runSuccessful(command, args, options) {
  const result = await run(command, args, options);
  if (result.code !== 0) {
    throw targetError('COMMAND_FAILED', 'A secure-network command did not complete successfully.', {
      command,
      exitCode: result.code,
      stderr: result.stderr.slice(-2_000),
    });
  }
  return result;
}

function validateRemoteTarget(input = {}) {
  const host = String(input.host || '').trim();
  const username = String(input.username || '').trim();
  const port = Number(input.port || 22);
  if (!/^[A-Za-z0-9][A-Za-z0-9.-]*$/.test(host)) {
    throw targetError('SSH_HOST_INVALID', 'Enter a valid remote server host name or address.');
  }
  if (!/^[A-Za-z_][A-Za-z0-9_-]*$/.test(username)) {
    throw targetError('SSH_USERNAME_INVALID', 'Enter a valid SSH username.');
  }
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw targetError('SSH_PORT_INVALID', 'Enter a valid SSH port.');
  }
  return { host, username, port };
}

function normaliseAuthMethod(value) {
  const method = String(value || 'ncp_managed_key').trim().toLowerCase();
  if (method === 'password') return 'temporary_password';
  if (['ncp_managed_key', 'existing_key', 'temporary_password'].includes(method)) return method;
  throw targetError('SSH_AUTH_METHOD_INVALID', 'Choose a supported SSH authentication method.');
}

function encryptFallback(plaintext, passphrase) {
  if (!passphrase) throw targetError('SECRETS_UNAVAILABLE', 'Enter a key-storage passphrase when the system keychain is unavailable.');
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = crypto.scryptSync(passphrase, salt, 32);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return {
    provider: 'scrypt-aes-256-gcm',
    salt: salt.toString('base64'),
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    ciphertext: ciphertext.toString('base64'),
  };
}

function decryptFallback(record, passphrase) {
  if (!passphrase) throw targetError('KEY_STORAGE_PASSPHRASE_REQUIRED', 'Enter the key-storage passphrase to use this remote target.');
  try {
    const key = crypto.scryptSync(passphrase, Buffer.from(record.salt, 'base64'), 32);
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(record.iv, 'base64'));
    decipher.setAuthTag(Buffer.from(record.tag, 'base64'));
    return Buffer.concat([decipher.update(Buffer.from(record.ciphertext, 'base64')), decipher.final()]).toString('utf8');
  } catch {
    throw targetError('KEY_STORAGE_PASSPHRASE_INVALID', 'The key-storage passphrase could not unlock this remote target.');
  }
}

function storeSecret(plaintext, passphrase) {
  if (safeStorage?.isEncryptionAvailable?.()) {
    return { provider: 'electron-safe-storage', ciphertext: safeStorage.encryptString(plaintext).toString('base64') };
  }
  return encryptFallback(plaintext, passphrase);
}

function loadSecret(record, passphrase) {
  if (record?.provider === 'electron-safe-storage') {
    try {
      return safeStorage.decryptString(Buffer.from(record.ciphertext, 'base64'));
    } catch {
      throw targetError('SECRETS_UNAVAILABLE', 'The operating-system keychain could not unlock the managed SSH key.');
    }
  }
  return decryptFallback(record || {}, passphrase);
}

async function createManagedKey(directory, targetId) {
  await fs.mkdir(directory, { recursive: true, mode: 0o700 });
  const temporaryDirectory = await fs.mkdtemp(path.join(directory, 'key-'));
  const privatePath = path.join(temporaryDirectory, targetId);
  try {
    await runSuccessful('ssh-keygen', ['-q', '-t', 'ed25519', '-N', '', '-f', privatePath]);
    const [privateKey, publicKey] = await Promise.all([
      fs.readFile(privatePath, 'utf8'),
      fs.readFile(`${privatePath}.pub`, 'utf8'),
    ]);
    return { privateKey, publicKey: publicKey.trim() };
  } finally {
    await fs.rm(temporaryDirectory, { recursive: true, force: true });
  }
}

class LocalExecutor {
  constructor() { this.mode = 'local'; }
  async run(command, args, options) { return runSuccessful(command, args, options); }
  async streamCommand(command, args, onOutput, options = {}) {
    return this.run(command, args, { ...options, onStdout: onOutput, onStderr: onOutput });
  }
  async readFile(filePath) { return fs.readFile(filePath, 'utf8'); }
  async writeFile(filePath, content, mode = '0600') {
    if (!path.isAbsolute(filePath) || filePath.includes('\u0000')) {
      throw targetError('LOCAL_PATH_INVALID', 'A valid absolute local path is required.');
    }
    await fs.mkdir(path.dirname(filePath), { recursive: true, mode: 0o700 });
    const temporary = `${filePath}.${process.pid}.${crypto.randomUUID()}.tmp`;
    try {
      await fs.writeFile(temporary, content, { mode: Number.parseInt(mode, 8) });
      await fs.rename(temporary, filePath);
    } finally {
      await fs.rm(temporary, { force: true });
    }
  }
  async removeFile(filePath) { await fs.rm(filePath, { force: true }); }
  async runElevated(command, args, options) {
    if (typeof process.getuid === 'function' && process.getuid() === 0) return this.run(command, args, options);
    try {
      return await runSuccessful('sudo', ['-n', '--', command, ...args], options);
    } catch (error) {
      if (error.code !== 'COMMAND_FAILED') throw error;
      if (!sudoRequiresInteractiveAuthorization(error)) throw error;
      if (process.platform === 'darwin') {
        const executablePath = elevatedExecutableSearchPath();
        const resolvedCommand = path.isAbsolute(command)
          ? command
          : String((await runSuccessful('/usr/bin/which', [command], {
            env: { PATH: executablePath },
          })).stdout || '').trim();
        if (!path.isAbsolute(resolvedCommand)) {
          throw targetError('COMMAND_UNAVAILABLE', 'Required secure-network command is not available.', { command });
        }
        try {
          return await runSuccessful(
            '/usr/bin/osascript',
            macosAuthorizationArguments(resolvedCommand, args, executablePath),
            options,
          );
        } catch (authorizationError) {
          const failure = boundedCommandFailure(authorizationError);
          if (!/(?:user canceled|\(-128\))/i.test(failure)) {
            const label = path.basename(resolvedCommand);
            throw targetError(
              'ELEVATED_COMMAND_FAILED',
              `Administrator approval succeeded, but ${label} failed${failure ? `: ${failure}` : '.'}`,
              {
                command: label,
                exitCode: authorizationError?.details?.exitCode ?? null,
                stderr: failure || null,
              },
            );
          }
          throw targetError(
            'ELEVATION_REQUIRED',
            'macOS administrator approval was canceled or did not complete. Approve the system dialog to configure the secure validator network.',
            { sourceCode: authorizationError?.code || 'COMMAND_FAILED' },
          );
        }
      }
      if (process.platform === 'linux' && (process.env.DISPLAY || process.env.WAYLAND_DISPLAY)) {
        try {
          return await runSuccessful('pkexec', [command, ...args], options);
        } catch (authorizationError) {
          throw targetError(
            'ELEVATION_REQUIRED',
            'Linux administrator approval was canceled or did not complete. Approve the desktop authorization dialog to configure the secure validator network.',
            { sourceCode: authorizationError?.code || 'COMMAND_FAILED' },
          );
        }
      }
      throw targetError('ELEVATION_REQUIRED', 'Administrator approval is required to configure the secure validator network.');
    }
  }
}

class RemoteExecutor {
  constructor(target, controlPath, knownHostsPath, identityFile = null) {
    this.mode = 'remote';
    this.target = target;
    this.controlPath = controlPath;
    this.knownHostsPath = knownHostsPath;
    this.identityFile = identityFile;
  }

  targetAddress() { return `${this.target.username}@${this.target.host}`; }

  baseArgs({ includeControlPath = true } = {}) {
    const args = [
      '-p', String(this.target.port),
      '-o', 'BatchMode=yes',
      '-o', 'StrictHostKeyChecking=accept-new',
      '-o', `UserKnownHostsFile=${this.knownHostsPath}`,
      '-o', 'ConnectTimeout=15',
    ];
    if (includeControlPath) args.push('-S', this.controlPath);
    if (this.identityFile) args.push('-i', this.identityFile, '-o', 'IdentitiesOnly=yes');
    return args;
  }

  async ensureMaster() {
    await fs.mkdir(path.dirname(this.controlPath), { recursive: true, mode: 0o700 });
    await fs.mkdir(path.dirname(this.knownHostsPath), { recursive: true, mode: 0o700 });
    const check = await run('ssh', [...this.baseArgs(), '-O', 'check', this.targetAddress()]);
    if (check.code === 0) return;
    await runSuccessful('ssh', [
      ...this.baseArgs({ includeControlPath: false }),
      '-S', this.controlPath,
      '-o', 'ControlMaster=yes',
      '-o', 'ControlPersist=10m',
      '-MNf',
      this.targetAddress(),
    ]);
  }

  async testConnection() { await this.ensureMaster(); return { connected: true }; }

  async run(command, args, options) {
    await this.ensureMaster();
    const remoteCommand = [command, ...args].map(shellQuote).join(' ');
    return runSuccessful('ssh', [...this.baseArgs(), this.targetAddress(), remoteCommand], options);
  }

  async streamCommand(command, args, onOutput, options = {}) {
    return this.run(command, args, { ...options, onStdout: onOutput, onStderr: onOutput });
  }

  async runElevated(command, args, options) {
    try {
      return await this.run('sudo', ['-n', '--', command, ...args], options);
    } catch (error) {
      if (error.code === 'COMMAND_FAILED' && sudoRequiresInteractiveAuthorization(error)) {
        throw targetError('REMOTE_SUDO_REQUIRED', 'The remote validator target must allow scoped non-interactive sudo for secure-network setup.');
      }
      throw error;
    }
  }

  async writeFile(remotePath, content, mode = '0600') {
    if (!remotePath.startsWith('/') || remotePath.includes('\u0000')) {
      throw targetError('REMOTE_PATH_INVALID', 'A valid absolute remote path is required.');
    }
    const temporary = `${remotePath}.${crypto.randomUUID()}.tmp`;
    const command = [
      'umask 077',
      `mkdir -p -- ${shellQuote(path.posix.dirname(remotePath))}`,
      `cat > ${shellQuote(temporary)}`,
      `chmod ${shellQuote(mode)} ${shellQuote(temporary)}`,
      `mv -f -- ${shellQuote(temporary)} ${shellQuote(remotePath)}`,
    ].join('; ');
    try {
      await this.run('sh', ['-lc', command], { input: content });
    } catch (error) {
      await this.removeFile(temporary).catch(() => {});
      throw error;
    }
  }

  async readFile(remotePath) {
    if (!remotePath.startsWith('/') || remotePath.includes('\u0000')) {
      throw targetError('REMOTE_PATH_INVALID', 'A valid absolute remote path is required.');
    }
    return (await this.run('cat', ['--', remotePath])).stdout;
  }

  async removeFile(remotePath) { await this.run('rm', ['-f', '--', remotePath]); }
}

class TargetRegistry {
  constructor(userDataPath) {
    this.directory = path.join(userDataPath, 'onboarding');
    this.targetsPath = path.join(this.directory, 'targets.json');
    this.controlDirectory = path.join(this.directory, 'ssh');
  }

  async resolveRemotePlatform(executor) {
    const [operatingSystem, architecture] = await Promise.all([
      executor.run('uname', ['-s']),
      executor.run('uname', ['-m']),
    ]);
    const osName = operatingSystem.stdout.trim().toLowerCase();
    const archName = architecture.stdout.trim().toLowerCase();
    if (osName !== 'linux') {
      throw targetError('REMOTE_PLATFORM_UNSUPPORTED', 'Remote validator onboarding currently supports Linux SSH targets.', { os: osName, architecture: archName });
    }
    if (['x86_64', 'amd64'].includes(archName)) return 'linux-amd64';
    if (['aarch64', 'arm64'].includes(archName)) return 'linux-arm64';
    throw targetError('REMOTE_PLATFORM_UNSUPPORTED', 'The remote validator CPU architecture is not supported by this release.', { os: osName, architecture: archName });
  }

  async resolveControlSidecar(platform) {
    const fileName = `synergy-control-${platform}`;
    const candidates = [
      process.resourcesPath && path.join(process.resourcesPath, 'binaries', fileName),
      path.join(path.resolve(__dirname, '..', '..'), 'binaries', fileName),
    ].filter(Boolean);
    for (const candidate of candidates) {
      try {
        const stat = await fs.stat(candidate);
        if (stat.isFile()) return candidate;
      } catch (error) {
        if (error?.code !== 'ENOENT') throw error;
      }
    }
    throw targetError(
      'REMOTE_RUNTIME_NOT_BUNDLED',
      `This build does not include the signed ${fileName} remote onboarding runtime. Use an official build that bundles this platform sidecar.`,
      { platform },
    );
  }

  async ensureRemoteControlRuntime(executor) {
    const platform = await this.resolveRemotePlatform(executor);
    const localPath = await this.resolveControlSidecar(platform);
    const binary = await fs.readFile(localPath);
    const digest = crypto.createHash('sha256').update(binary).digest('hex');
    const home = (await executor.run('sh', ['-lc', 'printf %s "$HOME"'])).stdout.trim();
    if (!path.posix.isAbsolute(home)) {
      throw targetError('REMOTE_HOME_INVALID', 'The remote SSH account did not return an absolute home directory.');
    }
    const remoteDirectory = path.posix.join(home, '.local', 'lib', 'synergy-ncp');
    const remotePath = path.posix.join(remoteDirectory, `synergy-control-${digest.slice(0, 24)}`);
    await executor.run('mkdir', ['-p', '--', remoteDirectory]);
    const remoteHash = (await executor.run('sh', ['-lc', [
      `if test -f ${shellQuote(remotePath)}; then`,
      `  (sha256sum -- ${shellQuote(remotePath)} 2>/dev/null || shasum -a 256 -- ${shellQuote(remotePath)}) | awk '{print $1}';`,
      'fi',
    ].join(' ')])).stdout.trim().toLowerCase();
    if (remoteHash !== digest) {
      await executor.writeFile(remotePath, binary, '0700');
    }
    const verifiedHash = (await executor.run('sh', ['-lc', `(
      sha256sum -- ${shellQuote(remotePath)} 2>/dev/null || shasum -a 256 -- ${shellQuote(remotePath)}
    ) | awk '{print $1}'`])).stdout.trim().toLowerCase();
    if (verifiedHash !== digest) {
      throw targetError('REMOTE_RUNTIME_CHECKSUM_FAILED', 'The remote onboarding runtime checksum did not match the packaged signed sidecar.');
    }
    return remotePath;
  }

  async runRemoteControl(input, command, payload = undefined, { timeoutMs = 30 * 60_000 } = {}) {
    return this.withExecutor(input, async (executor, target) => {
      if (target.mode !== 'remote') {
        throw targetError('REMOTE_TARGET_REQUIRED', 'This operation must run on a selected remote validator target.');
      }
      const runtimePath = await this.ensureRemoteControlRuntime(executor);
      const home = (await executor.run('sh', ['-lc', 'printf %s "$HOME"'])).stdout.trim();
      const requestPath = payload === undefined
        ? null
        : path.posix.join(home, '.cache', 'synergy-ncp', `onboarding-${crypto.randomUUID()}.json`);
      try {
        if (requestPath) await executor.writeFile(requestPath, JSON.stringify(payload), '0600');
        const arguments_ = requestPath ? [command, '--input', requestPath] : [command];
        const innernetPublicKey = String(process.env.SYNERGY_INNERNET_COORDINATOR_PUBLIC_KEY || '').trim();
        const invocation = innernetPublicKey
          ? ['SYNERGY_INNERNET_COORDINATOR_PUBLIC_KEY=' + innernetPublicKey, runtimePath, ...arguments_]
          : [runtimePath, ...arguments_];
        const result = await executor.run(innernetPublicKey ? 'env' : runtimePath,
          innernetPublicKey ? invocation : arguments_, { timeoutMs });
        try {
          return { ...JSON.parse(result.stdout), connection: { connected: true }, remote: true };
        } catch {
          throw targetError('REMOTE_RUNTIME_INVALID_RESPONSE', 'The remote validator runtime returned an invalid response.', {
            command,
            output: result.stdout.slice(-2_000),
          });
        }
      } finally {
        if (requestPath) await executor.removeFile(requestPath).catch(() => {});
      }
    });
  }

  async readTargets() {
    try {
      const parsed = JSON.parse(await fs.readFile(this.targetsPath, 'utf8'));
      return Array.isArray(parsed?.targets) ? parsed.targets : [];
    } catch (error) {
      if (error?.code === 'ENOENT') return [];
      throw targetError('TARGET_STORE_UNREADABLE', 'Saved remote targets could not be read.');
    }
  }

  async writeTargets(targets) {
    await fs.mkdir(this.directory, { recursive: true, mode: 0o700 });
    const temporary = `${this.targetsPath}.${process.pid}.${Date.now()}.tmp`;
    await fs.writeFile(temporary, JSON.stringify({ version: 1, targets }, null, 2), { mode: 0o600 });
    await fs.rename(temporary, this.targetsPath);
  }

  async list() {
    const remoteTargets = await this.readTargets();
    return [{ id: 'local', label: 'This computer', mode: 'local', host: null, port: null, username: null, connectionStatus: 'unknown' },
      ...remoteTargets.map(({ managedKey, existingKeyPath, ...target }) => ({ ...target, connectionStatus: target.lastConnectedAt ? 'verified' : 'unknown' }))];
  }

  async add(input = {}) {
    const remote = validateRemoteTarget(input);
    const authMethod = normaliseAuthMethod(input.authMethod);
    const targetId = `ssh-${crypto.randomUUID()}`;
    const target = {
      id: targetId,
      mode: 'remote',
      label: String(input.label || remote.host).trim() || remote.host,
      ...remote,
      authMethod,
      createdAt: new Date().toISOString(),
      lastConnectedAt: null,
    };
    let bootstrapInstalled = false;
    if (authMethod === 'existing_key') {
      const existingKeyPath = String(input.identityFile || input.existingKeyPath || '').trim();
      if (!path.isAbsolute(existingKeyPath)) throw targetError('SSH_KEY_PATH_REQUIRED', 'Choose an existing absolute SSH private-key path.');
      const keyStat = await fs.stat(existingKeyPath).catch(() => null);
      if (!keyStat?.isFile()) throw targetError('SSH_KEY_PATH_INVALID', 'The selected SSH private-key file does not exist.');
      target.existingKeyPath = existingKeyPath;
    } else {
      const managed = await createManagedKey(this.controlDirectory, targetId);
      target.managedKey = storeSecret(managed.privateKey, input.keyStoragePassphrase);
      target.publicKey = managed.publicKey;
      if (authMethod === 'temporary_password') {
        await bootstrapManagedKeyWithTemporaryPassword(
          target,
          this.controlDirectory,
          managed.publicKey,
          String(input.temporaryPassword || input.oneTimePassword || input.password || ''),
        );
        target.authMethod = 'ncp_managed_key';
        target.bootstrapMethod = 'temporary_password';
        bootstrapInstalled = true;
      }
    }
    const targets = await this.readTargets();
    targets.push(target);
    await this.writeTargets(targets);
    return { target, publicKeyToInstall: bootstrapInstalled ? null : target.publicKey || null, bootstrapInstalled };
  }

  async find(targetId) {
    if (!targetId || targetId === 'local') return { id: 'local', mode: 'local' };
    const target = (await this.readTargets()).find((candidate) => candidate.id === targetId);
    if (!target) throw targetError('TARGET_NOT_FOUND', 'The selected validator target is no longer available.');
    return target;
  }

  async withExecutor(input, callback) {
    const target = await this.find(String(input?.targetId || input?.target?.id || 'local'));
    if (target.mode === 'local') return callback(new LocalExecutor(), target);
    let temporaryKeyPath = null;
    try {
      let identityFile = target.existingKeyPath || null;
      if (target.managedKey) {
        const privateKey = loadSecret(target.managedKey, input?.keyStoragePassphrase);
        const keyDirectory = await fs.mkdtemp(path.join(os.tmpdir(), 'synergy-ncp-ssh-'));
        temporaryKeyPath = path.join(keyDirectory, 'id_ed25519');
        await fs.writeFile(temporaryKeyPath, privateKey, { mode: 0o600 });
        identityFile = temporaryKeyPath;
      }
      const controlStem = crypto.createHash('sha256').update(target.id).digest('hex').slice(0, 24);
      const executor = new RemoteExecutor(
        target,
        path.join(this.controlDirectory, `${controlStem}.sock`),
        path.join(this.controlDirectory, 'known_hosts'),
        identityFile,
      );
      const result = await callback(executor, target);
      if (result?.connected || result?.connection?.connected) {
        const targets = await this.readTargets();
        const index = targets.findIndex((candidate) => candidate.id === target.id);
        if (index >= 0) {
          targets[index] = { ...targets[index], lastConnectedAt: new Date().toISOString() };
          await this.writeTargets(targets);
        }
      }
      return result;
    } finally {
      if (temporaryKeyPath) await fs.rm(path.dirname(temporaryKeyPath), { recursive: true, force: true });
    }
  }
}

module.exports = {
  RemoteExecutor,
  TargetRegistry,
  macosAuthorizationArguments,
  sudoRequiresInteractiveAuthorization,
  targetError,
};
