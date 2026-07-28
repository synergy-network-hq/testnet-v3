const crypto = require('crypto');
const fs = require('fs/promises');
const fsSync = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');

const PACKAGE_FILE_NAMES = Object.freeze([
  'assignment.json',
  'identity.enc.json',
  'identity.pub.json',
  'manifest.json',
  'wireguard-private.key',
  'wireguard-public.key',
  'sy-vpn.conf',
  'vpn-binding.json',
]);

function packageError(code, message) {
  const error = new Error(message);
  error.code = code;
  return error;
}

function validatorPackageRoot() {
  const explicit = String(process.env.SYNERGY_VALIDATOR_PACKAGE_DIR || '').trim();
  if (explicit) return path.resolve(explicit);
  const packaged = process.resourcesPath
    ? path.join(process.resourcesPath, 'validator-package')
    : null;
  if (packaged && fsSync.existsSync(path.join(packaged, 'assignment.json'))) return packaged;
  return path.resolve(__dirname, '..', '..', 'build', 'validator-package');
}

async function sha256(filePath) {
  const bytes = await fs.readFile(filePath);
  return crypto.createHash('sha256').update(bytes).digest('hex');
}

async function readJson(filePath, label) {
  try {
    return JSON.parse(await fs.readFile(filePath, 'utf8'));
  } catch {
    throw packageError('VALIDATOR_PACKAGE_INVALID', `${label} is missing or invalid.`);
  }
}

function assertValidatorAssignment(assignment) {
  const assignmentId = String(assignment?.assignmentId || '').trim();
  const validator = Number(assignment?.validator);
  const address = String(assignment?.validatorAddress || '').trim();
  if (
    !/^validator-(?:0[1-9]|1[0-9]|2[0-1])$/.test(assignmentId)
    || !Number.isInteger(validator)
    || validator < 1
    || validator > 21
    || assignmentId !== `validator-${String(validator).padStart(2, '0')}`
    || !/^synv1[0-9a-z]+$/.test(address)
  ) {
    throw packageError('VALIDATOR_PACKAGE_INVALID', 'The packaged validator assignment is invalid.');
  }
}

async function loadValidatorPackage({ includeSecrets = false } = {}) {
  const root = validatorPackageRoot();
  const assignmentPath = path.join(root, 'assignment.json');
  try {
    await fs.access(assignmentPath);
  } catch {
    return { available: false };
  }

  const assignment = await readJson(assignmentPath, 'Validator assignment');
  assertValidatorAssignment(assignment);
  const expectedChecksums = assignment?.checksums;
  if (!expectedChecksums || typeof expectedChecksums !== 'object') {
    throw packageError('VALIDATOR_PACKAGE_INVALID', 'The validator package checksum manifest is missing.');
  }
  for (const fileName of PACKAGE_FILE_NAMES.filter((name) => name !== 'assignment.json')) {
    const expected = String(expectedChecksums[fileName] || '').trim().toLowerCase();
    if (!/^[a-f0-9]{64}$/.test(expected)) {
      throw packageError('VALIDATOR_PACKAGE_INVALID', `The checksum for ${fileName} is missing.`);
    }
    if (await sha256(path.join(root, fileName)) !== expected) {
      throw packageError('VALIDATOR_PACKAGE_CHECKSUM_FAILED', `${fileName} does not match its signed build assignment.`);
    }
  }

  const [identityPublic, identityManifest, vpnBinding] = await Promise.all([
    readJson(path.join(root, 'identity.pub.json'), 'Validator public identity'),
    readJson(path.join(root, 'manifest.json'), 'Validator identity manifest'),
    readJson(path.join(root, 'vpn-binding.json'), 'Validator VPN binding'),
  ]);
  const expectedAddress = assignment.validatorAddress;
  if (
    identityPublic.address !== expectedAddress
    || identityManifest.address !== expectedAddress
    || vpnBinding?.node_identity?.synv_address !== expectedAddress
    || Number(vpnBinding.chain_id) !== 1266
    || vpnBinding.network_id !== 'synergy-testnet-v3'
    || Number(vpnBinding.index) !== Number(assignment.validator)
  ) {
    throw packageError('VALIDATOR_PACKAGE_BINDING_FAILED', 'The identity and VPN files are not bound to the same Testnet-v3 validator assignment.');
  }

  const publicPackage = {
    available: true,
    assignmentId: assignment.assignmentId,
    validator: assignment.validator,
    validatorLabel: assignment.validatorLabel,
    validatorAddress: expectedAddress,
    validatorPublicKey: identityPublic.public_key,
    consensusPublicKey: identityPublic?.consensus_key?.public_key,
    vpnIp: vpnBinding?.route?.vpn_ip,
    wireguardPublicKey: (await fs.readFile(path.join(root, 'wireguard-public.key'), 'utf8')).trim(),
    vpnConfigVersion: vpnBinding.config_version,
    activationStatus: vpnBinding.activation_status,
    cohort: assignment.cohort,
    chainId: 1266,
    networkId: 'synergy-testnet-v3',
  };
  if (!includeSecrets) return publicPackage;
  return {
    ...publicPackage,
    root,
    assignment,
    identityPublic,
    identityManifest,
    vpnBinding,
    encryptedIdentity: await fs.readFile(path.join(root, 'identity.enc.json'), 'utf8'),
    wireguardPrivateKey: (await fs.readFile(path.join(root, 'wireguard-private.key'), 'utf8')).trim(),
    wireguardPublicKey: (await fs.readFile(path.join(root, 'wireguard-public.key'), 'utf8')).trim(),
    wireguardConfig: await fs.readFile(path.join(root, 'sy-vpn.conf'), 'utf8'),
  };
}

function keygenBinaryPath() {
  const explicit = String(process.env.SYNERGY_KEYGEN_BINARY || '').trim();
  if (explicit) return explicit;
  const suffix = process.platform === 'darwin'
    ? `darwin-${process.arch === 'arm64' ? 'arm64' : 'amd64'}`
    : process.platform === 'linux'
      ? `linux-${process.arch === 'arm64' ? 'arm64' : 'amd64'}`
      : '';
  if (!suffix) {
    throw packageError('VALIDATOR_KEYGEN_UNAVAILABLE', 'This platform does not support packaged validator identity installation.');
  }
  const packaged = process.resourcesPath
    ? path.join(process.resourcesPath, 'binaries', `synergy-keygen-${suffix}`)
    : null;
  if (packaged && fsSync.existsSync(packaged)) return packaged;
  return path.resolve(__dirname, '..', '..', 'binaries', `synergy-keygen-${suffix}`);
}

function runKeygenDecrypt(binary, encryptedPath, outputPath, passphrase) {
  return new Promise((resolve, reject) => {
    const child = spawn(binary, ['decrypt', encryptedPath, '--output', outputPath], {
      env: { ...process.env, SYNERGY_DECRYPT_PASSPHRASE: passphrase },
      stdio: ['ignore', 'ignore', 'pipe'],
      windowsHide: true,
    });
    let stderr = '';
    child.stderr.on('data', (chunk) => {
      stderr = `${stderr}${chunk}`.slice(-2_000);
    });
    child.once('error', () => {
      reject(packageError('VALIDATOR_KEYGEN_UNAVAILABLE', 'The packaged identity decryptor is unavailable.'));
    });
    child.once('close', (code) => {
      if (code === 0) resolve();
      else reject(packageError(
        'VALIDATOR_IDENTITY_UNLOCK_FAILED',
        /passphrase|decrypt|authentication/i.test(stderr)
          ? 'The validator identity passphrase was not accepted.'
          : 'The packaged validator identity could not be unlocked.',
      ));
    });
  });
}

async function decryptValidatorPackage(passphrase) {
  if (String(passphrase || '').length < 8) {
    throw packageError('VALIDATOR_PASSPHRASE_REQUIRED', 'Enter the validator identity passphrase.');
  }
  const packageData = await loadValidatorPackage({ includeSecrets: true });
  if (!packageData.available) {
    throw packageError('VALIDATOR_PACKAGE_REQUIRED', 'This is a generic installer and does not contain a validator assignment.');
  }
  const temporaryDirectory = await fs.mkdtemp(path.join(os.tmpdir(), 'synergy-validator-identity-'));
  const decryptedPath = path.join(temporaryDirectory, 'identity.json');
  try {
    await runKeygenDecrypt(
      keygenBinaryPath(),
      path.join(packageData.root, 'identity.enc.json'),
      decryptedPath,
      String(passphrase),
    );
    const decrypted = await readJson(decryptedPath, 'Decrypted validator identity');
    const roles = new Map(
      (Array.isArray(decrypted.keys) ? decrypted.keys : [])
        .map((entry) => [String(entry?.role || ''), entry]),
    );
    for (const role of ['primary', 'consensus', 'node_identity', 'account', 'entropy_contribution']) {
      if (!String(roles.get(role)?.private_key || '').trim()) {
        throw packageError('VALIDATOR_IDENTITY_INVALID', `The packaged validator identity is missing its ${role} key.`);
      }
    }
    if (decrypted.address !== packageData.validatorAddress) {
      throw packageError('VALIDATOR_IDENTITY_INVALID', 'The unlocked identity does not match this installer assignment.');
    }
    return {
      packageData,
      packagedValidatorIdentity: {
        address: packageData.validatorAddress,
        addressType: packageData.identityPublic.address_type,
        algorithm: packageData.identityPublic.algorithm,
        createdAt: packageData.identityPublic.created_at,
        primaryPublicKey: packageData.identityPublic.public_key,
        primaryPrivateKey: roles.get('primary').private_key,
        consensusAlgorithm: packageData.identityPublic.consensus_key.algorithm,
        consensusPublicKey: packageData.identityPublic.consensus_key.public_key,
        consensusPrivateKey: roles.get('consensus').private_key,
        nodeIdentityAlgorithm: packageData.identityPublic.node_identity_key.algorithm,
        nodeIdentityPublicKey: packageData.identityPublic.node_identity_key.public_key,
        nodeIdentityPrivateKey: roles.get('node_identity').private_key,
        accountAlgorithm: packageData.identityPublic.account_key.algorithm,
        accountPublicKey: packageData.identityPublic.account_key.public_key,
        accountPrivateKey: roles.get('account').private_key,
        entropyAlgorithm: packageData.identityPublic.entropy_contribution_key.algorithm,
        entropyPublicKey: packageData.identityPublic.entropy_contribution_key.public_key,
        entropyPrivateKey: roles.get('entropy_contribution').private_key,
        encryptedEnvelope: packageData.encryptedIdentity,
        assignmentId: packageData.assignmentId,
      },
    };
  } finally {
    await fs.rm(temporaryDirectory, { recursive: true, force: true });
  }
}

module.exports = {
  decryptValidatorPackage,
  loadValidatorPackage,
  validatorPackageRoot,
};
