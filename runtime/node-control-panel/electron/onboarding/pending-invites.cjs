const fs = require('fs/promises');
const path = require('path');
const { safeStorage } = require('electron');

const REDEEMED_INVITE_RECOVERY_GRACE_MS = 7 * 24 * 60 * 60 * 1_000;

function isPendingInviteRecoverable(invite, now = Date.now()) {
  const expiresAt = Date.parse(String(invite?.expiresAt || ''));
  return Number.isFinite(expiresAt)
    && expiresAt + REDEEMED_INVITE_RECOVERY_GRACE_MS > now;
}

class PendingInviteStore {
  constructor(userDataPath, storage = safeStorage) {
    this.storage = storage;
    this.filePath = path.join(userDataPath, 'onboarding', 'pending-innernet-invites.bin');
  }

  isAvailable() {
    return this.storage?.isEncryptionAvailable?.() === true;
  }

  async load() {
    if (!this.isAvailable()) return new Map();
    let encrypted;
    try {
      encrypted = await fs.readFile(this.filePath);
    } catch (error) {
      if (error?.code === 'ENOENT') return new Map();
      throw error;
    }
    try {
      const records = JSON.parse(this.storage.decryptString(encrypted));
      const now = Date.now();
      return new Map((Array.isArray(records) ? records : []).filter(([targetId, invite]) => {
        const recoverablePreconfiguredInvite = invite?.preconfigured === true
          && typeof invite?.enrollmentId === 'string' && invite.enrollmentId.length > 0
          && typeof invite?.confirmationToken === 'string' && invite.confirmationToken.length > 0
          && typeof invite?.activationToken === 'string' && invite.activationToken.length > 0;
        return typeof targetId === 'string'
          && ((typeof invite?.invite === 'string' && invite.invite.length > 0)
            || invite?.resumeExisting === true
            || recoverablePreconfiguredInvite)
          && isPendingInviteRecoverable(invite, now);
      }));
    } catch {
      await fs.rm(this.filePath, { force: true });
      return new Map();
    }
  }

  async save(invites) {
    if (!this.isAvailable()) return;
    if (!(invites instanceof Map) || invites.size === 0) {
      await fs.rm(this.filePath, { force: true });
      return;
    }
    const directory = path.dirname(this.filePath);
    await fs.mkdir(directory, { recursive: true, mode: 0o700 });
    const temporary = `${this.filePath}.${process.pid}.tmp`;
    try {
      const encrypted = this.storage.encryptString(JSON.stringify([...invites.entries()]));
      await fs.writeFile(temporary, encrypted, { mode: 0o600 });
      await fs.rename(temporary, this.filePath);
    } finally {
      await fs.rm(temporary, { force: true });
    }
  }
}

module.exports = {
  PendingInviteStore,
  REDEEMED_INVITE_RECOVERY_GRACE_MS,
  isPendingInviteRecoverable,
};
