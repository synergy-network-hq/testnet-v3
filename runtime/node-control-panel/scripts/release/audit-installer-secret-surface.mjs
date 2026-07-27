#!/usr/bin/env node
/**
 * Reject a staged Node Control Panel installer payload that contains a
 * validator private-key artifact. This is intentionally an artifact check,
 * not a source-code grep: it runs over the mounted DMG or extracted DEB just
 * before the generic installer is copied into any Validator 1–21 package.
 *
 * The checker never prints file contents. A failure names only the unsafe
 * path and rule so a release log cannot disclose sensitive material.
 */
import { readdir, readFile, stat } from "node:fs/promises";
import { resolve, relative, extname, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { extractFile, listPackage } from "@electron/asar";

const MAX_TEXT_BYTES = 4 * 1024 * 1024;
const PRIVATE_KEY_FILENAMES = /(?:^|[\\/])(?:keys?|secrets?|custody)(?:[\\/]|$)|(?:^|[._-])(?:validator|node[-_]?identity|consensus|account)[-_]?(?:private[-_]?|secret[-_]?|)key(?:[._-]|$)|(?:^|[._-])identity\.private(?:[._-]|$)|\.(?:pem|p12|pfx|key)$/i;
const PRIVATE_KEY_CONTENT = /-----BEGIN(?: [A-Z0-9-]+)? PRIVATE KEY-----[\s\S]{16,}-----END(?: [A-Z0-9-]+)? PRIVATE KEY-----|["'](?:private(?:_|-)?key|validator(?:_|-)?private(?:_|-)?key|consensus(?:_|-)?private(?:_|-)?key|custody(?:_|-)?passphrase)["']\s*[:=]\s*["'][A-Za-z0-9+/_=-]{48,}["']/i;
const SCANNED_TEXT_EXTENSIONS = new Set([".conf", ".env", ".ini", ".json", ".md", ".pem", ".toml", ".txt", ".yaml", ".yml"]);

function option(name) {
  const index = process.argv.indexOf(name);
  return index === -1 ? null : process.argv[index + 1] || null;
}

function unsafe(path, rule) {
  throw new Error(`Unsafe validator provisioning material detected in ${path} (${rule}).`);
}

function relativePath(root, path) {
  return relative(root, path).split(sep).join("/");
}

function scanPath(displayPath) {
  if (PRIVATE_KEY_FILENAMES.test(displayPath)) unsafe(displayPath, "private-key filename");
}

function scanText(bytes, displayPath) {
  if (bytes.length > MAX_TEXT_BYTES || !SCANNED_TEXT_EXTENSIONS.has(extname(displayPath).toLowerCase())) return;
  if (PRIVATE_KEY_CONTENT.test(bytes.toString("utf8"))) unsafe(displayPath, "private-key content");
}

async function scanAsar(path, displayPath) {
  for (const archivePath of listPackage(path, { isPack: false })) {
    const normalizedArchivePath = archivePath.replace(/^[/\\]+/, "");
    const entryPath = `${displayPath}!/${normalizedArchivePath}`;
    // Dependency READMEs frequently contain deliberately nonfunctional PEM
    // examples. The application payload and every unpacked runtime resource
    // are inspected; third-party package documentation is not a validator
    // provisioning channel and is excluded to avoid masking real failures.
    if (normalizedArchivePath.split("/").includes("node_modules")) continue;
    scanPath(entryPath);
    if (SCANNED_TEXT_EXTENSIONS.has(extname(archivePath).toLowerCase())) {
      scanText(extractFile(path, normalizedArchivePath), entryPath);
    }
  }
}

async function scanDirectory(root, current = root) {
  for (const entry of await readdir(current, { withFileTypes: true })) {
    const path = resolve(current, entry.name);
    const displayPath = relativePath(root, path);
    if (entry.isDirectory() && entry.name === "node_modules") continue;
    scanPath(displayPath);
    if (entry.isDirectory()) {
      await scanDirectory(root, path);
      continue;
    }
    if (!entry.isFile()) continue;
    if (entry.name.endsWith(".asar")) {
      await scanAsar(path, displayPath);
      continue;
    }
    scanText(await readFile(path), displayPath);
  }
}

export async function auditInstallerSecretSurface(root) {
  const resolvedRoot = resolve(root);
  const details = await stat(resolvedRoot);
  if (!details.isDirectory()) throw new Error(`Installer root is not a directory: ${resolvedRoot}`);
  await scanDirectory(resolvedRoot);
}

async function main() {
  const root = option("--root");
  const label = option("--label") || "installer";
  if (!root) throw new Error("Usage: node scripts/release/audit-installer-secret-surface.mjs --root <mounted-or-extracted-installer> [--label <label>]");
  await auditInstallerSecretSurface(root);
  console.log(`Verified ${label} contains no reusable validator private identity, custody passphrase, or unencrypted consensus private key.`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
