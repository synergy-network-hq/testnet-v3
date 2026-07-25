// Ad-hoc codesign for macOS unsigned builds.
// Signs inside-out: all nested bundles first, then the main app.
const { execSync } = require('child_process');
const path = require('path');
const fs = require('fs');

exports.default = async function afterPack(context) {
  if (context.electronPlatformName !== 'darwin') return;

  const appName = context.packager.appInfo.productFilename;
  const appPath = path.join(context.appOutDir, `${appName}.app`);
  const frameworksDir = path.join(appPath, 'Contents', 'Frameworks');

  console.log(`[afterPack] Ad-hoc signing: ${appPath}`);

  const sign = (target) => {
    console.log(`  signing: ${path.basename(target)}`);
    execSync(
      `codesign --force --sign - --timestamp=none "${target}"`,
      { stdio: 'inherit' }
    );
  };

  // 1. Sign ALL bundles inside Frameworks (.app helpers, .framework libs)
  if (fs.existsSync(frameworksDir)) {
    const entries = fs.readdirSync(frameworksDir);
    for (const entry of entries) {
      const fullPath = path.join(frameworksDir, entry);
      if (entry.endsWith('.app') || entry.endsWith('.framework')) {
        sign(fullPath);
      }
    }
  }

  // 2. Sign the main app bundle last
  sign(appPath);

  // 3. Verify the signature
  console.log('[afterPack] Verifying signature...');
  try {
    execSync(`codesign --verify --deep --strict "${appPath}"`, { stdio: 'inherit' });
    console.log('[afterPack] Signature verification passed');
  } catch (e) {
    console.error('[afterPack] Signature verification FAILED:', e.message);
    process.exit(1);
  }
};
