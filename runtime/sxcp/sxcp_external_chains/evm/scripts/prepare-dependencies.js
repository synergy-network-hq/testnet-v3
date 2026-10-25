import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";

const root = fileURLToPath(new URL("../", import.meta.url));
const patches = JSON.parse(fs.readFileSync(path.join(root, "patches/zod4-compat.json"), "utf8"));
const hash = (text) => createHash("sha256").update(text).digest("hex");

for (const patch of patches) {
  const packageRoot = path.join(root, "node_modules", patch.package);
  const installed = JSON.parse(fs.readFileSync(path.join(packageRoot, "package.json"), "utf8"));
  if (installed.version !== patch.version) {
    throw new Error(`Review the Zod 4 compatibility patch before updating ${patch.package}`);
  }
  const target = path.join(packageRoot, patch.file);
  let text = fs.readFileSync(target, "utf8");
  if (hash(text) === patch.patchedSha256) continue;
  if (hash(text) !== patch.sha256) {
    throw new Error(`Unexpected dependency contents: ${patch.package}/${patch.file}`);
  }
  for (const { before, after, count } of patch.replacements) {
    if (text.split(before).length - 1 !== count) {
      throw new Error(`Compatibility patch context changed: ${patch.package}/${patch.file}`);
    }
    text = text.split(before).join(after);
  }
  if (hash(text) !== patch.patchedSha256) {
    throw new Error(`Compatibility patch checksum mismatch: ${patch.package}/${patch.file}`);
  }
  fs.writeFileSync(target, text);
  console.log(`Applied Zod 4 compatibility: ${patch.package}/${patch.file}`);
}
