import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const controlServicePath = path.resolve(
  scriptDirectory,
  '../../control-service/src/control_service.rs',
);
const source = fs.readFileSync(controlServicePath, 'utf8');

assert.match(
  source,
  /\.route\(\s*"\/v1\/mesh\/transports\/current"\s*,\s*get\(mesh_transport_snapshot_current_handler\)\s*,?\s*\)/s,
  'the public current transport route must be registered as GET',
);

const handler = source.match(
  /async fn mesh_transport_snapshot_current_handler[\s\S]*?\n}\n\nasync fn mesh_transport_snapshot_refresh_handler/,
)?.[0];
assert.ok(handler, 'the public current transport handler must exist');
assert.match(
  handler,
  /innernet::public_validator_transport_snapshot\(\s*&state\.app_context,?\s*\)/s,
  'the public route must use the released coordinator-signed snapshot provider',
);
assert.match(handler, /public_transport_snapshot_response\(/);
assert.match(handler, /StatusCode::OK, Json\(payload\)/);
assert.match(
  handler,
  /StatusCode::SERVICE_UNAVAILABLE/s,
  'snapshot failures must not expose unsigned or secret state',
);
assert.match(
  handler,
  /testnet_v3_transport_release_not_published/,
  'a pre-release public request must receive a bounded, non-secret refusal',
);
assert.doesNotMatch(
  handler,
  /authorize_|X-Synergy-Innernet|X-Admin-Key|AUTHORIZATION/,
  'the public route must not require or inspect a secret/authentication token',
);
assert.doesNotMatch(
  handler,
  /mesh_status|validator_vpn_error/,
  'the public route must not return unsigned mesh or diagnostic state',
);

console.log(`control-service mesh transport current QA passed: ${controlServicePath}`);
