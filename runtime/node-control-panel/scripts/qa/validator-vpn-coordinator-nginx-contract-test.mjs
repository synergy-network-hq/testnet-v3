import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDirectory = path.dirname(fileURLToPath(import.meta.url));
const configPath = path.resolve(
  scriptDirectory,
  '../../deploy/validator-vpn-coordinator/nginx-vpn-coordinator.conf.example',
);
const config = fs.readFileSync(configPath, 'utf8');

const locations = [...config.matchAll(/^\s*location\s+(=\s+)?([^\s{]+)\s*\{/gm)];
const meshLocations = locations
  .map(([, exact, route]) => ({ exact: Boolean(exact), route }))
  .filter(({ route }) => route.startsWith('/v1/mesh'));

assert.ok(
  meshLocations.some(
    ({ exact, route }) => exact && route === '/v1/mesh/transports/current',
  ),
  'current transport endpoint must be exposed as an exact-match location',
);
assert.ok(
  meshLocations.every(({ exact }) => exact),
  'mesh endpoints must not be exposed through a broader prefix location',
);

const currentLocation = config.match(
  /location = \/v1\/mesh\/transports\/current\s*\{([\s\S]*?)\n\s*\}/,
)?.[1];
assert.ok(currentLocation, 'current transport location must have a complete block');
assert.match(
  currentLocation,
  /limit_except GET \{\s*deny all;\s*\}/,
  'current transport endpoint must fail closed for non-GET methods',
);
assert.match(
  currentLocation,
  /proxy_pass http:\/\/127\.0\.0\.1:47895\/v1\/mesh\/transports\/current;/,
  'current transport endpoint must proxy to the exact coordinator path',
);
assert.match(
  currentLocation,
  /include proxy_params;/,
  'current transport endpoint must use the existing proxy parameters',
);

for (const route of ['/v1/mesh/confirm', '/v1/mesh/status', '/v1/mesh/transports', '/v1/mesh/transports/refresh']) {
  assert.match(
    config,
    new RegExp(`location = ${route.replaceAll('/', '\\/')} \\{`),
    `${route} must remain an exact-match location`,
  );
}

console.log(`validator VPN coordinator Nginx contract QA passed: ${configPath}`);
