'use strict';
// Test-only process: only loopback + fixed synthetic identity/password.
// Never print the conninfo or exceptions, and never accept a real credential.
const fs = require('node:fs');
let Native;
try {
  if (Number(process.versions.node.split('.')[0]) !== 24) throw Error();
  Native = require(process.env.STRICT_BINDING_ADDON || 'pg-native');
  if (typeof Native !== 'function') throw Error();
} catch {
  process.stdout.write('addon_unavailable\n');
  process.exit(2);
}
if (process.argv[2] === '--probe') {
  process.stdout.write('addon_loaded\n');
  process.exit(0);
}
let input;
try {
  input = JSON.parse(fs.readFileSync(0, 'utf8'));
  if (!input || !Number.isInteger(input.port) || input.port < 1 || input.port > 65535 ||
      !['localhost', '127.0.0.1'].includes(input.hostname) || typeof input.ca !== 'string' ||
      !input.ca.startsWith('/') || /['\\\n\r\0]/.test(input.ca)) throw Error();
} catch {
  process.stdout.write('fixture_input_invalid\n');
  process.exit(3);
}
for (const key of Object.keys(process.env)) if (key.startsWith('PG')) delete process.env[key];
const info = `host=${input.hostname} hostaddr=127.0.0.1 port=${input.port} dbname=fixture ` +
  `user=fixture-user password=fixture-password sslmode=verify-full sslrootcert='${input.ca}' ` +
  'channel_binding=require require_auth=scram-sha-256 gssencmode=disable sslcertmode=disable connect_timeout=3';
const client = new Native();
let connected = false;
try {
  client.connectSync(info);
  connected = true;
  const rows = client.querySync('SELECT 1');
  if (!Array.isArray(rows) || rows.length !== 1 || String(rows[0]?.fixture) !== '1') throw Error();
  process.stdout.write('connected\n');
} catch {
  if (connected) {
    process.stdout.write('query_failed\n');
    process.exitCode = 4;
  } else process.stdout.write('rejected\n');
} finally {
  try { client.end(); } catch {}
}
