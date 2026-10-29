'use strict';
// Isolated one-shot child. Its parent supplies a minimal environment and never
// exposes this worker's raw output or driver errors.
const fs = require('node:fs');
// Some platforms add process variables after spawn; discard all except these
// before loading the native library. Spawn itself also omits loader variables.
for (const name of Object.keys(process.env)) if (!['PATH', 'LANG'].includes(name)) delete process.env[name];

let client, driverFailed = false;
try {
  const raw = fs.readFileSync(0, 'utf8');
  if (raw.length > 9000) throw Error();
  const {uri, trustedHost} = JSON.parse(raw);
  if (typeof uri !== 'string' || uri.length > 8192 || /[\u0000-\u0020\u007f]/.test(uri) ||
      typeof trustedHost !== 'string' || trustedHost.length > 253 ||
      !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/.test(trustedHost)) throw Error();
  const authority = /^postgres(?:ql)?:\/\/([^/?#]*)/i.exec(uri)?.[1];
  if (!authority || (authority.match(/@/g) || []).length !== 1) throw Error();
  const u = new URL(uri);
  if (!['postgres:', 'postgresql:'].includes(u.protocol) || !u.username || !u.password || u.hash ||
      u.hostname !== trustedHost || (u.port && u.port !== '5432') || !/^\/[A-Za-z0-9_-]+$/.test(u.pathname)) throw Error();
  for (const k of u.searchParams.keys()) if (!['sslmode', 'channel_binding'].includes(k)) throw Error();
  if (u.searchParams.getAll('sslmode').length > 1 || u.searchParams.getAll('channel_binding').length > 1 ||
      (u.searchParams.has('sslmode') && !['require', 'verify-full'].includes(u.searchParams.get('sslmode'))) ||
      (u.searchParams.has('channel_binding') && u.searchParams.get('channel_binding') !== 'require')) throw Error();
  u.searchParams.set('sslmode', 'verify-full');
  u.searchParams.set('channel_binding', 'require');
  u.searchParams.set('sslrootcert', 'system');
  u.searchParams.set('sslcertmode', 'disable');
  u.searchParams.set('gssencmode', 'disable');
  u.searchParams.set('require_auth', 'scram-sha-256');
  u.searchParams.set('connect_timeout', '5');
  const Native = require('pg-native');
  client = new Native();
  client.on('error', () => { driverFailed = true; process.exitCode = 1; try { client.end(); } catch {} });
  client.connectSync(u.toString());
  const rows = client.querySync('SELECT 1 AS value');
  if (driverFailed || !Array.isArray(rows) || rows.length !== 1 || Number(rows[0]?.value) !== 1) throw Error();
  client.end();
  client = undefined;
  process.stdout.write('{"ok":true}\n');
} catch {
  try { client?.end(); } catch {}
  process.stdout.write('{"ok":false}\n');
  process.exitCode = 1;
}
