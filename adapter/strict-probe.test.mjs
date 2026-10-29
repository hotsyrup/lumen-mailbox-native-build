import {test} from 'node:test';
import assert from 'node:assert/strict';
import {mkdtemp, mkdir, readFile, copyFile, writeFile, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {pathToFileURL} from 'node:url';

// Fake addon only. It proves process and error plumbing, not libpq or TLS.
async function isolated(t) {
  const dir = await mkdtemp(join(tmpdir(), 'strict-probe-synthetic-'));
  t.after(() => rm(dir, {recursive: true, force: true}));
  const moddir = join(dir, 'node_modules', 'pg-native');
  await mkdir(moddir, {recursive: true});
  for (const name of ['strict-probe.mjs', 'strict-worker.cjs'])
    await copyFile(new URL('./' + name, import.meta.url), join(dir, name));
  const capture = join(dir, 'observed.json');
  const fake = `const {EventEmitter}=require('node:events'); const fs=require('node:fs');
    module.exports=class extends EventEmitter {
      connectSync(uri){const u=new URL(uri); this.pass=u.password;
        fs.writeFileSync(${JSON.stringify(capture)},JSON.stringify({env:Object.keys(process.env).sort(),
          host:u.hostname,ssl:u.searchParams.get('sslmode'),binding:u.searchParams.get('channel_binding'),
          root:u.searchParams.get('sslrootcert'),gss:u.searchParams.get('gssencmode'),auth:u.searchParams.get('require_auth')}));
        if(this.pass==='failure'){process.stderr.write(uri);throw Error(uri)} }
      querySync(q){if(q!=='SELECT 1 AS value') throw Error('unexpected query');
        if(this.pass==='asyncfail') this.emit('error',Error('synthetic-secret')); return [{value:1}];}
      end(){} }`;
  await writeFile(join(moddir, 'index.js'), fake);
  const {probeStrictConnection} = await import(pathToFileURL(join(dir, 'strict-probe.mjs')).href);
  return {probeStrictConnection, capture};
}

const host = 'database.example.invalid';
const uri = `postgresql://synthetic:synthetic@${host}/fixture?sslmode=require&channel_binding=require`;
const error = /^Error: strict_probe_unavailable$/;

test('isolated worker sanitizes inherited environment and enforces strict options', async t => {
  const {probeStrictConnection, capture} = await isolated(t);
  const names = ['PGHOST', 'PGOPTIONS', 'SSL_CERT_FILE', 'OPENSSL_CONF', 'NODE_OPTIONS', 'LD_PRELOAD'];
  const saved = Object.fromEntries(names.map(k => [k, process.env[k]]));
  try {
    for (const name of names) process.env[name] = 'synthetic-untrusted';
    assert.equal(await probeStrictConnection(uri, host), true);
    const seen = JSON.parse(await readFile(capture, 'utf8'));
    assert.deepEqual(seen.env, ['LANG', 'PATH']);
    assert.deepEqual({host:seen.host, ssl:seen.ssl, binding:seen.binding, root:seen.root, gss:seen.gss, auth:seen.auth},
      {host, ssl:'verify-full', binding:'require', root:'system', gss:'disable', auth:'scram-sha-256'});
  } finally {
    for (const name of names) if (saved[name] === undefined) delete process.env[name]; else process.env[name] = saved[name];
  }
});

test('malformed or downgrade URLs fail before the fake addon loads', async t => {
  const {probeStrictConnection, capture} = await isolated(t);
  for (const bad of [uri.replace(host, `evil.example,${host}`), uri.replace(host, `evil.example%2C${host}`),
    uri.replace('synthetic:synthetic@', `synthetic:synthetic@evil.example,${host}@`),
    uri.replace('channel_binding=require', 'channel_binding=prefer'), uri + '&hostaddr=127.0.0.1',
    uri.replace(host, 'wrong.example.invalid')]) await assert.rejects(probeStrictConnection(bad, host), error);
  await assert.rejects(readFile(capture), {code:'ENOENT'});
});

test('synchronous and asynchronous driver errors are sanitized', async t => {
  const {probeStrictConnection} = await isolated(t);
  for (const password of ['failure', 'asyncfail']) {
    await assert.rejects(probeStrictConnection(uri.replace(':synthetic@', `:${password}@`), host), error);
  }
});

test('driver absence is a fixed failure', async t => {
  const dir = await mkdtemp(join(tmpdir(), 'strict-probe-no-addon-'));
  t.after(() => rm(dir, {recursive: true, force: true}));
  for (const name of ['strict-probe.mjs', 'strict-worker.cjs'])
    await copyFile(new URL('./' + name, import.meta.url), join(dir, name));
  const {probeStrictConnection} = await import(pathToFileURL(join(dir, 'strict-probe.mjs')).href);
  await assert.rejects(probeStrictConnection(uri, host), error);
});
