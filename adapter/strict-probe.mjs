/** Synthetic compatibility probe; not a mailbox database adapter. */
import {spawn} from 'node:child_process';
import {fileURLToPath} from 'node:url';

const worker = fileURLToPath(new URL('./strict-worker.cjs', import.meta.url));
const workdir = fileURLToPath(new URL('./', import.meta.url));
const unavailable = () => new Error('strict_probe_unavailable');

/** The caller supplies an exact trusted host, not an arbitrary DNS suffix.
 * Credentials flow only through a pipe to an isolated process; never put them
 * into argv, environment, logs, or the response. This fixed-query probe is for
 * controlled synthetic tests only and is not an application query API.
 */
export function probeStrictConnection(uri, trustedHost) {
  if (typeof uri !== 'string' || uri.length > 8192 || typeof trustedHost !== 'string' || trustedHost.length > 253 ||
      !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/.test(trustedHost)) {
    return Promise.reject(unavailable());
  }
  return new Promise((resolve, reject) => {
    let child;
    try {
      // No inherited PG*, Node, native-loader, OpenSSL or CA overrides.
      child = spawn(process.execPath, [worker], {
        cwd: workdir, env: {PATH: '/usr/bin:/bin', LANG: 'C'},
        stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true,
      });
    } catch { reject(unavailable()); return; }
    let output = '', done = false;
    const finish = (ok) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      if (ok) resolve(true); else reject(unavailable());
    };
    const timer = setTimeout(() => { child.kill('SIGKILL'); finish(false); }, 10000);
    child.on('error', () => finish(false));
    child.stdin.on('error', () => finish(false));
    child.stdout.on('error', () => finish(false));
    child.stderr.on('error', () => finish(false));
    child.stderr.resume(); // Never surface native error or diagnostic text.
    child.stdout.on('data', chunk => {
      output += chunk.toString('utf8');
      if (output.length > 64) { child.kill('SIGKILL'); finish(false); }
    });
    child.on('close', code => finish(code === 0 && output === '{"ok":true}\n'));
    child.stdin.end(JSON.stringify({uri, trustedHost}));
  });
}
