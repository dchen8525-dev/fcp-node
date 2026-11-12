// Acceptance gate: two independent CLI processes must complete a real UDP
// handshake and carry traffic. Delegates to scripts/self-interop.mjs so the
// exact same probe can be run standalone by a human.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');

test('self-interop: Node server <-> Node client over real UDP sockets', () => {
  const r = spawnSync(process.execPath, ['scripts/self-interop.mjs', '--json'], {
    cwd: root, encoding: 'utf8', timeout: 90000,
  });
  const out = (r.stdout ?? '').trim().split('\n').pop() ?? '';
  let report;
  try { report = JSON.parse(out); } catch {
    assert.fail(`self-interop produced no JSON report\nstdout: ${r.stdout}\nstderr: ${r.stderr}`);
  }
  assert.equal(r.status, 0, `self-interop exit=${r.status}: ${JSON.stringify(report.results)}`);
  assert.equal(report.failed, 0, JSON.stringify(report.results.filter((x) => !x.ok)));
  assert.ok(report.passed >= 7, `expected at least 7 checks, got ${report.passed}`);

  const byName = Object.fromEntries(report.results.map((x) => [x.name, x]));
  assert.ok(/both sides logged/.test(byName['handshake (2 processes, real UDP)'].detail),
    'handshake must be evidenced by the FCP established log on BOTH processes');
  for (const n of ['SOCKS5', 'HTTP CONNECT', 'absolute-form HTTP', '320 KiB payload']) {
    assert.equal(byName[n].ok, true, `${n}: ${byName[n].detail}`);
  }
  assert.ok(/local-entry=true/.test(byName['wrong PSK rejected'].detail),
    'the wrong-PSK probe must actually reach the local proxy, not just fail to connect');
});
