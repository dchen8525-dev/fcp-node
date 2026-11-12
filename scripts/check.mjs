// Zero-dependency gate. Verifies every library module loads under Node's
// type stripping, then runs the full test suite (unit + e2e).
// Usage: node scripts/check.mjs
import { mkdtempSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { spawnSync } from 'node:child_process';

const root = resolve(import.meta.dirname, '..');
const walk = (dir, out = []) => {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) walk(p, out);
    else if (p.endsWith('.ts')) out.push(p);
  }
  return out;
};
const all = [...walk(join(root, 'src')), ...walk(join(root, 'tests'))];
const entrypoints = new Set(['server.ts', 'client.ts', 'bench.ts', 'replay.ts', 'cli.ts']);
const isTest = (p) => p.includes('\\tests\\') || p.includes('/tests/');
const libs = all.filter((p) => !isTest(p) && !entrypoints.has(p.split(/[\\/]/).pop()));
const tests = all.filter(isTest);

const results = [];
let failed = 0;

// 1. Every library module must be importable under strip-only type erasure.
const imports = libs.map((p) => `  await import(${JSON.stringify(pathToFileURL(p).href)});`).join('\n');
const imp = spawnSync(process.execPath, ['--input-type=module', '-e', imports], {
  cwd: root, encoding: 'utf8',
});
const importOk = imp.status === 0;
results.push(['module imports', importOk ? 'PASS' : 'FAIL', `${libs.length} modules`]);
if (!importOk) { console.error(imp.stderr); ++failed; }

// 2. Full test suite, including real-socket e2e.
const testArgs = ['--test', ...tests.map((p) => relative(root, p).replace(/\\/g, '/'))];
const t = spawnSync(process.execPath, testArgs, { cwd: root, encoding: 'utf8', timeout: 180000 });
const out = (t.stdout ?? '') + (t.stderr ?? '');
const m = /# pass (\d+)/.exec(out);
const f = /# fail (\d+)/.exec(out);
const pass = m ? Number(m[1]) : 0;
const fail = f ? Number(f[1]) : 1;
const testOk = t.status === 0 && fail === 0;
results.push(['node:test suite', testOk ? 'PASS' : 'FAIL', `${pass} passed / ${fail} failed`]);
if (!testOk) { console.error(out.split('\n').filter((l) => /not ok|error:|# fail/.test(l)).join('\n')); ++failed; }

// 3. Acceptance line: two independent CLI processes, real UDP handshake +
// traffic. Also covered by tests/self-interop.test.ts in the suite above;
// running the probe directly gives the gate table an explicit verdict.
const self = spawnSync(process.execPath, ['scripts/self-interop.mjs', '--json'], {
  cwd: root, encoding: 'utf8', timeout: 90000,
});
let selfReport = null;
try { selfReport = JSON.parse((self.stdout ?? '').trim().split('\n').pop()); } catch { /* handled below */ }
const selfOk = self.status === 0 && selfReport?.failed === 0;
results.push(['self-interop', selfOk ? 'PASS' : 'FAIL',
  selfReport ? `${selfReport.passed}/${selfReport.total} checks (2 processes, real UDP)` : 'no JSON report']);
if (!selfOk) { console.error((self.stderr ?? '') + (self.stdout ?? '')); ++failed; }

// 4. CLI smoke: -h must work with no PSK and carry the version on its first
//    line (that is what --version used to do), and the removed --version must
//    be rejected instead of quietly printing the usage.
const helpRun = spawnSync(process.execPath, ['src/app/cli.ts', '--help'], { cwd: root, encoding: 'utf8' });
const helpFirst = (helpRun.stdout ?? '').split('\n')[0];
const helpOk = helpRun.status === 0 && /^FCP \d+\.\d+\.\d+/.test(helpFirst);
results.push(['cli --help', helpOk ? 'PASS' : 'FAIL', helpFirst]);
if (!helpOk) { console.error(helpRun.stderr); ++failed; }

const verRun = spawnSync(process.execPath, ['src/app/cli.ts', '--version'], { cwd: root, encoding: 'utf8' });
const verOk = verRun.status !== 0 && /--version is no longer accepted/.test(verRun.stderr ?? '');
results.push(['--version gone', verOk ? 'PASS' : 'FAIL',
  verOk ? 'rejected (points at -h)' : `status=${verRun.status}`]);
if (!verOk) { console.error(verRun.stderr); ++failed; }

// 5. Trace round-trip: a prefix written in one directory must be readable from
//    any working directory, and must not adopt unrelated *.jsonl neighbours.
//    Both rules were broken (replay listed '.' and matched `c*`), so this gate
//    keeps the reader pinned to the writer's naming.
const traceDir = mkdtempSync(join(tmpdir(), 'fcp-gate-trace-'));
writeFileSync(join(traceDir, 'run-client-aa.jsonl'), '{"t":"bbr"}\n');
writeFileSync(join(traceDir, 'run-server-aa.jsonl'), '{"t":"bbr"}\n{"t":"fec_k"}\n');
writeFileSync(join(traceDir, 'cache.jsonl'), '{"t":"bbr"}\n');
const replayRun = spawnSync(process.execPath,
  ['src/app/replay.ts', `--trace=${join(traceDir, 'run')}`], { cwd: root, encoding: 'utf8' });
const replayOut = (replayRun.stdout ?? '').trim();
const traceOk = replayRun.status === 0 && /2 file\(s\), 3 events/.test(replayOut) && !/cache/.test(replayOut);
results.push(['trace replay', traceOk ? 'PASS' : 'FAIL',
  traceOk ? '2 files / 3 events, no neighbours' : replayOut.split('\n')[0] || 'no output']);
if (!traceOk) { console.error((replayRun.stderr ?? '') + replayOut); ++failed; }
rmSync(traceDir, { recursive: true, force: true });

console.log('\nFCP-Node gate');
console.log('------------- ------ -------------------------');
for (const [name, status, detail] of results) {
  console.log(`${name.padEnd(16)} ${status.padEnd(6)} ${detail}`);
}
console.log(`\n${failed === 0 ? 'ALL GATES PASSED' : `${failed} GATE(S) FAILED`}`);
process.exit(failed ? 1 : 0);
