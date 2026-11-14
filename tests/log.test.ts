// The log sink sits on the data path: losing the log file must never take the
// tunnel with it. Run: node --test tests/log.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { makeLogger } from '../src/util/log.ts';

test('logger: an unwritable --log-file is reported once and never throws', async () => {
  // Passing a directory as --log-file makes appendFileSync throw EISDIR. The
  // old flush() ran raw inside a setInterval callback, so that exception was
  // uncaught and killed the process (here: the test runner) mid-session.
  const dir = mkdtempSync(join(tmpdir(), 'fcp-log-'));
  const problems: string[] = [];
  const chunks: string[] = [];
  const realWrite = process.stderr.write.bind(process.stderr);
  process.stderr.write = ((s: string | Uint8Array) => {
    chunks.push(String(s));
    return true;
  }) as typeof process.stderr.write;
  // Poll instead of sleeping a fixed multiple of LOG_FLUSH_MS: a loaded CI
  // runner can delay the interval and turn a correct flush into a red test.
  const waitFor = async (pred: () => boolean, ms = 5000): Promise<void> => {
    const end = Date.now() + ms;
    while (!pred() && Date.now() < end) await new Promise((r) => setTimeout(r, 20));
  };
  try {
    const log = makeLogger('info', dir, { onLogFileError: (m) => problems.push(m) });
    log('first line carries the version');
    await waitFor(() => chunks.join('').includes('first line'));
    log('second line after the file broke');
    await waitFor(() => chunks.join('').includes('second line'));
  } finally {
    process.stderr.write = realWrite;
    rmSync(dir, { recursive: true, force: true });
  }
  assert.equal(problems.length, 1, 'the failure is reported exactly once');
  assert.match(problems[0], /unwritable/);
  const text = chunks.join('');
  assert.match(text, /first line carries the version/, 'lines still reach stderr');
  assert.match(text, /second line/);
  assert.match(text, /log file .* is unwritable/, 'one advisory is emitted');
});

test('logger: a log directory that cannot be created is an advisory, not a crash', () => {
  // mkdirSync(dirname(logFile)) used to throw straight out of makeLogger, so
  // --log-file=<file>/x.log (or a read-only mount) aborted startup even though
  // logging is optional. The failure must be reported once and ignored.
  const dir = mkdtempSync(join(tmpdir(), 'fcp-log-'));
  const asFile = join(dir, 'not-a-directory');
  writeFileSync(asFile, 'x');
  const problems: string[] = [];
  try {
    const log = makeLogger('info', join(asFile, 'x.log'), { onLogFileError: (m) => problems.push(m) });
    assert.equal(problems.length, 1, 'reported at construction');
    assert.match(problems[0], /unwritable/);
    log('still usable'); // must not throw even though the sink is broken
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
