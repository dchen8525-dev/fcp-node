// Trace writer / reader tests. Every case here is a defect that used to be
// live: an unbuffered path could kill the process, the reader looked in the
// wrong directory and matched the wrong files.
// Run: node --test tests/trace.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  createTraceSink, flushTraces, normaliseTracePrefix, openTraceCount,
  resolveTraceFiles, summariseTrace, TRACE_MAX_BUFFERED,
} from '../src/util/trace.ts';

function tempDir(): string {
  return mkdtempSync(join(tmpdir(), 'fcp-trace-'));
}

test('writer creates missing parent directories', async () => {
  const dir = tempDir();
  const file = join(dir, 'a', 'b', 'c', 'x-client-00.jsonl');
  const sink = createTraceSink(file);
  sink.write('{"t":"bbr"}');
  sink.close();
  await flushTraces();
  assert.equal(readFileSync(file, 'utf8'), '{"t":"bbr"}\n');
  rmSync(dir, { recursive: true, force: true });
});

test('flushTraces waits for buffered lines: close then read loses nothing', async () => {
  const dir = tempDir();
  const file = join(dir, 'p-client-00.jsonl');
  const sink = createTraceSink(file);
  for (let i = 0; i < 500; ++i) sink.write(`{"t":"bbr","i":${i}}`);
  sink.close();
  // Reading before the flush used to see 0 lines: the writes were still queued
  // and `process.exit()` in the shutdown path threw them away.
  await flushTraces();
  assert.equal(readFileSync(file, 'utf8').trimEnd().split('\n').length, 500);
  rmSync(dir, { recursive: true, force: true });
});

test('an unwritable path reports once instead of throwing or exiting', async () => {
  const dir = tempDir();
  const blocker = join(dir, 'blocked');
  writeFileSync(blocker, 'not a directory'); // mkdirSync under this must fail
  const problems: string[] = [];
  const sink = createTraceSink(join(blocker, 'nested', 'x.jsonl'), { onProblem: (m) => problems.push(m) });
  assert.doesNotThrow(() => sink.write('{"t":"bbr"}'));   // packet path stays alive
  assert.doesNotThrow(() => sink.close());
  assert.equal(problems.length, 1, 'exactly one report, not one per line');
  assert.match(problems[0], /trace .*nested/, 'message names the file');
  assert.equal(existsSync(join(blocker, 'nested')), false);
  rmSync(dir, { recursive: true, force: true });
});

test('close is idempotent and writes after close are dropped, not thrown', async () => {
  const dir = tempDir();
  const file = join(dir, 'p-client-01.jsonl');
  const sink = createTraceSink(file);
  sink.write('{"t":"bbr"}');
  sink.close();
  sink.close();                                   // second close used to call end() again
  assert.doesNotThrow(() => sink.write('{"t":"late"}')); // write-after-end was an uncaught error
  await flushTraces();
  assert.equal(readFileSync(file, 'utf8'), '{"t":"bbr"}\n', 'the late line must not appear');
  rmSync(dir, { recursive: true, force: true });
});

test('a stalled disk drops lines instead of growing the heap without bound', async () => {
  const dir = tempDir();
  const sink = createTraceSink(join(dir, 'p-client-02.jsonl'));
  const big = 'x'.repeat(4096);
  // Push well past the cap without yielding to the file system, so the stream
  // buffer can only grow: the writer must start dropping instead.
  for (let i = 0; i < (TRACE_MAX_BUFFERED / 4096) * 3; ++i) sink.write(big);
  sink.close();
  await flushTraces();
  rmSync(dir, { recursive: true, force: true });
  assert.ok(true, 'no OOM, no throw');
});

test('nothing stays open after flushTraces', async () => {
  assert.equal(openTraceCount(), 0);
});

test('prefix normalisation strips .jsonl and rejects an empty value', () => {
  assert.equal(normaliseTracePrefix('out/run'), 'out/run');
  assert.equal(normaliseTracePrefix('out/run.jsonl'), 'out/run');
  assert.throws(() => normaliseTracePrefix(''), /empty value/);
  assert.throws(() => normaliseTracePrefix('   '), /empty value/);
});

test('a directory is rejected: --trace takes a prefix, not a folder', () => {
  const dir = tempDir();
  assert.throws(() => normaliseTracePrefix(dir), /is a directory/);
  rmSync(dir, { recursive: true, force: true });
});

test('resolveTraceFiles uses the prefix directory, not the working directory', () => {
  const dir = tempDir();
  const prefix = join(dir, 'run');
  writeFileSync(join(dir, 'run-client-aa.jsonl'), '{"t":"bbr"}\n');
  writeFileSync(join(dir, 'run-server-aa.jsonl'), '{"t":"bbr"}\n{"t":"fec_k"}\n');
  // Absolute path while cwd is somewhere else: this used to list '.' and
  // report "0 file(s)".
  const files = resolveTraceFiles(prefix);
  assert.equal(files.length, 2);
  assert.ok(files.every((f) => f.startsWith(prefix)));
  assert.deepEqual([...files].sort(), [
    join(dir, 'run-client-aa.jsonl'), join(dir, 'run-server-aa.jsonl'),
  ].sort());
  rmSync(dir, { recursive: true, force: true });
});

test('resolveTraceFiles matches <prefix>-* only: no cache.jsonl false positives', () => {
  const dir = tempDir();
  writeFileSync(join(dir, 'c-client-aa.jsonl'), '{"t":"bbr"}\n');
  writeFileSync(join(dir, 'cache.jsonl'), '{"t":"bbr"}\n');
  writeFileSync(join(dir, 'cfg.jsonl'), '{"t":"bbr"}\n');
  const files = resolveTraceFiles(join(dir, 'c'));
  assert.equal(files.length, 1, 'a prefix of "c" must not adopt cache.jsonl / cfg.jsonl');
  assert.ok(files[0].endsWith('c-client-aa.jsonl'));
  rmSync(dir, { recursive: true, force: true });
});

test('resolveTraceFiles accepts an explicit file name', () => {
  const dir = tempDir();
  const file = join(dir, 'only-client-aa.jsonl');
  writeFileSync(file, '{"t":"bbr"}\n');
  assert.deepEqual(resolveTraceFiles(file), [file]);
  rmSync(dir, { recursive: true, force: true });
});

test('resolveTraceFiles fails loudly when the directory is gone', () => {
  assert.throws(() => resolveTraceFiles(join(tmpdir(), 'fcp-trace-missing-dir', 'x')),
    /directory .* does not exist/);
});

test('summariseTrace counts kinds and reports malformed lines instead of hiding them', () => {
  const dir = tempDir();
  const file = join(dir, 'p-client-03.jsonl');
  writeFileSync(file, '{"t":"bbr"}\n{"t":"fec_k"}\nnot json\n{"v":1}\n{"t":5}\n');
  const s = summariseTrace([file]);
  assert.equal(s.events, 4);
  assert.equal(s.malformed, 1);
  assert.equal(s.kinds.get('bbr'), 1);
  assert.equal(s.kinds.get('fec_k'), 1);
  assert.equal(s.kinds.get('unknown'), 2, 'missing and non-string t both land in unknown');
  rmSync(dir, { recursive: true, force: true });
});

test('two sessions writing through the same prefix stay in separate files', async () => {
  const dir = tempDir();
  const a = createTraceSink(join(dir, 'p-client-aa.jsonl'));
  const b = createTraceSink(join(dir, 'p-client-bb.jsonl'));
  a.write('{"t":"bbr"}'); b.write('{"t":"bbr"}'); b.write('{"t":"fecstat_k"}');
  a.close(); b.close();
  await flushTraces();
  assert.deepEqual(resolveTraceFiles(join(dir, 'p')).length, 2);
  const s = summariseTrace(resolveTraceFiles(join(dir, 'p')));
  assert.equal(s.events, 3);
  rmSync(dir, { recursive: true, force: true });
});

test('the writer never writes outside the prefix directory', async () => {
  const dir = tempDir();
  const nested = join(dir, 'logs');
  mkdirSync(nested);
  const sink = createTraceSink(join(nested, 'p-client-cc.jsonl'));
  sink.write('{"t":"bbr"}');
  sink.close();
  await flushTraces();
  assert.ok(existsSync(join(nested, 'p-client-cc.jsonl')));
  assert.equal(existsSync(join(dir, 'p-client-cc.jsonl')), false);
  rmSync(dir, { recursive: true, force: true });
});
