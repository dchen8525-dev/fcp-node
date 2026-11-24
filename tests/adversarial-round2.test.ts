// Regression tests for the second adversarial pass (ten review rounds across
// crypto, FEC, stream/congestion control, proxy codecs, session lifecycle,
// path probing and packaging). Each test is a minimal reproduction of a
// measured failure, with the symptom in the comment above it.
//
// Run: node --test tests/adversarial-round2.test.ts

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:net';
import { randomBytes } from 'node:crypto';

import { detectEntry } from '../src/proxy/codec.ts';
import { Stream } from '../src/stream/stream.ts';
import { PathProbe, encodeProbe } from '../src/probe/pathprobe.ts';
import { TunnelServer } from '../src/app/tunnel.ts';
import { PROBE_TYPE_DOWN, PROBE_TYPE_SUM, PROBE_FLAG_DOWN } from '../src/constants.ts';

function recvStream(): Stream {
  return new Stream(
    { maxSegment: 1200, rcvBufBytes: 4 << 20, initialSrttMs: 40, idleTimeoutMs: 1e9 },
    { send: () => {}, read: () => {}, closed: () => {} },
  );
}

test('ENTRY: a method name split across TCP reads is not classified unknown', () => {
  // Symptom: detectEntry required the space after the method, so a first
  // segment of exactly "CONNECT" or "POST" (no space yet) answered 'unknown'
  // and the caller destroyed the connection before the parser saw it. GET and
  // PUT only survived because the 4-byte floor happened to cover them.
  assert.equal(detectEntry(Buffer.from('CONN', 'latin1')), 'need_more');
  assert.equal(detectEntry(Buffer.from('CONNECT', 'latin1')), 'need_more');
  assert.equal(detectEntry(Buffer.from('POST', 'latin1')), 'need_more');
  assert.equal(detectEntry(Buffer.from('OPTIONS', 'latin1')), 'need_more');
  assert.equal(detectEntry(Buffer.from('CONNECT ', 'latin1')), 'connect');
  assert.equal(detectEntry(Buffer.from('POST / HTTP/1.1\r\n\r\n', 'latin1')), 'forward');
  assert.equal(detectEntry(Buffer.from('!!!', 'latin1')), 'need_more');
  assert.equal(detectEntry(Buffer.from('!!!!!!!!', 'latin1')), 'unknown');
  assert.equal(detectEntry(Buffer.from([5, 1, 0])), 'socks5');
});

test('STREAM: a 1-byte reorder flood stays linear and keeps the oob buffer sane', () => {
  // Symptom: insertChunk rebuilt and sorted the whole reorder buffer on every
  // arrival. One authenticated peer holding a hole at rcvNxt and sending
  // 1-byte chunks at increasing offsets (up to oobMaxChunks = 8192) cost 1.3 s
  // of blocked event loop — measured — for ~8 KB of data.
  const st = recvStream();
  const api = st as unknown as {
    insertChunk: (offset: number, bytes: Buffer) => void;
    oob: Array<{ offset: number; bytes: Buffer }>; oobBytes: number;
    rcvNxt: number; deliveryPending: number;
  };
  api.rcvNxt = 1;
  const t0 = performance.now();
  for (let i = 0; i < 8192; ++i) api.insertChunk((2 + i * 4) >>> 0, Buffer.alloc(1));
  const ms = performance.now() - t0;
  assert.equal(api.oob.length, 8192, 'every chunk is held');
  assert.ok(ms < 500, `8192 arrivals took ${ms.toFixed(0)} ms`);
  for (let i = 1; i < api.oob.length; ++i) {
    const prevEnd = (api.oob[i - 1].offset + api.oob[i - 1].bytes.length) >>> 0;
    assert.ok(api.oob[i].offset > prevEnd, 'the buffer stays sorted and non-overlapping');
  }
  assert.equal(api.oobBytes, 8192, 'the byte count matches the contents');
});

test('STREAM: overlapping reorder chunks keep exactly the newest bytes', () => {
  // Invariant check for the same rewrite: the fast path must not drop, keep
  // stale or duplicate any byte when writes overlap partially.
  const st = recvStream();
  const api = st as unknown as {
    insertChunk: (offset: number, bytes: Buffer) => void;
    oob: Array<{ offset: number; bytes: Buffer }>; oobBytes: number;
    rcvNxt: number; deliveryPending: number;
  };
  api.rcvNxt = 1;
  let seed = 424242;
  const rnd = (): number => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
  for (let t = 0; t < 200; ++t) {
    const model = new Map<number, number>();
    api.oob = []; api.oobBytes = 0;
    for (let k = 0; k < 40; ++k) {
      const off = 1 + Math.floor(rnd() * 120);
      const len = 1 + Math.floor(rnd() * 25);
      const b = Buffer.alloc(len);
      for (let i = 0; i < len; ++i) b[i] = (k * 7 + i) & 0xff;
      api.insertChunk(off, b);
      for (let i = 0; i < len; ++i) model.set(off + i, b[i]); // newest write wins
    }
    const real = new Map<number, number>();
    for (const c of api.oob) {
      for (let i = 0; i < c.bytes.length; ++i) real.set((c.offset + i) >>> 0, c.bytes[i]);
    }
    assert.equal(real.size, model.size, 'the same offsets are buffered');
    for (const [o, v] of model) assert.equal(real.get(o), v, `byte at ${o}`);
    let sum = 0;
    for (const c of api.oob) sum += c.bytes.length;
    assert.equal(sum, api.oobBytes, 'oobBytes tracks the buffer');
    for (let i = 1; i < api.oob.length; ++i) {
      const prevEnd = (api.oob[i - 1].offset + api.oob[i - 1].bytes.length) >>> 0;
      assert.ok(api.oob[i].offset > prevEnd, 'sorted, non-overlapping, contiguous runs merged');
    }
  }
});

test('PROBE: a forged summary is ignored, a truncated train still reports loss', () => {
  // Symptom: onSum accepted any (got, total) pair under our token, so
  // (got=0, total=65535) published a 100% receive loss for an intact link.
  //
  // The bound must be the ADVERTISED train length, not the count actually
  // sent: a run that ends early (timeout / settle) sends fewer frames than the
  // total it named in every DAT header, and its legitimate summary counts the
  // unsent tail as lost. Bounding by "sent" silently dropped the receiver-side
  // number on exactly the slow, lossy paths it exists for.
  const DGRAM = 1200;
  const probe = new PathProbe({
    send: () => {},
    srttMs: () => 40,
    dgramSize: () => DGRAM,
    onResult: () => {},
  }, 64 * 1024);
  const api = probe as unknown as {
    start: (now: number, budget: number) => boolean;
    token: number;
    upResult: { bytes: number; lossRx: number; maxRun: number } | null;
    up: unknown;
    onFrame: (p: Uint8Array, now: number) => boolean;
  };
  assert.ok(api.start(0, 64 * 1024), 'the run starts');
  const token = api.token;
  const trainLen = Math.floor(Math.floor(64 * 1024 / DGRAM) * 0.55);
  // Finish the uplink half so the summary has something to attach to. Only
  // 10 of the train's frames made it out before the run was cut short.
  api.up = null;
  api.upResult = { bytes: 10 * DGRAM, lossRx: -1, maxRun: -1 } as unknown as typeof api.upResult;

  api.onFrame(encodeProbe({
    type: PROBE_TYPE_SUM, flags: 0, token, seq: 0,
    total: 65535, got: 0, sentMs: 0, size: DGRAM, aux: 65535,
  }, DGRAM), 1000);
  assert.equal(api.upResult!.lossRx, -1, 'a total above the advertised train is ignored');
  assert.equal(api.upResult!.maxRun, -1, 'and so is its maxRun');

  // Legitimate summary for the truncated run: total is what we advertised, not
  // what we managed to send. got=10 of 29 means the rest never arrived.
  api.onFrame(encodeProbe({
    type: PROBE_TYPE_SUM, flags: 0, token, seq: 0,
    total: trainLen, got: 10, sentMs: 0, size: DGRAM, aux: 3,
  }, DGRAM), 1000);
  assert.equal(api.upResult!.lossRx, 1 - 10 / trainLen, 'a truncated train still reports its loss');
  assert.equal(api.upResult!.maxRun, 3, 'its maxRun is applied');

  // got > total is a lie, not a measurement: it must not read as negative loss.
  api.onFrame(encodeProbe({
    type: PROBE_TYPE_SUM, flags: 0, token, seq: 0,
    total: 5, got: 65535, sentMs: 0, size: DGRAM, aux: 0,
  }, DGRAM), 1000);
  assert.equal(api.upResult!.lossRx, 0, 'got is clamped to total');
});

test('PROBE: served trains are rate-limited and budgeted', () => {
  // Symptom: one DOWN request bought a full local-budget train, and a request
  // re-issued the moment a train ended bought another — unlimited paced egress
  // driven by a peer's ~40-byte datagrams.
  const DGRAM = 1200;
  const BUDGET = 64 * 1024;
  const probe = new PathProbe({
    send: () => {}, srttMs: () => 40, dgramSize: () => DGRAM, onResult: () => {},
  }, BUDGET);
  const api = probe as unknown as {
    up: { total: number } | null;
    onFrame: (p: Uint8Array, now: number) => boolean;
    servedWindowBytes: number;
  };
  const req = (token: number): Buffer => encodeProbe({
    type: PROBE_TYPE_DOWN, flags: PROBE_FLAG_DOWN, token, seq: 0,
    total: 400, got: 0, sentMs: 0, size: DGRAM, aux: 0,
  }, DGRAM);

  api.onFrame(req(0x11111111), 0);
  assert.ok(api.up, 'the first request is served');

  // End that train, then ask again inside the cooldown: refused.
  api.up = null;
  api.onFrame(req(0x22222222), 100);
  assert.equal(api.up, null, 'a request inside the cooldown is refused');

  // Past the cooldown but with the window budget spent: refused again.
  api.servedWindowBytes = BUDGET;
  api.onFrame(req(0x33333333), 5000);
  assert.equal(api.up, null, 'the per-window byte budget is enforced');

  // token 0 can never be correlated by the requester: never served.
  api.servedWindowBytes = 0;
  api.onFrame(req(0), 6000);
  assert.equal(api.up, null, 'a train under token 0 is refused');
});

test('SSRF: --deny-private dials the vetted address, not a re-resolution', async () => {
  // Symptom: targetAllowed resolved the name and checked every answer, then
  // connect() resolved it again. An attacker controlling the record could
  // answer public for the check and private for the dial (DNS rebind).
  const server = new TunnelServer({ psk: randomBytes(16), port: 0, denyPrivate: true, log: () => {} });
  const target = createServer(() => {});
  await new Promise<void>((res) => target.listen(0, '127.0.0.1', res));
  const port = (target.address() as { port: number }).port;
  try {
    const dial = (server as unknown as {
      dialTarget: (h: string, p: number, f: 4 | 6, pinned?: string) => import('node:net').Socket;
    }).dialTarget;
    const sock = dial.call(server, 'this-name-does-not-resolve.invalid', port, 4, '127.0.0.1');
    await new Promise<void>((resolve, reject) => {
      sock.once('connect', () => resolve());
      sock.once('error', (e) => reject(e));
      setTimeout(() => reject(new Error('the pinned dial did not connect')), 3000);
    });
    sock.destroy();
  } finally {
    await new Promise<void>((res) => target.close(() => res()));
  }
});
