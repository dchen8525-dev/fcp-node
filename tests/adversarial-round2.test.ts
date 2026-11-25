// Regression tests for the second adversarial pass (ten review rounds across
// crypto, FEC, stream/congestion control, proxy codecs, session lifecycle,
// path probing and packaging). Each test is a minimal reproduction of a
// measured failure, with the symptom in the comment above it.
//
// Run: node --test tests/adversarial-round2.test.ts

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, connect } from 'node:net';
import { once } from 'node:events';
import { randomBytes } from 'node:crypto';

import { detectEntry, openWriteRequest } from '../src/proxy/codec.ts';
import { Stream } from '../src/stream/stream.ts';
import { encodeAck } from '../src/stream/segment.ts';
import { PathProbe, encodeProbe } from '../src/probe/pathprobe.ts';
import { TunnelServer, TunnelClient } from '../src/app/tunnel.ts';
import { ATYP_DOMAIN } from '../src/constants.ts';
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

test('STREAM: an ACK arriving after both FINs flushes the pending peer-FIN ACK', () => {
  // The receiver delays the ACK for a FIN by one tick. If the ACK for our own
  // FIN arrives first, finishing immediately used to discard that pending ACK;
  // the peer then sat in SendingFin until the idle timeout despite a clean,
  // bidirectional close.
  const aToB: Buffer[] = [], bToA: Buffer[] = [];
  let aClosed = 0, bClosed = 0;
  const cfg = { maxSegment: 1200, ackEvery: 1, initialSrttMs: 40, idleTimeoutMs: 1e9 };
  const a = new Stream(cfg, { send: (s) => aToB.push(Buffer.from(s)), read: () => {}, closed: () => { ++aClosed; } });
  const b = new Stream(cfg, { send: (s) => bToA.push(Buffer.from(s)), read: () => {}, closed: () => { ++bClosed; } });
  a.closeWrite(0); b.closeWrite(0);
  b.onSegment(aToB[0]!, 1);
  a.onSegment(bToA[0]!, 1);
  assert.equal(aToB.length, 1, 'the peer-FIN ACK is still delayed');
  a.onSegment(encodeAck(1, 262144, 0, 0), 2);
  assert.equal(aClosed, 1);
  assert.equal(aToB.length, 2, 'closing must flush the delayed peer-FIN ACK');
  b.onSegment(aToB[1]!, 3);
  assert.equal(bClosed, 1, 'the peer can now finish without waiting for idle timeout');
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

test('SSRF: --deny-private refuses an empty or failed DNS answer', async () => {
  // Returning allowed here made onStreamBytes dial the hostname again, turning
  // a resolver failure into a fail-open SSRF check.
  const server = new TunnelServer({ psk: randomBytes(16), port: 0, denyPrivate: true, log: () => {} });
  const verdict = await (server as unknown as {
    targetAllowed: (target: unknown, host: string) => Promise<{ allowed: boolean; address?: string }>;
  }).targetAllowed({ atyp: ATYP_DOMAIN, addr: Buffer.alloc(0) }, 'fcp-no-such-host.invalid');
  assert.equal(verdict.allowed, false);
  assert.equal(verdict.address, undefined);
});

test('CLIENT: a non-loopback proxy bind is rejected before any socket opens', async () => {
  for (const listenHost of ['0.0.0.0', '192.0.2.1', '::']) {
    const client = new TunnelClient({
      psk: randomBytes(16), port: 0, listenHost, listenPort: 0, log: () => {},
    });
    await assert.rejects(client.start(), /--bind must be loopback/);
    const udp = (client as unknown as { udp: { listening: boolean } }).udp;
    const tcp = (client as unknown as { tcp: { listening: boolean } }).tcp;
    assert.ok(!udp.listening, 'UDP socket must remain unbound');
    assert.ok(!tcp.listening, 'proxy socket must remain unbound');
    client.stop();
  }
});

test('CLIENT: stop destroys accepted sockets that are still parsing the proxy entry', async () => {
  let acceptedResolve!: () => void;
  const accepted = new Promise<void>((resolve) => { acceptedResolve = resolve; });
  const client = new TunnelClient({
    psk: randomBytes(16), host: '127.0.0.1', port: 0, listenPort: 0,
    log: () => {},
    debugLog: (line) => { if (line.includes('local conn accepted')) acceptedResolve(); },
  });
  await client.start();
  const port = (client as unknown as { tcp: { address(): { port: number } } }).tcp.address().port;
  const sock = connect(port, '127.0.0.1');
  sock.on('error', () => {});
  try {
    await once(sock, 'connect');
    sock.write('CONNECT ');
    await accepted;
    const closed = new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('accepted socket survived client stop')), 1000);
      sock.once('close', () => { clearTimeout(timer); resolve(); });
    });
    client.stop();
    await closed;
  } finally {
    sock.destroy();
    client.stop();
  }
});

test('SSRF: DNS vetting cannot dial after its tunnel was cleaned up', async () => {
  const server = new TunnelServer({ psk: randomBytes(16), port: 0, denyPrivate: true, log: () => {} });
  let release!: (v: { allowed: boolean; address?: string }) => void;
  const verdict = new Promise<{ allowed: boolean; address?: string }>((resolve) => { release = resolve; });
  let vettingStarted!: () => void;
  const started = new Promise<void>((resolve) => { vettingStarted = resolve; });
  let dials = 0;
  const api = server as unknown as {
    targetAllowed: () => Promise<{ allowed: boolean; address?: string }>;
    dialTarget: () => never;
    newSidTunnel: (key: string, sid: number, addr: { host: string; port: number }, trace?: undefined) => {
      cleanup: () => void; closed: boolean;
      stream: unknown;
    };
    onStreamBytes: (t: unknown, bytes: Buffer) => Promise<void>;
  };
  api.targetAllowed = () => { vettingStarted(); return verdict; };
  api.dialTarget = () => { ++dials; throw new Error('must not dial after cleanup'); };
  const t = api.newSidTunnel('00', 1, { host: '127.0.0.1', port: 4460 });
  t.stream = { write: () => 0, consumed: () => {}, closeWrite: () => {} };
  const request = openWriteRequest({ atyp: ATYP_DOMAIN, addr: Buffer.from('example.com'), port: 80 })!;
  const handling = api.onStreamBytes(t, request);
  await started;
  t.cleanup();
  release({ allowed: true, address: '203.0.113.10' });
  await handling;
  assert.equal(t.closed, true);
  assert.equal(dials, 0);
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
