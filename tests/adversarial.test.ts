// Regression tests for the six defects found by adversarial analysis.
//
// Each test below is a minimal reproduction of a failure that was measured
// against the real implementation, not a hypothetical: the comment above each
// one states the symptom so a future change that reintroduces it fails here
// with the same words that described the bug report.
//
// Run: node --test tests/adversarial.test.ts

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, connect } from 'node:net';
import { randomBytes } from 'node:crypto';
import { createSocket } from 'node:dgram';

import { Handshake, buildHello } from '../src/crypto/handshake.ts';
import { openBootstrapHello, sealOobBootstrap } from '../src/crypto/envelope.ts';
import { Session } from '../src/session/session.ts';
import { ipv4Denied, ipv6Denied, ipDenied, MAX_PREAUTH_PER_IP } from '../src/app/tunnel.ts';
import { TunnelServer, TunnelClient } from '../src/app/tunnel.ts';
import {
  HandshakeRole, TLV_TYPE_ACK_V2, TLV_TYPE_KEY_UPDATE, TLV_TYPE_MULTIPLEX,
  SymbolType, MAX_RX_SYMBOL_BYTES, PROBE_BUDGET_BYTES, SESSION_STREAM_BUDGET_BYTES,
  PROBE_TYPE_DOWN, PROBE_FLAG_DOWN, PROBE_HDR_LEN, DEFAULT_MTU_MIN, LOCAL_FLAGS_M1,
} from '../src/constants.ts';
import { FrameRx, FrameTx, computeMtuLimits } from '../src/fec/frame.ts';
import { packHdr, packTypeK } from '../src/fec/hdr.ts';
import { rsEncode } from '../src/fec/rs.ts';
import { putLe16 } from '../src/wire.ts';
import { Stream } from '../src/stream/stream.ts';
import { encodeAckV2, parseSegment, STREAM_TYPE_ACK_V2 } from '../src/stream/segment.ts';
import { PathProbe, encodeProbe, decodeProbe } from '../src/probe/pathprobe.ts';

const TLV_ALL = [
  { type: TLV_TYPE_ACK_V2, value: Buffer.alloc(0) },
  { type: TLV_TYPE_KEY_UPDATE, value: Buffer.alloc(0) },
  { type: TLV_TYPE_MULTIPLEX, value: Buffer.alloc(0) },
];

function mkHandshake(role: number) {
  const out: Buffer[] = [];
  const h = new Handshake({
    localD: 10, localP: 6, role, localTlvs: TLV_ALL,
    send: (m) => out.push(Buffer.from(m)),
  });
  return { h, out };
}

const negotiated = (h: Handshake) =>
  `tlv=${h.tlvNegotiated()} ackv2=${h.tlvAgreed(TLV_TYPE_ACK_V2)} ` +
  `mux=${h.tlvAgreed(TLV_TYPE_MULTIPLEX)} ku=${h.tlvAgreed(TLV_TYPE_KEY_UPDATE)}`;

// ---------------------------------------------------------------------------
// 1. Handshake TLV negotiation must be symmetric on every path
// ---------------------------------------------------------------------------

test('HANDSHAKE: a server that establishes from HELLO_ACK negotiates the same TLVs', () => {
  // Symptom: the server's own HELLO was lost (or reordered behind the client's
  // ACK), so it learned the peer's caps from HELLO_ACK instead of HELLO. It
  // then negotiated tlv=false while the client negotiated tlv=true. Both ends
  // logged ESTABLISHED; the client prefixed every DATA symbol with a stream id
  // and the server read that byte as the stream type, so not one byte crossed
  // and the session sat there until the 135 s peer_dead clock. One lost
  // datagram was enough to kill the tunnel.
  const c = mkHandshake(HandshakeRole.Client);
  const s = mkHandshake(HandshakeRole.Server);
  c.h.start(0); s.h.start(0);
  c.h.onTick(0); s.h.onTick(0);
  const cHello = c.out.shift()!;
  const sHello = s.out.shift()!;

  c.h.onOob(sHello);          // client establishes and answers
  const cAck = c.out.shift()!;
  s.h.onOob(cAck);            // server establishes from the ACK only
  assert.equal(s.h.established, true, 'the server considers the session up');

  s.h.onOob(cHello);          // the retried HELLO arrives afterwards
  while (s.out.length) c.h.onOob(s.out.shift()!);

  assert.equal(negotiated(c.h), negotiated(s.h),
    `client and server disagree: client[${negotiated(c.h)}] server[${negotiated(s.h)}]`);
  assert.equal(s.h.tlvAgreed(TLV_TYPE_MULTIPLEX), true,
    'the ACK path must still see the peer offering mux');
});

test('HANDSHAKE: a simultaneous open converges on the same TLVs', () => {
  const c = mkHandshake(HandshakeRole.Client);
  const s = mkHandshake(HandshakeRole.Server);
  c.h.start(0); s.h.start(0);
  c.h.onTick(0); s.h.onTick(0);
  const cHello = c.out.shift()!;
  const sHello = s.out.shift()!;
  c.h.onOob(sHello);
  s.h.onOob(cHello);
  while (c.out.length) s.h.onOob(c.out.shift()!);
  while (s.out.length) c.h.onOob(s.out.shift()!);
  assert.equal(negotiated(c.h), negotiated(s.h),
    `crossed HELLOs desynced: client[${negotiated(c.h)}] server[${negotiated(s.h)}]`);
});

test('HANDSHAKE: a peer without TLVs keeps both sides on the legacy wire', () => {
  // The symmetry fix must not flip the other way: a peer that offers nothing
  // has to leave BOTH ends with tlv off, or the session is just as broken.
  const plain = (role: number) => {
    const out: Buffer[] = [];
    const h = new Handshake({ localD: 10, localP: 6, role, localTlvs: [], send: (m) => out.push(Buffer.from(m)) });
    return { h, out };
  };
  const c = plain(HandshakeRole.Client);
  const s = plain(HandshakeRole.Server);
  c.h.start(0); s.h.start(0);
  c.h.onTick(0); s.h.onTick(0);
  const cHello = c.out.shift()!;
  const sHello = s.out.shift()!;
  c.h.onOob(sHello);
  s.h.onOob(cHello);
  while (c.out.length) s.h.onOob(c.out.shift()!);
  while (s.out.length) c.h.onOob(s.out.shift()!);
  assert.equal(c.h.established && s.h.established, true);
  assert.equal(negotiated(c.h), negotiated(s.h));
  assert.equal(c.h.tlvNegotiated(), false, 'no TLVs offered -> no TLV framing');
});

// ---------------------------------------------------------------------------
// 2. FEC recovered symbols must be booked into the heap budget
// ---------------------------------------------------------------------------

function fecRx(d: number, p: number) {
  const rx = new FrameRx({ d, p, deliver: () => {}, oob: () => {}, maxSymbolLen: 65535 });
  return rx as FrameRx & { symbolBytes: number; sets: Map<number, unknown> };
}

function dataSymbol(setId: number, index: number, k: number, bytes: Buffer, d: number): Buffer {
  return Buffer.concat([packHdr({ setId, index, d, typeK: packTypeK(k, 0, SymbolType.Data) }), bytes]);
}
function paritySymbol(setId: number, index: number, j: number, k: number, bytes: Buffer, d: number): Buffer {
  return Buffer.concat([packHdr({ setId, index, d, typeK: packTypeK(k, j, SymbolType.Parity) }), bytes]);
}

test('FEC: a reconstructed symbol is counted in the session byte budget', () => {
  // Symptom: tryDecode() wrote recovered rows straight into set.data without
  // adding them to symbolBytes. Retirement subtracts setBytes(), which DOES
  // include them, so every repaired group drove the counter down by bytes it
  // had never added. With d=10/k=6 and 2 KB symbols, 200 groups held 6.4 MB
  // while the counter read 4.0 MB, and after the 2 s settle it read -2.4 MB.
  // A negative counter can never trip MAX_RX_SYMBOL_BYTES again, so the only
  // heap ceiling on FrameRx was gone for the rest of the session — on exactly
  // the lossy path where recovery runs constantly.
  const size = 2000;
  const d = 10, k = 6;
  const rx = fecRx(d, k);
  let now = 0;
  const SETS = 20;
  for (let s = 0; s < SETS; ++s) {
    const syms = Array.from({ length: d }, (_, i) => {
      const b = Buffer.alloc(size); putLe16(size, b, 0); b[2] = i; return b;
    });
    const parity = rsEncode(syms, d, k, size)!;
    // 4 originals + 6 parity -> 6 reconstructed, 10 rows held per set.
    for (let i = 0; i < 4; ++i) rx.onDatagram(dataSymbol(s, i, k, syms[i]!, d), now);
    for (let j = 0; j < k; ++j) rx.onDatagram(paritySymbol(s, d + j, j, k, parity[j]!, d), now);
    now += 1;
  }
  const held = [...rx.sets.values()].reduce((acc: number, st) => {
    const set = st as { data: Map<number, Buffer> };
    return acc + [...set.data.values()].reduce((x, b) => x + b.length, 0);
  }, 0);
  assert.equal(rx.counters.recovered, SETS * k, 'every set really was repaired');
  assert.equal(rx.symbolBytes, held,
    `the budget must equal what is held: counter=${rx.symbolBytes} held=${held}`);

  // Retirement must return the counter to exactly zero, not below it.
  now += 3000;
  rx.onTick(now);
  assert.equal(rx.symbolBytes, 0,
    `retirement left the counter at ${rx.symbolBytes}; a negative value disables MAX_RX_SYMBOL_BYTES`);
  assert.ok(rx.symbolBytes <= MAX_RX_SYMBOL_BYTES);
});

// ---------------------------------------------------------------------------
// 3. ACKs must fit the datagram budget at every legal MTU
// ---------------------------------------------------------------------------

test('STREAM: an ACK is never larger than the payload budget', () => {
  // Symptom: ACK v2 is variable length (10 B + up to 2 x 5 B per range), and
  // the receiver always sent up to 64 ranges. FrameTx drops an oversize
  // segment silently (mtuDrops), so on a small MTU a wide ACK simply vanished.
  // An ACK that never arrives is indistinguishable from a lost one, which
  // turned every wide hole into an RTO stall.
  for (const mtu of [128, 140, 200, 300, 576, 1040]) {
    for (const ackV2 of [true, false]) {
      const limits = computeMtuLimits(mtu, 20);
      assert.equal(limits.valid, true);
      const tx = new FrameTx(10, limits, () => {});
      const sent: Buffer[] = [];
      const s = new Stream(
        { maxSegment: limits.payloadMax, initialSrttMs: 60, ackV2, rcvBufBytes: 512 * 1024,
          sendWindowBytes: 256 * 1024, idleTimeoutMs: 1e9 },
        { send: (b) => { sent.push(b); tx.onSegment(b, 0); }, read: () => {}, closed: () => {} },
      );
      let now = 0;
      // 40 disjoint one-byte runs force a wide SACK set.
      for (let i = 0; i < 40; ++i) {
        const off = 100 * i + 10;
        const seg = Buffer.concat([
          Buffer.from([1, off & 0xff, (off >>> 8) & 0xff, (off >>> 16) & 0xff, 0, 0]),
          Buffer.from([0x41]),
        ]);
        s.onSegment(seg, now);
        now += 1;
      }
      s.onTick(now + 1000);
      assert.ok(sent.length > 0, `mtu=${mtu} ackV2=${ackV2}: no ACK was produced at all`);
      for (const b of sent) {
        assert.ok(b.length <= limits.payloadMax,
          `mtu=${mtu} ackV2=${ackV2}: ${b.length} B ACK exceeds payloadMax ${limits.payloadMax}`);
      }
      assert.equal(tx.mtuDrops, 0, `mtu=${mtu} ackV2=${ackV2}: FrameTx had to drop an ACK`);
      const widest = sent.reduce((m, b) => Math.max(m, b.length), 0);
      assert.ok(widest >= 10, 'the ACK still carries cum and rwnd');
    }
  }
});

test('STREAM: a wide ACK keeps as many ranges as the budget allows', () => {
  // Dropping the tail of the SACK set is the intended degradation: cum and
  // rwnd always go out, and the remaining ranges still prove holes.
  const limits = computeMtuLimits(300, 20); // payloadMax 236 -> ~22 ranges
  const sent: Buffer[] = [];
  const s = new Stream(
    { maxSegment: limits.payloadMax, initialSrttMs: 60, ackV2: true, rcvBufBytes: 512 * 1024,
      sendWindowBytes: 256 * 1024, idleTimeoutMs: 1e9 },
    { send: (b) => sent.push(b), read: () => {}, closed: () => {} },
  );
  let now = 0;
  for (let i = 0; i < 64; ++i) {
    const off = 100 * i + 10;
    const seg = Buffer.concat([
      Buffer.from([1, off & 0xff, (off >>> 8) & 0xff, (off >>> 16) & 0xff, 0, 0]),
      Buffer.from([0x41]),
    ]);
    s.onSegment(seg, now);
    now += 1;
  }
  s.onTick(now + 1000);
  const acks = sent.filter((b) => parseSegment(b)?.type === STREAM_TYPE_ACK_V2);
  assert.ok(acks.length > 0, 'a v2 ACK was emitted');
  const widest = acks.reduce((m, b) => Math.max(m, b.length), 0);
  assert.ok(widest <= limits.payloadMax, `${widest} B fits ${limits.payloadMax} B`);
  assert.ok(widest > 10, 'it still carries at least one SACK range');
});

// ---------------------------------------------------------------------------
// 4. Reordering must not be mistaken for loss
// ---------------------------------------------------------------------------

function losslessStream() {
  const sent: Buffer[] = [];
  const s = new Stream(
    { maxSegment: 1200, initialSrttMs: 40, sendWindowBytes: 256 * 1024, rcvBufBytes: 512 * 1024,
      idleTimeoutMs: 1e9, ackV2: true },
    { send: (b) => sent.push(Buffer.from(b)), read: () => {}, closed: () => {}, eof: () => {} },
  );
  return { s, sent };
}

test('STREAM: a lossless link with 60 ms of reordering retransmits (almost) nothing', () => {
  // Symptom: the reorder gate was derived as min(minRtt x 1.25, srtt). srtt is a
  // MEAN, so on a 20 ms path with 60 ms of spread it reads ~57 ms while
  // individual segments legitimately take 80 ms. Every late-but-fine segment
  // was declared lost: measured 34-36% retransmissions on a zero-loss link,
  // and the throughput went with it (the window filled with copies).
  const JITTER = 60;
  let seed = 7;
  const rnd = (): number => {
    seed ^= seed << 13; seed >>>= 0;
    seed ^= seed >>> 17;
    seed ^= seed << 5; seed >>>= 0;
    return seed / 0x100000000;
  };
  let now = 0;
  const q: Array<{ at: number; buf: Buffer }> = [];
  const A = new Stream(
    { maxSegment: 1200, initialSrttMs: 40, sendWindowBytes: 512 * 1024, rcvBufBytes: 1 << 20,
      idleTimeoutMs: 1e9, ackV2: true },
    { send: (b) => q.push({ at: now + 20 + Math.floor(rnd() * (JITTER + 1)), buf: Buffer.from(b) }),
      read: () => {}, closed: () => {}, eof: () => {} },
  ) as Stream & { retransmits: number; segsSent: number };
  let delivered = 0;
  const B = new Stream(
    { maxSegment: 1200, initialSrttMs: 40, sendWindowBytes: 512 * 1024, rcvBufBytes: 1 << 20,
      idleTimeoutMs: 1e9, ackV2: true },
    { send: (b) => q.push({ at: now + 20 + Math.floor(rnd() * (JITTER + 1)), buf: Buffer.from(b) }),
      read: (b) => { delivered += b.length; B.consumed(b.length); }, closed: () => {}, eof: () => {} },
  );
  const TOTAL = 2 * 1024 * 1024;
  const payload = Buffer.alloc(65536, 0x5a);
  let wrote = 0, finned = false;
  // Measure the STEADY state, not the first round: until one full spread has
  // been sampled the gate can only fall back on srtt + 2*rttvar, and a burst of
  // reordering that has not been observed yet will look like loss. That
  // convergence is bounded and self-correcting; what must not happen is a
  // session that keeps retransmitting a third of its traffic forever.
  let baselineRetx = -1, baselineSent = -1;
  while (now < 20000 && delivered < TOTAL) {
    if (wrote < TOTAL) wrote += A.write(payload, now);
    if (wrote === TOTAL && !finned) { A.closeWrite(now); finned = true; }
    for (let i = 0; i < q.length; ++i) {
      if (q[i]!.at <= now) {
        const p = q.splice(i, 1)[0]!;
        (p.buf[0] === 1 ? B : A).onSegment(p.buf, now);
        --i;
      }
    }
    A.onTick(now); B.onTick(now);
    if (now === 300) { baselineRetx = A.retransmits; baselineSent = A.segsSent; }
    now += 1;
  }
  assert.ok(delivered >= TOTAL, `the transfer completed (${delivered}/${TOTAL})`);
  assert.ok(baselineRetx >= 0, 'the convergence window was measured');
  const steadyRetx = A.retransmits - baselineRetx;
  const steadySent = A.segsSent - baselineSent;
  assert.ok(steadySent > 0, 'the transfer kept sending after convergence');
  const ratio = steadyRetx / steadySent;
  assert.ok(ratio < 0.05,
    `after convergence ${(ratio * 100).toFixed(1)}% of segments were still being ` +
    `retransmitted on a LOSSLESS link (${steadyRetx}/${steadySent}); ` +
    `the reorder gate is below the path's spread`);
});

test('STREAM: SACK ranges alone never skip the reorder age gate', () => {
  // Symptom: "two ranges start beyond this segment" was treated as proof of
  // loss and skipped the age gate. A reordering path produces exactly that
  // shape — one delayed datagram leaves the receiver holding the runs on both
  // sides of it — so the segment in front of the delay was resent while still
  // in flight. No SACK pattern can distinguish "late" from "lost"; the gate is
  // the only thing that can.
  const { s, sent } = losslessStream();
  s.write(Buffer.alloc(94 * 8), 0);
  const datas = () => sent.filter((b) => parseSegment(b)?.type === 1).length;
  const before = datas();
  const ranges = [{ start: 94 * 2, end: 94 * 3 }, { start: 94 * 5, end: 94 * 6 }];
  for (let i = 0; i < 4; ++i) s.onSegment(encodeAckV2(0, 65535, ranges), 5 + i);
  assert.equal(datas(), before, 'young segments stay put even with two ranges beyond them');
});

test('STREAM: the reorder gate widens with the measured spread, not the mean', () => {
  const { s } = losslessStream();
  s.write(Buffer.alloc(94), 0);
  // A path whose samples swing between 40 and 120 ms: the gate has to cover
  // the upper end, because that is what "not yet arrived" legitimately means.
  const ack = (cum: number, at: number) => {
    const b = Buffer.alloc(10);
    b[0] = 4; b.writeUInt32LE(cum, 1); b.writeUInt32LE(65535, 5); b[9] = 0;
    s.onSegment(b, at);
  };
  ack(94, 40);
  const narrow = s.retxAgeGateMs;
  s.write(Buffer.alloc(94), 100);
  ack(188, 220); // a 120 ms sample: legal, just slow
  const wide = s.retxAgeGateMs;
  assert.ok(wide > narrow, `the gate followed the spread: ${narrow} -> ${wide}`);
});

// ---------------------------------------------------------------------------
// 5. A pipelined request must not be rejected by the entry guard
// ---------------------------------------------------------------------------

test('PROXY: a request head followed by a large body parses as one chunk', () => {
  // The tunnel used to cap the whole first chunk at 16 KiB and answer 431. Any
  // client that pipelines request + body in one write — curl -T, nc with a
  // here-doc, a browser POST whose body is already in the socket buffer — was
  // killed before the parser ran. The head limit belongs to the parser, and
  // everything after the head is firstPayload.
  const head = Buffer.from(
    'POST http://x.com/ HTTP/1.1\r\nHost: x.com\r\nContent-Length: 65536\r\n\r\n', 'latin1');
  const chunk = Buffer.concat([head, Buffer.alloc(65536, 0x41)]);
  // Imported lazily so this file does not depend on the codec for the other cases.
  return import('../src/proxy/codec.ts').then(({ httpParseForward }) => {
    const r = httpParseForward(chunk);
    assert.equal(r.status, 'ok', `the parser accepts head+body in one chunk (got ${r.status})`);
    assert.equal(r.consumed, head.length, 'exactly the head is consumed');
    const firstPayload = chunk.subarray(r.consumed);
    assert.equal(firstPayload.length, 65536, 'the whole body is preserved as firstPayload');
  });
});

// ---------------------------------------------------------------------------
// 6. Probe responder: a DOWN request may not order more egress than this end
//    is willing to spend
// ---------------------------------------------------------------------------

test('PROBE: the responder clamps a DOWN train to its own datagram size and budget', () => {
  // Symptom: the responder served exactly what the request named — total and
  // size are both u16 wire fields — so one authenticated DOWN datagram ordered
  // total × size ≈ 4.3 GB of paced egress and pinned the train slot for hours.
  const DGRAM = 1200;
  const host: {
    sent: Buffer[];
    srttMs: number; dgramSize: number;
  } = { sent: [], srttMs: 40, dgramSize: DGRAM };
  const probe = new PathProbe({
    send: (p) => { host.sent.push(Buffer.from(p)); },
    srttMs: () => host.srttMs,
    dgramSize: () => host.dgramSize,
    onResult: () => {},
  });
  const req = encodeProbe({
    type: PROBE_TYPE_DOWN, flags: PROBE_FLAG_DOWN, token: 0x5a5a5a5a,
    seq: 0, total: 65535, got: 0, sentMs: 0, size: 65400, aux: 0,
  }, DGRAM);
  probe.onFrame(req, 0);
  const up = (probe as unknown as { up: { total: number; size: number } | null }).up;
  assert.ok(up, 'the DOWN request is answered with a served train');
  assert.ok(up!.size <= DGRAM,
    `the served datagram is ${up!.size} B, larger than this end's own ${DGRAM} B budget`);
  const maxTotal = Math.max(4, Math.floor(PROBE_BUDGET_BYTES / DGRAM));
  assert.ok(up!.total <= maxTotal,
    `the train is ${up!.total} datagrams, above the ${maxTotal}-packet protocol budget`);
  assert.ok(up!.total * up!.size <= PROBE_BUDGET_BYTES,
    `one train is ${up!.total * up!.size} B, above the ${PROBE_BUDGET_BYTES} B per-run budget`);
});

test('PROBE: the responder clamps to its own --probe-budget, not the module default', () => {
  // The clamp used to read PROBE_BUDGET_BYTES directly, so an end configured
  // with a smaller --probe-budget still served up to the 1 MiB default when
  // asked. The serving end owns its own egress, so the local value decides.
  const DGRAM = 1200;
  const BUDGET = 64 * 1024;
  const probe = new PathProbe({
    send: () => {},
    srttMs: () => 40,
    dgramSize: () => DGRAM,
    onResult: () => {},
  }, BUDGET);
  const req = encodeProbe({
    type: PROBE_TYPE_DOWN, flags: PROBE_FLAG_DOWN, token: 0x6b6b6b6b,
    seq: 0, total: 65535, got: 0, sentMs: 0, size: DGRAM, aux: 0,
  }, DGRAM);
  probe.onFrame(req, 0);
  const up = (probe as unknown as { up: { total: number; size: number } | null }).up;
  assert.ok(up, 'the DOWN request is answered');
  assert.equal(up!.total, Math.floor(BUDGET / DGRAM), 'a 64 KiB budget buys 54 datagrams');
  assert.ok(up!.total * up!.size <= BUDGET,
    `one served train is ${up!.total * up!.size} B, above the local ${BUDGET} B budget`);
});

test('PROBE: a legitimate DOWN train is served intact', () => {
  // The clamp must not cost an ordinary requester anything: a small budget and
  // an in-MTU size are exactly what the peer asked for.
  const DGRAM = 1200;
  const probe = new PathProbe({
    send: () => {},
    srttMs: () => 40,
    dgramSize: () => DGRAM,
    onResult: () => {},
  });
  const req = encodeProbe({
    type: PROBE_TYPE_DOWN, flags: PROBE_FLAG_DOWN, token: 0x1234abcd,
    seq: 0, total: 400, got: 0, sentMs: 0, size: DGRAM, aux: 0,
  }, DGRAM);
  probe.onFrame(req, 0);
  const up = (probe as unknown as { up: { total: number; size: number } | null }).up;
  assert.equal(up!.total, 400, 'a train within the budget is served whole');
  assert.equal(up!.size, DGRAM, 'the datagram size the peer asked for is kept');
});

// ---------------------------------------------------------------------------
// 7. Session heap ceiling: one mux session may not pin rcvBuf × 255 streams
// ---------------------------------------------------------------------------

test('STREAM: trimReorderTo cuts a stream reorder tail to a budget', () => {
  // The per-stream ceiling is the stream's rcvBufBytes; a mux session carries
  // up to 255 streams, so the session total was bounded only by rcvBuf × 255.
  // The enforcement trims the heaviest streams' tails; this pins the mechanism.
  const s = new Stream(
    { maxSegment: 1200, rcvBufBytes: 1 << 20, initialSrttMs: 40, idleTimeoutMs: 1e9 },
    { send: () => {}, read: () => {}, closed: () => {} },
  );
  // 64 disjoint 1-byte runs at 100-byte strides: every one lands in the
  // reorder buffer, nothing is ever in order.
  let now = 0;
  for (let i = 0; i < 64; ++i) {
    const off = 100 * i + 10;
    s.onSegment(Buffer.from([1, off & 0xff, (off >>> 8) & 0xff, (off >>> 16) >>> 0, 0, 0, 0x41]), now);
    now += 1;
  }
  const before = s.reorderBytes;
  assert.ok(before >= 64, `64 one-byte runs left ${before} B buffered`);
  s.trimReorderTo(16);
  assert.ok(s.reorderBytes <= 16,
    `after trim the reorder buffer holds ${s.reorderBytes} B, above the 16 B budget`);
  assert.equal(s.recvNext, 0, 'the in-order pointer does not move while trimming');
});

// ---------------------------------------------------------------------------
// 8. PMTU ACK: a size above our ceiling must not raise the send budget
// ---------------------------------------------------------------------------

test('SESSION: a PMTU ACK naming a size above the ceiling is ignored', () => {
  // Symptom: the PROBE branch clamped its answers to pmtuMaxMtu, but the ACK
  // branch applied whatever arrived. A misbehaving peer ACK'd mtu=9000, every
  // send became an EMSGSIZE datagram, the udp-error log flooded, and the walk
  // pinned itself because every later probe target is <= pmtuAckedMtu.
  const CEILING = 1500;
  const s = new Session(
    {
      psk: Buffer.alloc(16, 7), salt: Buffer.alloc(8, 3),
      sendDirection: 0x02, recvDirection: 0x01, role: 1,
      mtu: DEFAULT_MTU_MIN, pmtud: true, pmtuMaxMtu: CEILING,
    },
    { sendWire: () => {}, read: () => {}, closed: () => {} },
  );
  (s as unknown as { pmtuToken: number }).pmtuToken = 0x0badf00d;
  const ack = (mtu: number): Buffer => {
    const out = Buffer.alloc(16);
    Buffer.from('FCP_PMTU', 'latin1').copy(out, 0);
    out[8] = 1; out[9] = 0;
    out.writeUInt32LE(0x0badf00d, 10);
    out.writeUInt16LE(mtu, 14);
    return out;
  };
  const api = s as unknown as {
    pmtuAckedMtu: number; pmtuMtu: number;
    pmtuHandle: (p: Buffer, t: number) => boolean;
  };
  assert.equal(api.pmtuHandle(ack(1400), 0), true, 'a size inside the ceiling is applied');
  assert.equal(api.pmtuAckedMtu, 1400, 'the proven size moved up');
  assert.equal(api.pmtuHandle(ack(9000), 0), true, 'the oversized ACK is still consumed');
  assert.equal(api.pmtuAckedMtu, 1400, 'the oversized ACK did not move the budget');
});

// ---------------------------------------------------------------------------
// 9. Pre-auth gate: an unknown-salt datagram must not allocate a Session
// ---------------------------------------------------------------------------

test('GATE: only a sealed HELLO unlocks the pre-auth gate', () => {
  // Symptom: the server built a full Session for every datagram with an unseen
  // salt before looking at the ciphertext again — the per-IP rate limit bounds
  // one source, but a flood from distinct addresses paid one Session object
  // tree (2 envelopes, KDF, Stream, PathProbe, 3 controllers) per packet.
  const psk = Buffer.from('00112233445566778899aabbccddeeff', 'hex');
  const salt = Buffer.alloc(8, 9);
  const hello = buildHello(
    { ver: 1, data: 10, parity: 6, flags: 0x21 }, Buffer.alloc(16, 1),
  );
  const sealed = sealOobBootstrap(psk, salt, hello, 0x01 /* C2S */)!;
  const ok = openBootstrapHello(psk, salt, sealed);
  assert.ok(ok !== null, 'a sealed HELLO passes the gate');
  assert.equal(ok!.toString('latin1').startsWith('FCP_HELLO_V1'), true,
    'the gate hands back the HELLO payload');
  const junk = Buffer.alloc(37, 0x41);
  assert.equal(openBootstrapHello(psk, salt, junk), null, 'garbage does not pass the gate');
  // A data symbol sealed under the same key still fails the gate: it is not a
  // HELLO, so the server answers with a reset, not a session.
  const data = Buffer.concat([
    packHdr({ setId: 1, index: 0, d: 0, typeK: packTypeK(0, 0, SymbolType.Data) }),
    Buffer.from([0, 4, 0x42, 0, 0, 0]),
  ]);
  const sealedData = sealOobBootstrap(psk, salt, data, 0x01)!;
  assert.equal(openBootstrapHello(psk, salt, sealedData), null,
    'a non-HELLO payload does not pass the gate');
});

// ---------------------------------------------------------------------------
// 10. --deny-private: an OPEN target must not reach the server's own network
// ---------------------------------------------------------------------------

function v4(n: string): Buffer { return Buffer.from(n.split('.').map(Number)); }
function v6bytes(groups: string[]): Buffer {
  const out = Buffer.alloc(16);
  for (let i = 0; i < 8; ++i) out.writeUInt16BE(parseInt(groups[i]!, 16), i * 2);
  return out;
}

test('SSRF: the deny-list classifies the internal space', () => {
  // Loopback, RFC1918, link-local (cloud metadata 169.254.169.254), CGNAT.
  for (const ip of ['127.0.0.1', '10.0.0.5', '172.16.0.1', '192.168.1.1',
                    '169.254.169.254', '100.64.0.1', '0.0.0.0', '224.0.0.1']) {
    assert.equal(ipv4Denied(ip.split('.').map(Number)), true, `${ip} must be denied`);
  }
  // The public internet must NOT be denied.
  for (const ip of ['93.184.216.34', '1.1.1.1', '8.8.8.8', '172.32.0.1', '11.0.0.1']) {
    assert.equal(ipv4Denied(ip.split('.').map(Number)), false, `${ip} must be allowed`);
  }
  // IPv6: loopback, link-local, ULA, IPv4-mapped link-local.
  assert.equal(ipv6Denied(v6bytes(['0', '0', '0', '0', '0', '0', '0', '1'])), true, '::1 denied');
  assert.equal(ipv6Denied(v6bytes(['fe80', '0', '0', '0', '0', '0', '0', '1'])), true, 'fe80::/10 denied');
  assert.equal(ipv6Denied(v6bytes(['fd00', '0', '0', '0', '0', '0', '0', '1'])), true, 'ULA fc00::/7 denied');
  const mapped = Buffer.concat([Buffer.alloc(10), Buffer.from([0xff, 0xff]), v4('169.254.169.254')]);
  assert.equal(ipv6Denied(mapped), true, '::ffff:169.254.169.254 denied');
  assert.equal(ipv6Denied(v6bytes(['2606', '2800', '220', '1', '248', '1893', '0', '1'])), false,
    'a public IPv6 address is allowed');
});

test('SSRF: ipDenied parses both families', () => {
  assert.equal(ipDenied(4, '127.0.0.1'), true);
  assert.equal(ipDenied(4, '8.8.8.8'), false);
  assert.equal(ipDenied(6, '::1'), true);
  assert.equal(ipDenied(6, 'fe80::1'), true);
  assert.equal(ipDenied(6, '2606:2800:220:1:248:1893:0:1'), false);
});

test('SSRF: the server refuses a loopback OPEN before connecting', async () => {
  // The client dials the local proxy and asks for 127.0.0.1:80. The server,
  // with --deny-private, must answer the SOCKS5 request with a refusal instead
  // of ever connecting to loopback. No internet is involved: the refusal is the
  // only observable, and it happens before any target socket is created.
  const PSK = randomBytes(16);
  const udpPort = 45330 + Math.floor(Math.random() * 500);
  const proxyPort = 46330 + Math.floor(Math.random() * 500);
  const server = new TunnelServer({ psk: PSK, port: udpPort, denyPrivate: true, log: () => {} });
  const client = new TunnelClient({ psk: PSK, host: '127.0.0.1', port: udpPort, listenPort: proxyPort });
  await server.start();
  await client.start();
  try {
    const rep = await new Promise<number>((resolve) => {
      const s = connect(proxyPort, '127.0.0.1');
      let phase = 0;
      let done = false;
      const finish = (v: number): void => { if (!done) { done = true; resolve(v); } };
      const timer = setTimeout(() => finish(-1), 5000);
      s.on('connect', () => s.write(Buffer.from([5, 1, 0]))); // SOCKS5 greeting
      s.on('data', (b: Buffer) => {
        if (phase === 0 && b.length === 2) {
          phase = 1;
          s.write(Buffer.concat([Buffer.from([5, 1, 0, 1]), v4('127.0.0.1'), Buffer.from([0, 80])]));
          return;
        }
        if (phase === 1 && b.length >= 2 && b[0] === 5) { clearTimeout(timer); finish(b[1]); }
      });
      s.on('error', () => { clearTimeout(timer); finish(-1); });
    });
    assert.notEqual(rep, 0, `a loopback OPEN must be refused before connecting (rep=${rep})`);
    assert.equal(rep, 5, 'the refusal maps to SOCKS5 ConnectionRefused');
  } finally {
    client.stop(); server.stop();
  }
});

// ---------------------------------------------------------------------------
// 11. Pre-auth budget: the CPU cost of the gate is charged before the crypto
// ---------------------------------------------------------------------------

test('GATE: the pre-auth budget is charged before the decryption', async (t) => {
  // Symptom: the pre-auth gate ran *before* the per-IP and global session rate
  // limits, so every unseen-salt datagram paid two HKDF derivations plus an
  // AES-GCM open no matter who sent it. A 37-byte forged-salt flood — no PSK
  // required — measured ~36 us/packet, i.e. ~28k pps saturated a core. The fix
  // charges a dedicated budget (per IP and global) *before* that decryption, so
  // the work an unauthenticated sender can force is bounded by a number.
  //
  // Observable: once one source has spent its budget, a genuinely valid sealed
  // HELLO from it must not create a session; after the 1 s window rolls over the
  // same HELLO must succeed. The second half matters — it proves the drop above
  // was the budget and not a malformed handshake.
  const PSK = randomBytes(16);
  const udpPort = 45900 + Math.floor(Math.random() * 400);
  const server = new TunnelServer({ psk: PSK, port: udpPort, log: () => {} });
  await server.start();
  const sock = createSocket('udp4');
  await new Promise<void>((r) => sock.bind(0, '127.0.0.1', () => r()));
  t.after(() => { sock.close(); server.stop(); });

  const sessions = (): number =>
    (server as unknown as { sessions: Map<string, unknown> }).sessions.size;
  const sealedHello = (saltByte: number): Buffer => {
    const salt = Buffer.alloc(8, saltByte);
    // flags without CAP_TLV: a HELLO that claims a TLV block but carries none
    // is rejected by the peer as BadCaps, and this test is not about TLVs.
    const hello = buildHello({ ver: 1, data: 10, parity: 6, flags: LOCAL_FLAGS_M1 }, randomBytes(16));
    return sealOobBootstrap(PSK, salt, hello, 0x01 /* C2S */)!;
  };
  const send = (b: Buffer): void => { sock.send(b, udpPort, '127.0.0.1'); };
  const wait = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

  // Baseline: a lone sealed HELLO from this source does create a session.
  send(sealedHello(0x21));
  await wait(150);
  assert.equal(sessions(), 1, 'a sealed HELLO with an unspent budget must establish');

  // Spend the whole per-IP budget on junk (each datagram gets a fresh random
  // salt so none is recognised). The gate must now refuse even a valid HELLO.
  const junk = Buffer.alloc(37);
  for (let i = 0; i < MAX_PREAUTH_PER_IP; ++i) { randomBytes(37).copy(junk); send(junk); }
  await wait(250);
  send(sealedHello(0x22));
  await wait(250);
  assert.equal(sessions(), 1,
    'a valid HELLO must not create a session once the source spent its pre-auth budget');

  // Roll the window: the same source is served again.
  await wait(1100);
  send(sealedHello(0x23));
  await wait(250);
  assert.equal(sessions(), 2, 'the budget window rolls over and the HELLO goes through');
});

// ---------------------------------------------------------------------------
// 12. Mux window recovery: a squeezed stream must not stay pinned at 1 byte
// ---------------------------------------------------------------------------

test('STREAM: a mux stream squeezed by the byte budget gets its window back', () => {
  // Symptom: enforceStreamBytesBudget() drives an over-share stream down to a
  // 1-byte receive window on every tick, and the only thing that lifts it back
  // is updateStreamWindows(). That call sat *behind* an early return comparing
  // the *default* stream's targets, and the squeezed stream is never the
  // default one — so on an idle path (bandwidth estimate 0) the targets never
  // changed, the return fired on every cadence, and the sid stayed at a 1-byte
  // window forever. The connection was dead but the session looked healthy.
  const s = new Session(
    { psk: Buffer.alloc(16, 7), salt: Buffer.alloc(8, 3), sendDirection: 0x02,
      recvDirection: 0x01, role: 1, mtu: 1040, pmtud: false },
    { sendWire: () => {}, read: () => {}, closed: () => {} },
  );
  const api = s as unknown as {
    mux: boolean; streams: Map<number, Stream>; lastWindowUpdateMs: number;
    bbr: { bwBytesPerMs: number };
    updateStreamWindows: (nowMs: number) => void;
  };
  api.mux = true;
  const st = new Stream(
    { maxSegment: 1200, rcvBufBytes: 4 << 20, initialSrttMs: 40, idleTimeoutMs: 1e9 },
    { send: () => {}, read: () => {}, closed: () => {} },
  );
  api.streams.set(7, st);

  st.setWindows(st.sendWindowBytes, 1);           // what the budget enforcer does
  assert.equal(st.rcvBufBytes, 1, 'the enforcer-style shrink lands');
  for (let i = 0; i < 10; ++i) { api.lastWindowUpdateMs = -1e9; api.updateStreamWindows(1000 * i); }
  assert.ok(st.rcvBufBytes > 1,
    `after 10 window updates the squeezed stream still advertises ${st.rcvBufBytes} B`);

  // Same on a path with a live bandwidth estimate, where the targets are
  // recomputed rather than inherited from the default stream.
  st.setWindows(st.sendWindowBytes, 1);
  api.bbr.bwBytesPerMs = 0.5;
  for (let i = 0; i < 5; ++i) { api.lastWindowUpdateMs = -1e9; api.updateStreamWindows(50000 + 1000 * i); }
  assert.ok(st.rcvBufBytes > 1,
    `with a bandwidth estimate the squeezed stream still advertises ${st.rcvBufBytes} B`);
});
