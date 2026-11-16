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

import { Handshake } from '../src/crypto/handshake.ts';
import {
  HandshakeRole, TLV_TYPE_ACK_V2, TLV_TYPE_KEY_UPDATE, TLV_TYPE_MULTIPLEX,
  SymbolType, MAX_RX_SYMBOL_BYTES,
} from '../src/constants.ts';
import { FrameRx, FrameTx, computeMtuLimits } from '../src/fec/frame.ts';
import { packHdr, packTypeK } from '../src/fec/hdr.ts';
import { rsEncode } from '../src/fec/rs.ts';
import { putLe16 } from '../src/wire.ts';
import { Stream } from '../src/stream/stream.ts';
import { encodeAckV2, parseSegment, STREAM_TYPE_ACK_V2 } from '../src/stream/segment.ts';

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

function dataSymbol(setId: number, index: number, k: number, bytes: Buffer): Buffer {
  return Buffer.concat([packHdr({ setId, index, typeK: packTypeK(k, 0, SymbolType.Data) }), bytes]);
}
function paritySymbol(setId: number, index: number, j: number, k: number, bytes: Buffer): Buffer {
  return Buffer.concat([packHdr({ setId, index, typeK: packTypeK(k, j, SymbolType.Parity) }), bytes]);
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
    for (let i = 0; i < 4; ++i) rx.onDatagram(dataSymbol(s, i, k, syms[i]!), now);
    for (let j = 0; j < k; ++j) rx.onDatagram(paritySymbol(s, d + j, j, k, parity[j]!), now);
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
