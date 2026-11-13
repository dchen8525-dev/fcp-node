// Tests for the throughput work: FEC convergence floor, ack coalescing,
// multi-segment fast retransmit with cool-down, and zero-window probing.
//
// Every case encodes a bug that was measured on the real VPS link; the comment
// above each one names the symptom it prevents from coming back.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { AdaptiveFec } from '../src/control/controller.ts';
import { Stream } from '../src/stream/stream.ts';
import { encodeData, encodeAck, encodeAckV2, parseSegment } from '../src/stream/segment.ts';
import {
  STREAM_TYPE_DATA, STREAM_TYPE_ACK, STREAM_TYPE_ACK_V2,
  ACK_EVERY_SEGMENTS, HOLE_DUP_ACK_MS, MIN_RETX_INTERVAL_MS, FAST_RETX_SEGMENTS,
  ZERO_WINDOW_PROBE_MS,
} from '../src/constants.ts';

function makeStream(over: Record<string, number> = {}) {
  const sent: Buffer[] = [];
  const read: Buffer[] = [];
  const s = new Stream(
    { maxSegment: 100, initialSrttMs: 50, idleTimeoutMs: 100000, ...over },
    {
      send: (b) => sent.push(b),
      read: (b) => read.push(b),
      closed: () => {},
    },
  );
  const acks = () => sent.filter((b) => {
    const t = parseSegment(b)?.type;
    return t === STREAM_TYPE_ACK || t === STREAM_TYPE_ACK_V2;
  }).length;
  const datas = () => sent.filter((b) => parseSegment(b)?.type === STREAM_TYPE_DATA).length;
  return { s, sent, read, acks, datas };
}

// --- FEC ------------------------------------------------------------------

/** Feed the receiver-side fallback `groups` settled groups of d=10 shards, each
 *  having lost `lossPct`% of its data shards, once per FECSTAT interval. The
 *  fallback reads the whole-session ratio, so the caller just has to advance
 *  the clock past one sampling interval between calls. */
function feedLocal(fec: AdaptiveFec, groups: number, lossPct: number): void {
  let g = 0;
  let now = 0;
  for (let i = 0; i < groups; i += 100) {
    now += 2000;
    g += 100;
    const expected = g * 10;
    fec.noteLocalCounters(expected, Math.round(expected * (1 - lossPct / 100)), now);
  }
}

test('FEC: k never settles at 0, because a hole-free report does not prove a clean path', () => {
  // Measured: with k=0 a single lost datagram froze cumAck until RTO, and the
  // link collapsed from ~190 KB/s to 46 KB/s. The floor is one repair symbol.
  const fec = new AdaptiveFec({ d: 10, p: 3 });
  assert.equal(fec.currentK(), 3);
  feedLocal(fec, 1200, 0);
  assert.equal(fec.currentK(), 1);
});

test('FEC: with parity capped at 0 the controller still works', () => {
  const fec = new AdaptiveFec({ d: 10, p: 0 });
  assert.equal(fec.currentK(), 0);
  feedLocal(fec, 600, 0);
  assert.equal(fec.currentK(), 0);
});

test('FEC: a group still incomplete at the 1 s deadline is not loss', () => {
  // Measured on the VPS path: every set is accounted 1 s after its first
  // symbol, while the path itself is 560 ms wide and ~360 groups are in flight
  // per second. 77% of groups were therefore "incomplete" at their deadline on
  // a link whose shard loss was 0%, and the old group ledger drove k to the
  // parity ceiling (6) and printed loss=77%. Counting shards reads 0% here.
  const fec = new AdaptiveFec({ d: 10, p: 6 });
  feedLocal(fec, 1200, 0);
  assert.equal(fec.currentLoss(), 0, 'no shard was actually missing');
  assert.equal(fec.currentK(), 1, 'k falls to the floor instead of pinning at 6');
});

test('FEC: the local fallback reports shard loss and raises k from it', () => {
  const fec = new AdaptiveFec({ d: 10, p: 6 });
  feedLocal(fec, 500, 30);
  assert.equal(fec.currentLoss(), 0.3, '30% of data shards never arrived');
  assert.equal(fec.currentK(), 5, 'ceil(10 * 0.30 * 1.5)');
});

test('FEC: the local fallback samples at the FECSTAT cadence, not per tick', () => {
  // A 10 ms delta divides arrivals from one flight by settlements from the
  // previous one and read 38% on a 0-4% path. Inside one interval nothing moves.
  const fec = new AdaptiveFec({ d: 10, p: 6 });
  assert.equal(fec.currentK(), 3);
  fec.noteLocalCounters(1000, 700, 0);   // 30% missing, but first call only arms
  fec.noteLocalCounters(1000, 700, 500);
  fec.noteLocalCounters(1000, 700, 1500);
  assert.equal(fec.currentK(), 3, 'no sample before FECSTAT_INTERVAL_MS');
  fec.noteLocalCounters(2000, 1400, 2600);
  assert.ok(fec.currentLoss() > 0.29, `sampled after the interval (${fec.currentLoss()})`);
});

test('FEC: the peer report wins over the local fallback', () => {
  // The fallback observes the inbound direction; on an asymmetric link it must
  // never overwrite what the peer measured about our outbound direction.
  const fec = new AdaptiveFec({ d: 10, p: 6 });
  feedLoss(fec, 3, 0);
  const settled = fec.currentK();
  feedLocal(fec, 500, 50);
  assert.equal(fec.currentK(), settled, 'local 50% does not move a peer-reported k');
  assert.equal(fec.currentLoss(), 0, 'and does not overwrite the peer loss rate');
});

/** Feed `rounds` FECSTAT reports, each covering 100 groups of d=10 shards at
 *  the given shard-loss percentage. Counters accumulate because the controller
 *  works on per-report deltas. */
function feedLoss(fec: AdaptiveFec, rounds: number, lossPct: number): void {
  let groups = 0;
  for (let i = 0; i < rounds; ++i) {
    groups += 100;
    const expected = groups * 10;
    fec.onFecstat({
      setsFull: groups, setsPartial: 0,
      dataExpected: expected,
      dataRxOrig: Math.round(expected * (1 - lossPct / 100)),
    } as never);
  }
}

test('FEC: repaired loss still counts, because the signal is raw shard loss', () => {
  // The old signal was `1 - setsPartial/groups`, which reads 1.0 whenever FEC
  // repairs everything — i.e. it was blind on exactly the paths where parity
  // matters. Counting shards that were never received first-hand reports 35%
  // loss here even though no set failed.
  const fec = new AdaptiveFec({ d: 10, p: 7 });
  const before = fec.currentK();
  feedLoss(fec, 3, 35);
  assert.ok(fec.currentK() > before, 'heavy shard loss raises k');
  assert.equal(fec.currentK(), 6, 'ceil(10 * 0.35 * 1.5)');
});

test('FEC: every loss sample maps to a target, so there is no dead band', () => {
  // Measured: 16.5% loss put every sample in the old 0.80..0.99 band and k
  // never moved for a whole session. Each of these must move k somewhere.
  const quiet = new AdaptiveFec({ d: 10, p: 7 });
  feedLoss(quiet, 8, 3);
  assert.equal(quiet.currentK(), 1, '3% loss needs one repair symbol');

  const rough = new AdaptiveFec({ d: 10, p: 7 });
  feedLoss(rough, 8, 40);
  assert.equal(rough.currentK(), 6, '40% loss needs six');
});

test('FEC: k pins at the negotiated parity ceiling instead of overshooting it', () => {
  const fec = new AdaptiveFec({ d: 10, p: 3 });
  feedLoss(fec, 3, 50);
  assert.equal(fec.currentK(), 3, '50% loss wants 8, the handshake allows 3');
});

test('FEC: tiny samples are ignored so one lost group cannot spike k', () => {
  const fec = new AdaptiveFec({ d: 10, p: 7 });
  for (let i = 1; i <= 5; ++i) {
    fec.onFecstat({ setsFull: i * 2, setsPartial: 0, dataExpected: i * 20, dataRxOrig: 2 } as never);
  }
  assert.equal(fec.currentK(), 3, 'the 3-symbol start is kept');
});

// --- ACK coalescing -------------------------------------------------------

test('STREAM: acks are coalesced, one per ACK_EVERY_SEGMENTS', () => {
  const { s, acks } = makeStream();
  for (let i = 0; i < ACK_EVERY_SEGMENTS - 1; ++i) {
    s.onSegment(encodeData(i * 94, 0, Buffer.alloc(94)), 1);
    assert.equal(acks(), 0, `no ack after ${i + 1} segment(s)`);
  }
  s.onSegment(encodeData((ACK_EVERY_SEGMENTS - 1) * 94, 0, Buffer.alloc(94)), 1);
  assert.equal(acks(), 1, 'one ack covers the whole batch');
});

test('STREAM: a sequence gap makes the ack immediate', () => {
  // Fast retransmit only works if the peer hears about the hole at once.
  const { s, acks } = makeStream();
  s.onSegment(encodeData(0, 0, Buffer.alloc(94)), 1);
  s.onSegment(encodeData(94 * 3, 0, Buffer.alloc(94)), 1); // leaves a gap
  assert.ok(acks() >= 1, 'gap is reported without waiting for the counter');
});

// --- Fast retransmit ------------------------------------------------------

test('STREAM: three duplicate acks resend FAST_RETX_SEGMENTS, not one', () => {
  const { s, sent, datas } = makeStream({ sendWindowBytes: 65536, ackV2: true });
  s.write(Buffer.alloc(94 * 10), 0);
  const before = datas();
  assert.equal(before, 10);
  // SACK reports only the last segment, so 0..8 are provably missing and the
  // burst cap is what has to hold them back.
  const blocks = [{ start: 94 * 9, end: 94 * 10 }];
  for (let i = 0; i < 4; ++i) s.onSegment(encodeAckV2(0, 65535, blocks), 300);
  assert.equal(datas() - before, FAST_RETX_SEGMENTS);
  assert.equal(sent.length > 0, true);
});

test('STREAM: a duplicate ack with no SACK evidence does not start a retransmit', () => {
  // Measured on the live path: 162 segments sent and 162 of them retransmits,
  // while 300 KB of new data sat queued. Every duplicate ack that carried no
  // new receive information walked six more segments out of the window and
  // most of them were already at the peer.
  const { s, datas } = makeStream({ sendWindowBytes: 65536 });
  s.write(Buffer.alloc(94 * 5), 0);
  const before = datas();
  for (let i = 0; i < 12; ++i) s.onSegment(encodeAck(0, 65535, 0, 0), 400);
  assert.equal(datas() - before, 0, 'nothing is proven missing');
});

test('STREAM: a segment is not resent inside the cool-down window', () => {
  // Measured: without this guard the same three segments were re-emitted every
  // duplicate-ack round and the retransmit ratio passed 80%.
  // Only FAST_RETX_SEGMENTS segments in flight, so every candidate has the same
  // send time and the cool-down applies to the whole retransmit set.
  const { s, datas } = makeStream({ sendWindowBytes: 65536, ackV2: true });
  s.write(Buffer.alloc(94 * FAST_RETX_SEGMENTS), 0);
  const before = datas();
  assert.equal(before, FAST_RETX_SEGMENTS);
  const blocks = [{ start: 94 * FAST_RETX_SEGMENTS, end: 94 * (FAST_RETX_SEGMENTS + 1) }];
  for (let i = 0; i < 4; ++i) s.onSegment(encodeAckV2(0, 65535, blocks), 300);
  assert.equal(datas() - before, FAST_RETX_SEGMENTS);
  for (let i = 0; i < 4; ++i) s.onSegment(encodeAckV2(0, 65535, blocks), 300 + MIN_RETX_INTERVAL_MS - 1);
  assert.equal(datas() - before, FAST_RETX_SEGMENTS, 'still inside the cool-down');
  for (let i = 0; i < 4; ++i) s.onSegment(encodeAckV2(0, 65535, blocks), 300 + MIN_RETX_INTERVAL_MS + 1);
  assert.equal(datas() - before, FAST_RETX_SEGMENTS * 2, 'cool-down expired, resend allowed');
});

// --- Zero window ----------------------------------------------------------

test('STREAM: a closed peer window is probed with one byte every 50 ms', () => {
  // The old probe was `nowMs % 1000 < 30`, which on a 10 ms tick could miss its
  // slot entirely and stall for a full second. It also called pump(), which
  // cannot send anything when the window is zero.
  const { s, datas } = makeStream({ sendWindowBytes: 500 });
  s.write(Buffer.alloc(2000), 0); // window fills, the rest stays queued
  const before = datas();
  s.onSegment(encodeAck(0, 0, 0, 0), 0); // peer advertises rwnd = 0
  s.onTick(ZERO_WINDOW_PROBE_MS - 1);
  assert.equal(datas(), before, 'nothing before the probe interval');
  s.onTick(ZERO_WINDOW_PROBE_MS);
  assert.equal(datas(), before + 1, 'exactly one probe byte');
});

test('STREAM: a re-sent segment waits a full RTT, a first-time one does not', () => {
  // Measured: the retransmit ratio was 58% because the fixed 120 ms cool-down
  // is shorter than a 200-400 ms path RTT, so every copy was duplicated while
  // its predecessor was still in flight. The first retransmit is free (three
  // dup acks already proved the loss); a repeat has to wait one RTT.
  const { s, datas } = makeStream({ sendWindowBytes: 65536, initialSrttMs: 400, ackV2: true });
  s.write(Buffer.alloc(94 * 6), 0);
  const blocks = [{ start: 94 * 6, end: 94 * 7 }];
  const dup = (at: number): void => {
    for (let i = 0; i < 4; ++i) s.onSegment(encodeAckV2(0, 65535, blocks), at);
  };
  const before = datas();
  assert.equal(before, 6);

  dup(100);
  assert.equal(datas() - before, 0, 'reordering guard: younger than one RTT');

  dup(450);
  assert.equal(datas() - before, 6, 'first retransmit goes out after a full RTT');

  dup(900);
  assert.equal(datas() - before, 6, 'still inside 1.25 RTT of the copy in flight');

  dup(960);
  assert.equal(datas() - before, 12, 'later the copy is provably lost too');
});

test('STREAM: the acked callback reports newly cum-acked bytes, not queued ones', () => {
  // Window sizing needs the send-direction delivery rate. Before this the BDP
  // was computed from stream.read(), i.e. from ACK trickle in the other
  // direction, which is why the send window never followed the path.
  const seen: number[] = [];
  const s = new Stream(
    { maxSegment: 100, initialSrttMs: 50, sendWindowBytes: 65536 },
    {
      send: () => {},
      read: () => {},
      closed: () => {},
      acked: (bytes) => seen.push(bytes),
    },
  );
  s.write(Buffer.alloc(94 * 3), 0);
  assert.deepEqual(seen, [], 'writing is not delivery');
  s.onSegment(encodeAck(188, 65535, 0, 0), 10);
  assert.deepEqual(seen, [188], 'cum ack of two segments');
  s.onSegment(encodeAck(188, 65535, 0, 0), 20);
  assert.deepEqual(seen, [188], 'a duplicate ack delivers nothing new');
  s.onSegment(encodeAck(282, 65535, 0, 0), 30);
  assert.deepEqual(seen, [188, 94], 'only the increment');
});

test('STREAM: a stale ACK never moves the cumulative point backwards', () => {
  // UDP/FEC deliver ACKs out of order. Assigning sndUna = cum unconditionally
  // inflated the in-flight count and shrank the send window for good.
  const { s } = makeStream({ sendWindowBytes: 65536 });
  s.write(Buffer.alloc(94 * 4), 0);
  s.onSegment(encodeAck(188, 65535, 0, 0), 10);
  assert.equal(s.cumAcked, 188);
  s.onSegment(encodeAck(94, 65535, 0, 0), 20); // reordered older ACK
  assert.equal(s.cumAcked, 188, 'the cumulative point is monotonic');
  assert.equal(s.inflightBytes, 188, 'in-flight bytes did not grow');
});

test('STREAM: a one-byte-per-run flood is bounded by the chunk ceiling', () => {
  // The byte window alone does not bound memory: 1024 one-byte runs cost a
  // Buffer object each and can be 100x their payload in heap.
  const { s, read } = makeStream({ rcvBufBytes: 256 * 1024 });
  for (let i = 0; i < 1200; ++i) {
    s.onSegment(encodeData(2 + i * 2, 0, Buffer.from([1])), i);
  }
  assert.ok(s.oobDrops > 0, 'the ceiling dropped runs instead of growing the heap');
  assert.equal(read.length, 0, 'nothing becomes contiguous');
  s.onSegment(encodeData(0, 0, Buffer.from([9])), 2000);
  assert.equal(Buffer.concat(read).length, 1, 'the hole itself is still accepted');
});

// --- Window ---------------------------------------------------------------

test('STREAM: setWindows moves both the send window and the advertised buffer', () => {
  const { s } = makeStream();
  s.setWindows(512 * 1024, 1024 * 1024);
  assert.equal(s.sendWindowBytes, 512 * 1024);
  assert.equal(s.rcvBufBytes, 1024 * 1024);
});

test('STREAM: a v2 ack with sack ranges suppresses retransmitting sacked data', () => {
  const { s, datas } = makeStream({ sendWindowBytes: 65536, ackV2: true });
  s.write(Buffer.alloc(94 * 10), 0);
  const before = datas();
  // cum stays at 0 (hole at the front) but the tail is reported as received.
  const blocks = [{ start: 94 * 3, end: 94 * 10 }];
  for (let i = 0; i < 4; ++i) s.onSegment(encodeAckV2(0, 65535, blocks), 300);
  assert.equal(datas() - before, 3, 'only the three unsacked segments');
});
