// Tests for the throughput work: FEC convergence floor, ack coalescing,
// multi-segment fast retransmit with cool-down, and zero-window probing.
//
// Every case encodes a bug that was measured on the real VPS link; the comment
// above each one names the symptom it prevents from coming back.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { AdaptiveFec } from '../src/control/controller.ts';
import { makeFecstatPacket } from '../src/fec/fecstat.ts';
import { Stream } from '../src/stream/stream.ts';
import { encodeData, encodeAck, encodeAckV2, parseSegment } from '../src/stream/segment.ts';
import {
  STREAM_TYPE_DATA, STREAM_TYPE_ACK, STREAM_TYPE_ACK_V2, STREAM_FLAG_FIN,
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

test('FEC: a single tiny sample is ignored so one lost group cannot spike k', () => {
  // One small report stays below the 256-shard noise floor and changes
  // nothing. (Consecutive small reports ACCUMULATE across the floor since the
  // slow-path fix — covered by the accumulation test further down.)
  const fec = new AdaptiveFec({ d: 10, p: 7 });
  for (let i = 1; i <= 4; ++i) {
    fec.onFecstat({ setsFull: i * 2, setsPartial: 0, dataExpected: i * 20, dataRxOrig: 2 } as never);
  }
  assert.equal(fec.currentK(), 3, 'accumulated 200 < 256: the 3-symbol start is kept');
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
  // Only FAST_RETX_SEGMENTS candidates in flight, so every candidate has the
  // same send time and the cool-down applies to the whole retransmit set. The
  // last segment is sacked to prove the others missing; a SACK block must stay
  // inside sndMax (ranges past it are discarded as protocol violations).
  const { s, datas } = makeStream({ sendWindowBytes: 65536, ackV2: true });
  s.write(Buffer.alloc(94 * (FAST_RETX_SEGMENTS + 1)), 0);
  const before = datas();
  assert.equal(before, FAST_RETX_SEGMENTS + 1);
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
  // Six candidates plus one sached tail; a SACK block may not extend past the
  // highest byte this side has sent.
  s.write(Buffer.alloc(94 * 7), 0);
  const blocks = [{ start: 94 * 6, end: 94 * 7 }];
  const dup = (at: number): void => {
    for (let i = 0; i < 4; ++i) s.onSegment(encodeAckV2(0, 65535, blocks), at);
  };
  const before = datas();
  assert.equal(before, 7);

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

// --- P0/P1/P2: burst budget, ack-triggered pump, TLP, adaptive fast-retx,
// --- loss clamp, slow-path FEC accumulation -------------------------------

test('STREAM: the pump budget covers a full ack cycle at large segment size', () => {
  // MTU 1500 -> maxSegment 1436: an ACK_EVERY_SEGMENTS ack cycle is 3 x 1430 B
  // (4290 B), and the budget floor is max(6 KiB, one full ack cycle) — a fixed
  // 6 KiB budget replenished only 71.6% per 6-segment cycle and capped steady
  // throughput at that fraction of window/RTT on the paths PMTUD improves.
  const { s, datas } = makeStream({ maxSegment: 1436, sendWindowBytes: 65536, ackV2: true });
  const payload = 1436 - 6;
  s.write(Buffer.alloc(payload * 20), 0);
  const before = datas();
  assert.ok(before >= 4, 'initial pump is budget-capped');
  s.onSegment(encodeAckV2(payload * 3, 65535, []), 100);
  assert.ok(datas() - before >= 3, `ack-driven pump emitted ${datas() - before}, need >= 3`);
});

test('STREAM: a duplicate ack still pumps queued data', () => {
  // The old onAck returned before pump() unless cum advanced, so queued data
  // waited for the 10 ms tick (679 KB/s ceiling) even after the peer's rwnd
  // reopened. A dup ack carries a fresh rwnd — that is enough to pump.
  const { s, datas } = makeStream({ sendWindowBytes: 200 });
  s.write(Buffer.alloc(94 * 4), 0); // window fills; a remainder stays queued
  const afterWrite = datas();
  assert.ok(afterWrite >= 3);
  s.onSegment(encodeAck(94, 0, 0, 0), 50); // cum advances, but rwnd = 0
  const afterZero = datas();
  s.onSegment(encodeAck(94, 65535, 0, 0), 100); // same cum, rwnd reopened
  assert.ok(datas() > afterZero, 'the dup ack released part of the queue');
});

test('STREAM: an unconfirmed tail is probed before the RTO', () => {
  // Only the tail unacked: no later segment can ever dup-ack it, so without a
  // probe it waited out srtt+4*rttvar (300 ms here). TLP fires at ~1 RTT.
  const { s, datas } = makeStream({ sendWindowBytes: 65536, initialSrttMs: 100 });
  s.write(Buffer.alloc(94 * 3), 0);
  const before = datas();
  assert.equal(before, 3);
  s.onSegment(encodeAck(94 * 2, 65535, 0, 0), 1); // tail is the only unacked
  s.onTick(199);
  assert.equal(datas(), before, 'nothing before the probe deadline');
  s.onTick(200);
  assert.equal(datas(), before + 1, 'tail probe #1 at pto = srtt + 2*rttvar');
  s.onTick(399);
  assert.equal(datas(), before + 1, 'no second probe inside the interval');
  s.onTick(400);
  assert.equal(datas(), before + 2, 'tail probe #2');
  s.onTick(599);
  assert.equal(datas(), before + 2, 'budget exhausted at TLP_MAX_PROBES');
  // A covering ack resets the budget; the NEXT tail is probed on its own clock.
  s.write(Buffer.alloc(94), 401);
  const after = datas();
  s.onSegment(encodeAck(94 * 3, 65535, 0, 0), 402);
  s.onTick(600);
  assert.equal(datas(), after, 'budget was reset by the covering ack');
  s.onTick(601);
  assert.equal(datas(), after + 1, 'the new tail is probed on its own deadline');
});

test('STREAM: a fast-retx round that bought nothing raises the age threshold', () => {
  // Proven-reordering paths kept paying full fast-retx rounds. A silent round
  // (una unchanged for 1.5 sRTT) relaxes the RTT-based age base (up to 2x);
  // fresh candidates whose age sits between the old base and the relaxed base
  // stay put until they are genuinely old.
  const { s, datas } = makeStream({ sendWindowBytes: 65536, initialSrttMs: 50, ackV2: true });
  s.write(Buffer.alloc(94 * 2), 0); // A1, offset 0 (age base = srtt = 50); A2 tail
  const sackA1 = [{ start: 94, end: 188 }];
  for (let i = 0; i < 4; ++i) s.onSegment(encodeAckV2(0, 65535, sackA1), 100);
  const afterRound = datas();
  assert.equal(afterRound, 3, 'A1 fast-retransmitted at age 100 >= base 50');
  s.onTick(250); // silent for 1.5*srtt: relax 1.0 -> 1.3 (base 50 -> 65)
  s.onSegment(encodeAck(188, 65535, 0, 0), 260); // A1+A2 delivered; tx empties
  s.write(Buffer.alloc(94 * 2), 300); // fresh A3, offset 188; A4 tail at 282
  const beforeRound2 = datas();
  const sackA2 = [{ start: 282, end: 376 }];
  for (let i = 0; i < 4; ++i) s.onSegment(encodeAckV2(188, 65535, sackA2), 340);
  assert.equal(datas(), beforeRound2, 'age 40 is below the old base 50');
  for (let i = 0; i < 4; ++i) s.onSegment(encodeAckV2(188, 65535, sackA2), 355);
  assert.equal(datas(), beforeRound2, 'age 55 crosses the old base but sits below relaxed 65');
  for (let i = 0; i < 4; ++i) s.onSegment(encodeAckV2(188, 65535, sackA2), 370);
  assert.equal(datas(), beforeRound2 + 1, 'age 70 crosses the relaxed base: round fires');
});

test('FEC: slow-path samples accumulate until the noise floor is crossed', () => {
  // Below 256 shards per report the controller used to be blind forever; a
  // ~100 KB/s path now sums its reports and gets a k decision like everyone.
  const fec = new AdaptiveFec({ d: 10, p: 7 });
  for (let i = 1; i <= 5; ++i) {
    fec.onFecstat({ setsFull: i * 2, setsPartial: 0, dataExpected: i * 20, dataRxOrig: 2 } as never);
  }
  assert.equal(fec.currentK(), 7, 'accumulated 300 shards at ~97% loss: k climbs to the ceiling');
  const fresh = new AdaptiveFec({ d: 10, p: 7 });
  fresh.onFecstat({ setsFull: 2, setsPartial: 0, dataExpected: 20, dataRxOrig: 2 } as never);
  assert.equal(fresh.currentK(), 3, 'a single tiny report alone stays at the start');
});

test('STREAM: two SACK ranges beyond a hole prove loss and skip the age wait', () => {
  // Two distinct received ranges starting beyond the hole cannot be produced
  // by reordering: the hole segment is provably lost. The age gate (which
  // exists to protect against reordering) is skipped — the retransmit fires
  // immediately even at age ~0.
  const { s, datas } = makeStream({ sendWindowBytes: 65536, initialSrttMs: 400, ackV2: true });
  s.write(Buffer.alloc(94 * 8), 0);
  const before = datas();
  assert.equal(before, 8);
  const ranges = [
    { start: 94 * 2, end: 94 * 3 },
    { start: 94 * 5, end: 94 * 6 },
  ];
  // fastRetransmit still needs the dup-ack trigger; the strong-evidence
  // bypass removes the AGE wait on top of that.
  for (let i = 0; i < 4; ++i) s.onSegment(encodeAckV2(0, 65535, ranges), 5 + i);
  // segs 2..5 are sacked (in-range) and skipped; segs 0..1 have two ranges
  // beyond their end -> the dup-ack trigger fires them with no age wait.
  assert.equal(datas() - before, 2, 'strong evidence fires at the 3rd dup-ack despite age 5ms');
});

test('STREAM: receiving data does not erase duplicate-ACK evidence', () => {
  // emitAck() and onAck() shared haveAckCum/lastAckCum. Emitting one ACK for
  // the *receive* direction rewrote them, so an interleaved inbound segment
  // made the next peer ACK look like a first one: dupAcks reset, fast
  // retransmit never armed, and the loss waited for the RTO chain (seconds).
  const { s, datas } = makeStream({ sendWindowBytes: 65536, initialSrttMs: 400 });
  s.write(Buffer.alloc(94 * 7), 0);
  const before = datas();
  const blocks = [{ start: 94 * 6, end: 94 * 7 }];
  const dupData = encodeData(0, 0, Buffer.alloc(10));
  for (let i = 0; i < 4; ++i) {
    s.onSegment(dupData, 10); // first copy is in-order...
    s.onSegment(dupData, 10); // ...the duplicate makes us emit an ACK
    s.onSegment(encodeAckV2(0, 65535, blocks), 450 + i);
  }
  assert.equal(datas() - before, FAST_RETX_SEGMENTS,
    'duplicate ACKs still arm fast retransmit across inbound traffic');
});

test('STREAM: a single SACK range keeps the age gate', () => {
  // One range beyond the hole is compatible with a single reordered segment;
  // the RTT-based reorder guard must stay in effect.
  const { s, datas } = makeStream({ sendWindowBytes: 65536, initialSrttMs: 400, ackV2: true });
  s.write(Buffer.alloc(94 * 8), 0);
  const before = datas();
  const ranges = [{ start: 94 * 2, end: 94 * 3 }];
  s.onSegment(encodeAckV2(0, 65535, ranges), 5);
  assert.equal(datas() - before, 0, 'single range: age gate holds');
});

// --- lifecycle regressions -------------------------------------------------

test('STREAM: closeWrite is idempotent and refuses data after the FIN', () => {
  // A second closeWrite (an 'end' plus an error path, or a defensive host) used
  // to emit a second FIN one byte past the first; the peer rejects that offset
  // as a protocol violation and never acks it, leaving the stream in SendingFin
  // until the idle timer. Writing after the FIN put bytes past the peer's
  // peerFinAt, where they are discarded while the sender thinks they were sent.
  const { s, sent, datas } = makeStream();
  assert.equal(s.write(Buffer.alloc(10, 1), 0), 10);
  const fins = () => sent.filter((b) => {
    const g = parseSegment(b);
    return g?.type === STREAM_TYPE_DATA && (g.flags & STREAM_FLAG_FIN) !== 0;
  }).length;
  s.closeWrite(0);
  assert.equal(fins(), 1, 'one FIN on the wire');
  s.closeWrite(0);
  assert.equal(fins(), 1, 'the second closeWrite is a no-op');
  assert.equal(s.write(Buffer.from('late'), 0), 0, 'no bytes accepted after the FIN');
  assert.equal(datas(), 2, 'one data segment + the FIN, nothing else');
});

test('STREAM: a SACK range past sndMax is discarded, not trusted', () => {
  // Trusting an over-large range raised sackedHigh beyond anything sent and
  // marked real in-flight segments sacked, which suppresses their fast/RTO
  // retransmission: the bytes are then lost for good.
  const { s } = makeStream();
  for (let i = 0; i < 3; ++i) assert.equal(s.write(Buffer.alloc(10, i + 1), 0), 10);
  s.onSegment(encodeAckV2(0, 1 << 20, [{ start: 0, end: 60000 }]), 0);
  assert.equal(s.sackedHighWater, 0, 'a range beyond the sent bytes changes nothing');
  s.onSegment(encodeAckV2(0, 1 << 20, [{ start: 0, end: 20 }]), 1);
  assert.equal(s.sackedHighWater, 20, 'a legitimate range is still honoured');
});

test('FEC: the local fallback resumes when the peer stops reporting', () => {
  // peerReports was a permanent latch: once any FECSTAT arrived, a peer that
  // went silent (one-way loss, wedged reporter) disabled the local ledger for
  // the rest of the session, so k frozen at its last value.
  const fec = new AdaptiveFec({ d: 10, p: 6 });
  const good = makeFecstatPacket(Buffer.alloc(8));
  good.dataExpected = 1000;
  good.dataRxOrig = 1000; // 0% loss
  good.accountedThroughSetId = 1;
  fec.onFecstat(good, 1000);
  const afterPeer = fec.currentK();
  fec.noteLocalCounters(1000, 500, 2000);
  assert.equal(fec.currentK(), afterPeer, 'a fresh peer report still outranks the local ledger');
  fec.noteLocalCounters(1000, 500, 8000);  // > 3 FECSTAT intervals since 1000
  fec.noteLocalCounters(2000, 1000, 8100); // arms the local sampler
  fec.noteLocalCounters(2000, 1000, 10100);
  assert.equal(fec.currentK(), 6, 'local 50% loss drives k to the ceiling once the peer is silent');
});
