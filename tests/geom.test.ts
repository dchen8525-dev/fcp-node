// Interleaved repair groups, group-size adaptation and ACK redundancy.
//
// These three features share one property: none of them is visible in a
// throughput number unless the path actually loses bursts, so each test here
// reproduces the failure mode it is meant to remove instead of asserting that
// a flag was parsed.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { computeMtuLimits, FrameTx, FrameRx, packTxFrame, type TxSymbol } from '../src/fec/frame.ts';
import { chooseGroupD } from '../src/control/controller.ts';
import { Stream } from '../src/stream/stream.ts';
import { encodeAckV2 } from '../src/stream/segment.ts';
import { D_FLOOR, MAX_ACTIVE_SETS, MAX_SETS_PER_SECOND } from '../src/constants.ts';

const LIMITS = computeMtuLimits(1400, 20);

/** Drive one sender, drop the symbols at the given wire positions, and count
 *  what the receiver ends up delivering. */
function runLaneless(d: number, k: number, lanes: number, nSegs: number, dropAt: Set<number>) {
  const emitted: TxSymbol[] = [];
  const tx = new FrameTx(d, LIMITS, (s) => emitted.push(s));
  tx.setInterleave(lanes);
  tx.setK(k);
  const payloads = Array.from({ length: nSegs }, (_, i) =>
    Buffer.alloc(40, 0).fill(i & 0xff, 0, 4));
  for (const p of payloads) tx.onSegment(p, 0);

  const delivered: Buffer[] = [];
  const rx = new FrameRx({
    d, p: k, maxSymbolLen: LIMITS.symbolMax,
    deliver: (b) => delivered.push(b), oob: () => {},
  });
  emitted.forEach((s, i) => { if (!dropAt.has(i)) rx.onDatagram(packTxFrame(s), 0); });

  // Every payload carries its index in the first byte, so completeness is
  // exact rather than a count of whatever happened to arrive.
  const got = new Set(delivered.map((b) => b[0]));
  return { emitted, delivered, got, payloads, tx };
}

test('interleave: the same k survives a burst L times longer', () => {
  // d=10, k=3. Four consecutive data symbols are dropped mid-stream. Without
  // interleaving they all land in one group, which then needs k >= 4 and
  // cannot be repaired at all. With four lanes they are one loss per group and
  // three repairs per group are plenty.
  const drop = new Set([4, 5, 6, 7]);

  const flat = runLaneless(10, 3, 1, 40, drop);
  assert.equal(flat.tx.closedFull, 4, '4 groups of 10');
  assert.equal(flat.got.size, 36, 'the burst wiped out one whole group');

  const spread = runLaneless(10, 3, 4, 40, drop);
  assert.equal(spread.tx.closedFull, 4, 'still 4 groups of 10');
  assert.equal(spread.got.size, 40, 'every payload recovered');

  // Interleaving must not buy that with extra redundancy: same number of
  // parity symbols, same number of groups.
  assert.equal(spread.tx.paritySymbols, flat.tx.paritySymbols, 'parity cost is unchanged');
  assert.equal(spread.emitted.length, flat.emitted.length, 'same datagrams on the wire');
});

test('interleave: segments are dealt round-robin across lanes', () => {
  const { emitted, tx } = runLaneless(10, 3, 3, 30, new Set());
  assert.equal(tx.closedFull, 3);
  assert.equal(tx.interleave, 3, 'the depth the caller asked for');
  // Set ids are allocated in the order lanes open, so the first three data
  // symbols belong to sets 0, 1, 2 and the fourth returns to set 0.
  const firstData = emitted.filter((s) => (s.typeK & 0x03) === 0).slice(0, 6);
  assert.deepEqual(firstData.map((s) => s.setId), [0, 1, 2, 0, 1, 2]);
  assert.deepEqual(firstData.map((s) => s.index), [0, 0, 0, 1, 1, 1]);
  // Set ids in flight stay inside a window of L, which is what keeps the
  // receiver's anchor logic and gap placeholders out of the picture.
  assert.equal(tx.openN, 0, 'all lanes closed after the last symbol');
});

test('interleave: a lane that stops filling still gets its parity', () => {
  // 23 segments over 4 lanes leaves two lanes one short of closing. The flush
  // timer must settle those lanes on its own, or their last symbols would sit
  // unrepaired forever.
  const emitted: TxSymbol[] = [];
  const tx = new FrameTx(10, LIMITS, (s) => emitted.push(s));
  tx.setInterleave(4);
  tx.setK(2);
  for (let i = 0; i < 23; ++i) tx.onSegment(Buffer.alloc(30, i), 0);
  assert.equal(tx.openN, 23, 'every lane still holds its symbols');
  tx.onTick(1000);
  assert.equal(tx.openN, 0, 'the flush timer settled every lane');
  const parity = emitted.filter((s) => (s.typeK & 0x03) === 1);
  assert.ok(parity.length > 0, 'partial lanes emitted repair symbols');
  // A short lane scales its parity: ceil(k*n/d), never more than k.
  for (const s of parity) assert.ok(((s.typeK >>> 5) & 0x07) <= 2);
});

test('a group that closes short still repairs, because the decoder derives kEff too', () => {
  // d=10 with two segments flushed early: the sender scales the code length to
  // kEff = ceil(6*2/10) = 2 (so a short group does not pay for six parity
  // symbols), and stamps the session's k=6 in every header. The Cauchy
  // coefficient is 1/(r XOR (k+c)), i.e. it depends on k, so decoding that
  // group with 6 solves a different linear system: the shard comes out garbage
  // and only the length/padding sanity check keeps it out of the stream.
  // Before this test existed the parity of *every* short group was dead weight
  // (recovered=0, badRecon=1), which interleaving and adaptive d make common.
  const payloads = [Buffer.alloc(40, 0x11), Buffer.alloc(40, 0x22)];
  const emitted: TxSymbol[] = [];
  const tx = new FrameTx(10, LIMITS, (s) => emitted.push(s));
  tx.setK(6);
  for (const p of payloads) tx.onSegment(p, 0);
  tx.onTick(5000);
  assert.equal(emitted.length, 4, '2 data + kEff=2 parity');

  const delivered: Array<{ payload: Buffer; recovered: boolean }> = [];
  const rx = new FrameRx({
    d: 10, p: 6, maxSymbolLen: LIMITS.symbolMax,
    deliver: (b, info) => delivered.push({ payload: Buffer.from(b), recovered: info.recovered }),
    oob: () => {},
  });
  // Everything except the first data symbol.
  emitted.forEach((s, i) => { if (i !== 0) rx.onDatagram(packTxFrame(s), 1); });
  const counters = (rx as unknown as { counters: { badRecon: number; recovered: number } }).counters;
  assert.equal(counters.badRecon, 0, 'the reconstruction must not be rejected as garbage');
  const repaired = delivered.filter((d) => d.recovered);
  assert.equal(repaired.length, 1, 'the lost shard was repaired from the short group');
  assert.deepEqual(repaired[0].payload, payloads[0], 'and it is the original bytes');
});

test('control segments never join a data group', () => {
  const emitted: TxSymbol[] = [];
  const tx = new FrameTx(10, LIMITS, (s) => emitted.push(s));
  tx.setInterleave(4);
  tx.setK(3);
  assert.equal(tx.groupD, 10, 'groups are cut with the negotiated geometry');
  tx.onSegment(Buffer.alloc(20, 1), 0);
  tx.onSegment(Buffer.alloc(20, 2), 0);
  assert.equal(tx.openN, 2, 'two data lanes hold one symbol each');

  tx.onSegment(Buffer.alloc(20, 3), 0, true); // an ACK
  assert.equal(tx.openN, 2, 'the control lane closed immediately');
  const ack = emitted.filter((s) => (s.typeK & 0x03) === 0 && s.symbol[2] === 3);
  assert.equal(ack.length, 1);
  assert.equal(emitted.filter((s) => s.setId === ack[0].setId).length, 2, 'one ACK, one repair symbol');
});

test('adaptive d: shrinks when k would saturate, never below the floor', () => {
  // p = 6, HEADROOM = 3. 20% loss wants k = 0.6 d, so d = 10 is exactly at the
  // ceiling; 30% wants 0.9 d and has to drop to d = 6.
  assert.equal(chooseGroupD({ dMax: 10, p: 6, loss: 0.0, symPerSec: 0 }), 10);
  assert.equal(chooseGroupD({ dMax: 10, p: 6, loss: 0.02, symPerSec: 0 }), 10);
  assert.equal(chooseGroupD({ dMax: 10, p: 7, loss: 0.30, symPerSec: 0 }), 7);
  assert.equal(chooseGroupD({ dMax: 10, p: 6, loss: 0.40, symPerSec: 0 }), 5);
  // 55% loss: 6 / (0.55*3) = 3.6 -> the floor holds it at 4, and the caller is
  // expected to see k pinned at the ceiling (that path is past what parity can
  // express, not something a group size can fix).
  assert.equal(chooseGroupD({ dMax: 10, p: 6, loss: 0.55, symPerSec: 0 }), D_FLOOR);
  // A negotiated ceiling below the floor wins: --fec-data=2 runs d = 2.
  assert.equal(chooseGroupD({ dMax: 2, p: 6, loss: 0.4, symPerSec: 0 }), 2);
  // p = 0 (framing without repair): group size is cosmetic, leave it alone.
  assert.equal(chooseGroupD({ dMax: 10, p: 0, loss: 0.4, symPerSec: 5000 }), 10);
});

test('adaptive d: the set-rate bound outranks the loss bound', () => {
  // 2000 symbols/s: at d = 10 that is 200 groups/s, above MAX_SETS_PER_SECOND,
  // so d is raised to the point where the receiver can still settle them.
  const d = chooseGroupD({ dMax: 40, p: 6, loss: 0.30, symPerSec: 2000 });
  assert.equal(d, Math.ceil(2000 / MAX_SETS_PER_SECOND));
  assert.ok(d * MAX_SETS_PER_SECOND >= 2000, 'the sender stays inside the set budget');
  // And the budget itself has to fit the receiver's map: a set occupies a slot
  // for 2 s (settle at 1 s, delete at 2 s), so the sustained rate must stay at
  // or below half of MAX_ACTIVE_SETS. The constant used to say 150, which is
  // 300 resident sets against a cap of 256.
  assert.ok(MAX_SETS_PER_SECOND * 2 <= MAX_ACTIVE_SETS,
    `set budget ${MAX_SETS_PER_SECOND}/s must fit ${MAX_ACTIVE_SETS} slots over 2 s`);
});

test('ACK copies: a flagged duplicate is not loss evidence', () => {
  const out: Buffer[] = [];
  const s = new Stream(
    { maxSegment: 1200, initialSrttMs: 50, ackV2: true, idleTimeoutMs: 1e9 },
    { send: (b) => out.push(b), read: () => {}, closed: () => {} },
  );
  const ack = encodeAckV2(0, 65536, []);
  s.onSegment(ack, 0);
  assert.equal(s.ackCopiesDropped, 0, 'the original is processed');
  const copy = encodeAckV2(0, 65536, [], true);
  s.onSegment(copy, 1);
  assert.equal(s.ackCopiesDropped, 1, 'the copy carried nothing new and was dropped');
  // Dropping it must not disturb the duplicate-ACK path: a genuine repeated
  // ACK (unflagged) is still allowed through.
  s.onSegment(ack, 2);
  assert.equal(s.ackCopiesDropped, 1, 'an unflagged repeat is not a copy');
});

test('ACK copies: a copy that arrives first is still a usable ACK', () => {
  // The whole point of the copies is that the original may be the one lost.
  const out: Buffer[] = [];
  const s = new Stream(
    { maxSegment: 1200, initialSrttMs: 50, ackV2: true, idleTimeoutMs: 1e9 },
    { send: (b) => out.push(b), read: () => {}, closed: () => {} },
  );
  s.onSegment(encodeAckV2(0, 7777, [], true), 0);
  assert.equal(s.ackCopiesDropped, 0, 'nothing to dedupe against');
  assert.equal(s.peerWindowBytes, 7777, 'the copy updated the send window');
  // A later copy of the same content is then recognised.
  s.onSegment(encodeAckV2(0, 7777, [], true), 1);
  assert.equal(s.ackCopiesDropped, 1);
});

test('ACK copies: the copy bit round-trips through the segment codec', () => {
  const plain = encodeAckV2(1234, 4096, [{ start: 2000, end: 2100 }]);
  const copy = encodeAckV2(1234, 4096, [{ start: 2000, end: 2100 }], true);
  assert.equal(plain[9] & 0x80, 0, 'the range count keeps bit 7 clear');
  assert.equal(copy[9] & 0x80, 0x80, 'the copy sets it');
  assert.equal(plain[9] & 0x7f, copy[9] & 0x7f, 'the count itself is unchanged');
});
