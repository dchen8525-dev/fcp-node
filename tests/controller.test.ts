// Direct unit tests for the two controllers that had no coverage of their own:
// BbrLite (bandwidth estimate / pacing) and FecstatReporter (128-byte report).
//
// They drive the whole session's send window and the peer's FEC controller, so
// a silent internal regression used to surface only as "throughput feels off".
// FecstatReporter is asserted through encode→decode so the wire fields — not
// just the in-memory packet — are what the tests pin down.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import { BbrLite, FecstatReporter } from '../src/control/controller.ts';
import { decodeFecstat, FecstatStatus } from '../src/fec/fecstat.ts';
import type { RxCounters } from '../src/fec/frame.ts';
import {
  BBR_BW_WINDOW_MS, DEFAULT_SRTT_MS, FECSTAT_INTERVAL_MS,
  Direction, FLG_DIRECTION, FLG_LEDGER, FLG_LATE_RECOVERY,
  FLG_TAIL_DROPPED,
} from '../src/constants.ts';

const SALT = Buffer.from('0123456789abcdef', 'latin1');

function counters(over: Partial<RxCounters> = {}): RxCounters {
  return {
    structFail: 0, stale: 0, lateDup: 0, recovered: 0, recoveredLate: 0,
    dataRxOrig: 0, parityRx: 0, dataDelivered: 0, dataLateRx: 0, retiredDropped: 0,
    aheadDropped: 0, setsPartial: 0, setsFull: 0, setsTailDropped: 0,
    decodeAttempts: 0, badRecon: 0, symbolBudgetDrops: 0,
    setsExpected: 0, dataExpected: 0, parityExpected: 0, setsKUnknown: 0,
    ledgerGroups: 0, ledgerFailed: 0, ledgerKHist: [],
    ...over,
  };
}

// --- BbrLite --------------------------------------------------------------

test('BbrLite: the estimate is the windowed MAX, not the last epoch', () => {
  const b = new BbrLite(200);
  // First delivery only anchors the epoch; the estimate lands one srtt later.
  b.onDelivery(1000, 100);
  assert.equal(b.bwBytesPerMs, 0);
  // Epoch 1: 1000 bytes over 200 ms = 5 B/ms.
  b.onDelivery(0, 300);
  assert.equal(b.bwBytesPerMs, 5);
  // Epoch 2: 200 bytes over 200 ms = 1 B/ms. A last-epoch estimator would
  // collapse the window here; the windowed max must hold at 5.
  b.onDelivery(200, 500);
  assert.equal(b.bwBytesPerMs, 5);
  assert.equal(b.pacingGapMs(100), 20);
});

test('BbrLite: samples older than the window are dropped', () => {
  const b = new BbrLite(100);
  b.onDelivery(1000, 100); // anchors the epoch
  b.onDelivery(0, 200); // fast epoch: 1000 / 100 = 10 B/ms
  assert.equal(b.bwBytesPerMs, 10);
  // Advance past the window with a zero-byte epoch: the fast sample (ms=200)
  // falls before the cutoff and is evicted, leaving only the zero sample.
  b.onDelivery(0, BBR_BW_WINDOW_MS + 300);
  assert.equal(b.bwBytesPerMs, 0);
});

test('BbrLite: with no estimate there is no pacing', () => {
  const b = new BbrLite();
  assert.equal(b.bwBytesPerMs, 0);
  assert.equal(b.pacingGapMs(5000), 0);
});

test('BbrLite: minRtt tracks the floor, srtt tracks the latest', () => {
  const b = new BbrLite();
  b.onRtt(300);
  b.onRtt(120);
  b.onRtt(250);
  assert.equal(b.minRttMs, 120);
  assert.equal(b.srttMs, 250);
});

test('BbrLite: a non-positive constructor srtt falls back to the default', () => {
  assert.equal(new BbrLite(0).srttMs, DEFAULT_SRTT_MS);
  assert.equal(new BbrLite(-5).srttMs, DEFAULT_SRTT_MS);
});

test('BbrLite: trace lines carry the version and current estimate', () => {
  const lines: string[] = [];
  const b = new BbrLite(100, (l) => lines.push(l));
  b.onDelivery(500, 100);
  b.onDelivery(0, 200); // closes the epoch, emits one trace line
  assert.equal(lines.length, 1);
  const j = JSON.parse(lines[0]);
  assert.equal(j.t, 'bbr');
  assert.equal(j.v, 2);
  assert.equal(j.bw, 5);
  assert.equal(j.srtt, 100);
});

// --- FecstatReporter ------------------------------------------------------

function decode(buf: Buffer) {
  const r = decodeFecstat(buf, SALT);
  assert.equal(r.status, FecstatStatus.Ok);
  assert.ok(r.packet);
  return r.packet!;
}

// onTick uses `lastMs === 0` as its "not primed" sentinel. Real callers pass
// Date.now(), so a non-zero anchor is the honest shape; starting at 0 would
// keep re-priming forever (an unrelated edge case, not what we test here).
const T0 = 1000;

test('FecstatReporter: first tick only primes, no report emitted', () => {
  const r = new FecstatReporter(SALT, Direction.C2S);
  assert.equal(r.onTick(T0, counters(), 0), null);
  assert.equal(r.onTick(T0 + FECSTAT_INTERVAL_MS - 1, counters(), 0), null);
});

test('FecstatReporter: fields are interval DELTAS, not cumulative totals', () => {
  const r = new FecstatReporter(SALT, Direction.C2S);
  r.onTick(T0, counters(), 0); // prime
  const c1 = counters({ setsExpected: 10, dataExpected: 100, dataRxOrig: 90 });
  r.onTick(T0 + FECSTAT_INTERVAL_MS, c1, 7);
  const p1 = decode(r.onTick(T0 + FECSTAT_INTERVAL_MS * 2, c1, 9)!);
  // Counters did not advance in the last interval → every delta is zero.
  assert.equal(p1.setsExpected, 0);
  assert.equal(p1.dataExpected, 0);
  assert.equal(p1.dataRxOrig, 0);

  const c2 = counters({ setsExpected: 12, dataExpected: 120, dataRxOrig: 105 });
  const p2 = decode(r.onTick(T0 + FECSTAT_INTERVAL_MS * 3, c2, 11)!);
  assert.equal(p2.setsExpected, 2);
  assert.equal(p2.dataExpected, 20);
  assert.equal(p2.dataRxOrig, 15);
  assert.equal(p2.accountedThroughSetId, 11);
});

test('FecstatReporter: repeated settlement keys are held and merged until the key advances', () => {
  const r = new FecstatReporter(SALT, Direction.C2S);
  r.onTick(T0, counters(), 0);
  r.addDataBytes(10);
  r.noteAuthFail();
  r.recordRepairLatency(10);
  const c1 = counters({ setsExpected: 1, dataExpected: 10 });
  const p1 = decode(r.onTick(T0 + FECSTAT_INTERVAL_MS, c1, 5)!);
  assert.equal(p1.dataBytesRx, 10);
  assert.equal(p1.authFail, 1);

  r.addDataBytes(20);
  r.noteAuthFail(); r.noteAuthFail();
  r.recordRepairLatency(20); r.recordRepairLatency(30);
  const c2 = counters({ setsExpected: 3, dataExpected: 30 });
  assert.equal(r.onTick(T0 + FECSTAT_INTERVAL_MS * 2, c2, 5), null);
  assert.equal(r.onTick(T0 + FECSTAT_INTERVAL_MS * 3, c2, 5), null);

  const c3 = counters({ setsExpected: 5, dataExpected: 50 });
  const p2 = decode(r.onTick(T0 + FECSTAT_INTERVAL_MS * 4, c3, 6)!);
  assert.equal(p2.accountedThroughSetId, 6);
  assert.equal(p2.intervalMs, 3000);
  assert.equal(p2.setsExpected, 4, 'delta spans all held intervals');
  assert.equal(p2.dataExpected, 40);
  assert.equal(p2.dataBytesRx, 20);
  assert.equal(p2.authFail, 2);
  assert.equal(p2.repairLatP50Ms, 20);
  assert.equal(p2.repairLatP95Ms, 30);
});

test('FecstatReporter: byte counters and failure counters reset each interval', () => {
  const r = new FecstatReporter(SALT, Direction.C2S);
  r.onTick(T0, counters(), 0);
  r.addDataBytes(1000);
  r.addParityBytes(200);
  r.noteAuthFail();
  r.noteStructFail();
  const p1 = decode(r.onTick(T0 + FECSTAT_INTERVAL_MS, counters(), 7)!);
  assert.equal(p1.dataBytesRx, 1000);
  assert.equal(p1.parityBytesRx, 200);
  assert.equal(p1.authFail, 1);
  assert.equal(p1.structFail, 1);

  // Nothing added in the second interval → local counters are zero, not sticky.
  const p2 = decode(r.onTick(T0 + FECSTAT_INTERVAL_MS * 2, counters(), 9)!);
  assert.equal(p2.dataBytesRx, 0);
  assert.equal(p2.parityBytesRx, 0);
  assert.equal(p2.authFail, 0);
  assert.equal(p2.structFail, 0);
});

test('FecstatReporter: repair latency uses nearest-rank percentiles and masks to 16 bits', () => {
  const r = new FecstatReporter(SALT, Direction.C2S);
  r.onTick(T0, counters(), 0);
  // 5 samples: 10, 20, 30, 40, 70001 (masked to 4465 by & 0xffff).
  for (const ms of [10, 20, 30, 40, 70001]) r.recordRepairLatency(ms);
  const p = decode(r.onTick(T0 + FECSTAT_INTERVAL_MS, counters(), 7)!);
  // Sorted: 10,20,30,40,4465. Nearest-rank P50 = ceil(0.5*5)=3 → 30.
  assert.equal(p.repairLatP50Ms, 30);
  // P95 = ceil(0.95*5)=5 → 4465, and the field is 16-bit clean.
  assert.equal(p.repairLatP95Ms, 4465);
  assert.ok(p.repairLatP95Ms <= 0xffff);
});

test('FecstatReporter: flag bits come from late recovery and tail-dropped sets', () => {
  const r = new FecstatReporter(SALT, Direction.C2S);
  r.onTick(T0, counters(), 0);
  const p = decode(r.onTick(T0 + FECSTAT_INTERVAL_MS, counters({ recoveredLate: 2, setsTailDropped: 1 }), 7)!);
  assert.equal(p.flg & FLG_DIRECTION, FLG_DIRECTION);
  assert.equal(p.flg & FLG_LATE_RECOVERY, FLG_LATE_RECOVERY);
  assert.equal(p.flg & FLG_TAIL_DROPPED, FLG_TAIL_DROPPED);
  assert.equal(p.flg & FLG_LEDGER, 0);
});

test('FecstatReporter: ledger fields only appear with a settled group, ppm capped', () => {
  const r = new FecstatReporter(SALT, Direction.C2S);
  r.onTick(T0, counters(), 0);
  const p = decode(r.onTick(T0 + FECSTAT_INTERVAL_MS, counters({
    ledgerGroups: 4, ledgerFailed: 1, ledgerKHist: [0, 1, 0, 3, 0, 0, 0, 0],
  }), 7)!);
  assert.equal(p.flg & FLG_LEDGER, FLG_LEDGER);
  assert.equal(p.ledgerGroups, 4);
  assert.equal(p.ledgerFailPpm, 250000);
  assert.equal(p.ledgerMeta, 3); // k=3 was the most frequent

  // More failures than groups must not wrap past 1e6.
  const r2 = new FecstatReporter(SALT, Direction.C2S);
  r2.onTick(T0, counters(), 0);
  const p2 = decode(r2.onTick(T0 + FECSTAT_INTERVAL_MS, counters({
    ledgerGroups: 1, ledgerFailed: 5,
  }), 9)!);
  assert.equal(p2.ledgerFailPpm, 1000000);
});

test('FecstatReporter: interval is clamped and matching salt is required', () => {
  const r = new FecstatReporter(SALT, Direction.C2S);
  r.onTick(T0, counters(), 0);
  const buf = r.onTick(T0 + FECSTAT_INTERVAL_MS * 100, counters(), 7)!;
  assert.equal(decode(buf).intervalMs, 60000);
  assert.equal(decodeFecstat(buf, Buffer.from('ffffffffffffffff', 'latin1')).status, FecstatStatus.BadSalt);
});

test('FecstatReporter: dataLateRx is independent of lateDup on the wire', () => {
  // REGRESSION: snapshotCounters used dataLateRx: c.lateDup, so an interval
  // with only duplicate arrivals reported a fake late-original count (and a
  // real late original could never be reported). The two are distinct C++
  // counters (settle.cc kDataLate vs kDataDuplicate).
  const r = new FecstatReporter(SALT, Direction.C2S);
  r.onTick(T0, counters(), 0); // prime
  const dupOnly = counters({ lateDup: 3, dataLateRx: 0 });
  const p1 = decode(r.onTick(T0 + FECSTAT_INTERVAL_MS, dupOnly, 7)!);
  assert.equal(p1.lateDup, 3);
  assert.equal(p1.dataLateRx, 0, 'duplicates must not appear as late originals');

  const both = counters({ lateDup: 5, dataLateRx: 2 });
  const p2 = decode(r.onTick(T0 + FECSTAT_INTERVAL_MS * 2, both, 9)!);
  assert.equal(p2.lateDup, 2, 'delta from 3 -> 5');
  assert.equal(p2.dataLateRx, 2, 'delta from 0 -> 2, independent of lateDup');
});
