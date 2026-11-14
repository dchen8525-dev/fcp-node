// Control plane: adaptive FEC redundancy, BBR-lite pacing hints, FECSTAT
// reporter and JSONL controller trace. Port shape of src/fcp/{strategy,bbr,
// reporter,trace}.{h,cc}. These controllers change only *when* and *how much*
// we send; no on-wire field depends on their internal state.

import {
  DEFAULT_D, DEFAULT_P, DEFAULT_SRTT_MS,
  FECSTAT_INTERVAL_MS, MAX_PARITY,
  BBR_BW_WINDOW_MS, FEC_HEADROOM, FEC_DROP_STREAK, FEC_LOSS_MIN_SHARDS,
  FLG_DIRECTION, FLG_LEDGER, FLG_TAIL_DROPPED, FLG_LATE_RECOVERY,
  type DirectionValue,
} from '../constants.ts';
import { encodeFecstat, makeFecstatPacket, type FecstatPacket } from '../fec/fecstat.ts';
import type { RxCounters } from '../fec/frame.ts';

export interface ControllerConfig {
  d?: number; p?: number; pinnedK?: number;
  initialSrttMs?: number; trace?: (line: string) => void;
}

/**
 * FEC redundancy controller.
 *
 * Drives `k` (repair symbols per group) from a directly measured **shard loss
 * rate**, not from a recovery ratio.
 *
 * The old rule was `recovery = 1 - failed/total`, raise when below 0.80 and
 * lower when above 0.99. On the VPS path 16.5% of datagrams are lost, which put
 * every sample in the 0.80..0.99 dead band: k never moved at all, so the
 * controller was decorative for the whole session. The replacement has no dead
 * band — every sample maps to a target k:
 *
 *     target = ceil(d * loss * FEC_HEADROOM), clamped to [kMin, agreed parity]
 *
 * Loss comes from FECSTAT as `1 - dataRxOrig / (settled groups x d)`: the
 * fraction of data shards that never arrived first-hand. That number is immune
 * to FEC doing its job — unlike the delivered/expected ratio, which reads 1.0
 * on a link that drops a sixth of its packets precisely *because* FEC repaired
 * them — and unlike "groups that were incomplete at a deadline", which reads
 * high on any path whose RTT is longer than that deadline.
 */
export class AdaptiveFec {
  private k: number;
  private pinnedK: number;
  /** Never drop below one repair symbol while the session allows parity at
   *  all. A loss report can arrive as 0 for a whole interval while a hole
   *  freezes cumAck — k would settle at 0 and then every single lost datagram
   *  stalls the stream until RTO. One symbol per group covers that for 10%
   *  bandwidth. */
  private kMin: number;
  /** Negotiated parity ceiling. k can never exceed it: parity symbols past
   *  index d+p-1 are rejected by the peer as IndexPastS, so sending more only
   *  burns bandwidth. This replaced the old ratio budget, which was computed
   *  from the compile-time DEFAULT_D and could therefore authorise k=7 while
   *  the session had only agreed to P=3. */
  private p: number;
  /** Group size, needed to turn a per-shard loss rate into a per-group k. */
  private d: number;
  /** Last local sample time; the fallback runs at the FECSTAT cadence. */
  private lastLocalMs = 0;
  /** Consecutive low-loss samples; a step down needs FEC_DROP_STREAK of them. */
  private lowStreak = 0;
  /** Last measured path shard-loss rate, for diagnostics. */
  private lossRate = 0;
  /** True once a usable FECSTAT has arrived. The local ledger is then only a
   *  fallback: it describes the *inbound* direction, and using it to size
   *  outbound parity is wrong on an asymmetric link. */
  private peerReports = false;
  /** Below-threshold accumulation: a slow path (< FEC_LOSS_MIN_SHARDS per
   *  report) used to be a permanent blind spot — k never moved on it. Samples
   *  from consecutive reports are summed until the noise floor is crossed,
   *  then evaluated as one window. */
  private pendExpected = 0;
  private pendOrig = 0;
  private trace?: (line: string) => void;

  constructor(cfg: ControllerConfig = {}) {
    this.p = Math.max(0, Math.min(MAX_PARITY, cfg.p ?? DEFAULT_P));
    this.d = Math.max(1, cfg.d ?? DEFAULT_D);
    this.pinnedK = cfg.pinnedK ?? 0;
    this.kMin = Math.min(1, this.p);
    this.k = this.pinnedK > 0 ? Math.min(this.pinnedK, this.p) : Math.min(3, this.p);
    this.trace = cfg.trace;
  }
  currentK(): number { return this.k; }
  /** Fraction of inbound data shards that had to be reconstructed. */
  currentLoss(): number { return this.lossRate; }

  /** Narrow the ceiling to the parity the handshake actually agreed on. The
   *  local P is only a proposal; the wire uses min(localP, peerP), and parity
   *  past that is rejected by the peer, so k has to follow the agreed value. */
  setParityCeiling(p: number): void {
    this.p = Math.max(0, Math.min(MAX_PARITY, p));
    this.kMin = Math.min(1, this.p);
    if (this.k > this.p) this.k = this.p;
  }

  /** Same for the group size: the target k is a per-group count, so it has to
   *  use the d the wire settled on, not the one this side proposed. */
  setGroupSize(d: number): void {
    if (d > 0) this.d = d;
  }

  /**
   * Receiver-side fallback, used only when the peer sends no FECSTAT (an older
   * peer, or a session that has not reported yet). Same numerator as onFecstat
   * — data shards that never arrived first-hand — but over the *whole session*
   * instead of an interval, sampled at the FECSTAT cadence.
   *
   * Two things this must not do, both learned by measuring:
   *
   *  - It must not judge a *group*. `noteGroup(k, failed)` counted groups whose
   *    orig+recov was still short of n when the 1 s settle clock fired. On a
   *    560 ms path at 3.5 MB/s that clock is shorter than the flight time of a
   *    whole second of groups, so 77% of them were "failed" on a 0%-loss path:
   *    k pinned at the parity ceiling and the stats line printed loss=77%.
   *  - It must not take a *fine-grained delta*. Shards arrive at T and their
   *    group settles at T+1 s, so a 10 ms delta divides arrivals from one
   *    flight by settlements from the previous one: on the same link that read
   *    38%. Lifetime counters take the clock out of the ratio entirely, and a
   *    fallback may be coarse — the peer's FECSTAT is the fast path.
   *
   * Direction caveat, unchanged: this observes the *inbound* direction while
   * our k governs the outbound one, which is why it is only a fallback.
   */
  noteLocalCounters(expectedShards: number, rxOrig: number, nowMs: number): void {
    if (this.pinnedK > 0 || this.peerReports) return;
    if (!this.lastLocalMs) { this.lastLocalMs = nowMs; return; }
    if (nowMs - this.lastLocalMs < FECSTAT_INTERVAL_MS) return;
    this.lastLocalMs = nowMs;
    if (expectedShards < FEC_LOSS_MIN_SHARDS) return;
    const lost = Math.max(0, Math.min(expectedShards, expectedShards - rxOrig));
    this.adjust(lost / expectedShards, 'fec_k_local');
  }

  /**
   * Peer's FECSTAT drives our send-side k.
   *
   * The loss rate is `1 - dataRxOrig / (groups x d)`: the fraction of data
   * shards the peer did *not* get first-hand. Two details matter more than the
   * formula:
   *
   *  - The denominator is the number of shards that were sent, not the number
   *    that were delivered. Dividing by `dataDelivered` silently forgives every
   *    group FEC failed to repair — those shards are not in the counter at all
   *    — so the worse the repair worked, the healthier the path looked. At 16%
   *    datagram loss that read 4%, which drove k down to 1 and made the
   *    underestimate self-fulfilling.
   *  - Deltas between reports, not lifetime counters, so a burst of loss moves
   *    k within one 2 s interval instead of being averaged away.
   */
  onFecstat(stat: FecstatPacket): void {
    if (this.pinnedK > 0) return;
    // FECSTAT counters are per interval (the reporter emits deltas), exactly
    // like the C++ settlement view. `data_expected` is Σ n_used over the sets
    // settled in this interval, so short flush groups cannot inflate the
    // denominator the way `groups x d` did. Samples below the noise floor are
    // summed across reports so a slow path (~120 KB/s and under) eventually
    // crosses FEC_LOSS_MIN_SHARDS and gets a k decision too.
    const expected = stat.dataExpected >>> 0;
    const rxOrig = stat.dataRxOrig >>> 0;
    if (expected < FEC_LOSS_MIN_SHARDS) {
      this.pendExpected += expected;
      this.pendOrig += rxOrig;
      if (this.pendExpected < FEC_LOSS_MIN_SHARDS) return;
      const evalExpected = this.pendExpected;
      const evalOrig = this.pendOrig;
      this.pendExpected = 0;
      this.pendOrig = 0;
      this.peerReports = true;
      const lost = Math.max(0, Math.min(evalExpected, evalExpected - evalOrig));
      this.adjust(lost / evalExpected, 'fecstat_loss');
      return;
    }
    this.pendExpected = 0;
    this.pendOrig = 0;
    this.peerReports = true;
    const lost = Math.max(0, Math.min(expected, expected - rxOrig));
    this.adjust(lost / expected, 'fecstat_loss');
  }

  /** No dead band: every sample has a target. Raise immediately, lower only
   *  after sustained evidence, hold only when the target equals the current k. */
  private adjust(loss: number, event: 'fecstat_loss' | 'fec_k_local'): void {
    this.lossRate = loss;
    const need = Math.ceil(this.d * loss * FEC_HEADROOM);
    const target = Math.min(this.p, Math.max(this.kMin, need));
    if (target > this.k) {
      this.k = target;
      this.lowStreak = 0;
    } else if (target < this.k) {
      if (++this.lowStreak >= FEC_DROP_STREAK) { this.lowStreak = 0; --this.k; }
    } else {
      this.lowStreak = 0;
    }
    this.trace?.(JSON.stringify({
      t: event, k: this.k, target, loss, cap: this.p,
      // A pin at the ceiling is not convergence: it means the path wants more
      // parity than the handshake agreed to.
      ceiling: this.k === this.p && need > this.p ? 1 : 0,
    }));
  }
}

/** BBR v1/v2 lite: only exposes pacing/srtt hints to the reactor. */
export class BbrLite {
  version: 1 | 2 = 2;
  srttMs: number;
  minRttMs = 0;
  bwBytesPerMs = 0;
  private epochStartMs = 0;
  private deliveredBytes = 0;
  private samples: Array<{ ms: number; bw: number }> = [];
  private trace?: (line: string) => void;

  constructor(initialSrttMs = DEFAULT_SRTT_MS, trace?: (line: string) => void) {
    this.srttMs = initialSrttMs > 0 ? initialSrttMs : DEFAULT_SRTT_MS;
    this.trace = trace;
  }
  onRtt(srttMs: number): void { this.srttMs = srttMs; if (!this.minRttMs || srttMs < this.minRttMs) this.minRttMs = srttMs; }
  onDelivery(bytes: number, nowMs: number): void {
    if (!this.epochStartMs) this.epochStartMs = nowMs;
    this.deliveredBytes += bytes;
    const span = nowMs - this.epochStartMs;
    if (span >= this.srttMs) {
      const bw = this.deliveredBytes / Math.max(1, span);
      this.epochStartMs = nowMs;
      this.deliveredBytes = 0;
      // Windowed maximum, not the last epoch. Delivery is bursty — one epoch
      // sees a whole window arrive, the next sees nothing — so the per-epoch
      // rate swings 10x. Feeding that into the BDP made the stream window flap
      // between 262 KiB and 690 KiB every 250 ms, which in turn flapped the
      // window we advertise to the peer.
      this.samples.push({ ms: nowMs, bw });
      const cutoff = nowMs - BBR_BW_WINDOW_MS;
      while (this.samples.length && this.samples[0].ms < cutoff) this.samples.shift();
      let best = 0;
      for (const s of this.samples) if (s.bw > best) best = s.bw;
      this.bwBytesPerMs = best;
      this.trace?.(JSON.stringify({ t: 'bbr', v: this.version, srtt: this.srttMs, bw: this.bwBytesPerMs }));
    }
  }
  pacingGapMs(bytes: number): number {
    if (this.bwBytesPerMs <= 0) return 0;
    return Math.max(0, bytes / this.bwBytesPerMs);
  }
}

/** The settlement counters FECSTAT carries, snapshotted per interval. */
interface CounterSnapshot {
  setsExpected: number; dataExpected: number; dataRxOrig: number;
  dataRecoveredDl: number; dataRecoveredLate: number; dataDelivered: number;
  parityRx: number; parityExpected: number; setsKUnknown: number;
  setsFull: number; lateDup: number; structFail: number;
  setsTailDropped: number; dataLateRx: number; setsPartial: number;
  ledgerGroups: number; ledgerFailed: number; ledgerKHist: number[];
}

function snapshotCounters(c: RxCounters): CounterSnapshot {
  return {
    setsExpected: c.setsExpected, dataExpected: c.dataExpected, dataRxOrig: c.dataRxOrig,
    dataRecoveredDl: c.recovered, dataRecoveredLate: c.recoveredLate,
    dataDelivered: c.dataDelivered, parityRx: c.parityRx, parityExpected: c.parityExpected,
    setsKUnknown: c.setsKUnknown, setsFull: c.setsFull, lateDup: c.lateDup,
    structFail: c.structFail, setsTailDropped: c.setsTailDropped,
    dataLateRx: c.lateDup, setsPartial: c.setsPartial,
    ledgerGroups: c.ledgerGroups, ledgerFailed: c.ledgerFailed,
    ledgerKHist: [...c.ledgerKHist],
  };
}

function counterDelta(now: number, before: number): number {
  return (now - before) >>> 0;
}

/** Builds one 128-byte FECSTAT every 2 s from the receiver's counters. */
export class FecstatReporter {
  private salt: Uint8Array;
  private lastMs = 0;
  private authFail = 0; private structFail = 0;
  private dataBytes = 0; private parityBytes = 0;
  private latencies: number[] = [];
  private direction: DirectionValue;
  /** Cumulative settlement counters as of the previous report, so every
   *  FECSTAT field is the interval delta the protocol specifies. Without it
   *  the same shard stayed in `data_rx_orig` forever and the peer's
   *  `1 - data_rx_orig/data_expected` converged on the session average. */
  private prev: CounterSnapshot | null = null;

  constructor(salt: Uint8Array, direction: DirectionValue) {
    this.salt = Buffer.from(salt); this.direction = direction;
  }
  addDataBytes(n: number): void { this.dataBytes = (this.dataBytes + n) >>> 0; }
  addParityBytes(n: number): void { this.parityBytes = (this.parityBytes + n) >>> 0; }
  recordRepairLatency(ms: number): void { this.latencies.push(ms & 0xffff); }
  noteAuthFail(): void { ++this.authFail; }
  noteStructFail(): void { ++this.structFail; }

  onTick(nowMs: number, counters: RxCounters, accountedThroughSetId: number): Buffer | null {
    if (!this.lastMs) {
      this.lastMs = nowMs;
      this.prev = snapshotCounters(counters);
      return null;
    }
    if (nowMs - this.lastMs < FECSTAT_INTERVAL_MS) return null;
    const interval = Math.min(60000, nowMs - this.lastMs);
    this.lastMs = nowMs;
    const cur = snapshotCounters(counters);
    const prev = this.prev ?? cur;
    this.prev = cur;
    const d = counterDelta;
    const p = makeFecstatPacket(this.salt);
    p.intervalMs = interval;
    p.flg = FLG_DIRECTION; // receiver reports the "you -> me" direction
    p.accountedThroughSetId = accountedThroughSetId >>> 0;
    p.setsExpected = d(cur.setsExpected, prev.setsExpected);
    p.dataExpected = d(cur.dataExpected, prev.dataExpected);
    p.dataRxOrig = d(cur.dataRxOrig, prev.dataRxOrig);
    p.dataRecoveredDl = d(cur.dataRecoveredDl, prev.dataRecoveredDl);
    p.dataRecoveredLate = d(cur.dataRecoveredLate, prev.dataRecoveredLate);
    p.dataDelivered = d(cur.dataDelivered, prev.dataDelivered);
    p.parityRx = d(cur.parityRx, prev.parityRx);
    p.parityExpected = d(cur.parityExpected, prev.parityExpected);
    p.setsKUnknown = d(cur.setsKUnknown, prev.setsKUnknown);
    p.setsFull = d(cur.setsFull, prev.setsFull);
    p.setsPartial = d(cur.setsPartial, prev.setsPartial);
    p.setsTailDropped = d(cur.setsTailDropped, prev.setsTailDropped);
    p.lateDup = d(cur.lateDup, prev.lateDup);
    p.dataLateRx = d(cur.dataLateRx, prev.dataLateRx);
    p.structFail = (d(cur.structFail, prev.structFail) + this.structFail) >>> 0;
    p.authFail = this.authFail >>> 0;
    p.dataBytesRx = this.dataBytes >>> 0;
    p.parityBytesRx = this.parityBytes >>> 0;
    if (p.dataRecoveredLate > 0) p.flg |= FLG_LATE_RECOVERY;
    if (p.setsTailDropped > 0) p.flg |= FLG_TAIL_DROPPED;
    const lats = this.latencies.slice().sort((a, b) => a - b);
    if (lats.length) {
      // Nearest rank, matching reporter.cc's percentile().
      const at = (pct: number): number => {
        const rank = Math.min(lats.length, Math.max(1, Math.ceil(pct * lats.length / 100)));
        return lats[rank - 1] & 0xffff;
      };
      p.repairLatP50Ms = at(50);
      p.repairLatP95Ms = at(95);
    }
    const ledgerGroups = d(cur.ledgerGroups, prev.ledgerGroups);
    if (ledgerGroups > 0) {
      const failed = d(cur.ledgerFailed, prev.ledgerFailed);
      p.ledgerGroups = ledgerGroups;
      p.ledgerFailPpm = Math.min(1000000, Math.round(1e6 * failed / ledgerGroups));
      let bestK = 0;
      let bestN = 0;
      for (let k = 1; k <= 7; ++k) {
        const n = d(cur.ledgerKHist[k] ?? 0, prev.ledgerKHist[k] ?? 0);
        if (n > bestN) { bestN = n; bestK = k; }
      }
      p.ledgerMeta = bestK;
      p.flg |= FLG_LEDGER;
    }
    this.authFail = 0; this.structFail = 0;
    this.dataBytes = 0; this.parityBytes = 0; this.latencies = [];
    return encodeFecstat(p);
  }
}
