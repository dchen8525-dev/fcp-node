// Idle-time path probe.
//
// Why this exists: every controller in the tunnel (k, d, the window) learns from
// data that is already flowing. FECSTAT needs 256 delivered shards before its
// loss estimate is used, so an idle session has no estimate at all — and the
// first request after a long idle period is served by a geometry chosen for a
// path that may no longer look anything like it. This module puts a bounded
// train of datagrams on the same 5-tuple while the tunnel is idle and reads the
// path back out of it: RTT, jitter, standing queue, one-way loss in each
// direction, and the rate at which loss starts.
//
// Design rules the code below follows:
//
//  - **Bounded.** One run puts at most PROBE_BUDGET_BYTES of DAT payload on the
//    wire, split between the two directions. Echoes are 32-byte oob datagrams
//    and are not counted against the budget (they cost ~5% on top).
//  - **Un-repaired on purpose.** Probes are oob: no FEC, no ARQ, no stream
//    state. ARQ would hide exactly the loss the measurement exists to find, and
//    a probe must never make the session look busy or move a sequence number.
//  - **Paced, never blasted.** The train ramps: PROBE_RAMP_ROUND datagrams at a
//    rate, wait one RTT, then decide. A round whose loss jumps above the running
//    baseline by more than max(PROBE_LOSS_LIMIT, 2.5 sigma) has hit the knee:
//    the rate is bisected once, then the rest of the budget is spent at
//    PROBE_SETTLE_FRACTION of the last clean rate. The comparison is relative
//    because a path that already drops 20% randomly would otherwise "hit the
//    knee" on the very first round and report the start rate as its capacity.
//  - **Both directions.** The initiator sends first (uplink), then asks the peer
//    to play the same train back (downlink). Only the initiator orchestrates:
//    a peer that cannot be reached would otherwise both probe and be probed.
//  - **Self-describing.** Every datagram carries total/seq/sentMs, so the
//    receiver computes its own loss without clock sync, and the sender computes
//    RTT from the echoed sentMs without clock sync either.

import {
  PROBE_MAGIC, PROBE_HDR_LEN,
  PROBE_TYPE_DAT, PROBE_TYPE_ECHO, PROBE_TYPE_SUM, PROBE_TYPE_DOWN,
  PROBE_FLAG_LAST, PROBE_FLAG_DOWN,
  PROBE_RATE_START_BPS, PROBE_RATE_CAP_BPS, PROBE_RAMP_ROUND,
  PROBE_LOSS_LIMIT, PROBE_SETTLE_FRACTION, PROBE_TIMEOUT_MS, PROBE_DRAIN_MS,
  PROBE_SUM_COPIES,
} from '../constants.ts';
import { bytesEqual, getLe16, getLe32, putLe16, putLe32 } from '../wire.ts';

export interface ProbeFrame {
  type: number; flags: number; token: number;
  seq: number; total: number; got: number;
  sentMs: number; size: number; aux: number;
}

export function isProbeFrame(payload: Uint8Array): boolean {
  return payload.length >= PROBE_HDR_LEN && bytesEqual(PROBE_MAGIC, payload, PROBE_MAGIC.length);
}

/** `padTo` gives a DAT its bulk. Padding is zeroed rather than uninitialised:
 *  the envelope already authenticates it, but a probe must never be a way to
 *  put heap contents on the wire. */
export function encodeProbe(f: ProbeFrame, padTo = 0): Buffer {
  const len = Math.max(PROBE_HDR_LEN, padTo);
  const out = Buffer.alloc(len);
  PROBE_MAGIC.copy(out, 0);
  out[8] = f.type;
  out[9] = f.flags;
  putLe32(f.token >>> 0, out, 10);
  putLe16(f.seq & 0xffff, out, 14);
  putLe16(f.total & 0xffff, out, 16);
  putLe16(f.got & 0xffff, out, 18);
  putLe32(f.sentMs >>> 0, out, 20);
  putLe16(f.size & 0xffff, out, 24);
  putLe16(f.aux & 0xffff, out, 26);
  return out;
}

export function decodeProbe(payload: Uint8Array): ProbeFrame | null {
  if (!isProbeFrame(payload)) return null;
  return {
    type: payload[8], flags: payload[9],
    token: getLe32(payload, 10),
    seq: getLe16(payload, 14),
    total: getLe16(payload, 16),
    got: getLe16(payload, 18),
    sentMs: getLe32(payload, 20),
    size: getLe16(payload, 24),
    aux: getLe16(payload, 26),
  };
}

/** One direction of one run. Losses are fractions in 0..1; -1 means "this side
 *  cannot see that number" (the receiver never sees echo loss, the sender never
 *  sees arrival times). */
export interface ProbeDirResult {
  /** DAT payload bytes in this direction. */
  bytes: number;
  /** Wall time of the measured window, ms. */
  ms: number;
  /** Delivered bytes per second, measured on the receiving end. */
  rateBps: number;
  /** Loss as the *sender* sees it (missing echoes ⇒ data lost or echo lost). */
  lossTx: number;
  /** Loss as the *receiver* reports it (summary). The authoritative one. */
  lossRx: number;
  /** Longest run of consecutive missing datagrams, as the receiver saw it. */
  maxRun: number;
  rttMin: number; rttAvg: number; rttMax: number;
  jitterMs: number;
  /** Growth of the one-way delay across the train: a standing queue, if any. */
  queueMs: number;
  /** Last ramp round that was clean, B/s. */
  rampBps: number;
  reason: string;
}

export interface ProbeResult {
  token: number;
  /** Monotonic clock of the local side when the run finished. */
  at: number;
  /** Total run duration, ms. */
  ms: number;
  up: ProbeDirResult | null;
  down: ProbeDirResult | null;
  usedBytes: number;
  budgetBytes: number;
}

/** The JSON contract the desktop shell renders: integers throughout, because
 *  every one of these is a measurement with an error bar, and `189611.890999`
 *  in a UI implies a precision no probe of 512 KiB has. */
export interface ProbeReport {
  at: number; ms: number;
  /** 0 when neither direction could be measured. */
  mtu: number; d: number; k: number;
  used: number; budget: number;
  up: ProbeDirReport | null;
  down: ProbeDirReport | null;
}

export interface ProbeDirReport {
  bytes: number; ms: number; rate: number;
  lossTx: number; lossRx: number; maxRun: number;
  rttMin: number; rttAvg: number; rttMax: number;
  jitter: number; queue: number; ramp: number;
  /** The ramp hit the probe's own pacing ceiling: `ramp` is a lower bound. */
  capped: boolean;
  reason: string;
}

const round = (v: number): number => (Number.isFinite(v) ? Math.round(v) : -1);

function dirReport(d: ProbeDirResult | null): ProbeDirReport | null {
  if (!d) return null;
  // "Effective" = what a bulk transfer would get at the proven pacing rate:
  // ramp x (1 - loss). The raw delivered-bytes-over-train-time number is *not*
  // that — it averages the slow start of the ramp into the result (135 KB/s on a
  // loopback that carries 8 MB/s), so it is left out of the contract entirely.
  const loss = d.lossRx >= 0 ? d.lossRx : d.lossTx;
  const effective = d.rampBps > 0 && loss >= 0 ? d.rampBps * (1 - loss) : d.rateBps;
  return {
    bytes: round(d.bytes), ms: round(d.ms), rate: round(effective),
    // Losses stay as the fraction the UI formats; -1 means "not observable here".
    lossTx: d.lossTx < 0 ? -1 : Math.round(d.lossTx * 10000) / 10000,
    lossRx: d.lossRx < 0 ? -1 : Math.round(d.lossRx * 10000) / 10000,
    maxRun: round(d.maxRun),
    rttMin: round(d.rttMin), rttAvg: round(d.rttAvg), rttMax: round(d.rttMax),
    jitter: round(d.jitterMs), queue: round(d.queueMs), ramp: round(d.rampBps),
    capped: d.rampBps >= PROBE_RATE_CAP_BPS * 0.98,
    reason: d.reason,
  };
}

export function probeReport(r: ProbeResult, geom: { mtu: number; d: number; k: number }): ProbeReport {
  return {
    at: Math.round(r.at), ms: round(r.ms),
    mtu: geom.mtu || 0, d: geom.d || 0, k: geom.k || 0,
    used: round(r.usedBytes), budget: round(r.budgetBytes),
    up: dirReport(r.up), down: dirReport(r.down),
  };
}

export interface ProbeHost {
  /** Put one probe datagram on the wire (already FEC-oob framed + sealed). */
  send: (payload: Buffer) => void;
  srttMs: () => number;
  /** Largest oob payload that still fits the current MTU, header included. */
  dgramSize: () => number;
  /** A local run finished. Never called on the responder side. */
  onResult: (r: ProbeResult) => void;
}

interface TxRun {
  token: number;
  total: number;
  size: number;
  sent: number;
  rateBps: number;
  nextAt: number;
  roundStart: number;
  roundDeadline: number;
  settle: boolean;
  lastCleanBps: number;
  /** Lowest chunk loss seen so far, -1 until the first chunk is judged. The
   *  ramp stops on a *jump* above this, not on absolute loss: a path that
   *  always loses 20% at random would otherwise look congested at every rate. */
  baseline: number;
  /** The rate of the chunk that exceeded the baseline, and whether the midpoint
   *  between it and the last clean rate has already been tried. */
  failedBps: number;
  probedMid: boolean;
  startedAt: number;
  lastTxAt: number;
  lastEchoAt: number;
  got: number;
  seen: Uint8Array;
  rttMin: number; rttMax: number; rttSum: number; rttN: number; rttPrev: number;
  jitterSum: number; jitterN: number;
  /** Report a ProbeDirResult when this train ends (false when serving a peer). */
  report: boolean;
  reason: string;
}

interface RxRun {
  token: number;
  total: number;          // 0 until the first DAT names it
  size: number;
  seen: Uint8Array;
  got: number;
  /** Last clean pacing rate the sender reported in a DAT header, B/s. */
  peerCleanBps: number;
  firstArrival: number;
  lastArrival: number;
  firstSent: number;
  lastSent: number;
  prevDelay: number;
  jitterSum: number; jitterN: number;
  sumAt: number;          // 0 = no summary pending
  sumSent: boolean;
  /** Our own downlink measurement: finish and report. */
  report: boolean;
  startedAt: number;
}

const MAX_RX_RUNS = 4;

function freshTx(token: number, total: number, size: number, rateBps: number, report: boolean, now: number): TxRun {
  return {
    token, total, size, sent: 0,
    rateBps, nextAt: now, roundStart: 0, roundDeadline: 0, settle: false,
    lastCleanBps: 0, baseline: -1, failedBps: 0, probedMid: false,
    startedAt: now, lastTxAt: now, lastEchoAt: 0,
    got: 0, seen: new Uint8Array(Math.max(1, total)),
    rttMin: 0, rttMax: 0, rttSum: 0, rttN: 0, rttPrev: 0,
    jitterSum: 0, jitterN: 0,
    report, reason: 'ok',
  };
}

function freshRx(token: number, report: boolean, now: number): RxRun {
  return {
    token, total: 0, size: 0, seen: new Uint8Array(0), got: 0, peerCleanBps: 0,
    firstArrival: 0, lastArrival: 0, firstSent: 0, lastSent: 0,
    prevDelay: 0, jitterSum: 0, jitterN: 0,
    sumAt: 0, sumSent: false, report, startedAt: now,
  };
}

/** Longest run of consecutive unseen seqs in [0, total). */
function longestGap(seen: Uint8Array, total: number): number {
  let best = 0, cur = 0;
  for (let i = 0; i < total; ++i) {
    if (seen[i]) { cur = 0; continue; }
    if (++cur > best) best = cur;
  }
  return best;
}

export class PathProbe {
  private host: ProbeHost;
  private now = 0;
  /** Local run in flight: 0 when idle. */
  private token = 0;
  private phase: 'up' | 'down' | '' = '';
  private startedAt = 0;
  private budgetBytes = 0;
  private upBudget = 0;
  private downBudget = 0;
  private size = 0;
  private up: TxRun | null = null;
  private upResult: ProbeDirResult | null = null;
  private downResult: ProbeDirResult | null = null;
  private rx = new Map<number, RxRun>();
  /** The down request goes out once and is re-sent if nothing comes back; the
   *  request itself is not part of the train. */
  private downReq: { token: number; total: number; size: number; sentAt: number; tries: number } | null = null;
  /** Highest clean ramp rate from the previous run, so a steady-state probe
   *  starts near the answer instead of re-walking the whole ramp every time. */
  private warmBps = 0;
  /** After the uplink train ends, one RTT is held open for the peer's summary.
   *  The summary is what turns "echoes missing" into "datagrams the receiver
   *  did not get", and it is sent PROBE_DRAIN_MS after the last arrival — so it
   *  lands right around the moment the train is otherwise considered over. */
  private sumWaitUntil = 0;
  private peerSum: { got: number; total: number; maxRun: number } | null = null;
  /** Previous tick, so the pacer can emit `rate x elapsed` per visit instead of
   *  assuming the host ticks every 10 ms. Windows timers land at 15.6 ms, and a
   *  fixed assumption there under-paces every chunk by a third. */
  private lastTickAt = 0;

  constructor(host: ProbeHost) { this.host = host; }

  get running(): boolean { return this.token !== 0; }

  /** Start one run. Returns false when a run is already in flight or the peer
   *  cannot be asked to play a train back (budget 0 / no room for datagrams). */
  start(nowMs: number, budgetBytes: number): boolean {
    if (this.token !== 0) return false;
    const size = this.host.dgramSize();
    if (size < PROBE_HDR_LEN + 64) return false;
    const total = Math.floor(budgetBytes / size);
    if (total < 4) return false;
    this.now = nowMs;
    this.token = (Math.floor(Math.random() * 0xffffffff) >>> 0) || 1;
    this.startedAt = nowMs;
    this.budgetBytes = total * size;
    this.size = size;
    // Uneven on purpose: the uplink train is the one the local end can also
    // read RTT from (echoes come back), and it is the direction a home
    // connection usually loses. The downlink half is still 45% of the budget.
    const upTotal = Math.floor(total * 0.55);
    this.upBudget = upTotal * size;
    this.downBudget = (total - upTotal) * size;
    const rate = this.warmBps > 0
      ? Math.max(PROBE_RATE_START_BPS, Math.min(PROBE_RATE_CAP_BPS, Math.round(this.warmBps * 0.6)))
      : PROBE_RATE_START_BPS;
    this.phase = 'up';
    this.up = freshTx(this.token, upTotal, size, rate, true, nowMs);
    this.upResult = null;
    this.downResult = null;
    this.sumWaitUntil = 0;
    this.peerSum = null;
    return true;
  }

  onTick(nowMs: number): void {
    const dtMs = this.lastTickAt > 0 ? Math.max(1, nowMs - this.lastTickAt) : 10;
    this.lastTickAt = nowMs;
    this.now = nowMs;
    if (this.up) this.driveTx(this.up, nowMs, dtMs);
    else if (this.phase === 'up' && this.upResult && nowMs >= this.sumWaitUntil) {
      this.applyPeerSum();
      this.startDown(nowMs);
    }
    this.driveRx(nowMs);
    this.driveDownRequest(nowMs);
  }

  /** Feed one inbound probe payload. Returns true when it was a probe frame. */
  onFrame(payload: Uint8Array, nowMs: number): boolean {
    const f = decodeProbe(payload);
    if (!f) return isProbeFrame(payload);
    this.now = nowMs;
    if (f.type === PROBE_TYPE_DAT) this.onDat(f, nowMs);
    else if (f.type === PROBE_TYPE_ECHO) this.onEcho(f, nowMs);
    else if (f.type === PROBE_TYPE_SUM) this.onSum(f, nowMs);
    else if (f.type === PROBE_TYPE_DOWN) this.onDownReq(f, nowMs);
    return true;
  }

  // ------------------------------------------------------------- sending

  private driveTx(run: TxRun, now: number, dtMs: number): void {
    // A round boundary we are waiting on: the round's echoes decide whether the
    // next one doubles. Nothing is sent until it resolves, which is why the ramp
    // has gaps — that is the cost of knowing where loss starts.
    if (run.roundDeadline > 0) {
      if (now < run.roundDeadline) return;
      this.evaluateRound(run, now);
      return;
    }
    // Budget for this visit is `rate x elapsed`, not a fixed 12 ms worth: the
    // host's tick is 10 ms by contract but 15.6 ms on Windows, and pacing that
    // ignores the difference runs the whole train a third slow.
    const perTick = Math.max(1, Math.ceil((run.rateBps * (dtMs + 2)) / 1000 / run.size));
    let burst = 0;
    while (run.sent < run.total && burst < perTick && run.nextAt <= now) {
      const seq = run.sent;
      const last = seq === run.total - 1;
      this.host.send(encodeProbe({
        type: PROBE_TYPE_DAT, flags: last ? PROBE_FLAG_LAST : 0, token: run.token,
        seq, total: run.total, got: 0, sentMs: now, size: run.size,
        // KB/s in the header so the *receiver* also learns the pacing rate the
        // sender had proven clean — the downlink half is paced by the peer, and
        // without this the receiver could only report delivery, never capacity.
        aux: Math.min(0xffff, Math.round(run.lastCleanBps / 1000)),
      }, run.size));
      run.sent += 1;
      ++burst;
      run.lastTxAt = now;
      run.nextAt += (run.size * 1000) / run.rateBps;
    }
    // Do not let a limited visit accumulate a debt that has to be repaid as one
    // giant burst: the burst would be the thing the path drops.
    if (run.sent > 0 && run.nextAt < now - dtMs) run.nextAt = now;
    if (!run.settle && run.sent < run.total && run.sent - run.roundStart >= PROBE_RAMP_ROUND) {
      run.roundDeadline = run.lastTxAt + Math.max(40, this.host.srttMs()) + 40;
      return;
    }
    if (run.sent < run.total) return;
    // Train complete. Wait for the stragglers: a lost datagram never answers, so
    // "all echoes in" is only reached on a clean run.
    const quiet = Math.max(300, 2 * this.host.srttMs() + PROBE_DRAIN_MS);
    const until = run.got >= run.total
      ? Math.min(run.lastTxAt + quiet, run.lastEchoAt + 60)
      : run.lastTxAt + quiet;
    if (now >= until) this.finishTx(run, now);
  }

  private evaluateRound(run: TxRun, now: number): void {
    const from = run.roundStart;
    const to = run.sent;
    const len = to - from;
    run.roundDeadline = 0;
    run.roundStart = to;
    run.nextAt = now;
    if (len <= 0) return;
    let lost = 0;
    for (let i = from; i < to; ++i) if (!run.seen[i]) ++lost;
    const frac = lost / len;
    const base = run.baseline < 0 ? 0 : run.baseline;
    // Tolerance = 2.5 binomial sigma on this chunk, floored at 2 points. On a
    // lossy path the sigma term is what keeps the ramp from stopping at chunk 1.
    const sigma = Math.sqrt((base * (1 - base)) / len);
    const tol = Math.max(PROBE_LOSS_LIMIT, 2.5 * sigma);
    // The first chunk has no baseline to compare with: whatever it loses *is* the
    // path's background loss until the rate moves. Only a collapse counts as
    // congestion there, because "loss is non-zero" is not evidence of anything on
    // a path that always loses.
    const jumped = run.baseline < 0
      ? frac > 0.5
      : len >= 8 && frac > run.baseline + tol;
    if (!jumped) {
      run.baseline = run.baseline < 0 ? frac : Math.min(run.baseline, frac);
      run.lastCleanBps = run.rateBps;
      if (run.rateBps >= PROBE_RATE_CAP_BPS) {
        run.settle = true;
        run.rateBps = Math.round(run.lastCleanBps * PROBE_SETTLE_FRACTION);
        return;
      }
      run.rateBps = Math.min(PROBE_RATE_CAP_BPS, run.rateBps * 2);
      return;
    }
    // The count that produced the knee. Spend one chunk on the midpoint so the
    // answer is within 1.5x instead of within 2x, then settle at 90% of whatever
    // was proven clean.
    run.failedBps = run.rateBps;
    const remaining = run.total - run.sent;
    if (!run.probedMid && run.lastCleanBps > 0 && remaining >= PROBE_RAMP_ROUND / 2) {
      run.probedMid = true;
      run.rateBps = Math.max(PROBE_RATE_START_BPS, Math.round((run.lastCleanBps + run.failedBps) / 2));
      return;
    }
    run.settle = true;
    const proven = run.lastCleanBps > 0 ? run.lastCleanBps : Math.round(run.rateBps * (1 - frac));
    run.rateBps = Math.max(PROBE_RATE_START_BPS, Math.round(proven * PROBE_SETTLE_FRACTION));
  }

  private finishTx(run: TxRun, now: number): void {
    if (this.up === run) this.up = null;
    if (!run.report) return;
    const res = this.txResult(run, now);
    this.upResult = res;
    this.applyPeerSum();
    if (this.warmBps === 0 || res.rampBps > this.warmBps) this.warmBps = res.rampBps;
    if (this.phase === 'up') {
      this.sumWaitUntil = now + Math.max(150, this.host.srttMs());
      return;
    }
    this.finish(now);
  }

  /** Attach the receiver's summary to the uplink result, whenever it arrived. */
  private applyPeerSum(): void {
    const s = this.peerSum;
    if (!s || !this.upResult || s.total <= 0) return;
    this.upResult.lossRx = 1 - s.got / s.total;
    this.upResult.maxRun = s.maxRun;
  }

  private txResult(run: TxRun, now: number): ProbeDirResult {
    const bytes = run.sent * run.size;
    const ms = Math.max(1, (run.lastEchoAt || now) - run.startedAt);
    const delivered = run.got * run.size;
    return {
      bytes, ms,
      rateBps: (delivered * 1000) / ms,
      lossTx: run.sent > 0 ? 1 - run.got / run.sent : -1,
      lossRx: -1,
      maxRun: -1,
      rttMin: run.rttN > 0 ? run.rttMin : -1,
      rttAvg: run.rttN > 0 ? run.rttSum / run.rttN : -1,
      rttMax: run.rttN > 0 ? run.rttMax : -1,
      jitterMs: run.jitterN > 0 ? run.jitterSum / run.jitterN : 0,
      queueMs: run.rttN > 1 ? run.rttMax - run.rttMin : 0,
      // The pacing rate proven clean, or — when even the first chunk was over
      // capacity — what the successful part of it actually delivered.
      rampBps: run.lastCleanBps > 0 ? run.lastCleanBps : Math.round(delivered * 1000 / ms),
      reason: run.reason,
    };
  }

  private onEcho(f: ProbeFrame, now: number): void {
    const run = this.up;
    if (!run || run.token !== f.token) return;
    if (f.seq >= run.total) return;
    // `sentMs` rides as 32 bits, and the local clock is wall-clock milliseconds,
    // so the difference has to be taken modulo 2^32 — subtracting the truncated
    // field from the full clock reported a 1.79e12 ms round trip. Signed on
    // purpose: it keeps the value continuous instead of wrapping every 49 days.
    const rtt = Math.max(0, ((now >>> 0) - (f.sentMs >>> 0)) | 0);
    run.lastEchoAt = now;
    run.rttSum += rtt;
    run.rttN += 1;
    if (run.rttN === 1 || rtt < run.rttMin) run.rttMin = rtt;
    if (rtt > run.rttMax) run.rttMax = rtt;
    if (run.rttN > 1) { run.jitterSum += Math.abs(rtt - run.rttPrev); run.jitterN += 1; }
    run.rttPrev = rtt;
    if (!run.seen[f.seq]) { run.seen[f.seq] = 1; run.got += 1; }
  }

  // ---------------------------------------------------------- down phase

  private startDown(now: number): void {
    this.phase = 'down';
    if (this.downBudget <= 0) { this.finish(now); return; }
    const total = Math.floor(this.downBudget / this.size);
    if (total < 4) { this.finish(now); return; }
    this.downReq = { token: this.token, total, size: this.size, sentAt: 0, tries: 0 };
  }

  private driveDownRequest(now: number): void {
    const req = this.downReq;
    if (!req) return;
    // Once one DAT has arrived the train is in flight: the rx side owns
    // completion from here, and re-sending the request would ask the peer to
    // start a second train (or, worse, retire a run that is still arriving).
    const live = this.rx.get(req.token);
    if (live && live.got > 0) return;
    // One request, then one retry if the peer did not answer: the request itself
    // is oob and can be lost, and without this a single lost datagram would end
    // the whole downlink half of the measurement.
    if (req.tries > 0 && now - req.sentAt < Math.max(600, 3 * this.host.srttMs())) return;
    if (req.tries >= 2) {
      this.downReq = null;
      if (live && live.report) this.finishRx(live, now, 'timeout');
      else this.finish(now);
      return;
    }
    this.host.send(encodeProbe({
      type: PROBE_TYPE_DOWN, flags: PROBE_FLAG_DOWN, token: req.token,
      seq: 0, total: req.total, got: 0, sentMs: now, size: req.size, aux: 0,
    }));
    req.tries += 1;
    req.sentAt = now;
    if (req.tries === 1) {
      // The receiver side starts now: the peer's train may arrive before our
      // next tick, and a run with no RxRun would drop every DAT unmeasured.
      const rx = freshRx(req.token, true, now);
      rx.total = req.total;
      rx.size = req.size;
      rx.seen = new Uint8Array(Math.max(1, req.total));
      this.rx.set(req.token, rx);
      this.trimRx();
    }
  }

  private onDownReq(f: ProbeFrame, now: number): void {
    // Serve exactly what was asked, and report nothing: the requester owns the
    // measurement. A fresh token would break the requester's correlation, so the
    // peer's token is reused verbatim. A peer that asks while this end is running
    // its own train is refused — one 5-tuple cannot carry two paced trains and
    // still report either rate honestly.
    if (f.total < 4 || f.size < PROBE_HDR_LEN + 64) return;
    if (this.up || this.token !== 0) return;
    this.up = freshTx(f.token, f.total, f.size, PROBE_RATE_START_BPS, false, now);
  }

  // ----------------------------------------------------------- receiving

  private onDat(f: ProbeFrame, now: number): void {
    if (f.seq >= f.total) return;
    const run = this.rx.get(f.token) ?? this.rxFor(f, now);
    if (!run) return;
    if (run.total === 0) {
      run.total = f.total;
      run.size = f.size;
      run.seen = new Uint8Array(Math.max(1, f.total));
    }
    this.host.send(encodeProbe({
      type: PROBE_TYPE_ECHO, flags: 0, token: f.token,
      seq: f.seq, total: f.total, got: 0, sentMs: f.sentMs, size: 0, aux: 0,
    }));
    // Same 32-bit field, different clock: the absolute value is meaningless
    // across processes, but it is a *constant* offset away from the true one-way
    // delay, so jitter and queue growth (both differences) stay exact.
    const delay = ((now >>> 0) - (f.sentMs >>> 0)) | 0;
    if (run.got === 0) { run.firstArrival = now; run.firstSent = f.sentMs; run.prevDelay = delay; }
    else { run.jitterSum += Math.abs(delay - run.prevDelay); run.jitterN += 1; run.prevDelay = delay; }
    if (f.aux > 0) run.peerCleanBps = f.aux * 1000;
    run.lastArrival = now;
    run.lastSent = f.sentMs;
    if (!run.seen[f.seq]) { run.seen[f.seq] = 1; run.got += 1; }
    // The summary is built after a quiet period so stragglers count as arrived
    // rather than as loss — reordering on a real path is common enough that a
    // summary sent on the last arrival alone over-reports loss. The last index
    // is accepted as an end marker even when the LAST flag did not survive:
    // there is nothing above it.
    if (f.flags & PROBE_FLAG_LAST || f.seq === f.total - 1) run.sumAt = now + PROBE_DRAIN_MS;
  }

  private rxFor(f: ProbeFrame, now: number): RxRun | null {
    // Only the down phase of our own run has no RxRun yet, and that one is
    // created by driveDownRequest. Anything else is either a peer's train (serve
    // it silently) or a stale token, which must not allocate.
    if (this.token !== 0 && f.token === this.token && this.phase === 'down') {
      const rx = freshRx(f.token, true, now);
      this.rx.set(f.token, rx);
      this.trimRx();
      return rx;
    }
    if (this.rx.size >= MAX_RX_RUNS) return null;
    const rx = freshRx(f.token, false, now);
    this.rx.set(f.token, rx);
    return rx;
  }

  private trimRx(): void {
    while (this.rx.size > MAX_RX_RUNS) {
      const first = this.rx.keys().next();
      if (first.done) return;
      this.rx.delete(first.value);
    }
  }

  private driveRx(now: number): void {
    for (const run of [...this.rx.values()]) {
      if (run.sumAt === 0) {
        // The tail of a train can be lost, and then no arrival ever carries the
        // LAST flag. A silence longer than any ramp pause (which is one sRTT)
        // is the only remaining end-of-train signal — without it a run whose
        // last datagram was lost would never produce the loss number it exists
        // to produce.
        const quiet = Math.max(2 * this.host.srttMs(), 400) + PROBE_DRAIN_MS * 2;
        if (run.got > 0 && now - run.lastArrival > quiet) run.sumAt = now;
        else if (run.report && now - run.startedAt > PROBE_TIMEOUT_MS) this.finishRx(run, now, 'timeout');
        else if (!run.report && now - Math.max(run.startedAt, run.lastArrival) > PROBE_TIMEOUT_MS) this.rx.delete(run.token);
        if (run.sumAt === 0) continue;
      }
      if (now < run.sumAt) continue;
      if (!run.sumSent) {
        const got = run.got;
        const maxRun = longestGap(run.seen, run.total);
        for (let i = 0; i < PROBE_SUM_COPIES; ++i) {
          this.host.send(encodeProbe({
            type: PROBE_TYPE_SUM, flags: 0, token: run.token,
            seq: 0, total: run.total, got, sentMs: now, size: 0, aux: maxRun,
          }));
        }
        run.sumSent = true;
      }
      if (run.report) this.finishRx(run, now, 'ok');
      else this.rx.delete(run.token);
    }
  }

  private finishRx(run: RxRun, now: number, reason: string): void {
    this.rx.delete(run.token);
    if (!run.report) return;
    const bytes = run.got * run.size;
    const ms = Math.max(1, run.lastArrival - run.firstArrival);
    this.downResult = {
      bytes, ms,
      rateBps: (bytes * 1000) / ms,
      lossTx: -1,
      lossRx: run.total > 0 ? 1 - run.got / run.total : -1,
      maxRun: run.total > 0 ? longestGap(run.seen, run.total) : -1,
      rttMin: -1, rttAvg: -1, rttMax: -1,
      jitterMs: run.jitterN > 0 ? run.jitterSum / run.jitterN : 0,
      // One-way delay growth cancels the clock offset between the two ends: both
      // terms are measured here, so only the path's queue shows up.
      queueMs: run.got > 1 ? (run.lastArrival - run.lastSent) - (run.firstArrival - run.firstSent) : 0,
      rampBps: run.peerCleanBps,
      reason,
    };
    this.downReq = null;
    this.finish(now);
  }

  private onSum(f: ProbeFrame, now: number): void {
    // Accepted in either phase: the summary is sent PROBE_DRAIN_MS after the
    // peer's last arrival, which can be before or after the train is retired
    // here. Late copies of a finished run are dropped by the token check.
    if (this.token === 0 || this.token !== f.token) return;
    this.peerSum = { got: f.got, total: f.total, maxRun: f.aux };
    this.applyPeerSum();
  }

  private finish(now: number): void {
    if (this.token === 0) return;
    const token = this.token;
    const result: ProbeResult = {
      token,
      at: now,
      ms: Math.max(0, now - this.startedAt),
      up: this.upResult,
      down: this.downResult,
      usedBytes: (this.upResult?.bytes ?? 0) + (this.downResult?.bytes ?? 0),
      budgetBytes: this.budgetBytes,
    };
    this.token = 0;
    this.phase = '';
    this.up = null;
    this.upResult = null;
    this.downResult = null;
    this.downReq = null;
    this.rx.delete(token);
    this.host.onResult(result);
  }
}
