// FEC framing: data/parity/oob symbols, RS repair and set accounting.
// Port of src/fcp/frame_tx.{h,cc}, frame_rx.cc, frame_rx_decode.cc, hdr.cc.
//
// One stream segment becomes exactly one data symbol and one UDP datagram:
//   data symbol   = len(2 LE) | payload        (len includes the 2-byte prefix)
//   parity symbol = symbol_max bytes of RS output
//   oob symbol    = raw oob message (set_id = index = 0)
// The 7-byte FEC header (v2: d was added to the 6-byte v1 layout) is prepended
// by Session before the AEAD envelope.

import {
  FEC_HDR_LEN, SymbolType, MAX_S, MAX_ACTIVE_SETS, MAX_GAP_PLACEHOLDERS,
  AHEAD_CONFIRM_TIMEOUT_MS, FRAME_ENVELOPE_OVERHEAD, DATA_WIRE_OVERHEAD,
  PARITY_WIRE_OVERHEAD, KCP_HEADER_RESERVE, MIN_FLUSH_MS, MAX_FLUSH_MS,
  DEFAULT_FLUSH_MS, DEFAULT_MTU, DEFAULT_IP_HEADER_LEN, MAX_RX_SYMBOL_BYTES,
  FLUSH_DRAIN_FACTOR, MAX_INTERLEAVE,
} from '../constants.ts';
import {
  getLe16, putLe16, getLe32, putLe32, bytesEqual, seqAfter,
} from '../wire.ts';
import { packHdr, parseHdr, validateHdr, HdrStatus, packTypeK, hdrType, hdrK, hdrJ, validSymbolType } from './hdr.ts';
import { rsEncode, rsDecode } from './rs.ts';

export interface MtuLimits {
  mtu: number; ipHdrLen: number; payloadMax: number; symbolMax: number; mss: number; valid: boolean;
}

export function computeMtuLimits(mtu: number, ipHdrLen = DEFAULT_IP_HEADER_LEN): MtuLimits {
  const base = mtu > ipHdrLen + 8 ? mtu - ipHdrLen - 8 : 0;
  if (base < DATA_WIRE_OVERHEAD + KCP_HEADER_RESERVE + 1) {
    return { mtu, ipHdrLen, payloadMax: 0, symbolMax: 0, mss: 0, valid: false };
  }
  return {
    mtu, ipHdrLen,
    payloadMax: base - DATA_WIRE_OVERHEAD,
    symbolMax: base - PARITY_WIRE_OVERHEAD,
    mss: base - DATA_WIRE_OVERHEAD - KCP_HEADER_RESERVE,
    valid: true,
  };
}
export function pmtuProbeLen(mtu: number, ipHdrLen = DEFAULT_IP_HEADER_LEN): number {
  return (mtu - ipHdrLen - 8) - FRAME_ENVELOPE_OVERHEAD - FEC_HDR_LEN;
}

export interface TxSymbol { setId: number; index: number; d: number; typeK: number; symbol: Buffer; }

/** One open repair group. The sender keeps `interleave` of these plus one
 *  control lane, and round-robins data segments across the former. */
interface TxLane {
  setId: number; n: number; k: number; d: number; symbolMax: number;
  symbols: Buffer[]; tLastMs: number;
}
function emptyLane(): TxLane {
  return { setId: 0, n: 0, k: 0, d: 0, symbolMax: 0, symbols: [], tLastMs: 0 };
}
function resetLane(l: TxLane): void {
  l.n = 0; l.k = 0; l.d = 0; l.symbolMax = 0; l.symbols = []; l.tLastMs = 0;
}

export class FrameTx {
  private d: number;
  private limits: MtuLimits;
  private emitFn: (s: TxSymbol) => void;
  private lanes: TxLane[] = [emptyLane()];
  /** Control segments (ACK/RST) never share a group with data: they are
   *  latency-critical and must close immediately, and putting them in the
   *  round-robin would truncate whichever data group they landed in. */
  private ctl: TxLane = emptyLane();
  private cursor = 0;
  private nextSetId = 0;
  private nextK = 0;
  private flushMs = DEFAULT_FLUSH_MS;
  private srttMs = DEFAULT_FLUSH_MS;
  /** Time the sender needs to put D symbols on the wire, or -1 when unknown.
   *  -1 keeps the old behaviour (flush after sRTT). */
  private drainMs = -1;
  closedFull = 0; closedIdle = 0; abortedSets = 0; dataSymbols = 0; paritySymbols = 0; mtuDrops = 0;

  constructor(d: number, limits: MtuLimits, emit: (s: TxSymbol) => void) {
    this.d = d; this.limits = limits; this.emitFn = emit;
  }
  setK(k: number): void { this.nextK = Math.min(k, 7); }
  setSrttMs(srtt: number): void { this.srttMs = srtt; this.recomputeFlush(); }
  /** Group size for groups opened from now on. Groups already open keep the d
   *  they were cut with — it travels in every symbol's header. */
  setGroupD(d: number): void { if (d >= 1) this.d = d; }
  get groupD(): number { return this.d; }

  /**
   * Interleave depth: how many repair groups stay open at once.
   *
   * With L=1 a burst of B consecutive losses lands in one group and needs
   * k >= B to survive. With L lanes the same burst is spread over L groups
   * (ceil(B/L) each), so the same k covers a burst L times longer. Redundancy
   * is unchanged: k/d per group, same bytes per group. The costs are that a
   * lane takes L times longer to fill (so parity for its tail is L times
   * later) and that the sender holds L groups of symbol buffers.
   */
  setInterleave(n: number): void {
    const want = Math.max(1, Math.min(MAX_INTERLEAVE, n | 0));
    if (want === this.lanes.length) return;
    if (want < this.lanes.length) {
      // Shrinking: settle the lanes we are dropping now rather than at the
      // flush timer, because nothing will ever add to them again.
      for (let i = want; i < this.lanes.length; ++i) this.closeLane(this.lanes[i], false);
      this.lanes.length = want;
    } else {
      while (this.lanes.length < want) this.lanes.push(emptyLane());
    }
    if (this.cursor >= this.lanes.length) this.cursor = 0;
  }
  get interleave(): number { return this.lanes.length; }

  /**
   * How long this sender needs to fill a whole group at its current rate.
   *
   * A partial group's parity is the only repair that arrives without an ARQ
   * round trip, and it cannot be emitted until the group closes — so the flush
   * timer is a direct floor on repair latency for whatever is already in the
   * group. Waiting sRTT (capped at 200 ms) for a group that would have closed
   * in 14 ms is pure delay on a fast path. On a slow path the same formula is
   * larger than sRTT and the cap collapses back to sRTT, so the set count and
   * the parity overhead of a trickle are unchanged.
   *
   * With interleaving the caller passes the time to fill the *lane*, i.e.
   * interleave x d symbols, not d: a lane only sees one segment in every L.
   */
  setGroupDrainMs(ms: number): void { this.drainMs = ms > 0 ? ms : -1; this.recomputeFlush(); }
  private recomputeFlush(): void {
    let ms = Math.min(Math.max(this.srttMs, MIN_FLUSH_MS), MAX_FLUSH_MS);
    if (this.drainMs > 0) {
      const byRate = Math.max(MIN_FLUSH_MS, Math.ceil(this.drainMs * FLUSH_DRAIN_FACTOR));
      if (byRate < ms) ms = byRate;
    }
    this.flushMs = ms;
  }
  /** Milliseconds until the earliest open group must be closed, or -1. */
  nextTimerMs(nowMs: number): number {
    let best = -1;
    const consider = (lane: TxLane): void => {
      if (lane.n < 1) return;
      const due = lane.tLastMs + this.flushMs - nowMs;
      const ms = due < 1 ? 1 : due;
      if (best < 0 || ms < best) best = ms;
    };
    for (const lane of this.lanes) consider(lane);
    consider(this.ctl);
    return best;
  }
  raiseLimits(l: MtuLimits): void { if (l.valid && l.payloadMax > this.limits.payloadMax) this.limits = l; }
  lowerLimits(l: MtuLimits): void { if (l.valid && l.payloadMax < this.limits.payloadMax) this.limits = l; }
  get limitsValue(): MtuLimits { return this.limits; }
  /** Symbols currently waiting for their group to close, across every lane. */
  get openN(): number {
    let n = this.ctl.n;
    for (const lane of this.lanes) n += lane.n;
    return n;
  }
  get openK(): number {
    for (const lane of this.lanes) if (lane.n > 0) return lane.k;
    return this.ctl.n > 0 ? this.ctl.k : 0;
  }
  get currentSetId(): number { return this.nextSetId; }

  /**
   * Add one segment.
   *
   * `control` routes it to the dedicated control lane and closes that lane
   * immediately: an ACK must not wait for a data group to fill, and it must
   * not truncate one either.
   */
  onSegment(seg: Uint8Array, nowMs: number, control = false): void {
    if (seg.length > this.limits.payloadMax) { ++this.mtuDrops; return; }
    this.maybeFlush(nowMs);
    let lane: TxLane;
    if (control) {
      lane = this.ctl;
    } else {
      lane = this.lanes[this.cursor];
      this.cursor = (this.cursor + 1) % this.lanes.length;
    }
    if (lane.n === 0) this.openLane(lane);
    const symLen = seg.length + 2;
    const symbol = Buffer.allocUnsafe(symLen); // len + payload fully written
    putLe16(symLen, symbol, 0);
    Buffer.from(seg).copy(symbol, 2);
    lane.symbolMax = Math.max(lane.symbolMax, symLen);
    lane.symbols.push(symbol);
    this.emitFn({
      setId: lane.setId, index: lane.n, d: lane.d,
      typeK: packTypeK(lane.k, 0, SymbolType.Data), symbol,
    });
    ++this.dataSymbols;
    ++lane.n;
    lane.tLastMs = nowMs;
    if (lane.n >= lane.d) this.closeLane(lane, true);
    else if (control) this.closeLane(lane, false);
  }

  private openLane(lane: TxLane): void {
    lane.setId = this.nextSetId;
    this.nextSetId = (this.nextSetId + 1) >>> 0;
    lane.k = this.nextK;
    lane.d = this.d;
    lane.symbolMax = 0;
    lane.symbols = [];
  }

  onTick(nowMs: number): void { this.maybeFlush(nowMs); }

  abort(): void {
    let any = false;
    for (const lane of this.lanes) if (lane.n > 0) { resetLane(lane); any = true; }
    if (this.ctl.n > 0) { resetLane(this.ctl); any = true; }
    if (any) ++this.abortedSets;
  }

  private maybeFlush(nowMs: number): void {
    for (const lane of this.lanes) {
      if (lane.n >= 1 && nowMs - lane.tLastMs >= this.flushMs) this.closeLane(lane, false);
    }
    if (this.ctl.n >= 1 && nowMs - this.ctl.tLastMs >= this.flushMs) this.closeLane(this.ctl, false);
  }

  private closeLane(lane: TxLane, full: boolean): void {
    if (lane.n === 0) return;
    if (lane.d === 0) { resetLane(lane); ++this.abortedSets; return; }
    const d = lane.d;
    let kEff = 0;
    if (lane.k >= 1) kEff = Math.max(1, Math.min(lane.k, Math.ceil(lane.k * lane.n / d)));
    if (kEff >= 1) {
      const padded = lane.symbols.map((s) => {
        const row = Buffer.alloc(lane.symbolMax);
        s.copy(row, 0);
        return row;
      });
      const parities = rsEncode(padded, lane.n, kEff, lane.symbolMax);
      if (parities === null) kEff = 0;
      for (let j = 0; j < kEff; ++j) {
        if (parities === null) break;
        this.emitFn({
          setId: lane.setId, index: lane.n + j, d,
          typeK: packTypeK(lane.k, j, SymbolType.Parity),
          symbol: parities[j],
        });
        ++this.paritySymbols;
      }
    }
    if (full) ++this.closedFull; else ++this.closedIdle;
    resetLane(lane);
  }
}


export interface RxEventInfo { event: string; setId: number; repairMs?: number; }

interface RxSet {
  setId: number;
  n: number; nKnown: boolean; k: number; kKnown: boolean;
  /** Data-shard count this set was cut with, taken from the first symbol's
   *  header. Sets are self-describing, so a sender may resize its groups
   *  mid-session without the decoder having to be told out of band. */
  d: number; dKnown: boolean;
  symbolMax: number; maxDataIndex: number;
  data: Map<number, Buffer>; parity: Map<number, Buffer>;
  orig: Set<number>; recov: Set<number>;
  tFirstMs: number; accounted: boolean; tombstoneUntilMs: number;
  hasAnySymbol: boolean; decodeAttempts: number;
}

export interface RxCounters {
  structFail: number; stale: number; lateDup: number; recovered: number;
  recoveredLate: number; dataRxOrig: number; parityRx: number;
  dataDelivered: number; dataLateRx: number;
  retiredDropped: number; aheadDropped: number;
  setsPartial: number; setsFull: number; setsTailDropped: number;
  decodeAttempts: number; badRecon: number; symbolBudgetDrops: number;
  /** Settlement view, reported in FECSTAT: accounted sets with symbols and
   *  the number of data shards those sets were expected to carry (Σ n_used). */
  setsExpected: number; dataExpected: number; parityExpected: number;
  setsKUnknown: number;
  /** M3 R(k) ledger: full-size groups with known k, of which this many failed. */
  ledgerGroups: number; ledgerFailed: number; ledgerKHist: number[];
}

export interface FrameRxOptions {
  d: number; p: number;
  deliver: (payload: Buffer, info: { recovered: boolean; late: boolean }) => void;
  oob: (payload: Buffer, nowMs: number) => void;
  event?: (e: RxEventInfo) => void;
  maxSymbolLen?: number;
}

export class FrameRx {
  /** Negotiated group-size ceiling. A set may declare any d up to this; the
   *  sender adapts downwards, never upwards, so the value doubles as the
   *  bound that keeps a corrupt or hostile header from allocating the world. */
  private dMax: number;
  private p: number;
  private deliverFn: FrameRxOptions['deliver'];
  private oobFn: FrameRxOptions['oob'];
  private eventFn?: (e: RxEventInfo) => void;
  private maxSymbolLen: number;
  private sets = new Map<number, RxSet>();
  private retired = new Set<number>();
  private accountBoundary = new Map<number, number>();
  private anchor = 0; private anchorValid = false;
  private pendingAhead = 0; private pendingAheadValid = false; private pendingAheadMs = 0;
  /** Session-level monotonic FECSTAT key. It must not be derived from the live
   *  set map: retired sets are deleted 2 s after arrival, so a quiet interval
   *  would otherwise report key 0 and the peer's validator would mark every
   *  later report stale. */
  private accountedThrough = 0;
  private haveAccounted = false;
  private symbolBytes = 0;
  readonly counters: RxCounters = {
    structFail: 0, stale: 0, lateDup: 0, recovered: 0, recoveredLate: 0,
    dataRxOrig: 0, parityRx: 0, dataDelivered: 0, dataLateRx: 0, retiredDropped: 0,
    aheadDropped: 0, setsPartial: 0, setsFull: 0, setsTailDropped: 0,
    decodeAttempts: 0, badRecon: 0, symbolBudgetDrops: 0,
    setsExpected: 0, dataExpected: 0, parityExpected: 0, setsKUnknown: 0,
    ledgerGroups: 0, ledgerFailed: 0, ledgerKHist: new Array(8).fill(0),
  };
  // (No per-recovery latency array here: it was write-only and grew for the
  // whole session. The FecstatReporter keeps its own per-interval list.)

  constructor(o: FrameRxOptions) {
    this.dMax = o.d; this.p = o.p;
    this.deliverFn = o.deliver; this.oobFn = o.oob; this.eventFn = o.event;
    this.maxSymbolLen = o.maxSymbolLen ?? 65535;
  }

  setMaxSymbolLen(n: number): void { if (n > 0) this.maxSymbolLen = n; }

  activeSetIds(): number[] { return [...this.sets.keys()]; }
  view(setId: number): RxSet | undefined { return this.sets.get(setId); }

  private emit(event: string, setId: number, repairMs?: number): void {
    this.eventFn?.({ event, setId, repairMs });
  }

  onDatagram(plain: Uint8Array, nowMs: number): void {
    const hdr = parseHdr(plain);
    if (!hdr) { ++this.counters.structFail; return; }
    const symbol = Buffer.from(plain.subarray(FEC_HDR_LEN));
    const type = hdrType(hdr.typeK);
    if (type === SymbolType.Oob) { this.oobFn(symbol, nowMs); return; }
    if (!validSymbolType(type)) { ++this.counters.structFail; return; }

    // Staleness: only structurally valid headers may move the anchor.
    if (this.anchorValid) {
      const behind = (this.anchor - hdr.setId) >>> 0;
      if (behind > MAX_ACTIVE_SETS && behind < 0x80000000) { ++this.counters.stale; return; }
    }

    // A set declares its own group size. Anything above the negotiated ceiling
    // is a protocol violation: the sender only ever adapts downwards, so this
    // bound is what stops a bogus header from claiming d = 255.
    if (hdr.d < 1 || hdr.d > this.dMax) { ++this.counters.structFail; return; }
    const existing = this.sets.get(hdr.setId);
    const nKnown = existing?.nKnown ?? false;
    const n = existing?.n ?? 0;
    if (validateHdr(hdr, this.p, nKnown, n) !== HdrStatus.Ok) { ++this.counters.structFail; return; }
    if (symbol.length < 2 || symbol.length > this.maxSymbolLen) { ++this.counters.structFail; return; }
    const kField = hdrK(hdr.typeK), jField = hdrJ(hdr.typeK);
    let nNew = 0;
    if (type === SymbolType.Data) {
      const declared = getLe16(symbol, 0);
      if (declared !== symbol.length) { ++this.counters.structFail; return; }
    } else {
      nNew = hdr.index - jField;
      if (nKnown && n !== nNew) { ++this.counters.structFail; return; }
    }
    if (this.retired.has(hdr.setId)) { ++this.counters.retiredDropped; return; }

    // A8: a lone far-ahead set_id must not re-anchor the window by itself.
    if (this.anchorValid && seqAfter(hdr.setId, this.anchor) &&
        ((hdr.setId - this.anchor) >>> 0) > MAX_GAP_PLACEHOLDERS) {
      const same = this.pendingAheadValid && hdr.setId === this.pendingAhead;
      const consecutive = this.pendingAheadValid && seqAfter(hdr.setId, this.pendingAhead) &&
        ((hdr.setId - this.pendingAhead) >>> 0) <= MAX_GAP_PLACEHOLDERS;
      const expired = this.pendingAheadValid && nowMs - this.pendingAheadMs >= AHEAD_CONFIRM_TIMEOUT_MS;
      if (same || consecutive || expired) {
        this.anchor = hdr.setId; this.pendingAheadValid = false; this.pruneRetired();
      } else {
        this.pendingAhead = hdr.setId; this.pendingAheadValid = true; this.pendingAheadMs = nowMs;
        ++this.counters.aheadDropped;
        return;
      }
    } else {
      this.pendingAheadValid = false;
    }
    const hadAnchor = this.anchorValid;
    const prevAnchor = this.anchor;
    if (!this.anchorValid || seqAfter(hdr.setId, this.anchor)) { this.anchor = hdr.setId; this.anchorValid = true; this.pruneRetired(); }
    if (hadAnchor && seqAfter(hdr.setId, (prevAnchor + 1) >>> 0)) this.createPlaceholders((prevAnchor + 1) >>> 0, hdr.setId, nowMs);

    const set = this.getOrCreate(hdr.setId, nowMs);
    if (!set) { ++this.counters.structFail; return; }
    // k is first-wins and clamped to the negotiated parity ceiling (C++ A9).
    // Once known, a symbol declaring a different k is a structural violation:
    // decoding with the wrong geometry could reconstruct corrupt data. C++
    // note_k() returns false in that case and the datagram is dropped with
    // struct_fail; do the same instead of silently keeping the first value.
    const kClamped = Math.min(kField, this.p);
    if (!set.kKnown) { set.k = kClamped; set.kKnown = true; }
    else if (set.k !== kClamped) { ++this.counters.structFail; return; }
    // Same rule for the group size: first symbol wins, and a later symbol of
    // the same set declaring a different d is a structural violation. Mixing
    // geometries inside one set would decode against the wrong code length.
    if (!set.dKnown) { set.d = hdr.d; set.dKnown = true; }
    else if (set.d !== hdr.d) { ++this.counters.structFail; return; }

    if (type === SymbolType.Data) {
      const idx = hdr.index;
      if (set.orig.has(idx) || set.recov.has(idx)) { ++this.counters.lateDup; this.emit('data_duplicate', hdr.setId); return; }
      set.orig.add(idx);
      set.maxDataIndex = Math.max(set.maxDataIndex, idx);
      this.store(set, idx, symbol);
      const late = set.accounted;
      const boundary = this.accountBoundary.get(hdr.setId);
      const lateUnexpected = late && (boundary === undefined || idx >= boundary);
      // Shard counters are settlement-based (see accountSet): counting an
      // arrival here would put shards from still-active sets into the period's
      // numerator while their sets have not entered the denominator yet.
      ++this.counters.dataDelivered;
      // FECSTAT data_late_rx counts unique originals arriving during the
      // tombstone window WITHIN the accounted code length (C++ settle.cc:188).
      // late_unexpected (k-unknown / index past the accounted boundary) is a
      // separate condition and must not inflate this field, or the peer's
      // data_lost() identity would exceed expected.
      if (late && !lateUnexpected) ++this.counters.dataLateRx;
      this.deliverFn(symbol.subarray(2), { recovered: false, late: late || lateUnexpected });
      this.tryDecode(set, nowMs);
      return;
    }

    // Parity: n = index - j is the only source of n.
    if (set.parity.has(hdr.index)) return;
    if (!set.nKnown && set.maxDataIndex >= nNew) { ++this.counters.structFail; return; }
    set.n = nNew; set.nKnown = true;
    // Only register the parity when the byte budget accepted it, otherwise
    // retirement would subtract bytes that were never added and the global
    // budget could drift below zero, silently disabling the ceiling.
    if (this.store(set, hdr.index, symbol)) set.parity.set(hdr.index, symbol);
    this.tryDecode(set, nowMs);
  }

  private store(set: RxSet, idx: number, symbol: Buffer): boolean {
    set.hasAnySymbol = true;
    set.symbolMax = Math.max(set.symbolMax, symbol.length);
    const old = set.data.get(idx);
    const oldLen = old ? old.length : 0;
    if (this.symbolBytes - oldLen + symbol.length > MAX_RX_SYMBOL_BYTES) {
      // Same policy as frame_rx.cc: dropping is recovered by the peer's ARQ,
      // growing the heap is not. Index masks stay set, exactly as in C++.
      ++this.counters.symbolBudgetDrops;
      return false;
    }
    this.symbolBytes += symbol.length - oldLen;
    set.data.set(idx, symbol);
    return true;
  }

  /**
   * Book a reconstructed symbol into the set AND into the byte budget.
   *
   * tryDecode() used to write recovered rows straight into set.data, so the
   * rows were held on the heap but never added to symbolBytes. Retirement
   * subtracts setBytes() — which does include them — so every repaired group
   * drove the counter down by the bytes it had never added. Measured with
   * d=10, k=6 and 2 KB symbols: 200 groups held 6.4 MB while the counter read
   * 4.0 MB, and after the 2 s settle it read -2.4 MB. A negative counter can
   * never trip MAX_RX_SYMBOL_BYTES again, so the only heap ceiling on FrameRx
   * is gone for the rest of the session, on exactly the lossy path where
   * recovery runs constantly.
   */
  private storeRecovered(set: RxSet, idx: number, symbol: Buffer): void {
    const old = set.data.get(idx);
    const oldLen = old ? old.length : 0;
    // A reconstructed row is a real heap allocation and must obey the same
    // session ceiling as an arriving symbol (C++ frame_rx.cc:452 store_symbol,
    // called from the recovery path). Without this check, heavy loss could push
    // symbolBytes past MAX_RX_SYMBOL_BYTES and defeat the only heap guard.
    // A refusal is safe: the caller still delivers this reconstruction, and a
    // later parity can repair the slot again.
    if (this.symbolBytes - oldLen + symbol.length > MAX_RX_SYMBOL_BYTES) {
      ++this.counters.symbolBudgetDrops;
      return;
    }
    this.symbolBytes += symbol.length - oldLen;
    set.data.set(idx, symbol);
  }

  private setBytes(set: RxSet): number {
    let n = 0;
    for (const b of set.data.values()) n += b.length;
    return n;
  }

  private tryDecode(set: RxSet, nowMs: number): void {
    if (!set.nKnown || !set.kKnown || set.k === 0) return;
    const missing: number[] = [];
    for (let i = 0; i < set.n; ++i) {
      if (!set.orig.has(i) && !set.recov.has(i)) missing.push(i);
    }
    // The code length is not the header's k when the group closed early: the
    // sender scales it to kEff = max(1, min(k, ceil(k*n/d))) so a short group
    // does not pay for full parity. The Cauchy coefficient is 1/(r XOR (k+c)),
    // i.e. it *depends on k*, so decoding a kEff-encoded group with the
    // header's k solves a different linear system: the reconstruction is
    // garbage, and only the length/zero-tail sanity check below keeps it out
    // of the stream. Deriving the same kEff here is exact rather than a guess —
    // n is final the moment a parity symbol exists (parity is only emitted at
    // close), and d and k both travel in the header.
    const dSet = set.dKnown ? set.d : this.dMax;
    const kUsed = dSet > 0
      ? Math.max(1, Math.min(set.k, Math.ceil((set.k * set.n) / dSet)))
      : set.k;
    if (missing.length === 0 || missing.length > kUsed || set.symbolMax < 2) return;
    const n = set.n, k = kUsed;
    if (n + k > 256) return;
    const size = set.symbolMax;
    const shards: (Buffer | null)[] = new Array(n + k).fill(null);
    for (let i = 0; i < n; ++i) {
      const s = set.data.get(i);
      if (!s) continue;
      if (!set.orig.has(i) && !set.recov.has(i)) continue;
      const row = Buffer.alloc(size); s.copy(row, 0); shards[i] = row;
    }
    for (let r = 0; r < k; ++r) {
      const idx = n + r;
      const s = set.parity.get(idx);
      if (!s) continue;
      const row = Buffer.alloc(size); s.copy(row, 0); shards[idx] = row;
    }
    ++set.decodeAttempts;
    ++this.counters.decodeAttempts;
    const recovered = rsDecode(shards, n, k, size);
    if (!recovered) return;
    for (const i of missing) {
      const s = recovered[i];
      if (!s || s.length !== size) { ++this.counters.badRecon; continue; }
      const declared = getLe16(s, 0);
      let ok = declared >= 2 && declared <= size;
      if (ok) for (let b = declared; b < size; ++b) if (s[b] !== 0) { ok = false; break; }
      if (!ok) { ++this.counters.badRecon; continue; }
      set.recov.add(i);
      this.storeRecovered(set, i, s);
      const repairMs = Math.min(0xffff, Math.max(0, nowMs - set.tFirstMs));
      const late = set.accounted;
      if (late) ++this.counters.recoveredLate; else ++this.counters.recovered;
      ++this.counters.dataDelivered;
      this.emit('recovered', set.setId, repairMs);
      this.deliverFn(s.subarray(2, declared), { recovered: true, late });
    }
  }

  private getOrCreate(setId: number, nowMs: number): RxSet | null {
    const found = this.sets.get(setId);
    if (found) return found;
    if (this.sets.size >= MAX_ACTIVE_SETS) {
      let victim: number | undefined;
      for (const [id, st] of this.sets) if (!st.accounted) { victim = id; break; }
      if (victim === undefined) for (const id of this.sets.keys()) { victim = id; break; }
      if (victim === undefined) return null;
      const victimSet = this.sets.get(victim);
      if (victimSet) {
        this.symbolBytes -= this.setBytes(victimSet);
        if (!victimSet.accounted) ++this.counters.setsTailDropped;
        else {
          // An ACCOUNTED set is final: retire its id so a late symbol cannot
          // re-create and settle it a second time (mirror C++ frame_rx.cc:415
          // "Evicted after accounting"). A tail-dropped set is only a 1 s
          // heuristic verdict — a late parity may legitimately rebuild it, so
          // it is deliberately NOT retired.
          this.retired.add(victim);
          this.pruneRetired();
        }
      }
      this.sets.delete(victim);
      this.accountBoundary.delete(victim);
    }
    const set: RxSet = {
      setId, n: 0, nKnown: false, k: 0, kKnown: false, d: 0, dKnown: false, symbolMax: 0, maxDataIndex: 0,
      data: new Map(), parity: new Map(), orig: new Set(), recov: new Set(),
      tFirstMs: nowMs, accounted: false, tombstoneUntilMs: 0,
      hasAnySymbol: false, decodeAttempts: 0,
    };
    this.sets.set(setId, set);
    return set;
  }

  private createPlaceholders(first: number, last: number, nowMs: number): void {
    const gap = (last - first) >>> 0;
    if (gap === 0 || gap > MAX_GAP_PLACEHOLDERS || this.sets.size + gap >= MAX_ACTIVE_SETS) return;
    for (let id = first; id !== last; id = (id + 1) >>> 0) {
      if (this.sets.has(id)) continue;
      const set: RxSet = {
        setId: id, n: 0, nKnown: false, k: 0, kKnown: false, d: 0, dKnown: false, symbolMax: 0, maxDataIndex: 0,
        data: new Map(), parity: new Map(), orig: new Set(), recov: new Set(),
        tFirstMs: nowMs, accounted: false, tombstoneUntilMs: 0,
        hasAnySymbol: false, decodeAttempts: 0,
      };
      this.sets.set(id, set);
    }
  }

  private pruneRetired(): void {
    for (const id of [...this.retired]) {
      const behind = (this.anchor - id) >>> 0;
      if (behind > MAX_ACTIVE_SETS && behind < 0x80000000) this.retired.delete(id);
    }
  }

  /** Settle sets that have gone quiet; mirrors FcpSettle's 1 s / 2 s clocks. */
  onTick(nowMs: number): void {
    for (const [id, set] of [...this.sets]) {
      const boundary = set.hasAnySymbol ? (set.nKnown ? set.n : set.maxDataIndex + 1) : 0;
      if (!set.accounted && nowMs - set.tFirstMs >= 1000) {
        set.accounted = true;
        this.accountBoundary.set(id, boundary);
        this.accountSet(set);
        this.emit('accounted', id);
      }
      if (nowMs - set.tFirstMs >= 2000) {
        this.symbolBytes -= this.setBytes(set);
        if (set.accounted) { this.retired.add(id); this.pruneRetired(); }
        this.sets.delete(id);
        this.accountBoundary.delete(id);
      }
    }
  }

  /**
   * Account one settled set into the cumulative counters. Mirrors
   * FcpSettle::account(): data_rx_orig/parity_rx are counted over the settled
   * code length, not at arrival, so the period's numerator and denominator
   * describe the same groups.
   */
  private accountSet(set: RxSet): void {
    if (!set.hasAnySymbol) {
      // A gap placeholder: the whole set never produced a symbol (seen only
      // as a set-id jump). C++ settle.cc:127 counts this as sets_k_unknown —
      // NOT a tail drop, which is the 1 s heuristic for a set that had data
      // but no parity. Reporting it as tailDropped also mis-set FLG_TAIL_DROPPED.
      ++this.counters.setsKUnknown;
      return;
    }
    const nUsed = set.nKnown ? set.n : set.maxDataIndex + 1;
    let orig = 0;
    let recov = 0;
    for (let i = 0; i < nUsed; ++i) {
      if (set.orig.has(i)) ++orig;
      if (set.recov.has(i)) ++recov;
    }
    ++this.counters.setsExpected;
    this.counters.dataExpected += nUsed;
    this.counters.dataRxOrig += orig;
    this.counters.parityRx += set.parity.size;
    if (set.kKnown && set.k > 0) this.counters.parityExpected += set.k;
    if (orig + recov >= nUsed) ++this.counters.setsFull;
    // C++ semantics: "partial" is a short code (a flush before D symbols), not
    // an unrepaired group. setsFull/setsPartial therefore overlap.
    // The yardstick is the d this set declared, not the session ceiling: with
    // adaptive group sizes every full group would otherwise read as partial
    // the moment the sender shrinks d below the negotiated maximum.
    const dSet = set.dKnown ? set.d : this.dMax;
    if (nUsed < dSet) ++this.counters.setsPartial;
    if (set.kKnown && set.k > 0 && set.k <= 7 && nUsed === dSet) {
      ++this.counters.ledgerGroups;
      this.counters.ledgerKHist[set.k] = (this.counters.ledgerKHist[set.k] ?? 0) + 1;
      if (orig + recov < nUsed) ++this.counters.ledgerFailed;
    }
    if (!this.haveAccounted || seqAfter(set.setId, this.accountedThrough)) {
      this.accountedThrough = set.setId;
      this.haveAccounted = true;
    }
  }

  /** Highest set id that has been accounted for (FECSTAT monotonic key). */
  accountedThroughSetId(): number {
    return this.accountedThrough;
  }
}

/** §4.7: oob headers carry set_id = 0, index = 0, type = oob. */
export function packOobFrame(msg: Uint8Array): Buffer {
  const out = Buffer.allocUnsafe(FEC_HDR_LEN + msg.length);
  packHdr({ setId: 0, index: 0, d: 0, typeK: packTypeK(0, 0, SymbolType.Oob) }).copy(out, 0);
  Buffer.from(msg).copy(out, FEC_HDR_LEN);
  return out;
}
export function packTxFrame(s: TxSymbol): Buffer {
  const out = Buffer.allocUnsafe(FEC_HDR_LEN + s.symbol.length);
  packHdr({ setId: s.setId, index: s.index, d: s.d, typeK: s.typeK }).copy(out, 0);
  s.symbol.copy(out, FEC_HDR_LEN);
  return out;
}
export { MAX_S };
