// FEC framing: data/parity/oob symbols, RS repair and set accounting.
// Port of src/fcp/frame_tx.{h,cc}, frame_rx.cc, frame_rx_decode.cc, hdr.cc.
//
// One stream segment becomes exactly one data symbol and one UDP datagram:
//   data symbol   = len(2 LE) | payload        (len includes the 2-byte prefix)
//   parity symbol = symbol_max bytes of RS output
//   oob symbol    = raw oob message (set_id = index = 0)
// The 6-byte FEC header is prepended by Session before the AEAD envelope.

import {
  FEC_HDR_LEN, SymbolType, MAX_S, MAX_ACTIVE_SETS, MAX_GAP_PLACEHOLDERS,
  AHEAD_CONFIRM_TIMEOUT_MS, FRAME_ENVELOPE_OVERHEAD, DATA_WIRE_OVERHEAD,
  PARITY_WIRE_OVERHEAD, KCP_HEADER_RESERVE, MIN_FLUSH_MS, MAX_FLUSH_MS,
  DEFAULT_FLUSH_MS, DEFAULT_MTU, DEFAULT_IP_HEADER_LEN, MAX_RX_SYMBOL_BYTES,
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

export interface TxSymbol { setId: number; index: number; typeK: number; symbol: Buffer; }

export class FrameTx {
  private d: number;
  private limits: MtuLimits;
  private emitFn: (s: TxSymbol) => void;
  private setId = 0;
  private n = 0;
  private k = 0;
  private nextK = 0;
  private symbolMax = 0;
  private tLastMs = 0;
  private flushMs = DEFAULT_FLUSH_MS;
  private symbols: Buffer[] = [];
  closedFull = 0; closedIdle = 0; abortedSets = 0; dataSymbols = 0; paritySymbols = 0; mtuDrops = 0;

  constructor(d: number, limits: MtuLimits, emit: (s: TxSymbol) => void) {
    this.d = d; this.limits = limits; this.emitFn = emit;
  }
  setK(k: number): void { this.nextK = Math.min(k, 7); }
  setSrttMs(srtt: number): void { this.flushMs = Math.min(Math.max(srtt, MIN_FLUSH_MS), MAX_FLUSH_MS); }
  raiseLimits(l: MtuLimits): void { if (l.valid && l.payloadMax > this.limits.payloadMax) this.limits = l; }
  lowerLimits(l: MtuLimits): void { if (l.valid && l.payloadMax < this.limits.payloadMax) this.limits = l; }
  get limitsValue(): MtuLimits { return this.limits; }
  get openN(): number { return this.n; }
  get openK(): number { return this.n > 0 ? this.k : 0; }
  get currentSetId(): number { return this.setId; }

  onSegment(seg: Uint8Array, nowMs: number): void {
    if (seg.length > this.limits.payloadMax) { ++this.mtuDrops; return; }
    this.maybeFlush(nowMs);
    if (this.n === 0) { this.k = this.nextK; this.symbolMax = 0; this.symbols = []; }
    const symLen = seg.length + 2;
    const symbol = Buffer.alloc(symLen);
    putLe16(symLen, symbol, 0);
    Buffer.from(seg).copy(symbol, 2);
    this.symbolMax = Math.max(this.symbolMax, symLen);
    this.symbols.push(symbol);
    this.emitFn({ setId: this.setId, index: this.n, typeK: packTypeK(this.k, 0, SymbolType.Data), symbol });
    ++this.dataSymbols;
    ++this.n;
    this.tLastMs = nowMs;
    if (this.n === this.d) this.closeSet(true);
  }

  onTick(nowMs: number): void { this.maybeFlush(nowMs); }
  /**
   * Close the open set now instead of waiting for D segments or flushMs.
   * Control segments (ACK/RST) must not sit in a repair group: on a quiet link
   * a group only closes when the flush timer (≈srtt, capped at 200 ms) fires,
   * which caps acknowledgement at D symbols per flush — about 68 KB/s.
   */
  flush(): void { this.closeSet(false); }
  abort(): void {
    if (this.n === 0) return;
    ++this.abortedSets;
    this.setId = (this.setId + 1) >>> 0;
    this.n = 0; this.k = 0; this.symbolMax = 0; this.symbols = [];
  }

  private maybeFlush(nowMs: number): void {
    if (this.n >= 1 && nowMs - this.tLastMs >= this.flushMs) this.closeSet(false);
  }

  private closeSet(full: boolean): void {
    if (this.n === 0) return;
    if (this.d === 0) { this.abort(); return; }
    let kEff = 0;
    if (this.k >= 1) kEff = Math.max(1, Math.min(this.k, Math.ceil(this.k * this.n / this.d)));
    if (kEff >= 1) {
      const padded = this.symbols.map((s) => {
        const row = Buffer.alloc(this.symbolMax);
        s.copy(row, 0);
        return row;
      });
      const parities = rsEncode(padded, this.n, this.k, this.symbolMax);
      if (parities === null) kEff = 0;
      for (let j = 0; j < kEff; ++j) {
        if (parities === null) break;
        this.emitFn({
          setId: this.setId, index: this.n + j,
          typeK: packTypeK(this.k, j, SymbolType.Parity),
          symbol: parities[j],
        });
        ++this.paritySymbols;
      }
    }
    if (full) ++this.closedFull; else ++this.closedIdle;
    this.setId = (this.setId + 1) >>> 0;
    this.n = 0; this.k = 0; this.symbolMax = 0; this.symbols = [];
  }
}

export interface RxEventInfo { event: string; setId: number; repairMs?: number; }

interface RxSet {
  setId: number;
  n: number; nKnown: boolean; k: number; kKnown: boolean;
  symbolMax: number; maxDataIndex: number;
  data: Map<number, Buffer>; parity: Map<number, Buffer>;
  orig: Set<number>; recov: Set<number>;
  tFirstMs: number; accounted: boolean; tombstoneUntilMs: number;
  hasAnySymbol: boolean; decodeAttempts: number;
}

export interface RxCounters {
  structFail: number; stale: number; lateDup: number; recovered: number;
  recoveredLate: number; dataRxOrig: number; parityRx: number;
  dataDelivered: number; retiredDropped: number; aheadDropped: number;
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
  private d: number;
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
    dataRxOrig: 0, parityRx: 0, dataDelivered: 0, retiredDropped: 0,
    aheadDropped: 0, setsPartial: 0, setsFull: 0, setsTailDropped: 0,
    decodeAttempts: 0, badRecon: 0, symbolBudgetDrops: 0,
    setsExpected: 0, dataExpected: 0, parityExpected: 0, setsKUnknown: 0,
    ledgerGroups: 0, ledgerFailed: 0, ledgerKHist: new Array(8).fill(0),
  };
  readonly repairLatencies: number[] = [];

  constructor(o: FrameRxOptions) {
    this.d = o.d; this.p = o.p;
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

    const s = this.d + this.p;
    const existing = this.sets.get(hdr.setId);
    const nKnown = existing?.nKnown ?? false;
    const n = existing?.n ?? 0;
    if (validateHdr(hdr, this.d, s, nKnown, n) !== HdrStatus.Ok) { ++this.counters.structFail; return; }
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
    // k is first-wins and clamped to the negotiated parity ceiling.
    const kClamped = Math.min(kField, this.p);
    if (!set.kKnown) { set.k = kClamped; set.kKnown = true; }

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
      this.deliverFn(symbol.subarray(2), { recovered: false, late: late || lateUnexpected });
      this.tryDecode(set, nowMs);
      return;
    }

    // Parity: n = index - j is the only source of n.
    if (set.parity.has(hdr.index)) return;
    if (!set.nKnown && set.maxDataIndex >= nNew) { ++this.counters.structFail; return; }
    set.n = nNew; set.nKnown = true;
    set.parity.set(hdr.index, symbol);
    this.store(set, hdr.index, symbol);
    this.tryDecode(set, nowMs);
  }

  private store(set: RxSet, idx: number, symbol: Buffer): void {
    set.hasAnySymbol = true;
    set.symbolMax = Math.max(set.symbolMax, symbol.length);
    const old = set.data.get(idx);
    const oldLen = old ? old.length : 0;
    if (this.symbolBytes - oldLen + symbol.length > MAX_RX_SYMBOL_BYTES) {
      // Same policy as frame_rx.cc: dropping is recovered by the peer's ARQ,
      // growing the heap is not. Index masks stay set, exactly as in C++.
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
    if (missing.length === 0 || missing.length > set.k || set.symbolMax < 2) return;
    const n = set.n, k = set.k;
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
      set.data.set(i, s);
      const repairMs = Math.min(0xffff, Math.max(0, nowMs - set.tFirstMs));
      this.repairLatencies.push(repairMs);
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
      }
      this.sets.delete(victim);
      this.accountBoundary.delete(victim);
    }
    const set: RxSet = {
      setId, n: 0, nKnown: false, k: 0, kKnown: false, symbolMax: 0, maxDataIndex: 0,
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
        setId: id, n: 0, nKnown: false, k: 0, kKnown: false, symbolMax: 0, maxDataIndex: 0,
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
      // A gap placeholder: the whole set never produced a symbol.
      ++this.counters.setsTailDropped;
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
    if (nUsed < this.d) ++this.counters.setsPartial;
    if (set.kKnown && set.k > 0 && set.k <= 7 && nUsed === this.d) {
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
  const out = Buffer.alloc(FEC_HDR_LEN + msg.length);
  packHdr({ setId: 0, index: 0, typeK: packTypeK(0, 0, SymbolType.Oob) }).copy(out, 0);
  Buffer.from(msg).copy(out, FEC_HDR_LEN);
  return out;
}
export function packTxFrame(s: TxSymbol): Buffer {
  const out = Buffer.alloc(FEC_HDR_LEN + s.symbol.length);
  packHdr({ setId: s.setId, index: s.index, typeK: s.typeK }).copy(out, 0);
  s.symbol.copy(out, FEC_HDR_LEN);
  return out;
}
export { MAX_S };
