// FCP-STREAM v1 reliable ordered byte stream. Port of src/fcp/stream*.cc.
//
// Sequence numbers are BYTE offsets, numbered from 0 independently in each
// direction. A segment is exactly one data symbol / one UDP datagram, so
// segment boundaries survive the wire. FEC repairs erasures but never
// retransmits: ARQ lives here. A FIN is a pseudo byte at the end of the peer's
// stream, so cum_ack covers it and the sender can close without a second ack.
//
// No sockets and no clocks: the host passes nowMs and drives onTick(); the
// emitted segments go to Session.onStreamSegment().

import {
  STREAM_TYPE_DATA, STREAM_TYPE_ACK, STREAM_TYPE_ACK_V2, STREAM_TYPE_RST,
  STREAM_FLAG_FIN, STREAM_DATA_HDR_LEN, STREAM_ACK_LEN, DUP_ACK_THRESH, ACK_DELAY_MS,
  DEFAULT_SEND_WINDOW_BYTES, DEFAULT_RCV_BUF_BYTES, DEFAULT_SRTT_MS,
  DEFAULT_IDLE_TIMEOUT_MS, PUMP_BURST_BYTES, ZERO_WINDOW_PROBE_MS, ACK_EVERY_SEGMENTS,
  HOLE_DUP_ACK_MS, FAST_RETX_SEGMENTS, MIN_RETX_INTERVAL_MS,
  FAST_RETX_MIN_AGE_MS, RETX_RTT_FACTOR,
  FAST_RETX_TIGHTEN_STEP, FAST_RETX_TIGHTEN_FLOOR,
  RTT_PEAK_DECAY_MS, RTT_PEAK_MAX_MS, RTTVAR_NOISE_FLOOR_MS,
  MIN_OOB_CHUNKS, MAX_OOB_CHUNKS,
  TLP_MIN_PTO_MS, TLP_MAX_PROBES,
  HOLE_DUP_ACK_MIN_MS, HOLE_DUP_ACK_DIVISOR, RETX_LAT_SAMPLES,
} from '../constants.ts';
import {
  seqAfter, seqAtOrAfter, seqDist, getLe32, putLe32,
} from '../wire.ts';
import {
  parseSegment, encodeData, encodeAck, encodeAckV2, encodeRst,
  type Segment,
} from './segment.ts';

export interface StreamConfig {
  maxSegment: number;
  sendWindowBytes?: number;
  rcvBufBytes?: number;
  ackEvery?: number;
  ackV2?: boolean;
  initialSrttMs?: number;
  rtoMinMs?: number;
  rtoMaxMs?: number;
  idleTimeoutMs?: number;
}
export interface StreamCallbacks {
  send: (seg: Buffer) => void;
  read: (bytes: Buffer) => void;
  closed: (reason: string) => void;
  eof?: () => void;
  rtt?: (srttMs: number) => void;
  /** Bytes newly cum-acked, i.e. confirmed delivered to the peer. This is the
   *  only honest measure of the *send*-direction rate: `read` reports the
   *  receive direction, which is an ACK trickle during a download. */
  acked?: (bytes: number, nowMs: number) => void;
}

interface SndSeg {
  offset: number; bytes: Buffer; fin: boolean; end: number;
  sentMs: number; acked: boolean; sacked: boolean; retransmits: number;
  /** A TLP probe re-sent this segment without counting as a loss
   *  (retransmits stays 0, so fast-retransmit's ratio is unaffected). Multiple
   *  copies are then in flight, so an ACK can no longer be attributed to one
   *  of them — the same ambiguity Karn's guard handles for real retransmits.
   *  The RTT sampler must skip probed segments rather than sample against the
   *  probe's rewritten sentMs. */
  probed: boolean;
  /** Send time of the FIRST copy, never rewritten by a retransmission. This is
   *  the only honest denominator for "how long did this loss cost us": sentMs
   *  moves forward with every copy, so measuring against it reported the
   *  retransmit interval (tens of ms) instead of the recovery time. */
  firstSentMs: number;
}
interface RcvChunk { offset: number; bytes: Buffer; }

export const StreamState = { Open: 0, SendingFin: 1, PeerClosed: 2, Closed: 3 } as const;

export class Stream {
  private cfg: Required<StreamConfig>;
  private cb: StreamCallbacks;
  state: number = StreamState.Open;
  closeReason = '';
  badSegs = 0; segsSent = 0; retransmits = 0; dupBytes = 0;
  /** Out-of-order runs dropped because the chunk ceiling was reached. */
  oobDrops = 0;
  /** Retransmits split by trigger, so a ratio can be attributed instead of
   *  guessed at. Not used for control flow. */
  retxFast = 0; retxRto = 0; fastRounds = 0;
  /** Ring of recovery latencies (ms) for segments that needed at least one
   *  retransmission: first send -> cum/sacked confirmation. FEC has had a
   *  p50/p95 for a while; ARQ recovery was invisible, which made every change
   *  to it unverifiable. */
  private retxLat: number[] = [];
  private retxLatNext = 0;
  srttMs: number;

  // Send side.
  private pending: Buffer[] = [];
  private pendingBytes = 0;
  private sndUna = 0; private sndNext = 0; private sndMax = 0;
  private tx: SndSeg[] = [];
  private peerRwnd: number;
  private finPending = false; private finSent = false; private finOffset = 0;
  // Duplicate-ACK detection for the send direction. Kept separate from the
  // SACK-rotation state below: sharing one pair made an inbound ACK we emitted
  // (which rewrites these to our own rcvNxt) look like a repeated peer ACK, and
  // made a delivered segment clear the duplicate-ACK tally, so fast retransmit
  // either fired spuriously or never armed.
  private lastAckCum = 0; private haveAckCum = false; private dupAcks = 0;
  private sackRotateCum = 0; private sackRotateHave = false;
  /** Highest byte offset the peer has ever reported receiving (cum ack or any
   *  SACK block). Anything below it that is neither acked nor sacked is
   *  provably missing, which is the only safe basis for fast retransmit. */
  private sackedHigh = 0;
  private rtoMs: number;
  private rttvarMs: number;
  /** Best RTT ever observed. Anchors the estimator so hole-delayed segments
   *  (a segment that sat behind a gap for seconds) cannot inflate srtt. */
  private minRttMs = 0;
  /** Largest RTT a single segment has legitimately taken, over a sliding
   *  window. srtt is a *mean*, so on a path with real jitter the mean sits far
   *  below the spread: a 20 ms path with 60 ms of reordering has srtt ~57 ms
   *  while individual segments routinely take 80 ms. Deriving the reorder gate
   *  from the mean therefore declared every late-but-fine segment lost —
   *  measured on a zero-loss link at 27-43% retransmissions, almost all of them
   *  spurious. The gate has to be bounded by what the path has actually been
   *  observed to deliver, not by its average. */
  private rttPeakMs = 0;
  /** Decay for rttPeakMs so a one-off spike cannot pin the gate for a session. */
  private rttPeakAtMs = 0;
  /** Tail-loss probing: 0 = no probe in flight, counts toward TLP_MAX_PROBES. */
  private tlpProbes = 0;
  /** Send time of the most recent data segment (TLP clock base). */
  private lastSendMs = 0;
  /** Fast-retransmit reorder relaxation: multiplies the RTT-derived age base
   *  (1 = off, up to 2 = quic-go's relaxed time threshold). Raised after
   *  rounds that bought nothing (reordering), decayed after rounds that
   *  recovered real loss. */
  private retxRelax = 1;
  /** Mirror of retxRelax: divides the age base after rounds that recovered real
   *  loss. Without it the gate stayed at a full RTT for the whole session even
   *  after a hundred rounds proved the losses were genuine, so every single-hole
   *  recovery paid ~1.75 RTT. Snapped back to 1 as soon as a round turns out to
   *  have been reordering (see noteSpurious(), which has the evidence). */
  private retxTighten = 1;
  /** Set when the current round's copy was not the one that got through. */
  private fastRoundSpurious = false;
  /** Diagnostic only: rounds that were reordering, not loss. */
  spuriousFastRetx = 0;
  /** SACK ranges carried by the most recent ACK (v2: up to 64; v1: 0 or 1).
   *  Kept for marking segments `sacked` and for diagnostics. It is deliberately
   *  NOT used as loss evidence: see fastRetransmit() for why "ranges start
   *  beyond this segment" cannot distinguish a lost segment from a late one. */
  private sackRanges: Array<{ start: number; end: number }> = [];
  private fastRoundMs = 0;
  private fastRoundUna = 0;
  private fastRoundSeq = -1;

  // Receive side.
  private rcvNxt = 0; private oob: RcvChunk[] = []; private oobBytes = 0;
  private deliveryPending = 0;
  private peerFin = false; private peerFinAt = 0; private eofDelivered = false;
  private ackPending = false; private lastAckMs = 0; private sackRotate = 0;
  private ackDebt = 0;
  private lastInboundMs = 0; private lastRttSampleMs = 0;
  private lastZeroWinProbeMs = 0;

  constructor(config: StreamConfig, cb: StreamCallbacks) {
    this.cfg = {
      maxSegment: config.maxSegment,
      sendWindowBytes: config.sendWindowBytes ?? DEFAULT_SEND_WINDOW_BYTES,
      rcvBufBytes: config.rcvBufBytes ?? DEFAULT_RCV_BUF_BYTES,
      ackEvery: config.ackEvery ?? 1,
      ackV2: config.ackV2 ?? false,
      initialSrttMs: config.initialSrttMs ?? DEFAULT_SRTT_MS,
      rtoMinMs: config.rtoMinMs ?? 100,
      rtoMaxMs: config.rtoMaxMs ?? 5000,
      idleTimeoutMs: config.idleTimeoutMs ?? DEFAULT_IDLE_TIMEOUT_MS,
    };
    this.cb = cb;
    this.srttMs = this.cfg.initialSrttMs > 0 ? this.cfg.initialSrttMs : DEFAULT_SRTT_MS;
    // RFC 6298: RTO = SRTT + 4 x RTTVAR, so jitter on a long path widens the
    // timer instead of retransmitting into it.
    this.rttvarMs = Math.max(1, Math.round(this.srttMs / 2));
    this.rtoMs = this.rtoFor();
    this.peerRwnd = this.cfg.rcvBufBytes;
  }

  private rtoFor(): number {
    return Math.min(Math.max(this.srttMs + 4 * this.rttvarMs, this.cfg.rtoMinMs), this.cfg.rtoMaxMs);
  }

  setAckV2(on: boolean): void { this.cfg.ackV2 = on; }
  /**
   * `n` is the whole stream segment size (DATA header included).
   * Shrinking happens when PMTUD falls back after a raised size black-holed:
   * segments already carved at the larger size can no longer be emitted
   * (FrameTx drops them as oversize), so a retransmit of one would be lost
   * forever. Re-cut them here; byte offsets and the queued bytes stay
   * identical, so cumulative/SACK accounting is unaffected.
   */
  setMaxSegment(n: number): void {
    if (n <= 0 || n === this.cfg.maxSegment) return;
    if (n > this.cfg.maxSegment) { this.cfg.maxSegment = n; return; }
    if (n <= STREAM_DATA_HDR_LEN) return; // cannot carry a payload; keep the old carving
    this.cfg.maxSegment = n;
    const piece = n - STREAM_DATA_HDR_LEN;
    const recut: SndSeg[] = [];
    for (const s of this.tx) {
      if (s.bytes.length <= piece) { recut.push(s); continue; }
      for (let off = 0; off < s.bytes.length; off += piece) {
        const len = Math.min(piece, s.bytes.length - off);
        const fin = s.fin && off + len === s.bytes.length;
        const part: SndSeg = {
          offset: (s.offset + off) >>> 0,
          bytes: s.bytes.subarray(off, off + len),
          fin,
          end: (s.offset + off + len + (fin ? 1 : 0)) >>> 0,
          // A SACKed piece stays delivered; everything else has never been on
          // the wire at this size, so the RTO pass must re-emit it.
          sentMs: s.sacked ? s.sentMs : 0,
          acked: false,
          sacked: s.sacked,
          retransmits: s.sacked ? s.retransmits : Math.max(1, s.retransmits),
          probed: s.probed,
          firstSentMs: s.firstSentMs,
        };
        recut.push(part);
      }
    }
    this.tx = recut;
    this.dupAcks = 0;
  }

  /**
   * In-flight budget. Both halves have to move together: growing only the send
   * window is useless because `window()` is min(sendWindow, peerRwnd), and the
   * peer's rwnd is derived from the buffer we advertise here.
   */
  setWindows(sendBytes: number, rcvBytes: number): void {
    if (sendBytes > 0) this.cfg.sendWindowBytes = sendBytes;
    if (rcvBytes > 0) this.cfg.rcvBufBytes = rcvBytes;
  }
  get sendWindowBytes(): number { return this.cfg.sendWindowBytes; }
  get rcvBufBytes(): number { return this.cfg.rcvBufBytes; }
  /** Bytes queued but not yet handed to the wire. */
  get pendingQueueBytes(): number { return this.pendingBytes; }
  /** Bytes on the wire not yet cum-acked. */
  get inflightBytes(): number { return seqDist(this.sndNext, this.sndUna); }
  /** Window the peer last advertised. */
  get peerWindowBytes(): number { return this.peerRwnd; }
  /** Next byte offset we can deliver in order. A stalled value with a large
   *  reorder buffer means one hole is holding everything back. */
  get recvNext(): number { return this.rcvNxt; }
  get reorderBytes(): number { return this.oobBytes; }
  get canWrite(): boolean { return this.sendSpace() > 0 && !this.finPending; }
  get isClosed(): boolean { return this.state === StreamState.Closed; }
  get eofReceived(): boolean { return this.eofDelivered; }
  get cumAcked(): number { return this.sndUna; }
  get deliveryPendingBytes(): number { return this.deliveryPending; }
  /** Negotiated wide ACK. Diagnostic: sid streams must inherit it. */
  get ackV2Enabled(): boolean { return this.cfg.ackV2; }
  /** Highest byte the peer has ever reported (cumulative or SACK). Diagnostic:
   *  a SACK range past sndMax must not raise it. */
  get sackedHighWater(): number { return this.sackedHigh; }

  private recordRetxLatency(ms: number): void {
    if (this.retxLat.length < RETX_LAT_SAMPLES) {
      this.retxLat.push(ms);
    } else {
      this.retxLat[this.retxLatNext] = ms;
      this.retxLatNext = (this.retxLatNext + 1) % RETX_LAT_SAMPLES;
    }
  }

  /** Copy of the latency ring, for the session-level aggregate. */
  retxLatencySamples(): number[] { return this.retxLat.slice(); }

  /** Nearest-rank percentile over the ring, like the FEC reporter's. */
  private retxLatPct(pct: number): number {
    if (this.retxLat.length === 0) return 0;
    const sorted = this.retxLat.slice().sort((a, b) => a - b);
    const rank = Math.min(sorted.length, Math.max(1, Math.ceil((pct / 100) * sorted.length)));
    return sorted[rank - 1]!;
  }
  get retxLatencyP50Ms(): number { return this.retxLatPct(50); }
  get retxLatencyP95Ms(): number { return this.retxLatPct(95); }
  get retxLatencyCount(): number { return this.retxLat.length; }

  /** Bytes the host may still write. In-flight bytes count: the C++ send_space()
   *  subtracts (queued - acked), and leaving them out let the host queue a full
   *  window on top of a full window already on the wire. */
  private sendSpace(): number {
    if (this.state === StreamState.Closed) return 0;
    const used = this.pendingBytes + this.inflightBytes;
    return this.cfg.sendWindowBytes > used ? this.cfg.sendWindowBytes - used : 0;
  }

  /** Host accepted `n` previously delivered bytes (backpressure release). */
  consumed(n: number): void { this.deliveryPending = Math.max(0, this.deliveryPending - n); }

  write(data: Uint8Array, nowMs: number): number {
    // Once our FIN has been emitted the byte stream ends at finOffset: new data
    // would be sequenced *after* the fin pseudo-byte, reach the peer as bytes
    // past its peerFinAt, and be thrown away as badSegs while the local side
    // believed it had been queued. Refuse it instead.
    if (this.finPending || this.finSent || this.state === StreamState.Closed) return 0;
    const room = this.sendSpace();
    const take = Math.min(data.length, room);
    if (take <= 0) return 0;
    this.pending.push(Buffer.from(data.subarray(0, take)));
    this.pendingBytes += take;
    this.pump(nowMs);
    return take;
  }

  closeWrite(nowMs: number): void {
    // `finSent` matters: after the FIN was emitted once, finPending is false
    // again, so a second closeWrite (an 'end' plus an error path, a host that
    // calls it defensively) used to enqueue a *second* FIN one byte past the
    // first. The peer rejects the new fin offset as a protocol violation and
    // never acks it, so the stream hung in SendingFin until the idle timer.
    if (this.finPending || this.finSent || this.state === StreamState.Closed) return;
    this.finPending = true;
    this.state = StreamState.SendingFin;
    this.pump(nowMs);
  }

  sendRst(): void { this.cb.send(encodeRst()); this.finish('reset'); }

  private window(): number {
    return Math.max(0, Math.min(this.cfg.sendWindowBytes, this.peerRwnd));
  }

  private pump(nowMs: number): void {
    // Burst budget must cover one full ACK cycle (ACK_EVERY_SEGMENTS segments).
    // A fixed byte budget starves the replenish loop once PMTUD grows the
    // segment past ~1 KiB payload: at 1430 B/segment six segments need 8580 B,
    // and a 6 KiB budget caps steady-state throughput at 71.6% of window/RTT.
    const burstBytes = Math.max(
      PUMP_BURST_BYTES,
      ACK_EVERY_SEGMENTS * Math.max(0, this.cfg.maxSegment - STREAM_DATA_HDR_LEN),
    );
    if (this.state === StreamState.Closed) return;
    let guard = 0;
    let sentBytes = 0;
    while (guard++ < 4096) {
      const inflight = seqDist(this.sndNext, this.sndUna);
      if (inflight >= this.window()) break;
      if (this.pendingBytes === 0 && !this.finPending) break;
      // maxSegment is the WHOLE stream segment (6-byte DATA header included),
      // matching C++ StreamConfig::max_segment = Session::payload_max().
      const room = Math.min(this.cfg.maxSegment, this.window() - inflight);
      const payloadRoom = Math.min(room, this.cfg.maxSegment) - STREAM_DATA_HDR_LEN;
      if (payloadRoom <= 0 && !(this.finPending && this.pendingBytes === 0)) break;
      const chunk = this.takePending(Math.max(0, payloadRoom));
      let fin = false;
      if (this.finPending && this.pendingBytes === 0) { fin = true; this.finSent = true; this.finPending = false; }
      if (chunk.length === 0 && !fin) break;
      const end = (this.sndNext + chunk.length + (fin ? 1 : 0)) >>> 0;
      const seg: SndSeg = {
        offset: this.sndNext, bytes: chunk, fin, end,
        sentMs: nowMs, acked: false, sacked: false, retransmits: 0, probed: false,
        firstSentMs: nowMs,
      };
      if (fin) this.finOffset = (this.sndNext + chunk.length) >>> 0;
      this.tx.push(seg);
      this.sndNext = end;
      if (seqAfter(end, this.sndMax)) this.sndMax = end;
      this.emitData(seg, nowMs);
      if (fin) break;
      // Hand the rest to the next tick / ACK. Emitting a whole window in one
      // synchronous loop is what made the path drop the tail of every burst.
      sentBytes += chunk.length;
      if (sentBytes >= burstBytes) break;
    }
  }

  private takePending(n: number): Buffer {
    if (n <= 0 || this.pendingBytes === 0) return Buffer.alloc(0);
    const out = Buffer.allocUnsafe(Math.min(n, this.pendingBytes)); // fully copied below
    let off = 0;
    while (off < out.length && this.pending.length) {
      const head = this.pending[0];
      const take = Math.min(head.length, out.length - off);
      head.copy(out, off, 0, take);
      off += take;
      if (take === head.length) this.pending.shift();
      else this.pending[0] = head.subarray(take);
    }
    this.pendingBytes -= off;
    return out;
  }

  private emitData(s: SndSeg, nowMs: number): void {
    this.cb.send(encodeData(s.offset, s.fin ? STREAM_FLAG_FIN : 0, s.bytes));
    ++this.segsSent;
    this.lastSendMs = nowMs;
  }

  onSegment(buf: Uint8Array, nowMs: number): void {
    if (this.state === StreamState.Closed) return;
    const seg = parseSegment(buf);
    if (!seg) { ++this.badSegs; return; }
    this.lastInboundMs = Math.max(this.lastInboundMs, nowMs);
    switch (seg.type) {
      case STREAM_TYPE_DATA: this.onData(seg, nowMs); break;
      case STREAM_TYPE_ACK: this.onAck(seg.cum, seg.rwnd, [{ start: seg.sackStart, end: seg.sackEnd }], nowMs); break;
      case STREAM_TYPE_ACK_V2: this.onAck(seg.cum, seg.rwnd, seg.ranges, nowMs); break;
      case STREAM_TYPE_RST: this.finish('reset'); break;
      default: ++this.badSegs; break;
    }
  }

  private onData(seg: Extract<Segment, { type: typeof STREAM_TYPE_DATA }>, nowMs: number): void {
    const offset = seg.seq;
    const fin = (seg.flags & STREAM_FLAG_FIN) !== 0;
    const n = seg.payload.length;
    const dataEnd = (offset + n) >>> 0;
    const segEnd = (dataEnd + (fin ? 1 : 0)) >>> 0;
    if (!seqAfter(segEnd, this.rcvNxt)) {
      this.dupBytes += n;
      this.emitAck(nowMs);
      return;
    }
    if (seqDist(offset, this.rcvNxt) > this.cfg.rcvBufBytes) return;
    if (this.deliveryPending >= this.cfg.rcvBufBytes) { this.emitAck(nowMs); return; }
    if (this.peerFin) {
      if (fin && dataEnd !== this.peerFinAt) { ++this.badSegs; return; }
      if (!fin && seqAfter(dataEnd, this.peerFinAt)) { ++this.badSegs; return; }
    }
    let at = offset;
    let payload = seg.payload;
    if (seqDist(at, this.rcvNxt) < 0) {
      const drop = -seqDist(at, this.rcvNxt);
      this.dupBytes += Math.min(drop, payload.length);
      if (drop >= payload.length) payload = Buffer.alloc(0);
      else payload = payload.subarray(drop);
      at = (at + drop) >>> 0;
    }
    if (payload.length) this.insertChunk(at, payload);
    if (fin) { this.peerFin = true; this.peerFinAt = dataEnd; }
    this.deliverPrefix(nowMs);
    // A gap makes the ack urgent: duplicate acks are what drive fast retransmit.
    // A FIN is urgent even when it lands exactly at rcvNxt: that ACK is what
    // lets the peer finish instead of waiting for its idle clock.
    this.ackDue(nowMs, fin || this.rcvNxt !== segEnd);
  }

  /**
   * Coalesce acknowledgements. The wire cost is not the problem — the burst is:
   * a 64 KiB window arrives as ~46 datagrams and answering each one individually
   * produced 46 back-to-back acks, most of which the uplink dropped. The sender
   * then saw cumAck creep forward a few segments per round trip while its
   * window stayed full.
   */
  private ackDue(nowMs: number, urgent: boolean): void {
    ++this.ackDebt;
    // A hole must be reported at once, but not once per arriving datagram: at
    // ~800 segments/s that was 800 acks/s, each leaving immediately as its own
    // encrypted datagram. Two segments still prove a hole and halve the ack
    // rate; detection is delayed by at most one segment.
    const need = urgent ? 2 : ACK_EVERY_SEGMENTS;
    if (this.ackDebt >= need) {
      this.ackDebt = 0;
      this.emitAck(nowMs);
      return;
    }
    this.ackPending = true;
  }

  private oobMaxChunks(): number {
    return Math.min(MAX_OOB_CHUNKS, Math.max(MIN_OOB_CHUNKS, Math.floor(this.cfg.rcvBufBytes / 512)));
  }

  private insertChunk(offset: number, bytes: Buffer): void {
    // A segment landing exactly on rcvNxt fills the hole the cumulative ack is
    // waiting on, so it must never be dropped. Anything else is bounded by the
    // chunk ceiling: a byte ceiling alone lets a peer put one byte in each run
    // and turn 256 KiB of reorder data into 128 k Buffer objects.
    if (offset !== this.rcvNxt && this.oob.length >= this.oobMaxChunks()) {
      ++this.oobDrops;
      return;
    }
    // Clip against already buffered ranges, then merge contiguous neighbours.
    const end = (offset + bytes.length) >>> 0;
    const kept: RcvChunk[] = [];
    for (const c of this.oob) {
      const cEnd = (c.offset + c.bytes.length) >>> 0;
      if (seqAtOrAfter(c.offset, end) || seqAtOrAfter(offset, cEnd)) { kept.push(c); continue; }
      // overlap: keep only the non-overlapping prefix/suffix of the old chunk
      if (seqAfter(c.offset, offset) === false && seqDist(c.offset, offset) < 0) {
        const headLen = seqDist(offset, c.offset);
        if (headLen > 0) kept.push({ offset: c.offset, bytes: c.bytes.subarray(0, headLen) });
      }
      if (seqAfter(cEnd, end)) {
        const tailOff = seqDist(end, c.offset);
        if (tailOff > 0 && tailOff < c.bytes.length) kept.push({ offset: end, bytes: c.bytes.subarray(tailOff) });
      }
    }
    kept.push({ offset, bytes: Buffer.from(bytes) });
    kept.sort((a, b) => seqDist(a.offset, b.offset));
    const merged: RcvChunk[] = [];
    for (const c of kept) {
      const last = merged[merged.length - 1];
      if (last && (last.offset + last.bytes.length) >>> 0 === c.offset) {
        last.bytes = Buffer.concat([last.bytes, c.bytes]);
      } else {
        merged.push({ offset: c.offset, bytes: c.bytes });
      }
    }
    this.oob = merged;
    this.oobBytes = merged.reduce((a, c) => a + c.bytes.length, 0);
  }

  private deliverPrefix(nowMs: number): void {
    let guard = 0;
    while (guard++ < 65536) {
      let advanced = false;
      for (let i = 0; i < this.oob.length; ++i) {
        const c = this.oob[i];
        const cEnd = (c.offset + c.bytes.length) >>> 0;
        if (seqAtOrAfter(this.rcvNxt, c.offset) && seqAfter(cEnd, this.rcvNxt)) {
          const skip = seqDist(this.rcvNxt, c.offset);
          const part = c.bytes.subarray(skip);
          this.deliveryPending += part.length;
          this.cb.read(part);
          this.rcvNxt = cEnd;
          this.oob.splice(i, 1);
          this.oobBytes -= c.bytes.length;
          advanced = true;
          break;
        }
      }
      if (!advanced) break;
    }
    if (this.peerFin && !this.eofDelivered && this.rcvNxt === this.peerFinAt) {
      this.rcvNxt = (this.rcvNxt + 1) >>> 0; // the fin pseudo byte
      this.eofDelivered = true;
      this.state = StreamState.PeerClosed;
      this.cb.eof?.();
      // The peer's FIN can arrive after its ACK of ours. handle_ack() already
      // ran on that ACK (eof was not delivered yet), so nothing else would
      // complete the close and the stream would sit until the idle timer.
      if (this.finSent && seqAtOrAfter(this.sndUna, (this.finOffset + 1) >>> 0)) {
        // ACK the peer's FIN before finish(): the close callback may tear the
        // host's send path down, and this is the only packet that lets the
        // peer complete its own close.
        this.emitAck(nowMs);
        this.finish('peer_close');
      }
    }
    void nowMs;
  }

  private cumOut(): number { return this.rcvNxt; }
  private rwndOut(): number {
    const used = this.oobBytes + this.deliveryPending;
    return this.cfg.rcvBufBytes > used ? this.cfg.rcvBufBytes - used : 0;
  }

  private emitAck(nowMs: number): void {
    this.ackPending = false;
    // Any path that answers settles the coalescing debt; leaving it set made
    // the next few segments emit an extra ACK sooner than ACK_EVERY_SEGMENTS.
    this.ackDebt = 0;
    this.lastAckMs = nowMs;
    const cum = this.cumOut();
    const rwnd = this.rwndOut();
    if (this.cfg.ackV2) {
      // An ACK is a stream segment and has to fit the same datagram budget as
      // data. ACK v2 is variable length: 10 B fixed plus up to 2 x 5 B per
      // range, so 64 ranges is 650 B worst case. FrameTx drops anything over
      // payloadMax without a word (mtuDrops), so on a small MTU a wide ACK
      // simply vanished — and an ACK that never arrives is indistinguishable
      // from a lost one, which turns every wide hole into an RTO stall. Cap the
      // range count at what the budget actually holds; the dropped tail is
      // still covered by the next ACK, and cum/ rwnd always go out.
      const budget = this.cfg.maxSegment;
      const maxRanges = Math.max(0, Math.min(64, Math.floor((budget - 10) / 10)));
      const blocks = this.oob.slice(0, maxRanges).map((c) => ({ start: c.offset, end: (c.offset + c.bytes.length) >>> 0 }));
      let ack = encodeAckV2(cum, rwnd, blocks);
      // The estimate above is an upper bound per range; shrink until it fits
      // for real (a range can encode shorter than 5+5).
      while (ack.length > budget && blocks.length > 0) {
        blocks.pop();
        ack = encodeAckV2(cum, rwnd, blocks);
      }
      if (ack.length > budget) return; // even an empty v2 ACK does not fit
      this.cb.send(ack);
      return;
    }
    let sackStart = cum, sackEnd = cum;
    if (this.oob.length) {
      if (this.sackRotateHave && cum === this.sackRotateCum) ++this.sackRotate;
      else this.sackRotate = 0;
      this.sackRotateCum = cum; this.sackRotateHave = true;
      const blk = this.oob[this.sackRotate % this.oob.length];
      sackStart = blk.offset;
      sackEnd = (blk.offset + blk.bytes.length) >>> 0;
    } else {
      this.sackRotateHave = false; this.sackRotate = 0;
    }
    // A v1 ACK is a fixed 17 bytes. That is below every legal payloadMax except
    // the very smallest budgets, and dropping it silently is worse than sending
    // it without the SACK block (cum still advances the peer's window).
    if (STREAM_ACK_LEN > this.cfg.maxSegment) {
      if (10 > this.cfg.maxSegment) return;
      this.cb.send(encodeAckV2(cum, rwnd, []));
      return;
    }
    this.cb.send(encodeAck(cum, rwnd, sackStart, sackEnd));
  }

  private onAck(cum: number, rwnd: number, ranges: Array<{ start: number; end: number }>, nowMs: number): void {
    if (seqAfter(cum, this.sndMax)) { ++this.badSegs; return; }
    this.peerRwnd = rwnd;
    // A SACK block can never describe bytes this side has not sent. Ranges
    // past sndMax are discarded instead of being trusted: an over-large range
    // would raise sackedHigh and mark real in-flight segments sacked, which
    // suppresses their retransmission and permanently loses them.
    this.sackRanges = ranges.filter((r) => seqAfter(r.end, r.start) && seqAtOrAfter(this.sndMax, r.end));
    const prevUna = this.sndUna;
    // A cumulative point that does not move forward is a duplicate or a stale
    // ACK reordered behind a newer one. Moving sndUna backwards would inflate
    // the in-flight count and shrink the window for good; C++ guards this in
    // ack_advance_cum, and the SACK/dup-ack halves still run.
    const advanced = seqAfter(cum, prevUna);
    let newlyAcked = false;
    let sampleMs = -1;
    if (advanced) {
      for (const s of this.tx) {
        if (!s.acked && seqAtOrAfter(cum, s.end)) {
          s.acked = true; newlyAcked = true;
          // Karn: a retransmitted segment cannot tell us which copy the ACK
          // refers to. Sampling it measured the retransmit interval (~15 ms)
          // instead of the path RTT (220 ms), which shrank RTO to rtoMin, which
          // triggered yet more retransmits — the link ended up spending ~73% of
          // its bandwidth resending data the peer already had.
          // A probed segment has two copies in flight even though
          // retransmits stayed 0: the ACK could be for either, so its timing
          // is not a valid RTT sample (Karn). Skip it just like a retransmit.
          if (sampleMs < 0 && s.retransmits === 0 && !s.probed) sampleMs = Math.max(0, nowMs - s.sentMs);
          // Recovery latency, the opposite question: for a segment that DID
          // need retransmission, how long after its first copy did recovery
          // finally happen. Counted separately from the RTT sample so the two
          // cannot contaminate each other.
          if (s.retransmits > 0) this.recordRetxLatency(Math.max(0, nowMs - s.firstSentMs));
          // Was the last copy the one that arrived? A copy needs a full minRtt
          // to make the round trip, so a confirmation that arrives sooner came
          // from an earlier copy: the round that sent the copy was a reordering
          // false positive. This is RACK's spurious-detection test and it is the
          // only honest evidence for deciding whether the age gate may narrow.
          if (s.retransmits > 0 && this.minRttMs > 0 && nowMs - s.sentMs < this.minRttMs) {
            ++this.spuriousFastRetx;
            this.fastRoundSpurious = true;
          }
        }
      }
      this.sndUna = cum;
    }
    // Delivery rate for window sizing. Counted here, off the ACK clock, so it
    // reflects bytes the peer actually confirmed — not bytes we queued.
    if (newlyAcked) this.cb.acked?.(seqDist(cum, prevUna), nowMs);
    if (sampleMs >= 0 && sampleMs <= 1000 &&
        (this.minRttMs === 0 || sampleMs < this.minRttMs)) this.minRttMs = sampleMs;
    // A sample far above the best RTT is not the path RTT: it is a segment
    // that sat in a sequence hole until the gap was repaired. Feeding those in
    // dragged srtt from 190 ms to 3.6 s, which pushed RTO to seconds and
    // stalled every recovery.
    const rttCeiling = this.minRttMs > 0 ? Math.max(4 * this.minRttMs, this.cfg.rtoMinMs) : 2000;
    const plausible = sampleMs >= 0 && sampleMs <= Math.min(rttCeiling, 2000);
    if (newlyAcked) {
      if (plausible && nowMs - this.lastRttSampleMs >= 10) {
        const err = Math.abs(sampleMs - this.srttMs);
        this.rttvarMs = Math.round((3 * this.rttvarMs + err) / 4);
        this.srttMs = Math.max(1, Math.round((7 * this.srttMs + sampleMs) / 8));
        this.lastRttSampleMs = nowMs;
        this.cb.rtt?.(this.srttMs);
      }
      // Track the worst *legitimate* delay, not just the mean. Only plausible
      // samples qualify: a hole-delayed segment is exactly the delay this must
      // not learn, or the gate would grow to the RTO. Decay keeps one spike
      // from pinning it for the rest of the session.
      if (plausible && sampleMs > 0) {
        if (sampleMs >= this.rttPeakMs || nowMs - this.rttPeakAtMs >= RTT_PEAK_DECAY_MS) {
          this.rttPeakMs = sampleMs;
          this.rttPeakAtMs = nowMs;
        }
      }
      // Clamp drift: a single burst of hole-delayed samples must not leave the
      // estimator stuck at seconds for the rest of the session.
      if (this.minRttMs > 0 && this.srttMs > rttCeiling) this.srttMs = rttCeiling;
      // Any forward progress ends the backoff, even when no sample was usable
      // (all of it was retransmitted). Otherwise one burst of losses doubles
      // RTO repeatedly and recovery takes seconds.
      this.rtoMs = this.rtoFor();
    }
    for (const r of this.sackRanges) {
      if (seqAfter(r.end, this.sackedHigh)) this.sackedHigh = r.end;
      for (const s of this.tx) {
        if (s.acked) continue;
        if (seqAtOrAfter(s.offset, r.start) && seqAtOrAfter(r.end, s.end)) s.sacked = true;
      }
    }
    if (advanced && seqAfter(cum, this.sackedHigh)) this.sackedHigh = cum;
    this.tx = this.tx.filter((s) => !s.acked);
    if (this.haveAckCum && cum === this.lastAckCum && this.tx.length) {
      if (++this.dupAcks >= DUP_ACK_THRESH) {
        this.dupAcks = 0;
        this.fastRetransmit(nowMs);
      }
    } else {
      this.dupAcks = 0;
    }
    this.lastAckCum = cum; this.haveAckCum = true;
    if (advanced) {
      // Cumulative progress proves the tail is not lost: the probe budget
      // restarts for the next tail.
      this.tlpProbes = 0;
      this.resolveFastRound(cum);
    }
    if (this.finSent && seqAtOrAfter(cum, (this.finOffset + 1) >>> 0) && this.eofDelivered) {
      this.finish('local_eof');
      return;
    }
    // Pump on every ACK, not only on cumulative advance: a duplicate ack
    // still carries a fresh rwnd, and once the peer's window opens again this
    // is the only trigger before the next tick (whose budget alone caps
    // recovery at ~600 KB/s).
    this.pump(nowMs);
  }

  /** The age base the reorder gate is derived from.
   *
   *  minRtt when known, not srtt: under a deep queue srtt reads twice the path
   *  delay, and waiting a queue-inflated RTT is exactly when recovery has to be
   *  prompt. minRtt is the path's own floor, which is what RACK uses too.
   *
   *  But minRtt is a *floor*, and a reorder gate needs a *ceiling*: it has to
   *  cover how long a segment may legitimately take, not how fast one can go.
   *  Bounding it by srtt (a mean) is what broke reordering: on a 20 ms path
   *  with 60 ms of spread srtt reads ~57 ms while individual segments take
   *  80 ms, so the gate called every late segment lost. Take the larger of
   *  minRtt x 1.25 and the worst legitimate sample instead.
   *
   *  Until that worst sample has been observed the gate falls back to the
   *  estimator's own idea of the spread. RTTVAR is the mean deviation, so
   *  srtt + 2*rttvar covers roughly the 95th percentile of a jittery path —
   *  but on a clean path rttvar is a couple of ms, so the fallback stays close
   *  to srtt and genuine loss is still recovered promptly. The 1.25 floor on
   *  minRtt is kept as the absolute lower bound. */
  private get retxAgeBaseMs(): number {
    const srtt = Math.max(1, this.srttMs);
    if (this.minRttMs <= 0) return srtt;
    const floor = Math.round(this.minRttMs * 1.25);
    // rttPeak is bounded by the plausibility filter in onAck (it never learns
    // hole-delayed samples) and decayed by RTT_PEAK_DECAY_MS, so it cannot run
    // away to the RTO.
    const observed = this.rttPeakMs > 0 ? Math.min(this.rttPeakMs, RTT_PEAK_MAX_MS) : 0;
    // Only trust the variance term when the path actually has variance. A
    // sub-5 ms rttvar is measurement noise on a clean link, and letting it
    // widen the gate would cost real recovery latency for no benefit.
    const fromVar = this.rttvarMs >= RTTVAR_NOISE_FLOOR_MS ? srtt + 2 * this.rttvarMs : 0;
    return Math.max(floor, observed, fromVar);
  }

  /** How long a segment must have been on the wire before it may be called
   *  lost and retransmitted for the first time.
   *
   *  Do not call a segment lost before one RTT has actually passed: a copy still
   *  in flight is indistinguishable from a lost one, and srtt/2 declared half of
   *  every window's in-flight bytes lost — 43 retransmits per second against 4
   *  lost segments per second. That is what retxRelax (up to 2x) is for.
   *
   *  The opposite mistake cost just as much: the gate never came back down, so
   *  every genuine single-hole loss waited a full RTT before its copy even left,
   *  putting recovery at ~1.75 RTT. retxTighten narrows it while the evidence
   *  says the losses are real. Diagnostic as well as load-bearing. */
  get retxAgeGateMs(): number {
    return Math.max(FAST_RETX_MIN_AGE_MS,
      Math.round(this.retxAgeBaseMs * this.retxRelax * this.retxTighten));
  }

  /**
   * Replace the oldest holes, up to one burst worth per duplicate-ack round.
   *
   * The retransmit ratio was 58% because this loop had no notion of time: the
   * 120 ms floor is shorter than the 200-400 ms path RTT, so every copy of a
   * segment was re-sent at least once while its predecessor was still in
   * flight, and duplicate acks arrive fast enough to drive the loop far more
   * often than one round per RTT.
   *
   * Now: a segment that has never been retransmitted goes out as soon as a
   * duplicate ack proves it missing (plus the age gate for reordering); a
   * segment that *was* already retransmitted waits a full RTT, because until
   * then its copy is still in flight and a second copy is guaranteed waste.
   *
   * And only SACK can prove a segment missing. If the peer reports having
   * bytes past this segment, it does not have this segment; if it reports
   * nothing past it, the segment is merely unknown — in flight, or dropped at
   * the tail — and belongs to the RTO path. Without that test every duplicate
   * ack walked six more segments out of the window, most of which the peer
   * already had: two consecutive stats samples showed 162 segments sent and
   * 162 of them retransmissions, with 300 KB of new data stuck in the queue
   * because the window was full of copies.
   *
   * SACK never removes the age wait. "Two ranges start beyond this segment"
   * used to be treated as proof of loss that skipped the gate entirely, but a
   * reordering path produces exactly that shape: one delayed datagram leaves
   * the receiver holding the ranges on both sides of it, and the segment in
   * front of the delayed one sees two ranges starting past its end while it is
   * still in flight. Measured on a zero-loss link: 34% retransmissions. The
   * gate is the only thing that distinguishes "late" from "lost", and no SACK
   * pattern can make that distinction for it.
   */
  private fastRetransmit(nowMs: number): void {
    const repeatAfter = Math.max(MIN_RETX_INTERVAL_MS,
      Math.round(this.retxAgeBaseMs * RETX_RTT_FACTOR * 1.25));
    const firstAfter = this.retxAgeGateMs;
    let sent = 0;
    let firstSeq = -1;
    for (const s of this.tx) {
      if (s.acked || s.sacked) continue;
      // Not proven missing: the peer has not reported anything past it yet.
      if (!seqAtOrAfter(this.sackedHigh, s.end)) continue;
      const wait = s.retransmits !== 0 ? repeatAfter : firstAfter;
      if (nowMs - s.sentMs < wait) continue;
      if (firstSeq < 0) firstSeq = s.offset;
      this.emitData(s, nowMs);
      ++s.retransmits; // Karn: this copy must not feed the RTT estimator
      ++this.retransmits; ++this.retxFast;
      s.sentMs = nowMs;
      if (++sent >= FAST_RETX_SEGMENTS) break;
    }
    if (sent > 0) {
      // Counted only when the round actually put copies on the wire: with
      // DUP_ACK_THRESH at 1 this function runs on every duplicate ack, and
      // counting the no-ops made `retxFast / fastRounds` read better than the
      // link really was.
      ++this.fastRounds;
    }
    if (sent > 0 && this.fastRoundSeq < 0) {
      this.fastRoundMs = nowMs;
      this.fastRoundUna = this.sndUna;
      this.fastRoundSeq = firstSeq;
      this.fastRoundSpurious = false;
    }
  }

  /** A cumulative ack covering the round's first retransmitted segment resolves
   *  it. Which way the gate moves depends on evidence, not on the fact that it
   *  resolved: reordering (the copy never made it in time) widens it and resets
   *  the tightening, genuine loss narrows it. */
  private resolveFastRound(cum: number): void {
    if (this.fastRoundSeq < 0) return;
    if (!seqAtOrAfter(cum, this.fastRoundSeq)) return;
    if (this.fastRoundSpurious) {
      this.retxRelax = Math.min(2, Math.round(this.retxRelax * 1.3 * 100) / 100);
      this.retxTighten = 1;
    } else {
      this.retxTighten = Math.max(FAST_RETX_TIGHTEN_FLOOR,
        Math.round(this.retxTighten * FAST_RETX_TIGHTEN_STEP * 1000) / 1000);
      this.retxRelax = Math.max(1, Math.round(this.retxRelax * 0.8 * 100) / 100);
    }
    this.fastRoundSeq = -1;
    this.fastRoundSpurious = false;
  }

  /** Repeating an acknowledgement for an open hole. Scaled to the path so the
   *  repeat lands inside the same round trip the hole was discovered in: a
   *  fixed 50 ms was a fifth of an RTT on the long path and 2.5 RTTs on the
   *  short one. */
  private holeDupAckMs(): number {
    const scaled = Math.round(this.srttMs / HOLE_DUP_ACK_DIVISOR);
    return Math.max(HOLE_DUP_ACK_MIN_MS, Math.min(HOLE_DUP_ACK_MS, scaled));
  }

  /**
   * Milliseconds until this stream next has something to do on its own, or -1.
   *
   * The host used to drive everything off a fixed 10 ms interval, which quantised
   * every deadline in here: a delayed ack due in 4 ms went out at the next tick
   * boundary (up to 10 ms late, and later still when the event loop was busy),
   * a partial repair group due at flushMs waited for a boundary, and an RTO that
   * had already expired was checked up to 10 ms late. None of that is a lot per
   * event, but acks and repairs are exactly the events this protocol lives on.
   *
   * Only *future* deadlines are reported (>= 1 ms), so a host that reschedules
   * on this value cannot spin: each wake-up has to clear its own deadline
   * (onTick emits the ack, closes the group, resends the segment).
   */
  nextTimerMs(nowMs: number): number {
    if (this.state === StreamState.Closed) return -1;
    let best = -1;
    const take = (dueMs: number): void => {
      if (dueMs < 1) dueMs = 1;
      if (best < 0 || dueMs < best) best = dueMs;
    };
    if (this.ackPending) take(this.lastAckMs + ACK_DELAY_MS - nowMs);
    else if (this.oobBytes > 0) take(this.lastAckMs + this.holeDupAckMs() - nowMs);
    // Mirror probeZeroWindow's tx cap: once it refuses to probe (tx > 64), an
    // expired lastZeroWinProbeMs deadline would be clamped by take() to 1 ms
    // forever while onTick makes no progress — a peer advertising rwnd=0 could
    // pin the host in a 1 ms busy loop. Above the cap the outstanding segments'
    // RTO deadlines drive recovery instead.
    if ((this.pendingBytes > 0 || (this.finPending && !this.finSent)) &&
        this.window() === 0 && this.tx.length <= 64) {
      take(this.lastZeroWinProbeMs + ZERO_WINDOW_PROBE_MS - nowMs);
    }
    if (this.tx.length > 0 && this.tlpProbes < TLP_MAX_PROBES && this.window() > 0 &&
        (this.pendingBytes === 0 || this.inflightBytes >= this.window())) {
      take(this.lastSendMs + Math.max(TLP_MIN_PTO_MS, Math.round(this.srttMs + 2 * this.rttvarMs)) - nowMs);
    }
    for (const s of this.tx) {
      if (s.acked || s.sacked) continue;
      take(s.sentMs + this.rtoMs * (1 << Math.min(s.retransmits, 5)) - nowMs);
      break; // the RTO loop only ever resends the oldest
    }
    return best;
  }

  onTick(nowMs: number): void {
    if (this.state === StreamState.Closed) return;
    if (!this.lastInboundMs) this.lastInboundMs = nowMs;
    if (this.ackPending && nowMs - this.lastAckMs >= ACK_DELAY_MS) this.emitAck(nowMs);
    // A hole means inbound traffic stops, and with it our acks. The peer then
    // holds a full window with nothing to trigger a retransmit until its RTO
    // fires — the stalls observed on the VPS link lasted seconds. Repeating the
    // ack keeps the peer's duplicate-ack counter moving so the missing segment
    // is resent within one round trip. Same ack, no extra state on the wire.
    else if (this.oobBytes > 0 && nowMs - this.lastAckMs >= this.holeDupAckMs()) this.emitAck(nowMs);
    if (nowMs - this.lastInboundMs >= this.cfg.idleTimeoutMs) { this.finish('idle'); return; }
    // Tail-loss probe: the tail is unconfirmed and nothing after it will ever
    // produce a duplicate ack, so without a probe it waits out the full
    // backed-off RTO. Resend the tail early — the duplicate makes the receiver
    // answer at once, and the probe budget resets as soon as cum moves again.
    //
    // The guard used to be `pendingBytes === 0` alone, which covers the end of a
    // flow but not a window that filled up: the queue can only be non-empty
    // while the window is full if the peer shrank its window below the bytes
    // already in flight (its app stopped reading). Then the queue cannot drain,
    // pump() sends nothing, no later segment exists to dup-ack the lost tail,
    // and the RTO chain (srtt + 4*rttvar, then 2^n) was the only trigger left.
    // A stalled full window and an empty queue both mean "nothing else will
    // move", so both allow the probe.
    const stalled = this.pendingBytes === 0 || this.inflightBytes >= this.window();
    if (this.tx.length > 0 && stalled && !this.finPending &&
        this.window() > 0 && this.tlpProbes < TLP_MAX_PROBES) {
      const pto = Math.max(TLP_MIN_PTO_MS, Math.round(this.srttMs + 2 * this.rttvarMs));
      if (nowMs - this.lastSendMs >= pto) {
        const tail = this.tx[this.tx.length - 1]!;
        // A probe is not a retransmission. It carries no loss evidence — the
        // tail is merely unconfirmed — so it must not consume the segment's
        // retransmit budget. Counting it made the segment look "already resent"
        // to fast retransmit, which then applied repeatAfter measured from the
        // probe instead of the original send, and inflated the retransmit ratio
        // that the ARQ stats are judged by. It still has to be a real copy on
        // the wire (that is the whole point: it makes the peer answer), and it
        // still restarts the probe clock.
        //
        // The probe still moves sentMs (it is a real copy on the wire, and the
        // RTO pass must time from the latest copy). But with two copies in
        // flight an ACK cannot be attributed to one of them, so flag `probed`
        // and let the RTT sampler skip it — exactly the Karn ambiguity that
        // `retransmits > 0` handles for real retransmits. Without the flag, a
        // late ACK for the original measured against this probe's sentMs gave
        // a few-ms fake RTT (srtt 100 -> 89).
        this.emitData(tail, nowMs);
        tail.sentMs = nowMs;
        tail.probed = true;
        ++this.tlpProbes;
      }
    }
    // A fast-retransmit round that bought nothing within 1.5 sRTT points at
    // reordering rather than loss: relax the next round's age base (up to 2x)
    // and stop narrowing it, because the narrow gate was what produced the
    // round in the first place.
    if (this.fastRoundSeq >= 0 && nowMs - this.fastRoundMs >= Math.round(1.5 * this.srttMs)) {
      if (this.sndUna === this.fastRoundUna) {
        this.retxRelax = Math.min(2, Math.round(this.retxRelax * 1.3 * 100) / 100);
        this.retxTighten = 1;
      } else {
        this.retxTighten = Math.max(FAST_RETX_TIGHTEN_FLOOR,
          Math.round(this.retxTighten * FAST_RETX_TIGHTEN_STEP * 1000) / 1000);
        this.retxRelax = Math.max(1, Math.round(this.retxRelax * 0.8 * 100) / 100);
      }
      this.fastRoundSeq = -1;
      this.fastRoundSpurious = false;
    }
    // Retransmission timeout: resend the oldest unacked, unsacked segment.
    // The per-segment 2^retransmits deadline IS the backoff; a global rtoMs
    // doubling here would make the *next* segment's first RTO pay for this
    // one's loss (six losses inflated the timer 64x on the old loop).
    for (const s of this.tx) {
      if (s.acked || s.sacked) continue;
      if (nowMs - s.sentMs >= this.rtoMs * (1 << Math.min(s.retransmits, 5))) {
        this.emitData(s, nowMs);
        ++s.retransmits; ++this.retransmits; ++this.retxRto;
        s.sentMs = nowMs;
        break;
      }
    }
    // Drain what the burst cap left behind. With a zero peer window pump()
    // cannot emit anything at all (inflight >= window() == 0 breaks on the
    // first iteration), so that case needs a real one-byte probe.
    if (this.window() === 0) this.probeZeroWindow(nowMs);
    else if (this.pendingBytes > 0 || this.finPending) this.pump(nowMs);
  }

  /**
   * Zero-window probe. One byte of real data is the only thing that makes the
   * peer answer with an ACK carrying a fresh rwnd — a bare pump() sends nothing
   * when the window is closed. Retransmission is the RTO path's job, so this
   * only ever advances one byte at a time and stops once enough probes are
   * outstanding.
   */
  private probeZeroWindow(nowMs: number): void {
    const hasData = this.pendingBytes > 0;
    // A pending FIN can itself be the one-byte persist probe (as in TCP): once
    // all data is acknowledged, refusing to probe left the FIN stranded in
    // SendingFin until the idle timeout, with both sides silent.
    if (!hasData && !this.finPending) return;
    if (nowMs - this.lastZeroWinProbeMs < ZERO_WINDOW_PROBE_MS) return;
    if (this.tx.length > 64) return;
    this.lastZeroWinProbeMs = nowMs;
    const chunk = hasData ? this.takePending(1) : Buffer.alloc(0);
    const fin = !hasData && this.finPending;
    if (chunk.length === 0 && !fin) return;
    if (fin) { this.finSent = true; this.finPending = false; }
    const end = (this.sndNext + chunk.length + (fin ? 1 : 0)) >>> 0;
    const seg: SndSeg = {
      offset: this.sndNext, bytes: chunk, fin, end,
      sentMs: nowMs, acked: false, sacked: false, retransmits: 0, probed: false,
      firstSentMs: nowMs,
    };
    if (fin) this.finOffset = (this.sndNext + chunk.length) >>> 0;
    this.tx.push(seg);
    this.sndNext = end;
    if (seqAfter(end, this.sndMax)) this.sndMax = end;
    this.emitData(seg, nowMs);
  }

  private finish(reason: string): void {
    if (this.state === StreamState.Closed) return;
    this.state = StreamState.Closed;
    this.closeReason = reason;
    this.tx = []; this.pending = []; this.oob = [];
    this.cb.closed(reason);
  }
}
