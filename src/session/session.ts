// FCP session: wires together the two key epochs, handshake, FEC framing,
// FCP-STREAM ARQ, oob dispatch and the control plane.
// Port of src/fcp/session.cc (state machine + dispatch order), with the
// clock/socket-free shape preserved: host drives onWire()/onTick().

import { randomBytes } from 'node:crypto';
import {
  SALT_LEN, Direction, type DirectionValue,
  HandshakeRole, HandshakeState, HandshakeError,
  CAP_PMTUD, CAP_TLV, TLV_TYPE_ACK_V2, TLV_TYPE_KEY_UPDATE, TLV_TYPE_PREWARM,
  TLV_TYPE_MULTIPLEX, MUX_MAX_STREAMS, LOCAL_FLAGS_M1, TLV_TYPE_PATH_PROBE,
  HANDSHAKE_SEND_BUDGET, BOOTSTRAP_PROBES_PER_SECOND,
  NAT_KEEPALIVE_MS, PEER_ALIVE_GRACE_MS, KEEPALIVE_MAGIC, KEEPALIVE_LEN,
  RESET_MAGIC, RESET_MAGIC_LEN, ENVELOPE_OVERHEAD, NONCE_LIMIT,
  PMTU_MAGIC, PMTU_HEADER_LEN, PMTU_TYPE_PROBE, PMTU_TYPE_ACK,
  PMTU_ABSOLUTE_MAX_MTU, DEFAULT_PMTU_MAX_MTU, PMTU_PROBE_STEP, PMTU_BACKOFF_MAX_MS,
  DEFAULT_MTU_MIN, DEFAULT_IP_HEADER_LEN, DEFAULT_D, DEFAULT_P,
  DEFAULT_SRTT_MS, FEC_HDR_LEN, SymbolType, MAX_INTERLEAVE, D_FLOOR,
  D_STEP_MIN, D_ADAPT_INTERVAL_MS,
  MAX_ACK_COPIES, ACK_V2_FLAG_COPY,
  DATA_WIRE_OVERHEAD,
  STREAM_TYPE_ACK, STREAM_TYPE_ACK_V2, STREAM_TYPE_RST,
  DEFAULT_WINDOW_MIN_BYTES, DEFAULT_WINDOW_CEILING_BYTES,
  DEFAULT_RCV_BUF_FLOOR_BYTES, RCV_BUF_BDP_FACTOR,
  WINDOW_BDP_FACTOR, WINDOW_UPDATE_INTERVAL_MS, WINDOW_CHANGE_RATIO,
  SESSION_STREAM_BUDGET_BYTES,
  PROBE_BUDGET_BYTES,
} from '../constants.ts';
import { bytesEqual, getLe16, getLe32, putLe16, putLe32 } from '../wire.ts';
import { Envelope, sealReset } from '../crypto/envelope.ts';
import { deriveSessionKeyV7 } from '../crypto/keys.ts';
import {
  Handshake, HandshakeStatus, isHello, isHelloAck,
  encodePrewarmTlv, decodePrewarmTlv,
  type HandshakeTlv,
} from '../crypto/handshake.ts';
import {
  computeMtuLimits, pmtuProbeLen, FrameTx, FrameRx, packOobFrame, packTxFrame,
  type MtuLimits, type TxSymbol,
} from '../fec/frame.ts';
import { hdrType, parseHdr } from '../fec/hdr.ts';
import { FecstatValidator, FecstatStatus } from '../fec/fecstat.ts';
import { Stream, type StreamCallbacks } from '../stream/stream.ts';
import { AdaptiveFec, BbrLite, FecstatReporter, chooseGroupD } from '../control/controller.ts';
import { PathProbe, isProbeFrame, type ProbeResult } from '../probe/pathprobe.ts';

/** Host-side stream bookkeeping for multiplexed sessions. The default stream
 *  (sid 0) stays wired through the SessionCallbacks read/eof/closed; sids
 *  1..255 arrive via inboundStream and leave via streamClosed. */
export interface StreamHost {
  /** Inbound stream the host did not open (server: an OPEN arrived on it).
   *  Return null to drop the stream's bytes. */
  inboundStream(sid: number): StreamCallbacks | null;
  /** The Stream instance for a just-created inbound stream (host writes into
   *  it). Called before the first segment is processed. */
  streamReady?(sid: number, stream: Stream): void;
  /** A sid stream finished (both directions or reset): free host state. */
  streamClosed(sid: number, reason: string): void;
}

export interface SessionConfig {
  psk: Uint8Array;
  salt: Uint8Array;
  sendDirection: DirectionValue;
  recvDirection: DirectionValue;
  role: number; // HandshakeRole.Client / Server
  d?: number; p?: number;
  /** Interleave depth: repair groups kept open in parallel (1 = off). */
  interleave?: number;
  /** Redundant copies of every ACK v2 (1 = off). */
  ackCopies?: number;
  /** Offer the idle path probe TLV (default true). False on either end removes
   *  the feature: no train is started and no train is answered. */
  probe?: boolean;
  /** Per-run probe budget in bytes (--probe-budget). Caps both the train this
   *  end starts and the train it serves for the peer. */
  probeBudgetBytes?: number;
  mtu?: number; ipHdrLen?: number;
  pinnedK?: number;
  initialSrttMs?: number;
  keyUpdate?: boolean;
  ack_v2?: boolean;
  pmtud?: boolean;
  pmtuMaxMtu?: number;
  prewarmTicket?: { initialK: number; srttMs: number; windowKb: number; bwKbps: number; minRttMs: number };
  trace?: (line: string) => void;
}

export interface SessionCallbacks {
  sendWire: (wire: Buffer, kind: number) => void;
  read: (bytes: Buffer) => void;
  closed: (reason: string) => void;
  eof?: () => void;
  log?: (line: string) => void;
  /** Verbose per-datagram / per-segment trace. No-op unless --log-level=debug. */
  debug?: (line: string) => void;
  /** Multiplexing host (server side): creates per-sid stream state. */
  streamHost?: StreamHost;
  /** An idle-time path measurement finished on this end (initiator only).
   *  Stamped with the session's current geometry so a reader can tell what the
   *  measured loss would have cost. */
  pathProbe?: (r: SessionProbeResult) => void;
}

export type SessionProbeResult = ProbeResult & { mtu: number; d: number; k: number };

export interface SessionStats {
  authFail: number; structFail: number; dataTx: number; dataRx: number;
  fecstatDropped: number; fecstatDup: number; fecstatStale: number;
  established: boolean; state: number; k: number; d: number; lanes: number; srttMs: number;
  resetByPeer: boolean; peerAliveMs: number;
}

export class Session {
  readonly salt: Buffer;
  readonly cfg: SessionConfig;
  private cb: SessionCallbacks;
  private env: Envelope;
  private hsEnv: Envelope;
  private hs: Handshake;
  private limits: MtuLimits;
  private tx: FrameTx | null = null;
  private rx: FrameRx | null = null;
  private stream: Stream;
  private strategy: AdaptiveFec;
  private reporter: FecstatReporter;
  private bbr: BbrLite;
  /** Separate estimator for the *send* direction, fed by cum-acked bytes.
   *  `bbr` is fed by `stream.read`, i.e. the receive direction — during a
   *  download that is a trickle of ACK segments, so using it to size the send
   *  window was measuring the wrong pipe. */
  private sndBbr: BbrLite;
  private validator = new FecstatValidator();
  private configured = false;
  private nowMs = 0;
  /** Group size currently being cut. Starts at the negotiated value, then
   *  adapts between D_FLOOR and that ceiling; every symbol carries its own d,
   *  so changing it needs no coordination with the peer. Also bounds how long
   *  a partial group may sit before its parity goes out (groupDrainMs). */
  private groupD = DEFAULT_D;
  private dMax = DEFAULT_D;
  private interleave = 1;
  private ackCopies = 1;
  private lastDChangeMs = 0;
  private bootstrapWindowMs = -1;
  private bootstrapProbes = 0;
  private lastWireOutMs = 0;
  private lastPeerInMs = 0;
  private lastWindowUpdateMs = 0;
  resetByPeer = false;
  authFail = 0; structFail = 0; dataTx = 0; dataRx = 0;
  fecstatDropped = 0; fecstatDup = 0; fecstatStale = 0;
  private pmtuToken = 0;
  private pmtuMtu: number;
  private pmtuMaxMtu: number;
  private pmtuLastProbeMs = 0;
  private pmtuProbeMtu = 0;
  private pmtuProbesSent = 0;
  private pmtuProbesLost = 0;
  private pmtuAckedMtu = 0;
  private pmtuBackoffMs = 0;
  private pmtuCeilingLogged = false;
  private pmtuStartMtu = 0;
  /** Upper bound proven by blackholed probes (0 = unknown, still walking up).
   *  DPLPMTUD-style binary search between the acked floor and this ceiling
   *  converges in ~3 probes instead of 100 B linear steps. */
  private pmtuCeiling = 0;
  /** Targets of probes that are still awaiting an answer, oldest first. A probe
   *  leaves this list when the next one goes out (it timed out) or when the
   *  peer acknowledges a size at least as large. */
  private pmtuPending: number[] = [];
  /** Largest symbol this end will accept, independent of its send budget. */
  private rxSymbolMax = 65535;
  private pinnedK: number;
  private dbg: (line: string) => void;
  private tag: () => string;
  /** cb.closed is emitted at most once, and hosts can query it: a session that
   *  failed its handshake or got a stateless reset never closes its Stream, so
   *  "streamRef.isClosed" is not a sufficient liveness test. */
  private closeNotified = false;
  /** M1 multiplexing: negotiated in the handshake, a 1-byte stream id prefixes
   *  every DATA symbol payload (0 = the session's default stream). */
  private mux = false;
  private streams = new Map<number, Stream>();
  private streamHost: StreamHost | null = null;
  /** Idle-time path measurement. Answers a peer's train unconditionally (that
   *  costs nothing and needs no negotiation beyond the TLV), but only *starts*
   *  one when the peer also offered TLV 6 — see startPathProbe. */
  private probe: PathProbe;
  private probeEnabled = false;

  get isClosed(): boolean { return this.closeNotified; }

  private notifyClosed(reason: string): void {
    if (this.closeNotified) return;
    this.closeNotified = true;
    // The session is terminal from here: hosts stop ticking it and remove it.
    // Wiping the key material now bounds how long the derived keys outlive the
    // connection instead of leaving them in the heap until GC.
    this.env.destroy();
    this.hsEnv.destroy();
    this.cb.closed(reason);
  }

  constructor(cfg: SessionConfig, cb: SessionCallbacks) {
    this.cfg = cfg;
    this.cb = cb;
    this.dbg = cb.debug ?? (() => {});
    this.streamHost = cb.streamHost ?? null;
    const tag = () => Buffer.from(cfg.salt).toString('hex').slice(0, 8);
    this.tag = tag;
    this.salt = Buffer.from(cfg.salt);
    this.pinnedK = cfg.pinnedK ?? 0;
    const ipHdrLen = cfg.ipHdrLen ?? DEFAULT_IP_HEADER_LEN;
    // `mtu` is the *floor* of the probe walk (and the fixed budget when PMTUD
    // is off), not a ceiling: the ceiling is `pmtuMaxMtu`.
    this.pmtuMaxMtu = Math.min(cfg.pmtuMaxMtu ?? DEFAULT_PMTU_MAX_MTU, PMTU_ABSOLUTE_MAX_MTU);
    const mtu = Math.min(cfg.mtu ?? DEFAULT_MTU_MIN, this.pmtuMaxMtu);
    this.limits = computeMtuLimits(mtu, ipHdrLen);
    this.pmtuMtu = mtu;
    this.pmtuAckedMtu = mtu;
    this.pmtuStartMtu = mtu;
    // The receive limit is decoupled from the send budget on purpose. Filtering
    // inbound symbols by our own send size made PMTUD self-defeating: a probe
    // larger than the peer's current budget was dropped as structFail before it
    // ever reached pmtuHandle, so no ACK could ever come back. The kernel
    // already accepted the datagram, so we can decode anything up to the
    // protocol's absolute ceiling.
    const rxLimits = computeMtuLimits(this.pmtuMaxMtu, ipHdrLen);
    this.rxSymbolMax = rxLimits.valid ? rxLimits.symbolMax : PMTU_ABSOLUTE_MAX_MTU;
    this.pmtuToken = randomBytes(4).readUInt32LE(0);

    this.env = new Envelope(cfg.psk, cfg.salt, cfg.sendDirection, cfg.recvDirection);
    this.hsEnv = new Envelope(cfg.psk, cfg.salt, cfg.sendDirection, cfg.recvDirection);
    this.hsEnv.initBootstrapNonce(HANDSHAKE_SEND_BUDGET);

    const d = cfg.d ?? DEFAULT_D, p = cfg.p ?? DEFAULT_P;
    let flags = LOCAL_FLAGS_M1;
    if (cfg.pmtud) flags |= CAP_PMTUD;
    this.hs = new Handshake({
      localD: d, localP: p,
      role: cfg.role as 0 | 1,
      localFlags: flags,
      send: (msg) => this.sendOob(msg, true),
      initialSrttMs: cfg.initialSrttMs,
      rttSeedMs: cfg.initialSrttMs,
    });

    this.strategy = new AdaptiveFec({ d, p, pinnedK: this.pinnedK, trace: cfg.trace });
    this.bbr = new BbrLite(cfg.initialSrttMs ?? DEFAULT_SRTT_MS, cfg.trace);
    this.sndBbr = new BbrLite(cfg.initialSrttMs ?? DEFAULT_SRTT_MS, cfg.trace);
    this.reporter = new FecstatReporter(cfg.salt, cfg.recvDirection);
    this.probe = new PathProbe({
      send: (payload) => this.sendOob(payload),
      srttMs: () => Math.max(1, this.bbr.srttMs),
      // Fills the current MTU exactly: envelope(28) + fec header(7) + payload.
      dgramSize: () => (this.limits.valid ? this.limits.symbolMax : 0),
      onResult: (r) => this.cb.pathProbe?.({ ...r, mtu: this.limits.mtu, d: this.groupD, k: this.k }),
    }, cfg.probeBudgetBytes ?? PROBE_BUDGET_BYTES);

    this.stream = new Stream(
      { maxSegment: this.limits.payloadMax, initialSrttMs: cfg.initialSrttMs ?? DEFAULT_SRTT_MS },
      {
        send: (seg) => this.sendStreamSegment(0, seg),
        read: (bytes) => { this.bbr.onDelivery(bytes.length, this.nowMs); this.cb.read(bytes); },
        // In mux mode the default stream may idle out while sid streams are
        // still alive (a shared session serves many local connections); only a
        // default-stream close with no live sid streams ends the session.
        closed: (reason) => {
          if (this.mux && this.streams.size > 0) {
            this.dbg(`[${this.tag()}] default stream closed (${reason}) with live sid streams; session stays`);
            return;
          }
          this.notifyClosed(reason);
        },
        eof: () => {
          if (this.mux && this.streams.size > 0) return;
          this.cb.eof?.();
        },
        rtt: (ms) => {
          this.bbr.onRtt(ms); this.sndBbr.onRtt(ms); this.tx?.setSrttMs(ms);
        },
        acked: (bytes, nowMs) => this.sndBbr.onDelivery(bytes, nowMs),
      },
    );
  }

  get established(): boolean { return this.hs.established; }
  /** True only when both ends offered TLV type 4, i.e. the roll is safe. */
  get keyUpdateActive(): boolean { return this.env.keyUpdate; }
  /** The peer understands the idle-time path probe. */
  get pathProbeReady(): boolean { return this.probeEnabled && this.configured; }
  get pathProbeRunning(): boolean { return this.probe.running; }

  /** Put one bounded probe train on the path. Returns false when the peer did not
   *  offer the TLV, the session is not usable, or a run is already in flight.
   *  Only the initiator side gets a result; the answering side just answers. */
  startPathProbe(budgetBytes: number): boolean {
    if (!this.pathProbeReady || this.closeNotified) return false;
    if (this.tx === null || this.rx === null) return false;
    return this.probe.start(this.nowMs, budgetBytes);
  }
  get state(): number { return this.hs.state; }
  get mtuLimits(): MtuLimits { return this.limits; }
  get streamRef(): Stream { return this.stream; }
  get k(): number { return this.strategy.currentK(); }
  stats(): SessionStats {
    return {
      authFail: this.authFail, structFail: this.structFail,
      dataTx: this.dataTx, dataRx: this.dataRx,
      fecstatDropped: this.fecstatDropped, fecstatDup: this.fecstatDup,
      fecstatStale: this.fecstatStale,
      established: this.established, state: this.state, k: this.k,
      d: this.groupD, lanes: this.interleave,
      srttMs: this.bbr.srttMs, resetByPeer: this.resetByPeer,
      peerAliveMs: this.lastPeerInMs ? this.nowMs - this.lastPeerInMs : 0,
    };
  }

  start(nowMs: number): boolean {
    this.nowMs = nowMs;
    this.dbg(`[${this.tag()}] session start role=${this.cfg.role === HandshakeRole.Client ? 'client' : 'server'} d=${this.cfg.d ?? DEFAULT_D} p=${this.cfg.p ?? DEFAULT_P} mtu=${this.pmtuStartMtu}${this.cfg.pmtud ? `..${this.pmtuMaxMtu} (pmtud)` : ' (fixed)'} payloadMax=${this.limits.payloadMax} pinnedK=${this.pinnedK}`);
    if (!this.limits.valid) { this.cb.log?.('FCP config invalid: MTU leaves no room for a data symbol'); return false; }
    const d = this.cfg.d ?? DEFAULT_D;
    const p = this.cfg.p ?? DEFAULT_P;
    if (d < 1 || d > 256 || p < 0 || p > 7 || d + p > 256) return false;
    if (this.hs.failed) { this.cb.log?.(`FCP handshake refused: ${HandshakeError[this.hs.error] ?? this.hs.error}`); return false; }
    const tlvs: HandshakeTlv[] = [];
    if (this.cfg.ack_v2) tlvs.push({ type: TLV_TYPE_ACK_V2, value: Buffer.alloc(0) });
    // Advertised, not assumed: without this the sender would start rolling its
    // key after FIRST_ROLL_AT packets while a peer that did not opt in keeps
    // decrypting with the session key, and the link dies with no error at all.
    if (this.cfg.keyUpdate) tlvs.push({ type: TLV_TYPE_KEY_UPDATE, value: Buffer.alloc(0) });
    // M1: always offered. A peer that does not echo it keeps the single-stream
    // wire (sid framing only engages when BOTH ends offered).
    tlvs.push({ type: TLV_TYPE_MULTIPLEX, value: Buffer.alloc(0) });
    // Advertised like M1: the probe is passive support on the answering side, so
    // offering it costs one byte in the handshake and nothing afterwards. It only
    // runs when both ends offered it, which is what keeps a legacy peer from
    // being hit by a train it would answer with silence.
    if (this.cfg.probe !== false) tlvs.push({ type: TLV_TYPE_PATH_PROBE, value: Buffer.alloc(0) });
    if (this.cfg.prewarmTicket) tlvs.push({ type: TLV_TYPE_PREWARM, value: encodePrewarmTlv(this.cfg.prewarmTicket) });
    this.hs.setLocalTlvs(tlvs);
    // #77: no TLVs at all -> plain v7 shape (no kCapTlv bit), which an old
    // C++ peer accepts. The downgrade probe also covers the offered case.
    this.hs.start(nowMs);
    return true;
  }

  /** Feed one UDP datagram. Returns false when authentication failed. */
  onWire(wire: Uint8Array, nowMs: number): boolean {
    this.nowMs = nowMs;
    // A closed session must not keep decrypting, dispatching or emitting: the
    // host removes it on its next tick, and anything arriving in between used
    // to be processed as if the session were alive (including sending data on
    // a stream the peer already considers gone).
    if (this.closeNotified) return false;
    // Stateless reset first, by shape. A reset is sealed under the *bootstrap*
    // key, so it is also a valid bootstrap envelope. Detecting it only after
    // env.open() misses the case where the envelope layer can still decrypt it
    // (before rekey) and the 8-byte plaintext then looks like a bad FEC header.
    if (!this.resetByPeer && wire.length === ENVELOPE_OVERHEAD + RESET_MAGIC_LEN &&
        this.hsEnv.openReset(wire)) {
      // Both roles must honour this, not just the client: a server whose peer
      // walked away (browser tab closed, curl --max-time, process restart) kept
      // pushing a full window into a void — 544 KB queued, 1000+ RTO copies in
      // the stats — while the peer was answering every datagram with exactly
      // this packet. A rejected datagram never refreshes lastPeerInMs, so the
      // only other exit was peer_dead, 135 s later.
      this.resetByPeer = true;
      this.cb.log?.('FCP stateless reset: the peer has no session for this salt');
      this.notifyClosed('stateless_reset');
      return true;
    }
    let plain = this.env.open(wire);
    let bootstrap = false;
    if (plain === null) {
      let mayProbe = true;
      if (this.hs.established) {
        if (this.bootstrapWindowMs < 0 || nowMs - this.bootstrapWindowMs >= 1000) {
          this.bootstrapWindowMs = nowMs; this.bootstrapProbes = 0;
        }
        mayProbe = this.bootstrapProbes < BOOTSTRAP_PROBES_PER_SECOND;
        if (mayProbe) ++this.bootstrapProbes;
      }
      if (mayProbe) {
        plain = this.hsEnv.open(wire);
        bootstrap = plain !== null;
      }
    }
    if (plain === null) {
      ++this.authFail; this.reporter.noteAuthFail();
      this.dbg(`[${this.tag()}] wire rx ${wire.length}B REJECT auth-fail (wrong PSK, replay or malformed envelope)`);
      return false;
    }
    this.lastPeerInMs = nowMs;
    this.dbg(`[${this.tag()}] wire rx ${wire.length}B -> plain ${plain.length}B ${bootstrap ? 'bootstrap-key' : 'session-key'}`);
    if (bootstrap) { this.onWireBootstrap(plain, nowMs); return true; }
    return this.onWireData(plain, nowMs, wire.length);
  }

  private onWireBootstrap(plain: Buffer, nowMs: number): void {
    if (plain.length < FEC_HDR_LEN) { ++this.structFail; return; }
    const hdr = parseHdr(plain);
    const symbol = plain.subarray(FEC_HDR_LEN);
    if (hdr && hdrType(hdr.typeK) === SymbolType.Oob && (isHello(symbol) || isHelloAck(symbol))) {
      this.dbg(`[${this.tag()}] bootstrap oob ${isHello(symbol) ? 'HELLO' : 'HELLO_ACK'} rx len=${symbol.length}`);
      this.onOob(symbol, nowMs);
    } else {
      ++this.structFail;
    }
  }

  private onWireData(plain: Buffer, nowMs: number, wireLen: number): boolean {
    const hdr = parseHdr(plain);
    if (hdr) this.dbg(`[${this.tag()}] sym rx set=${hdr.setId} idx=${hdr.index} type=${hdrType(hdr.typeK)} k=${(hdr.typeK >>> 5) & 7} len=${plain.length - FEC_HDR_LEN} wire=${wireLen}B`);
    else this.dbg(`[${this.tag()}] wire rx ${wireLen}B plain=${plain.length}B BAD FEC header`);
    if (hdr) {
      const type = hdrType(hdr.typeK);
      if (type === SymbolType.Data) {
        this.dataRx += Math.max(0, wireLen - DATA_WIRE_OVERHEAD);
        this.reporter.addDataBytes(wireLen);
      } else if (type === SymbolType.Parity) {
        this.reporter.addParityBytes(wireLen);
      }
    }
    if (this.rx) { this.rx.onDatagram(plain, nowMs); return true; }
    // Pre-negotiation: only oob is actionable. Inbound data must NOT be
    // echoed into the handshake cache (erratum #4).
    if (hdr && hdrType(hdr.typeK) === SymbolType.Oob) {
      this.onOob(plain.subarray(FEC_HDR_LEN), nowMs);
    } else {
      ++this.structFail; this.reporter.noteStructFail();
    }
    return true;
  }

  private onOob(payload: Buffer, nowMs: number): void {
    if (payload.length === KEEPALIVE_LEN && bytesEqual(KEEPALIVE_MAGIC, payload, KEEPALIVE_LEN)) { this.dbg(`[${this.tag()}] keepalive rx`); return; }
    if (payload.length === KEEPALIVE_LEN && bytesEqual(RESET_MAGIC, payload, RESET_MAGIC_LEN)) {
      // Same meaning whichever envelope carried it: the peer has no session.
      // Closing here (instead of only logging, as the client used to) is what
      // stops a sender from retransmitting a window that can never land.
      if (!this.resetByPeer) {
        this.resetByPeer = true;
        this.cb.log?.('FCP stateless reset: the peer has no session for this salt');
        this.notifyClosed('stateless_reset');
      }
      return;
    }
    if (this.dispatchHandshake(payload, nowMs)) return;
    if (this.isPmtuFrame(payload) && this.pmtuHandle(payload, nowMs)) return;
    if (this.probeEnabled && isProbeFrame(payload)) { this.probe.onFrame(payload, nowMs); return; }
    this.handleFecstat(payload, nowMs);
  }

  private dispatchHandshake(payload: Buffer, nowMs: number): boolean {
    if (payload.length < 36 || (!isHello(payload) && !isHelloAck(payload))) return false;
    this.dbg(`[${this.tag()}] ${isHello(payload) ? 'HELLO' : 'HELLO_ACK'} rx len=${payload.length}`);
    if (this.hs.onOob(payload) === HandshakeStatus.ProtocolFailure) {
      this.cb.log?.(`FCP handshake failed: error=${this.hs.error}`);
      this.notifyClosed('handshake_failure');
    }
    if (this.hs.established && !this.configured) this.configure(nowMs);
    return true;
  }

  private configure(nowMs: number): void {
    const np = this.hs.params;
    const sessionKey = deriveSessionKeyV7(this.cfg.psk, this.salt, this.hs.clientNonce, this.hs.serverNonce);
    this.env.rekey(sessionKey);
    // Both ends must have offered it. `tlvNegotiated()` alone is not enough:
    // ACK v2 is offered unconditionally, so every Node<->Node session has
    // CAP_TLV, and that test would let one end roll its keys while the peer
    // still uses the session key — every packet after the first roll decrypted
    // to garbage, with nothing logged on either side.
    this.env.setKeyUpdate(this.hs.tlvAgreed(TLV_TYPE_KEY_UPDATE));
    // M1: framing engages only when BOTH ends offered the TLV; an old peer
    // keeps today's single-stream wire, byte for byte.
    this.mux = this.hs.tlvAgreed(TLV_TYPE_MULTIPLEX);
    this.probeEnabled = this.hs.tlvAgreed(TLV_TYPE_PATH_PROBE);
    // The 1-byte sid prefix rides inside the symbol payload, so every stream
    // must carve segments one byte below payloadMax or FrameTx drops each
    // full-size segment as oversize.
    this.stream.setMaxSegment(this.mux ? this.limits.payloadMax - 1 : this.limits.payloadMax);
    this.dMax = np.d;
    this.groupD = np.d;
    this.interleave = Math.max(1, Math.min(MAX_INTERLEAVE, this.cfg.interleave ?? 1));
    this.tx = new FrameTx(np.d, this.limits, (s) => this.emitSymbol(s, false));
    this.tx.setInterleave(this.interleave);
    this.tx.setSrttMs(this.bbr.srttMs);
    // Follow the agreed parity, not our own proposal: a peer may have offered a
    // lower P, and anything above it is dropped as IndexPastS on arrival.
    this.strategy.setParityCeiling(np.p);
    this.strategy.setGroupSize(np.d);
    this.tx.setK(this.strategy.currentK());
    // Copied ACKs are only safe with the v2 marker bit; a v1 ACK has no spare
    // byte and a blind duplicate would read as loss evidence on the peer.
    const ackV2 = this.hs.tlvAgreed(TLV_TYPE_ACK_V2);
    this.ackCopies = ackV2
      ? Math.max(1, Math.min(MAX_ACK_COPIES, this.cfg.ackCopies ?? 1))
      : 1;
    this.rx = new FrameRx({
      d: np.d, p: np.p,
      maxSymbolLen: this.rxSymbolMax,
      deliver: (bytes) => { this.deliverStreamFrame(bytes); },
      oob: (msg, t) => { this.onOob(msg, t); },
      event: (e) => {
        if (e.event === 'recovered' && e.repairMs !== undefined) this.reporter.recordRepairLatency(e.repairMs);
        // No per-group decision here: a set is accounted 1 s after its first
        // symbol, which on this path (srtt 560 ms, ~360 groups in flight per
        // second) is before most of it has arrived, so "incomplete at the
        // deadline" was true for 77% of groups on a 0%-loss path. The loss
        // estimate is taken from shard counters instead, in onTick.
      },
    });
    this.stream.setAckV2(this.hs.tlvAgreed(TLV_TYPE_ACK_V2));
    const prewarm = this.hs.peerTlv(TLV_TYPE_PREWARM);
    if (prewarm) {
      const p = decodePrewarmTlv(prewarm);
      if (p && p.srttMs > 0) { this.bbr.onRtt(p.srttMs); this.tx.setSrttMs(p.srttMs); }
    }
    this.configured = true;
    this.cb.log?.(`FCP established: D=${np.d} P=${np.p} L=${this.interleave} ackCopies=${this.ackCopies} tlv=${this.hs.tlvNegotiated()} ackv2=${this.hs.tlvAgreed(TLV_TYPE_ACK_V2)} ` +
      `mtu=${this.pmtuMtu}${this.cfg.pmtud ? `->${this.pmtuMaxMtu} (pmtud)` : ' (fixed)'} payloadMax=${this.limits.payloadMax}`);
    this.dbg(`[${this.tag()}] ESTABLISHED D=${np.d} P=${np.p} tlv=${this.hs.tlvNegotiated()} ackv2=${this.hs.tlvAgreed(TLV_TYPE_ACK_V2)} k=${this.strategy.currentK()} keyUpdate=${this.env.keyUpdate} srtt=${this.bbr.srttMs}ms`);
    // Data queued before the handshake was cached unframed, because mux was not
    // known yet. Replaying it raw put the stream type at offset 0; a mux peer
    // read it as the sid byte, routed it to a phantom sid and never ACKed the
    // default stream, so the bytes were retransmitted until the idle timeout.
    for (const seg of this.hs.takeCachedData()) {
      this.tx.onSegment(this.mux ? this.frameSid(0, seg) : seg, nowMs);
    }
  }

  private handleFecstat(payload: Buffer, nowMs: number): void {
    const r = this.validator.validate(payload, this.salt);
    if (r.status === FecstatStatus.Duplicate) { ++this.fecstatDup; return; }
    if (r.status !== FecstatStatus.Ok || !r.packet) {
      ++this.fecstatDropped;
      if (r.status === FecstatStatus.Stale) ++this.fecstatStale;
      return;
    }
    this.strategy.onFecstat(r.packet, nowMs);
    this.tx?.setK(this.strategy.currentK());
  }

  private isPmtuFrame(payload: Buffer): boolean {
    return payload.length >= PMTU_MAGIC.length && bytesEqual(PMTU_MAGIC, payload, PMTU_MAGIC.length);
  }
  private pmtuHandle(payload: Buffer, nowMs: number): boolean {
    if (payload.length < PMTU_HEADER_LEN) return false;
    const type = payload[8];
    const token = getLe32(payload, 10);
    const mtu = getLe16(payload, 14);
    if (type === PMTU_TYPE_ACK) {
      // The clamp the PROBE branch below has: an ACK naming a size above our
      // own ceiling used to be applied verbatim (computeMtuLimits has no upper
      // bound), so a misbehaving peer could blow the send budget up to 65 KB
      // datagrams — EMSGSIZE on every send, an udp-error log line per datagram,
      // and the walk pinned because every later probe target is ≤ pmtuAckedMtu.
      if (token === this.pmtuToken && mtu > this.pmtuAckedMtu && mtu <= this.pmtuMaxMtu) {
        this.pmtuAckedMtu = mtu; this.pmtuMtu = mtu;
        this.pmtuProbesLost = 0; this.pmtuBackoffMs = 0;
        // The peer just proved the path carries this size, so a ceiling that
        // was written from probes that went unanswered is stale. Leaving it
        // in place froze the walk one step below a size that demonstrably
        // works: `ceiling - acked <= PMTU_PROBE_STEP` stops every further
        // probe, for the rest of the session.
        if (this.pmtuCeiling > 0 && mtu >= this.pmtuCeiling) this.pmtuCeiling = 0;
        // Every probe at or below the acknowledged size has been answered.
        this.pmtuPending = this.pmtuPending.filter((t) => t > mtu);
        this.applyPmtuMtu(mtu, 'ack');
        if (mtu >= this.pmtuMaxMtu && !this.pmtuCeilingLogged) {
          this.pmtuCeilingLogged = true;
          this.cb.log?.(`FCP PMTUD: path carries ${mtu}B (ceiling reached, started at ${this.pmtuStartMtu}B)`);
        }
      }
      return true;
    }
    if (type !== PMTU_TYPE_PROBE || mtu > this.pmtuMaxMtu || mtu < 576) return true;
    // The probe arrived at exactly `mtu` bytes once IP/UDP are added back, so
    // the path really carries that size. Answer with the same token — no matter
    // whether *our* own walk has already passed this size, otherwise two ends
    // probing at the same time would knock each other's probes out.
    this.dbg(`[${this.tag()}] PMTU probe rx mtu=${mtu} (local=${this.pmtuMtu}) -> ack`);
    const ack = Buffer.alloc(PMTU_HEADER_LEN);
    PMTU_MAGIC.copy(ack, 0);
    ack[8] = PMTU_TYPE_ACK; ack[9] = 0;
    putLe32(token, ack, 10);
    putLe16(mtu, ack, 14);
    this.sendOob(ack);
    return true;
  }

  private applyPmtuMtu(mtu: number, why: string): void {
    const l = computeMtuLimits(mtu, this.cfg.ipHdrLen ?? DEFAULT_IP_HEADER_LEN);
    if (!l.valid) return;
    const up = mtu > this.limits.mtu;
    this.limits = l;
    if (up) this.tx?.raiseLimits(l); else this.tx?.lowerLimits(l);
    this.stream.setMaxSegment(l.payloadMax - (this.mux ? 1 : 0));
    if (this.mux) for (const st of this.streams.values()) st.setMaxSegment(l.payloadMax - 1);
    this.dbg(`[${this.tag()}] PMTU ${why} mtu=${mtu} payloadMax=${l.payloadMax}`);
  }

  private sendPmtuProbe(nowMs: number): void {
    if (!this.cfg.pmtud) return;
    const gap = Math.max(1000, 5 * this.bbr.srttMs) + this.pmtuBackoffMs;
    if (nowMs - this.pmtuLastProbeMs < gap) return;
    // A probe that is still outstanding when the next one goes out has timed
    // out: the peer did not answer it within a full probe gap. The probe that
    // goes out right now has not had a chance to be answered yet, so it must
    // not be counted as lost — the verdict used to fire on the third probe at
    // the instant it was sent, and it pinned the ceiling to a size the peer
    // was about to answer.
    if (this.pmtuPending.length) {
      const timedOut = this.pmtuPending.shift()!;
      if (++this.pmtuProbesLost >= 3) {
        this.pmtuProbesLost = 0;
        this.pmtuBackoffMs = Math.min(PMTU_BACKOFF_MAX_MS, Math.max(1000, this.pmtuBackoffMs * 2));
        // The ceiling is the smallest size the path is suspected not to
        // carry: a bigger probe that went unanswered says nothing about a
        // smaller one.
        if (this.pmtuCeiling === 0 || timedOut < this.pmtuCeiling) this.pmtuCeiling = timedOut;
        if (this.pmtuMtu !== this.pmtuAckedMtu) {
          this.pmtuMtu = this.pmtuAckedMtu;
          this.applyPmtuMtu(this.pmtuMtu, 'blackhole-fallback');
        }
        this.dbg(`[${this.tag()}] PMTU probe ${timedOut} unanswered x3; ceiling=${this.pmtuCeiling} pinned at ${this.pmtuMtu}, backoff=${this.pmtuBackoffMs}ms`);
      }
    }
    // Within one step of the proven ceiling: the acked size is the answer,
    // further probing only burns datagrams.
    if (this.pmtuCeiling > 0 && this.pmtuCeiling - this.pmtuAckedMtu <= PMTU_PROBE_STEP) return;
    const target = this.pmtuCeiling > 0
      ? Math.floor((this.pmtuAckedMtu + this.pmtuCeiling) / 2)
      : Math.min(this.pmtuMaxMtu, this.pmtuMtu + PMTU_PROBE_STEP);
    if (target <= this.pmtuAckedMtu) return;
    const len = pmtuProbeLen(target, this.cfg.ipHdrLen ?? DEFAULT_IP_HEADER_LEN);
    if (len < PMTU_HEADER_LEN) return;
    const msg = Buffer.alloc(len);
    PMTU_MAGIC.copy(msg, 0);
    msg[8] = PMTU_TYPE_PROBE; msg[9] = 0;
    putLe32(this.pmtuToken, msg, 10);
    putLe16(target, msg, 14);
    this.sendOob(msg);
    this.pmtuProbeMtu = target;
    this.pmtuLastProbeMs = nowMs;
    ++this.pmtuProbesSent;
    this.pmtuPending.push(target);
    this.dbg(`[${this.tag()}] PMTU probe tx mtu=${target} (cur=${this.pmtuMtu} ceiling=${this.pmtuCeiling || '—'} lost=${this.pmtuProbesLost})`);
  }

  /**
   * Size each half of the flow-control window from the BDP of *its own*
   * direction. Getting this wrong in either direction is a hard cap:
   *
   *  - The send window sized from `bbr` (receive direction) was measuring the
   *    ACK trickle of a download, so it never followed the path and a 512 KiB
   *    floor was doing all the work.
   *  - The advertised receive window sized from `sndBbr` (send direction) is
   *    the mirror image: on a download the uplink is idle, so rcvBuf never
   *    grew and the peer was capped at 256 KiB / RTT = 0.5 MB/s no matter what
   *    it did.
   *
   * The two use different factors on purpose. The send window is 2 x BDP: any
   * more is a standing queue. The receive buffer is 4 x BDP with a 1 MiB floor:
   * it is a liveness buffer, not a rate knob — it has to absorb a full window
   * of out-of-order bytes while the hole ahead of them is repaired. Making it
   * small does not slow the sender down gracefully, it makes the receiver drop
   * segments it has already been sent and turns the sender into a retransmit
   * engine.
   *
   * Receive buffer is raised but never lowered: shrinking it below the current
   * reorder buffer would make `seqDist(offset, rcvNxt) > rcvBufBytes` drop
   * segments already in flight.
   */
  private updateStreamWindows(nowMs: number): void {
    if (nowMs - this.lastWindowUpdateMs < WINDOW_UPDATE_INTERVAL_MS) return;
    this.lastWindowUpdateMs = nowMs;
    const srtt = Math.max(1, this.bbr.srttMs);
    const sendWant = this.bdpWindow(this.sndBbr.bwBytesPerMs, this.stream.sendWindowBytes,
      WINDOW_BDP_FACTOR, DEFAULT_WINDOW_MIN_BYTES, srtt);
    const rcvWant = this.bdpWindow(this.bbr.bwBytesPerMs, this.stream.rcvBufBytes,
      RCV_BUF_BDP_FACTOR, DEFAULT_RCV_BUF_FLOOR_BYTES, srtt);
    const rcvNext = Math.max(this.stream.rcvBufBytes, rcvWant);
    const changed = sendWant !== this.stream.sendWindowBytes || rcvNext !== this.stream.rcvBufBytes;
    if (changed) {
      this.stream.setWindows(sendWant, rcvNext);
      this.dbg(`[${this.tag()}] window send ${this.stream.sendWindowBytes}B rcv ${this.stream.rcvBufBytes}B ` +
        `(sendBw=${this.sndBbr.bwBytesPerMs.toFixed(2)}B/ms rcvBw=${this.bbr.bwBytesPerMs.toFixed(2)}B/ms srtt=${this.bbr.srttMs}ms)`);
    }
    // Mux streams share the same window targets; the per-stream advertise
    // still collapses under each stream's own reorder occupancy, which is
    // what actually throttles a busy multiplexed session.
    //
    // This must run even when the default stream's own targets did not change.
    // enforceStreamBytesBudget() squeezes an over-share stream down to a 1-byte
    // receive window on every tick, and this loop is the only thing that lifts
    // it back. Behind the early return above it never lifted: the squeezed
    // stream is never `this.stream`, so the default stream's targets stayed
    // stable, the return fired every cadence, and the squeezed sid stayed
    // pinned at 1 byte for the life of the session.
    if (this.mux) for (const st of this.streams.values()) st.setWindows(sendWant, rcvNext);
  }

  /** factor x BDP for one direction, with ratio hysteresis so the advertised
   *  window does not flap on every estimate wobble. */
  private bdpWindow(bwPerMs: number, cur: number, factor: number, floor: number, srtt: number): number {
    if (bwPerMs <= 0) return cur;
    const bdp = bwPerMs * srtt;
    const target = Math.min(
      DEFAULT_WINDOW_CEILING_BYTES,
      Math.max(floor, Math.round(factor * bdp)),
    );
    const changed = target > cur * WINDOW_CHANGE_RATIO || target * WINDOW_CHANGE_RATIO < cur;
    return changed ? target : cur;
  }

  private onStreamSegment(seg: Buffer): void {
    if (!this.hs.established) { this.hs.cacheData(seg); return; }
    if (this.hs.failed || this.closeNotified) return;
    if (!this.tx) return;
    // In mux mode every segment (control included) is prefixed with its 1-byte
    // sid, so the stream type is at offset 1. Reading seg[0] there returned the
    // sid instead: sid 1..3 looked like DATA/ACK/RST and sid 0 like nothing, so
    // no ACK ever took the fast-flush path. Every ack then waited for D symbols
    // or the ≈srtt flush timer, which delays SACK evidence by a whole round and
    // capped recovery in the one mode the client actually uses.
    const kind = this.mux ? (seg.length > 1 ? seg[1] : 0) : (seg.length > 0 ? seg[0] : 0);
    this.dbg(`[${this.tag()}] stream seg tx len=${seg.length} cumAcked=${this.stream.cumAcked}`);
    const control = kind === STREAM_TYPE_ACK || kind === STREAM_TYPE_ACK_V2 || kind === STREAM_TYPE_RST;
    this.tx.onSegment(seg, this.nowMs, control);
    ++this.dataTx;
    // Acknowledgements and resets must leave immediately, so they get the
    // dedicated control lane that FrameTx closes on arrival instead of sharing
    // a group with data.
    //
    // The extra ACK copies go through the *data* lanes on purpose. They are
    // spread by the interleave (one copy per lane, not adjacent datagrams),
    // and they share the group's parity with data instead of each paying for a
    // one-symbol group of their own. The copy bit tells the peer not to count
    // them as duplicate-ACK evidence, which at DUP_ACK_THRESH = 1 would
    // otherwise fire a retransmit for every ACK.
    if (kind === STREAM_TYPE_ACK_V2) {
      for (let i = 1; i < this.ackCopies; ++i) {
        const copy = this.markAckCopy(seg);
        if (copy) this.tx.onSegment(copy, this.nowMs, false);
      }
    }
  }

  /** Duplicate an ACK v2 segment with its "redundant copy" bit set. */
  private markAckCopy(seg: Buffer): Buffer | null {
    const at = this.mux ? 1 : 0;
    // type byte + cum(4) + rwnd(4) + range count(1)
    if (seg.length < at + 10) return null;
    if (seg[at] !== STREAM_TYPE_ACK_V2) return null;
    const out = Buffer.from(seg);
    out[at + 9] |= ACK_V2_FLAG_COPY;
    return out;
  }

  /** M1: host-initiated stream (client side). Mux sessions only; sid 0 is the
   *  session's default stream and is never opened through here. */
  openStream(sid: number, cb: StreamCallbacks): Stream | null {
    if (!this.mux || sid === 0 || sid > MUX_MAX_STREAMS || this.streams.has(sid)) return null;
    return this.makeStream(sid, cb);
  }

  get muxActive(): boolean { return this.mux; }

  private makeStream(sid: number, cb: StreamCallbacks): Stream {
    const stream = new Stream(
      {
        maxSegment: this.limits.payloadMax - (this.mux ? 1 : 0),
        initialSrttMs: this.cfg.initialSrttMs ?? DEFAULT_SRTT_MS,
        // The default stream gets this in configure(); sid streams are created
        // later and used to fall back to the classic single-block ACK even when
        // ACK v2 was negotiated, silently halving SACK coverage on every
        // multiplexed connection.
        ackV2: this.hs.tlvAgreed(TLV_TYPE_ACK_V2),
      },
      {
        ...cb,
        send: (seg) => this.sendStreamSegment(sid, seg),
        // The bbr/sndBbr estimators and the FEC srtt are session-wide: every
        // stream's delivery/ack/rtt sample must reach them, exactly like the
        // default stream's callbacks do.
        read: (bytes) => { this.bbr.onDelivery(bytes.length, this.nowMs); cb.read(bytes); },
        closed: (reason) => {
          this.streams.delete(sid);
          cb.closed(reason);
          this.streamHost?.streamClosed(sid, reason);
        },
        eof: () => cb.eof?.(),
        rtt: (ms) => {
          this.bbr.onRtt(ms); this.sndBbr.onRtt(ms); this.tx?.setSrttMs(ms);
        },
        acked: (bytes, nowMs) => this.sndBbr.onDelivery(bytes, nowMs),
      },
    );
    this.streams.set(sid, stream);
    return stream;
  }

  /** Route a delivered DATA symbol payload to its stream. Mux sessions prefix
   *  a 1-byte sid (0 = default stream); legacy sessions take the whole
   *  payload. An inbound sid without host state (server: an OPEN arrived on a
   *  fresh stream) is created through the host, or dropped when refused. */
  private deliverStreamFrame(bytes: Buffer): void {
    if (!this.mux) { this.stream.onSegment(bytes, this.nowMs); return; }
    // A zero-length symbol cannot carry the sid byte. FrameRx can legitimately
    // produce one (a repaired symbol whose declared length is 2), and reading
    // bytes[0] of it yielded `undefined`, which the server then used as a map
    // key and a stream id.
    if (bytes.length === 0) { ++this.structFail; return; }
    const sid = bytes[0];
    let stream = sid === 0 ? this.stream : this.streams.get(sid);
    if (!stream) {
      if (sid === 0) { ++this.structFail; return; }
      const cb = this.streamHost?.inboundStream(sid);
      if (!cb) { this.dbg(`[${this.tag()}] stream ${sid} refused by host; bytes dropped`); return; }
      stream = this.makeStream(sid, cb);
      this.streamHost?.streamReady?.(sid, stream);
    }
    stream.onSegment(bytes.subarray(1), this.nowMs);
  }

  private sendStreamSegment(sid: number, seg: Buffer): void {
    this.onStreamSegment(this.mux ? this.frameSid(sid, seg) : seg);
  }

  /** The 1-byte sid prefix is fully written here, so allocUnsafe is safe. */
  private frameSid(sid: number, seg: Buffer): Buffer {
    const framed = Buffer.allocUnsafe(1 + seg.length);
    framed[0] = sid;
    seg.copy(framed, 1);
    return framed;
  }

  private emitSymbol(s: TxSymbol, bootstrap: boolean): void {
    const plain = packTxFrame(s);
    const env = bootstrap ? this.hsEnv : this.env;
    const wire = env.seal(plain);
    if (!wire) { this.cb.log?.('FCP session exhausted nonce space'); return; }
    this.lastWireOutMs = this.nowMs;
    this.dbg(`[${this.tag()}] sym tx set=${s.setId} idx=${s.index} type=${hdrType(s.typeK)} len=${s.symbol.length} wire=${wire.length}B ${bootstrap ? 'bootstrap-key' : 'session-key'}`);
    this.cb.sendWire(wire, hdrType(s.typeK));
  }

  private sendOob(msg: Uint8Array, bootstrap = false): void {
    const plain = packOobFrame(msg);
    const env = bootstrap ? this.hsEnv : this.env;
    const wire = env.seal(plain);
    if (!wire) return;
    this.lastWireOutMs = this.nowMs;
    this.dbg(`[${this.tag()}] oob tx len=${msg.length} wire=${wire.length}B ${bootstrap ? 'bootstrap-key' : 'session-key'}`);
    this.cb.sendWire(wire, SymbolType.Oob);
  }

  /** #86: build an authenticated stateless-reset datagram for this salt.
   *
   *  The counter must stay under NONCE_LIMIT (2^32) or sealAt() returns null —
   *  which is what this used to do, always and silently, because it drew a
   *  random *64-bit* value. No reset was ever put on the wire, so a peer that
   *  lost its session could only be detected by the 135 s peer_dead timer while
   *  the sender kept retransmitting. Drawing from the top of the range also
   *  keeps a reset from ever colliding with a handshake nonce, which counts up
   *  from 0 under the same bootstrap key. */
  makeReset(counter?: bigint): Buffer | null {
    const c = counter ?? (NONCE_LIMIT - 1n - BigInt(randomBytes(2).readUInt16LE(0)));
    return sealReset(this.cfg.psk, this.salt, this.cfg.sendDirection, this.cfg.recvDirection, c);
  }

  write(data: Uint8Array): number { return this.stream.write(data, this.nowMs); }
  closeWrite(): void { this.stream.closeWrite(this.nowMs); }
  consumed(n: number): void { this.stream.consumed(n); }
  /** Aggregate over the default stream + every live sid stream (dbg lines). */
  private eachStream(fn: (s: Stream) => number): number {
    let total = fn(this.stream);
    for (const st of this.streams.values()) total += fn(st);
    return total;
  }
  get inflightBytes(): number { return this.eachStream((s) => s.inflightBytes); }
  get peerWindowBytes(): number { return this.stream.peerWindowBytes; }
  get queuedBytes(): number { return this.eachStream((s) => s.pendingQueueBytes); }
  get recvNext(): number { return this.stream.recvNext; }
  get reorderBytes(): number { return this.eachStream((s) => s.reorderBytes); }
  get recvPendingBytes(): number { return this.eachStream((s) => s.deliveryPendingBytes); }
  get segsSent(): number { return this.eachStream((s) => s.segsSent); }
  get segsRetransmitted(): number { return this.eachStream((s) => s.retransmits); }
  /** ACKs whose SACK list did not fit the datagram, and the holes left out of
   *  them. A non-zero count says the path cannot carry the receiver's hole
   *  list, so the sender works from a partial view of what arrived. */
  get ackRangesTruncated(): number { return this.eachStream((s) => s.ackRangesTruncated); }
  get ackRangesDropped(): number { return this.eachStream((s) => s.ackRangesDropped); }
  /** fast-retransmit copies / RTO copies / fast-retransmit rounds. */
  get retxSplit(): string {
    return `${this.stream.retxFast}/${this.stream.retxRto}/${this.stream.fastRounds}`;
  }
  /** Recovery latency for segments that needed retransmission: first send to
   *  the confirmation of a later copy. The acceptance measure for anything that
   *  claims to make recovery faster. */
  get retxLatencyP50Ms(): number { return this.retxLatencyPct(50); }
  get retxLatencyP95Ms(): number { return this.retxLatencyPct(95); }
  get retxLatencyCount(): number { return this.eachStream((s) => s.retxLatencyCount); }
  /** Nearest-rank percentile over every stream's ring, pooled. */
  private retxLatencyPct(pct: number): number {
    const all = this.stream.retxLatencySamples();
    for (const st of this.streams.values()) all.push(...st.retxLatencySamples());
    if (all.length === 0) return 0;
    all.sort((a, b) => a - b);
    const rank = Math.min(all.length, Math.max(1, Math.ceil((pct / 100) * all.length)));
    return all[rank - 1]!;
  }
  /** Measured send-direction delivery rate, B/ms. Diagnostic only. */
  get sendRateBytesPerMs(): number { return this.sndBbr.bwBytesPerMs; }
  /** Path shard-loss rate as measured by the peer's FECSTAT. */
  get fecLoss(): number { return this.strategy.currentLoss(); }

  /**
   * Session-wide heap ceiling on reorder + delivered-but-unconsumed bytes.
   *
   * Each stream's own ceiling is its rcvBufBytes — up to 4 MiB once the BDP
   * walk grows it — and a mux session can carry 255 sid streams, so the
   * per-stream bound alone lets one authenticated peer pin ~1 GiB of heap by
   * holding a single hole per stream until the idle timeout. This pass sums
   * every stream's reorderBytes + deliveryPendingBytes and, over budget,
   * trims the heaviest streams' reorder tails first. What cannot be trimmed
   * (deliveryPending is already in the host's hands) is starved instead: any
   * stream still holding more than its fair share has its receive window
   * re-shrunk here every tick, so new bytes are refused until the aggregate
   * drains back under the cap. updateStreamWindows re-grows those windows on
   * its 250 ms cadence, which is why this runs on every tick: the shrink is
   * re-applied far more often than the growth.
   */
  private enforceStreamBytesBudget(): void {
    const rows: Array<{ s: Stream; bytes: number }> = [];
    let total = 0;
    const collect = (s: Stream): void => {
      const b = s.reorderBytes + s.deliveryPendingBytes;
      if (b > 0) { rows.push({ s, bytes: b }); total += b; }
    };
    collect(this.stream);
    for (const st of this.streams.values()) collect(st);
    if (total <= SESSION_STREAM_BUDGET_BYTES) return;
    rows.sort((a, b) => b.bytes - a.bytes);
    let over = total - SESSION_STREAM_BUDGET_BYTES;
    for (const r of rows) {
      if (over <= 0) break;
      const reorder = r.s.reorderBytes;
      if (reorder <= 0) continue;
      const cut = Math.min(over, reorder);
      r.s.trimReorderTo(reorder - cut);
      // Keep the row honest: the fair-share test below must judge what is left
      // after the trim, not what was there before it.
      r.bytes -= cut;
      over -= cut;
    }
    if (over > 0) {
      const share = Math.max(1, Math.floor(SESSION_STREAM_BUDGET_BYTES / Math.max(1, rows.length)));
      for (const r of rows) {
        if (r.bytes > share) r.s.setWindows(r.s.sendWindowBytes, 1);
      }
    }
  }

  /** Feed the controller the receiver-side loss fallback and push the resulting
   *  k into the encoder. The setK call matters on its own: only handleFecstat
   *  used to do it, so a k changed by the local fallback never reached FrameTx
   *  and the number in the stats line could disagree with the parity actually
   *  on the wire for a whole session. */
  private syncFecControl(nowMs: number): void {
    const c = this.rx?.counters;
    if (c) {
      this.strategy.noteLocalCounters(c.dataExpected, c.dataRxOrig, nowMs);
    }
    this.adaptGroupD(nowMs);
    this.tx?.setK(this.strategy.currentK());
    // Filling one group takes d x payloadMax bytes at the measured send rate.
    // FrameTx caps the partial-group flush timer at a small multiple of that, so
    // a group that would close in 14 ms stops waiting 200 ms for parity.
    // With interleaving a lane only sees one segment in every L, so the time it
    // needs to fill is L times the time to put d symbols on the wire.
    this.tx?.setGroupDrainMs(this.groupDrainMs());
  }

  /**
   * Group size follows the loss rate: d is the resolution at which k can
   * express "cover this much loss".
   *
   * k = ceil(d x loss x HEADROOM) and k cannot exceed the negotiated p. Once
   * d x loss x HEADROOM reaches p the formula saturates and every extra data
   * symbol added to the group only dilutes the repair ratio k/d — the group
   * gets wider while its tail coverage stops growing. So the rule is to keep
   * d on the large side while k has room, and cut d as loss climbs until k
   * fits under the ceiling again.
   *
   * The second bound runs the other way: if d is too small the sender emits
   * groups faster than the receiver settles them (MAX_ACTIVE_SETS with the
   * 1 s/2 s settle clocks), and groups start being evicted half-decoded. That
   * is a correctness limit, not a tuning knob, so it wins over the loss rule.
   */
  private adaptGroupD(nowMs: number): void {
    const target = this.pickGroupD();
    if (target === this.groupD) return;
    if (nowMs - this.lastDChangeMs < D_ADAPT_INTERVAL_MS) return;
    if (Math.abs(target - this.groupD) < D_STEP_MIN &&
        target !== D_FLOOR && target !== this.dMax) return;
    this.lastDChangeMs = nowMs;
    this.groupD = target;
    this.tx?.setGroupD(target);
    this.strategy.setGroupSize(target);
    this.cfg.trace?.(JSON.stringify({ t: 'geom', d: target, dMax: this.dMax, lanes: this.interleave }));
  }

  private pickGroupD(): number {
    const bw = this.sndBbr.bwBytesPerMs;
    const symPerSec = bw > 0 && this.limits.payloadMax > 0
      ? (bw * 1000) / this.limits.payloadMax : 0;
    return chooseGroupD({
      dMax: this.dMax,
      p: this.strategy.currentParityCeiling(),
      loss: this.strategy.currentLoss(),
      symPerSec,
    });
  }

  /** Estimated time to put one full group on the wire, or -1 when unknown. */
  private groupDrainMs(): number {
    const bw = this.sndBbr.bwBytesPerMs;
    if (bw <= 0 || this.groupD <= 0) return -1;
    return (this.interleave * this.groupD * this.limits.payloadMax) / bw;
  }

  /**
   * Milliseconds until the earliest self-driven deadline in this session, or -1.
   *
   * The host used to tick every 10 ms and that interval was the real resolution
   * of every protocol timer: a delayed ack due in 4 ms left up to 10 ms late, a
   * partial repair group waited for a tick boundary, an expired RTO was noticed
   * on the next boundary. Feeding this value to a single rescheduling timeout
   * costs nothing when no deadline is near (the host still falls back to its
   * coarse interval) and removes the quantisation when one is.
   */
  nextTimerMs(nowMs: number): number {
    if (this.closeNotified) return -1;
    let best = -1;
    const take = (ms: number): void => {
      if (ms < 1) return;
      if (best < 0 || ms < best) best = ms;
    };
    if (this.hs.established && this.tx) {
      take(this.tx.nextTimerMs(nowMs));
      take(this.stream.nextTimerMs(nowMs));
      if (this.mux) for (const st of this.streams.values()) take(st.nextTimerMs(nowMs));
    }
    return best;
  }

  onTick(nowMs: number): void {
    this.nowMs = nowMs;
    if (this.closeNotified) return;
    if (!this.hs.established) this.hs.onTick(nowMs);
    if (this.hs.established && !this.configured) this.configure(nowMs);
    if (this.hs.failed) { this.notifyClosed('handshake_failure'); return; }
    if (this.hs.established) {
      this.tx?.onTick(nowMs);
      this.rx?.onTick(nowMs);
      this.syncFecControl(nowMs);
      this.updateStreamWindows(nowMs);
      this.stream.onTick(nowMs);
      if (this.mux) for (const st of this.streams.values()) st.onTick(nowMs);
      this.enforceStreamBytesBudget();
      const report = this.reporter.onTick(nowMs, this.rx?.counters ?? emptyCounters(), this.rx?.accountedThroughSetId() ?? 0);
      if (report) {
        // FECSTAT is oob and never retransmitted; reporter.cc sends the 128-byte
        // report twice so one lost datagram cannot blind the peer's controller
        // for a whole period. The peer validator drops the second copy by its
        // monotonic key.
        this.sendOob(report);
        this.sendOob(report);
      }
      this.sendPmtuProbe(nowMs);
      this.probe.onTick(nowMs);
    }
    if (!this.lastWireOutMs) this.lastWireOutMs = nowMs;
    if (nowMs - this.lastWireOutMs >= NAT_KEEPALIVE_MS) {
      this.dbg(`[${this.tag()}] keepalive tx (NAT)`);
      this.sendOob(KEEPALIVE_MAGIC);
    }
    if (this.lastPeerInMs && nowMs - this.lastPeerInMs >= PEER_ALIVE_GRACE_MS && !this.resetByPeer) {
      this.resetByPeer = true;
      this.dbg(`[${this.tag()}] CLOSE peer_dead (silent ${nowMs - this.lastPeerInMs}ms)`);
      this.notifyClosed('peer_dead');
    }
  }
}

function emptyCounters() {
  return {
    structFail: 0, stale: 0, lateDup: 0, recovered: 0, recoveredLate: 0,
    dataRxOrig: 0, parityRx: 0, dataDelivered: 0, dataLateRx: 0, retiredDropped: 0,
    aheadDropped: 0, setsPartial: 0, setsFull: 0, setsTailDropped: 0,
    decodeAttempts: 0, badRecon: 0, symbolBudgetDrops: 0,
    setsExpected: 0, dataExpected: 0, parityExpected: 0, setsKUnknown: 0,
    ledgerGroups: 0, ledgerFailed: 0, ledgerKHist: new Array(8).fill(0),
  };
}
