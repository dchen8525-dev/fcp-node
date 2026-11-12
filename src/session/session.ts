// FCP session: wires together the two key epochs, handshake, FEC framing,
// FCP-STREAM ARQ, oob dispatch and the control plane.
// Port of src/fcp/session.cc (state machine + dispatch order), with the
// clock/socket-free shape preserved: host drives onWire()/onTick().

import { randomBytes } from 'node:crypto';
import {
  SALT_LEN, Direction, type DirectionValue,
  HandshakeRole, HandshakeState, HandshakeError,
  CAP_PMTUD, CAP_TLV, TLV_TYPE_ACK_V2, TLV_TYPE_KEY_UPDATE, TLV_TYPE_PREWARM, LOCAL_FLAGS_M1,
  HANDSHAKE_SEND_BUDGET, BOOTSTRAP_PROBES_PER_SECOND,
  NAT_KEEPALIVE_MS, PEER_ALIVE_GRACE_MS, KEEPALIVE_MAGIC, KEEPALIVE_LEN,
  RESET_MAGIC, RESET_MAGIC_LEN, ENVELOPE_OVERHEAD, NONCE_LIMIT,
  PMTU_MAGIC, PMTU_HEADER_LEN, PMTU_TYPE_PROBE, PMTU_TYPE_ACK,
  PMTU_ABSOLUTE_MAX_MTU, DEFAULT_PMTU_MAX_MTU, PMTU_PROBE_STEP, PMTU_BACKOFF_MAX_MS,
  DEFAULT_MTU_MIN, DEFAULT_IP_HEADER_LEN, DEFAULT_D, DEFAULT_P,
  DEFAULT_SRTT_MS, FEC_HDR_LEN, SymbolType,
  DATA_WIRE_OVERHEAD,
  STREAM_TYPE_ACK, STREAM_TYPE_ACK_V2, STREAM_TYPE_RST,
  DEFAULT_WINDOW_MIN_BYTES, DEFAULT_WINDOW_CEILING_BYTES,
  DEFAULT_RCV_BUF_FLOOR_BYTES, RCV_BUF_BDP_FACTOR,
  WINDOW_BDP_FACTOR, WINDOW_UPDATE_INTERVAL_MS, WINDOW_CHANGE_RATIO,
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
import { Stream } from '../stream/stream.ts';
import { AdaptiveFec, BbrLite, FecstatReporter } from '../control/controller.ts';

export interface SessionConfig {
  psk: Uint8Array;
  salt: Uint8Array;
  sendDirection: DirectionValue;
  recvDirection: DirectionValue;
  role: number; // HandshakeRole.Client / Server
  d?: number; p?: number;
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
}

export interface SessionStats {
  authFail: number; structFail: number; dataTx: number; dataRx: number;
  fecstatDropped: number; fecstatDup: number; fecstatStale: number;
  established: boolean; state: number; k: number; srttMs: number;
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
  /** Largest symbol this end will accept, independent of its send budget. */
  private rxSymbolMax = 65535;
  private pinnedK: number;
  private dbg: (line: string) => void;
  private tag: () => string;

  constructor(cfg: SessionConfig, cb: SessionCallbacks) {
    this.cfg = cfg;
    this.cb = cb;
    this.dbg = cb.debug ?? (() => {});
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

    this.stream = new Stream(
      { maxSegment: this.limits.payloadMax, initialSrttMs: cfg.initialSrttMs ?? DEFAULT_SRTT_MS },
      {
        send: (seg) => this.onStreamSegment(seg),
        read: (bytes) => { this.bbr.onDelivery(bytes.length, this.nowMs); this.cb.read(bytes); },
        closed: (reason) => this.cb.closed(reason),
        eof: () => this.cb.eof?.(),
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
      srttMs: this.bbr.srttMs, resetByPeer: this.resetByPeer,
      peerAliveMs: this.lastPeerInMs ? this.nowMs - this.lastPeerInMs : 0,
    };
  }

  start(nowMs: number): boolean {
    this.nowMs = nowMs;
    this.dbg(`[${this.tag()}] session start role=${this.cfg.role === HandshakeRole.Client ? 'client' : 'server'} d=${this.cfg.d ?? DEFAULT_D} p=${this.cfg.p ?? DEFAULT_P} mtu=${this.pmtuStartMtu}${this.cfg.pmtud ? `..${this.pmtuMaxMtu} (pmtud)` : ' (fixed)'} payloadMax=${this.limits.payloadMax} pinnedK=${this.pinnedK}`);
    if (!this.limits.valid) { this.cb.log?.('FCP config invalid: MTU leaves no room for a data symbol'); return false; }
    if ((this.cfg.d ?? DEFAULT_D) < 1 || (this.cfg.p ?? DEFAULT_P) > 7) return false;
    if (this.hs.failed) { this.cb.log?.(`FCP handshake refused: ${HandshakeError[this.hs.error] ?? this.hs.error}`); return false; }
    const tlvs: HandshakeTlv[] = [];
    if (this.cfg.ack_v2) tlvs.push({ type: TLV_TYPE_ACK_V2, value: Buffer.alloc(0) });
    // Advertised, not assumed: without this the sender would start rolling its
    // key after FIRST_ROLL_AT packets while a peer that did not opt in keeps
    // decrypting with the session key, and the link dies with no error at all.
    if (this.cfg.keyUpdate) tlvs.push({ type: TLV_TYPE_KEY_UPDATE, value: Buffer.alloc(0) });
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
    let plain = this.env.open(wire);
    let bootstrap = false;
    // Stateless reset first, by shape. A reset is sealed under the *bootstrap*
    // key, so it is also a perfectly valid bootstrap envelope: probing with
    // hsEnv.open() below would decrypt it, find no HELLO inside and count it as
    // a structure failure, and the session would never learn the peer is gone.
    if (plain === null && !this.resetByPeer && this.hs.established &&
        wire.length === ENVELOPE_OVERHEAD + RESET_MAGIC_LEN && this.hsEnv.openReset(wire)) {
      // Both roles must honour this, not just the client: a server whose peer
      // walked away (browser tab closed, curl --max-time, process restart) kept
      // pushing a full window into a void — 544 KB queued, 1000+ RTO copies in
      // the stats — while the peer was answering every datagram with exactly
      // this packet. A rejected datagram never refreshes lastPeerInMs, so the
      // only other exit was peer_dead, 135 s later.
      this.resetByPeer = true;
      this.cb.log?.('FCP stateless reset: the peer has no session for this salt');
      this.cb.closed('stateless_reset');
      return true;
    }
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
        this.cb.closed('stateless_reset');
      }
      return;
    }
    if (this.dispatchHandshake(payload, nowMs)) return;
    if (this.isPmtuFrame(payload) && this.pmtuHandle(payload, nowMs)) return;
    this.handleFecstat(payload);
  }

  private dispatchHandshake(payload: Buffer, nowMs: number): boolean {
    if (payload.length < 36 || (!isHello(payload) && !isHelloAck(payload))) return false;
    this.dbg(`[${this.tag()}] ${isHello(payload) ? 'HELLO' : 'HELLO_ACK'} rx len=${payload.length}`);
    if (this.hs.onOob(payload) === HandshakeStatus.ProtocolFailure) {
      this.cb.log?.(`FCP handshake failed: error=${this.hs.error}`);
      this.cb.closed('handshake_failure');
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
    this.tx = new FrameTx(np.d, this.limits, (s) => this.emitSymbol(s, false));
    this.tx.setSrttMs(this.bbr.srttMs);
    // Follow the agreed parity, not our own proposal: a peer may have offered a
    // lower P, and anything above it is dropped as IndexPastS on arrival.
    this.strategy.setParityCeiling(np.p);
    this.strategy.setGroupSize(np.d);
    this.tx.setK(this.strategy.currentK());
    this.rx = new FrameRx({
      d: np.d, p: np.p,
      maxSymbolLen: this.rxSymbolMax,
      deliver: (bytes) => { this.stream.onSegment(bytes, this.nowMs); },
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
    this.stream.setMaxSegment(this.limits.payloadMax);
    const prewarm = this.hs.peerTlv(TLV_TYPE_PREWARM);
    if (prewarm) {
      const p = decodePrewarmTlv(prewarm);
      if (p && p.srttMs > 0) { this.bbr.onRtt(p.srttMs); this.tx.setSrttMs(p.srttMs); }
    }
    this.configured = true;
    this.cb.log?.(`FCP established: D=${np.d} P=${np.p} tlv=${this.hs.tlvNegotiated()} ackv2=${this.hs.tlvAgreed(TLV_TYPE_ACK_V2)} ` +
      `mtu=${this.pmtuMtu}${this.cfg.pmtud ? `->${this.pmtuMaxMtu} (pmtud)` : ' (fixed)'} payloadMax=${this.limits.payloadMax}`);
    this.dbg(`[${this.tag()}] ESTABLISHED D=${np.d} P=${np.p} tlv=${this.hs.tlvNegotiated()} ackv2=${this.hs.tlvAgreed(TLV_TYPE_ACK_V2)} k=${this.strategy.currentK()} keyUpdate=${this.env.keyUpdate} srtt=${this.bbr.srttMs}ms`);
    for (const seg of this.hs.takeCachedData()) this.tx.onSegment(seg, nowMs);
  }

  private handleFecstat(payload: Buffer): void {
    const r = this.validator.validate(payload, this.salt);
    if (r.status === FecstatStatus.Duplicate) { ++this.fecstatDup; return; }
    if (r.status !== FecstatStatus.Ok || !r.packet) {
      ++this.fecstatDropped;
      if (r.status === FecstatStatus.Stale) ++this.fecstatStale;
      return;
    }
    this.strategy.onFecstat(r.packet);
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
      if (token === this.pmtuToken && mtu > this.pmtuAckedMtu) {
        this.pmtuAckedMtu = mtu; this.pmtuMtu = mtu;
        this.pmtuProbesLost = 0; this.pmtuBackoffMs = 0;
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
    this.stream.setMaxSegment(l.payloadMax);
    this.dbg(`[${this.tag()}] PMTU ${why} mtu=${mtu} payloadMax=${l.payloadMax}`);
  }

  private sendPmtuProbe(nowMs: number): void {
    if (!this.cfg.pmtud) return;
    const gap = Math.max(1000, 5 * this.bbr.srttMs) + this.pmtuBackoffMs;
    if (nowMs - this.pmtuLastProbeMs < gap) return;
    const target = Math.min(this.pmtuMaxMtu, this.pmtuMtu + PMTU_PROBE_STEP);
    if (target <= this.pmtuMtu) return;
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
    this.dbg(`[${this.tag()}] PMTU probe tx mtu=${target} (cur=${this.pmtuMtu} lost=${this.pmtuProbesLost})`);
    // Three unacknowledged probes = black hole: fall back to the proved size
    // and back off, so a path that cannot grow is not hammered every second.
    if (++this.pmtuProbesLost >= 3) {
      this.pmtuProbesLost = 0;
      this.pmtuBackoffMs = Math.min(PMTU_BACKOFF_MAX_MS, Math.max(1000, this.pmtuBackoffMs * 2));
      if (this.pmtuMtu !== this.pmtuAckedMtu) {
        this.pmtuMtu = this.pmtuAckedMtu;
        this.applyPmtuMtu(this.pmtuMtu, 'blackhole-fallback');
      }
      this.dbg(`[${this.tag()}] PMTU probe ${target} unanswered x3; pinned at ${this.pmtuMtu}, backoff=${this.pmtuBackoffMs}ms`);
    }
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
    if (sendWant === this.stream.sendWindowBytes && rcvNext === this.stream.rcvBufBytes) return;
    this.stream.setWindows(sendWant, rcvNext);
    this.dbg(`[${this.tag()}] window send ${this.stream.sendWindowBytes}B rcv ${this.stream.rcvBufBytes}B ` +
      `(sendBw=${this.sndBbr.bwBytesPerMs.toFixed(2)}B/ms rcvBw=${this.bbr.bwBytesPerMs.toFixed(2)}B/ms srtt=${this.bbr.srttMs}ms)`);
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
    if (this.hs.failed) return;
    if (!this.tx) return;
    const kind = seg.length > 0 ? seg[0] : 0;
    this.dbg(`[${this.tag()}] stream seg tx len=${seg.length} cumAcked=${this.stream.cumAcked}`);
    this.tx.onSegment(seg, this.nowMs);
    ++this.dataTx;
    // Acknowledgements and resets must leave immediately. Left in the repair
    // group they wait for D segments or the flush timer, and since the flush
    // timer is ~srtt (200 ms), a download can never exceed D symbols per
    // 200 ms no matter how fast the path is.
    if (kind === STREAM_TYPE_ACK || kind === STREAM_TYPE_ACK_V2 || kind === STREAM_TYPE_RST) this.tx.flush();
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
  get inflightBytes(): number { return this.stream.inflightBytes; }
  get peerWindowBytes(): number { return this.stream.peerWindowBytes; }
  get queuedBytes(): number { return this.stream.pendingQueueBytes; }
  get recvNext(): number { return this.stream.recvNext; }
  get reorderBytes(): number { return this.stream.reorderBytes; }
  get recvPendingBytes(): number { return this.stream.deliveryPendingBytes; }
  get segsSent(): number { return this.stream.segsSent; }
  get segsRetransmitted(): number { return this.stream.retransmits; }
  /** fast-retransmit copies / RTO copies / fast-retransmit rounds. */
  get retxSplit(): string {
    return `${this.stream.retxFast}/${this.stream.retxRto}/${this.stream.fastRounds}`;
  }
  /** Measured send-direction delivery rate, B/ms. Diagnostic only. */
  get sendRateBytesPerMs(): number { return this.sndBbr.bwBytesPerMs; }
  /** Path shard-loss rate as measured by the peer's FECSTAT. */
  get fecLoss(): number { return this.strategy.currentLoss(); }

  /** Feed the controller the receiver-side loss fallback and push the resulting
   *  k into the encoder. The setK call matters on its own: only handleFecstat
   *  used to do it, so a k changed by the local fallback never reached FrameTx
   *  and the number in the stats line could disagree with the parity actually
   *  on the wire for a whole session. */
  private syncFecControl(nowMs: number): void {
    const c = this.rx?.counters;
    if (c) {
      this.strategy.noteLocalCounters((c.setsFull >>> 0) + (c.setsPartial >>> 0), c.dataRxOrig >>> 0, nowMs);
    }
    this.tx?.setK(this.strategy.currentK());
  }

  onTick(nowMs: number): void {
    this.nowMs = nowMs;
    if (!this.hs.established) this.hs.onTick(nowMs);
    if (this.hs.established && !this.configured) this.configure(nowMs);
    if (this.hs.failed) { this.cb.closed('handshake_failure'); return; }
    if (this.hs.established) {
      this.tx?.onTick(nowMs);
      this.rx?.onTick(nowMs);
      this.syncFecControl(nowMs);
      this.updateStreamWindows(nowMs);
      this.stream.onTick(nowMs);
      const report = this.reporter.onTick(nowMs, this.rx?.counters ?? emptyCounters(), this.rx?.accountedThroughSetId() ?? 0);
      if (report) this.sendOob(report);
      this.sendPmtuProbe(nowMs);
    }
    if (!this.lastWireOutMs) this.lastWireOutMs = nowMs;
    if (nowMs - this.lastWireOutMs >= NAT_KEEPALIVE_MS) {
      this.dbg(`[${this.tag()}] keepalive tx (NAT)`);
      this.sendOob(KEEPALIVE_MAGIC);
    }
    if (this.lastPeerInMs && nowMs - this.lastPeerInMs >= PEER_ALIVE_GRACE_MS && !this.resetByPeer) {
      this.resetByPeer = true;
      this.dbg(`[${this.tag()}] CLOSE peer_dead (silent ${nowMs - this.lastPeerInMs}ms)`);
      this.cb.closed('peer_dead');
    }
  }
}

function emptyCounters() {
  return {
    structFail: 0, stale: 0, lateDup: 0, recovered: 0, recoveredLate: 0,
    dataRxOrig: 0, parityRx: 0, dataDelivered: 0, retiredDropped: 0,
    aheadDropped: 0, setsPartial: 0, setsFull: 0, setsTailDropped: 0,
    decodeAttempts: 0, badRecon: 0,
  };
}
