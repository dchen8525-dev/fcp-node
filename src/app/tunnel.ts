// UDP reactor + local TCP proxy. Port shape of apps/cli (reactor) and
// src/proxy/proxy_engine.{h,cc}: one local TCP connection = one FCP session
// = one target, all sessions sharing a single UDP 5-tuple and keyed by salt.

import { createSocket, type Socket as UdpSocket, type RemoteInfo } from 'node:dgram';
import { createServer, connect, isIP, type Socket as TcpSocket, type Server as TcpServer } from 'node:net';
import { randomBytes } from 'node:crypto';
import {
  SALT_LEN, Direction, HandshakeRole, DEFAULT_MTU_MIN, DEFAULT_D, DEFAULT_P,
  OPEN_MAX_BYTES, ATYP_DOMAIN, ATYP_IPV4, DATA_WIRE_OVERHEAD, NONCE_LIMIT,
  MUX_MAX_STREAMS, MUX_SESSION_POOL,
} from '../constants.ts';
import { Session, type SessionConfig } from '../session/session.ts';
import { Stream, type StreamCallbacks } from '../stream/stream.ts';
import { sealReset } from '../crypto/envelope.ts';
import {
  detectEntry, socks5ParseGreeting, socks5GreetingReply, socks5ParseRequest,
  socks5Reply, socks5RepForOpenError, Socks5Rep,
  httpParseConnect, httpParseForward,
  HTTP_OK, HTTP_BAD_REQUEST, HTTP_BAD_GATEWAY, HTTP_METHOD_NOT_ALLOWED,
  HTTP_HEAD_TOO_LARGE, HTTP_FORWARD_METHOD_NOT_ALLOWED,
  openWriteRequest, openWriteOk, openWriteErr, openParseRequest, openParseReply,
  targetText, type ProxyTarget, type ParseResult,
} from '../proxy/codec.ts';
import { OpenError } from '../constants.ts';
import { createTraceSink, type TraceSink } from '../util/trace.ts';

const TICK_MS = 10;
/** Stats line cadence: fast enough for a live graph, slow enough not to spam. */
const STATS_PERIOD_MS = 500;

export interface TunnelOptions {
  psk: Buffer;
  host?: string; port?: number;
  listenHost?: string; listenPort?: number;
  /** PMTUD floor: the probe walk starts here (and stays here with --no-pmtud). */
  mtu?: number;
  /** PMTUD ceiling: the walk never goes above this. */
  pmtuMaxMtu?: number;
  d?: number; p?: number;
  pinnedK?: number;
  ack_v2?: boolean; pmtud?: boolean; keyUpdate?: boolean;
  log?: (line: string) => void;
  /**
   * Machine-readable one-line counters, emitted every 500 ms on the wire side
   * regardless of --log-level. The desktop shell parses these to draw the
   * throughput graph; keeping them out of `log` is deliberate, because a
   * `--log-level=error` tunnel must still report what it moved.
   * Shape: `stats <uptime>s live=N up=N tunnels=N tx=NB rx=NB tx_rate=B/s
   * rx_rate=B/s`.
   */
  onStats?: (line: string) => void;
  /** Verbose per-datagram / per-connection trace, enabled by --log-level=debug. */
  debugLog?: (line: string) => void;
  tracePrefix?: string;
}

interface Binding {
  session: Session;
  /** M1: per-sid tunnels on a multiplexed session (server side). */
  sidTunnels?: Map<number, ServerTunnel>;
  /** Latest authenticated peer address. Mutable on purpose: sendWire reads it
   *  on every datagram, so a NAT rebinding mid-session is followed instead of
   *  starving the tunnel for 135 s. */
  addr?: { host: string; port: number };
  cleanup: () => void;
  trace?: TraceSink;
}

/** M1: the session every eligible local connection multiplexes onto. */
interface SharedClientSession {
  session: Session;
  key: string;
  sids: Set<number>;
  /** Attached connections riding this session, keyed by sid. */
  streams: Map<number, ConnStreamState>;
  trace?: TraceSink;
}
/** Client-side state of one attached connection (freed on stream close). */
interface ConnStreamState {
  sock: TcpSocket;
  kill: (reason: string) => void;
}

/** Per-IP session creation budget: a browser page load opens dozens of local
 *  TCP connections (one FCP session each), so the cap must sit far above that
 *  while still cutting a garbage-flood's allocation churn to noise. */
const MAX_NEW_SESSIONS_PER_IP = 64;
const RATE_WINDOW_MS = 1000;
/** Bound the bookkeeping maps: a spoofed-source flood must not grow them. */
const RATE_MAP_MAX = 4096;

function nowMs(): number { return Date.now(); }

/**
 * Socket buffer sizing. Node leaves SO_RCVBUF at the OS default — 64 KiB on
 * Windows — which is far below the 256 KiB send window, so a sender that fills
 * the window in one synchronous loop has most of the burst dropped by the
 * kernel before the application ever sees it. Measured on loopback with plain
 * dgram: 400 back-to-back 1400 B datagrams delivered 47 with the default
 * buffer (88.3% loss) and 400/400 with 4 MiB. The loss arrives as stream holes,
 * which collapse the advertised window and cap throughput near 200 KB/s.
 *
 * `setRecvBufferSize` throws ENOTSOCK before bind on Windows, so this has to
 * run from the bind callback.
 */
const UDP_BUFFER_BYTES = 4 * 1024 * 1024;
/** Cap on live sessions on the server. Every local TCP connection owns one and
 *  a peer that disappears is reaped by peer_dead, but a PSK holder can still
 *  open more than the process should carry. */
const MAX_TUNNEL_SESSIONS = 1024;

function enlargeUdpBuffers(sock: UdpSocket, dbg: (line: string) => void, log: (line: string) => void): void {
  for (const which of ['recv', 'send'] as const) {
    try {
      if (which === 'recv') sock.setRecvBufferSize(UDP_BUFFER_BYTES);
      else sock.setSendBufferSize(UDP_BUFFER_BYTES);
    } catch (e) {
      // Not fatal: the tunnel keeps working with the default profile.
      log(`WRN udp ${which} buffer not enlarged (${(e as Error).message}); expect burst loss`);
    }
  }
  dbg(`udp buffers recv=${sock.getRecvBufferSize()} send=${sock.getSendBufferSize()}`);
}

/**
 * One JSONL file per session, named from the prefix. The sink never throws:
 * a trace that cannot be written disables itself and logs one warning, so a
 * mistyped --trace path cannot kill a session (or the server) on handshake.
 */
function sessionTrace(opts: TunnelOptions, role: 'client' | 'server', key: string): TraceSink | undefined {
  const prefix = opts.tracePrefix;
  if (!prefix) return undefined;
  return createTraceSink(`${prefix}-${role}-${key}.jsonl`, {
    onProblem: (m) => opts.log?.(`WRN ${m}`),
  });
}

/** Accumulates the first bytes of a tunnel stream until one OPEN message is parsed. */
class PrefixParser<T> {
  private buf = Buffer.alloc(0);
  private parse: (b: Buffer) => ParseResult<T>;
  done = false;
  result: ParseResult<T> | null = null;
  constructor(parse: (b: Buffer) => ParseResult<T>) { this.parse = parse; }
  push(chunk: Buffer): Buffer {
    if (this.done) return chunk;
    this.buf = this.buf.length ? Buffer.concat([this.buf, chunk]) : chunk;
    const r = this.parse(this.buf);
    if (r.status === 'need_more') return Buffer.alloc(0);
    this.result = r;
    this.done = true;
    if (r.status !== 'ok') { this.buf = Buffer.alloc(0); return Buffer.alloc(0); }
    const rest = Buffer.from(this.buf.subarray(r.consumed));
    this.buf = Buffer.alloc(0);
    return rest;
  }
}

function dialHost(t: ProxyTarget): string {
  if (t.atyp === ATYP_DOMAIN) return t.addr.toString('latin1');
  if (t.atyp === ATYP_IPV4) return [...t.addr].join('.');
  const hex = Buffer.from(t.addr).toString('hex');
  return (hex.match(/.{1,4}/g) ?? []).join(':');
}

// ---------------------------------------------------------------------------
// Client: local SOCKS5 / HTTP CONNECT / absolute-form HTTP -> FCP UDP tunnel
// ---------------------------------------------------------------------------

export class TunnelClient {
  private udp: UdpSocket;
  private tcp: TcpServer;
  private sessions = new Map<string, Binding>();
  /** M1: eligible local connections multiplex onto up to MUX_SESSION_POOL
   *  shared sessions, assigned round-robin — each session is an independent
   *  window and an independent loss/NAT domain, so concurrent streams
   *  aggregate their throughput instead of queueing behind one window. */
  private pool: SharedClientSession[] = [];
  private poolNext = 0;
  private timer: NodeJS.Timeout | null = null;
  private statsTimer: NodeJS.Timeout | null = null;
  private opts: TunnelOptions;
  private running = false;
  private log: (line: string) => void;
  private dbg: (line: string) => void;
  // Wire-side totals for the stats line. Counted before any decrypt/parse: the
  // graph is about what the socket carried, not what the stream accepted.
  private bytesTx = 0;
  private bytesRx = 0;
  private statsPrevTx = 0;
  private statsPrevRx = 0;
  private statsPrevMs = 0;
  private startedMs = 0;
  /** One reset per second for unknown salts: the reply is cheap, but an
   *  unrelated flood must not turn the client into a packet reflector. */
  private lastResetMs = 0;

  constructor(opts: TunnelOptions) {
    this.opts = opts;
    this.log = opts.log ?? (() => {});
    this.dbg = opts.debugLog ?? (() => {});
    this.udp = createSocket('udp4');
    // allowHalfOpen is load-bearing: with the default (false), a local app that
    // half-closes after its upload (request body, "POST + read the response")
    // makes Node auto-end the proxy socket the moment the app's FIN lands, the
    // app sees EOF at once, closes fully, and the abort path RSTs the tunnel —
    // the response never crosses. The endPending/flushPending machinery below
    // owns the FIN instead: queue the close until the backlog has drained.
    this.tcp = createServer({ allowHalfOpen: true }, (sock) => this.onLocalConnection(sock));
    this.udp.on('message', (msg, rinfo) => this.onUdp(msg, rinfo));
    this.udp.on('error', (e) => this.log(`udp error: ${e.message}`));
    this.tcp.on('error', (e) => this.log(`tcp error: ${e.message}`));
  }

  async start(): Promise<void> {
    if (this.running) return;
    const port = this.opts.port ?? 4460;
    const host = this.opts.host ?? '127.0.0.1';
    await new Promise<void>((resolve, reject) => {
      const onErr = (e: Error) => reject(e);
      this.udp.once('error', onErr);
      this.udp.bind(0, () => {
        this.udp.off('error', onErr);
        enlargeUdpBuffers(this.udp, this.dbg, this.log);
        resolve();
      });
    });
    await new Promise<void>((resolve, reject) => {
      const onErr = (e: Error) => reject(e);
      this.tcp.once('error', onErr);
      this.tcp.listen(this.opts.listenPort ?? 1080, this.opts.listenHost ?? '127.0.0.1', () => {
        this.tcp.off('error', onErr); resolve();
      });
    });
    this.running = true;
    this.timer = setInterval(() => this.tick(), TICK_MS);
    this.startedMs = nowMs();
    this.statsPrevMs = this.startedMs;
    if (this.opts.onStats) {
      this.statsTimer = setInterval(() => this.emitStats(), STATS_PERIOD_MS);
    }
    this.log(`client: proxy 127.0.0.1:${this.opts.listenPort ?? 1080} -> udp ${host}:${port}`);
  }

  stop(): void {
    this.running = false;
    if (this.timer) clearInterval(this.timer);
    if (this.statsTimer) { clearInterval(this.statsTimer); this.statsTimer = null; }
    for (const b of this.sessions.values()) { b.cleanup(); b.trace?.close(); }
    this.sessions.clear();
    this.tcp.close();
    this.udp.close();
  }

  get sessionCount(): number { return this.sessions.size; }

  /** Wire-side byte totals since start(); the desktop shell reads these too. */
  get counters(): { tx: number; rx: number; sessions: number; uptimeMs: number } {
    return {
      tx: this.bytesTx,
      rx: this.bytesRx,
      sessions: this.sessions.size,
      uptimeMs: this.startedMs === 0 ? 0 : nowMs() - this.startedMs,
    };
  }

  /** M1: create one pool session. Callers attach connections round-robin; a
   *  session whose negotiation turns out legacy is skipped by the attach
   *  policy and its connections fall back to per-conn sessions. */
  private ensurePoolEntry(): SharedClientSession {
    const salt = randomBytes(SALT_LEN);
    const key = salt.toString('hex');
    const trace = sessionTrace(this.opts, 'client', key);
    const cfg: SessionConfig = {
      psk: this.opts.psk, salt,
      sendDirection: Direction.C2S, recvDirection: Direction.S2C,
      role: HandshakeRole.Client,
      d: this.opts.d ?? DEFAULT_D, p: this.opts.p ?? DEFAULT_P,
      mtu: this.opts.mtu ?? DEFAULT_MTU_MIN,
      pmtuMaxMtu: this.opts.pmtuMaxMtu,
      pinnedK: this.opts.pinnedK,
      ack_v2: this.opts.ack_v2, pmtud: this.opts.pmtud, keyUpdate: this.opts.keyUpdate,
      trace: trace?.write,
    };
    const entry: SharedClientSession = {
      session: null as unknown as Session, key, sids: new Set(), streams: new Map(), trace,
    };
    const session = new Session(cfg, {
      sendWire: (wire) => {
        if (!this.running) return;
        this.dbg(`[${key.slice(0, 8)}] udp tx ${wire.length}B -> ${this.opts.host ?? '127.0.0.1'}:${this.opts.port ?? 4460}`);
        this.bytesTx += wire.length;
        this.udp.send(wire, this.opts.port ?? 4460, this.opts.host ?? '127.0.0.1');
      },
      // Sid streams deliver through the StreamHost; the default stream carries
      // no connection on a pooled session.
      read: () => {},
      closed: () => {
        // Session-level death (peer_dead, reset, handshake failure): every
        // attached connection goes down with it.
        for (const st of entry.streams.values()) st.kill('pool session closed');
        entry.streams.clear();
        this.pool = this.pool.filter((p) => p.key !== key);
      },
      eof: () => {},
      streamHost: {
        // The client opens every stream itself; nothing inbound to accept.
        inboundStream: () => null,
        streamClosed: (sid) => {
          entry.sids.delete(sid);
          entry.streams.delete(sid);
        },
      },
      log: this.log,
      debug: this.dbg,
    });
    entry.session = session;
    if (!session.start(nowMs())) { trace?.close(); throw new Error('pool session start failed'); }
    this.dbg(`[${key.slice(0, 8)}] pool session+ (${this.pool.length + 1}/${MUX_SESSION_POOL}, mux pending negotiation)`);
    this.pool.push(entry);
    this.sessions.set(key, {
      session,
      cleanup: () => {
        for (const st of entry.streams.values()) st.kill('session closed');
        entry.streams.clear();
        this.pool = this.pool.filter((p) => p.key !== key);
      },
      trace,
    });
    session.onTick(nowMs());
    return entry;
  }


  /** M1: attach a local connection round-robin across the session pool.
   *  Returns null when the caller must build a per-conn session instead
   *  (legacy negotiation detected, or the round-robin session is full). The
   *  Stream comes back immediately when the session is already established;
   *  otherwise sendOpen allocates it once the handshake lands. */
  private tryAttachPool(sock: TcpSocket, callbacks: StreamCallbacks, kill: (reason: string) => void): { session: Session; entry: SharedClientSession; sid: number; stream: Stream | null } | null {
    // Legacy gate: if ANY established pool session negotiated without mux,
    // this peer speaks the single-stream wire — per-conn sessions for all.
    for (const p of this.pool) {
      if (p.session.established && !p.session.muxActive) return null;
    }
    // Grow the pool toward the cap on the first MUX_SESSION_POOL attaches so
    // even a simultaneous burst disperses across sessions deterministically.
    const want = Math.min(MUX_SESSION_POOL, this.poolNext + 1);
    while (this.pool.length < want) this.ensurePoolEntry();
    const entry = this.pool[this.poolNext % this.pool.length];
    ++this.poolNext;
    if (entry.session.established && !entry.session.muxActive) return null;
    if (entry.sids.size >= MUX_MAX_STREAMS) return null;
    let sid = 0;
    for (let i = 1; i <= MUX_MAX_STREAMS; ++i) if (!entry.sids.has(i)) { sid = i; break; }
    if (sid === 0) return null;
    entry.sids.add(sid);
    entry.streams.set(sid, { sock, kill });
    const stream = entry.session.established && entry.session.muxActive
      ? entry.session.openStream(sid, callbacks)
      : null;
    if (stream === null && entry.session.established) {
      // Established sessions must be able to open a reserved sid; failing here
      // would strand the connection.
      entry.sids.delete(sid);
      entry.streams.delete(sid);
      return null;
    }
    return { session: entry.session, entry, sid, stream };
  }

  private releasePoolSid(entry: SharedClientSession, sid: number): void {
    entry.sids.delete(sid);
    entry.streams.delete(sid);
  }


  private emitStats(): void {
    const now = nowMs();
    const dt = Math.max(1, now - this.statsPrevMs) / 1000;
    const txRate = Math.round((this.bytesTx - this.statsPrevTx) / dt);
    const rxRate = Math.round((this.bytesRx - this.statsPrevRx) / dt);
    let up = 0;
    for (const b of this.sessions.values()) if (b.session.established) up += 1;
    const uptime = ((now - this.startedMs) / 1000).toFixed(1);
    this.opts.onStats?.(
      `stats ${uptime}s live=${this.sessions.size} up=${up} tunnels=${this.sessions.size} ` +
        `tx=${this.bytesTx}B rx=${this.bytesRx}B tx_rate=${txRate}B/s rx_rate=${rxRate}B/s`,
    );
    this.statsPrevTx = this.bytesTx;
    this.statsPrevRx = this.bytesRx;
    this.statsPrevMs = now;
  }

  private onUdp(msg: Buffer, rinfo: RemoteInfo): void {
    if (msg.length < SALT_LEN) return;
    this.bytesRx += msg.length;
    const salt = msg.subarray(0, SALT_LEN).toString('hex');
    this.dbg(`[${salt.slice(0, 8)}] udp rx ${msg.length}B known=${this.sessions.has(salt)}`);
    const b = this.sessions.get(salt);
    if (b) { b.session.onWire(msg, nowMs()); return; }
    this.resetUnknownSalt(msg, rinfo);
  }

  /**
   * A peer that still holds a session we no longer have keeps sending data we
   * cannot authenticate. Without an answer it can only notice via its 135 s
   * peer_dead clock; a stateless reset closes it immediately. Building the
   * reset directly (no Session) keeps this path allocation-free enough for a
   * spoofed flood, and the source check + 1 Hz cap keep it from reflecting.
   */
  private resetUnknownSalt(msg: Buffer, rinfo: RemoteInfo): void {
    if (msg.length < DATA_WIRE_OVERHEAD) return;
    const port = this.opts.port ?? 4460;
    if (rinfo.port !== port) return;
    const host = this.opts.host ?? '127.0.0.1';
    if (isIP(host) !== 0 && rinfo.address !== host) return;
    const now = nowMs();
    if (now - this.lastResetMs < 1000) return;
    const salt = msg.subarray(0, SALT_LEN);
    const counter = NONCE_LIMIT - 1n - BigInt(randomBytes(2).readUInt16LE(0));
    const reset = sealReset(this.opts.psk, salt, Direction.C2S, Direction.S2C, counter);
    if (!reset) return;
    this.lastResetMs = now;
    this.dbg(`[${salt.toString('hex').slice(0, 8)}] unknown salt -> stateless reset tx ${reset.length}B`);
    this.udp.send(reset, rinfo.port, rinfo.address);
  }

  private tick(): void {
    const now = nowMs();
    for (const [key, b] of [...this.sessions]) {
      b.session.onTick(now);
      if (b.session.established && now % 2000 < TICK_MS) {
        const st = b.session.stats();
        this.dbg(`stats inflight=${b.session.inflightBytes}B rwnd=${b.session.peerWindowBytes}B ` +
          `queued=${b.session.queuedBytes}B retx=${b.session.segsRetransmitted}/${b.session.segsSent} ` +
          `retxSplit=${b.session.retxSplit} k=${st.k} loss=${(b.session.fecLoss * 100).toFixed(1)}% srtt=${st.srttMs}ms ` +
          `sendBw=${(b.session.sendRateBytesPerMs * 1000 / 1048576).toFixed(2)}MB/s ` +
          `recvNext=${b.session.recvNext} ` +
          `reorder=${b.session.reorderBytes}B delivPending=${b.session.recvPendingBytes}B`);
      }
      // Session-level isClosed only: on a shared mux session the default
      // stream may idle out while sid streams live — that must not tear the
      // session down (the default stream's close callback already guards).
      if (b.session.isClosed) { this.sessions.delete(key); b.cleanup(); b.trace?.close(); }
    }
  }

  private onLocalConnection(sock: TcpSocket): void {
    sock.setNoDelay(true);
    this.dbg(`local conn accepted ${sock.remoteAddress ?? '?'}:${sock.remotePort ?? 0}`);
    let entryBuf = Buffer.alloc(0);
    let entryKind: 'socks5' | 'connect' | 'forward' | '' = '';
    let socksGreeted = false;
    let target: ProxyTarget | null = null;
    let firstPayload: Buffer | null = null;
    let opened = false;
    let dead = false;
    let session: Session | null = null;
    let saltKey = '';
    let handshakeWait: NodeJS.Timeout | null = null;
    let endPending = false;
    let streamRead: (b: Buffer) => void = () => {};
    // M1: attached-shared connections write through their sid stream;
    // per-conn sessions write through the session's default stream.
    let connStream: Stream | null = null;
    let attachedShared = false;
    let attachedEntry: SharedClientSession | null = null;
    let connSid = 0;
    let writeConn: (b: Buffer) => number = () => 0;
    let consumedConn: (n: number) => void = () => {};
    let closeWriteConn: () => void = () => {};
    let rstConn: () => void = () => {};
    let connClosedNow = (): boolean => true;
    const pendingLocal: Buffer[] = [];
    let pendingLocalBytes = 0;
    let localPaused = false;
    let drainTimer: NodeJS.Timeout | null = null;
    const replyParser = new PrefixParser(openParseReply);

    const killConn = (reason: string) => {
      if (dead) return;
      dead = true;
      this.dbg(`[${saltKey.slice(0, 8)}] local conn killed: ${reason}`);
      sock.destroy();
    };

    // The per-sid Stream and the legacy default stream share one callback
    // shape; makeStream overrides send/closed, the rest lands here.
    const streamCallbacks: StreamCallbacks = {
      send: () => {},
      read: (b: Buffer) => streamRead(b),
      closed: (reason: string) => {
        if (!dead) { dead = true; sock.destroy(); }
      },
      eof: () => { if (!sock.destroyed) sock.end(); },
    };

    const destroy = (buf?: Buffer) => {
      if (dead) return;
      dead = true; // no second reply, no further data handling while the 30 ms drain runs
      if (buf && !sock.destroyed) sock.write(buf);
      setTimeout(() => sock.destroy(), 30);
    };

    // Before OPEN completes, bytes from the local app cannot enter the stream
    // at all. Queue them, but pause the socket once the backlog is a whole
    // window: a black-holed handshake used to accumulate this without bound.
    const LOCAL_BACKLOG_LIMIT = 1 << 20;
    const queueLocal = (b: Buffer) => {
      pendingLocal.push(Buffer.from(b));
      pendingLocalBytes += b.length;
      if (!localPaused && pendingLocalBytes >= LOCAL_BACKLOG_LIMIT && !sock.destroyed) {
        localPaused = true;
        sock.pause();
      }
    };

    // Same rule as the server side: a short `Stream.write` leaves a remainder
    // behind, and the FIN must not overtake it.
    const flushPending = () => {
      while (pendingLocal.length && session) {
        const b = pendingLocal[0];
        const n = writeConn(b);
        if (n <= 0) break;
        pendingLocalBytes -= n;
        if (n < b.length) { pendingLocal[0] = b.subarray(n); break; }
        pendingLocal.shift();
      }
      if (localPaused && !pendingLocal.length && !sock.destroyed) {
        localPaused = false;
        sock.resume();
      }
      if (session && !pendingLocal.length && endPending) {
        endPending = false;
        closeWriteConn();
      }
      // Whatever the write window still holds continues on the tick; without a
      // timer it waited for another local data event, which may never come.
      if (pendingLocal.length && !drainTimer) {
        drainTimer = setInterval(() => {
          flushPending();
          if (!pendingLocal.length || dead) {
            if (drainTimer) clearInterval(drainTimer);
            drainTimer = null;
          }
        }, TICK_MS);
      }
    };

    const sendOpen = () => {
      if (!session || !target || opened || dead) return;
      if (!session.established) {
        handshakeWait = setTimeout(sendOpen, 20);
        return;
      }
      if (handshakeWait) { clearTimeout(handshakeWait); handshakeWait = null; }
      if (attachedShared && !connStream) {
        // The handshake just landed and negotiated multiplexing: allocate this
        // connection's sid stream before any byte flows.
        connStream = session.openStream(connSid, streamCallbacks);
        if (!connStream) { destroy(); return; }
        writeConn = (b) => connStream!.write(b, nowMs());
        consumedConn = (n) => connStream!.consumed(n);
        closeWriteConn = () => connStream!.closeWrite(nowMs());
        rstConn = () => connStream!.sendRst();
        connClosedNow = () => connStream!.isClosed;
      }
      const open = openWriteRequest(target);
      if (!open) { destroy(); return; }
      opened = true;
      this.dbg(`[${saltKey.slice(0, 8)}] OPEN tx ${open.length}B -> ${targetText(target)} (sid ${attachedShared ? connSid : 0})`);
      // Queue rather than write: a short Stream.write must keep its remainder,
      // and the first payload may not overtake the OPEN.
      queueLocal(open);
      if (firstPayload && firstPayload.length) queueLocal(firstPayload);
      flushPending();
      this.log(`open sent -> ${targetText(target)}`);
    };

    streamRead = (bytes: Buffer) => {
      // Consumption is what releases the peer's send window. Doing it only
      // after the local socket has flushed applies real backpressure; the old
      // immediate consumed() let a slow reader grow Node's writable buffer
      // without bound.
      const writeAndConsume = (b: Buffer, len: number) => {
        if (sock.destroyed || b.length === 0) { consumedConn(len); return; }
        sock.write(b, () => consumedConn(len));
      };
      if (replyParser.done) {
        this.dbg(`[${saltKey.slice(0, 8)}] tunnel->local ${bytes.length}B`);
        writeAndConsume(bytes, bytes.length);
        return;
      }
      const rest = replyParser.push(bytes);
      if (!replyParser.done) { consumedConn(bytes.length); return; }
      const r = replyParser.result;
      if (!r || r.status !== 'ok' || !r.value) { consumedConn(bytes.length); destroy(); return; }
      this.dbg(`[${saltKey.slice(0, 8)}] OPEN reply rx ok=${r.value.ok} err=${r.value.ok ? 0 : r.value.err} kind=${entryKind}`);
      if (!r.value.ok) {
        const rep = socks5RepForOpenError(r.value.err);
        consumedConn(bytes.length);
        destroy(entryKind === 'socks5' ? socks5Reply(rep) : HTTP_BAD_GATEWAY);
        return;
      }
      if (entryKind === 'socks5') sock.write(socks5Reply(Socks5Rep.Succeeded));
      else if (entryKind === 'connect') sock.write(HTTP_OK);
      if (rest.length) writeAndConsume(rest, bytes.length);
      else consumedConn(bytes.length);
      flushPending();
    };

    /** M1: attach round-robin across the session pool (each session an
     *  independent window and loss domain); fall back to a per-conn session
     *  for old peers or an exhausted pool. */
    const openTunnel = (): void => {
      const attached = this.tryAttachPool(sock, streamCallbacks, killConn);
      if (attached) {
        session = attached.session;
        attachedEntry = attached.entry;
        saltKey = attached.entry.key;
        connSid = attached.sid;
        connStream = attached.stream;
        attachedShared = true;
        if (connStream) {
          writeConn = (b) => connStream!.write(b, nowMs());
          consumedConn = (n) => connStream!.consumed(n);
          closeWriteConn = () => connStream!.closeWrite(nowMs());
          rstConn = () => connStream!.sendRst();
          connClosedNow = () => connStream!.isClosed;
        }
        this.dbg(`[${saltKey.slice(0, 8)}] session+ (shared${attached.stream ? ' established' : ', awaiting handshake'}) local conn -> ${targetText(target)}`);
        session.onTick(nowMs());
        sendOpen();
        return;
      }
      createOwnSession();
      sendOpen();
    };

    const createOwnSession = (): void => {
      const salt = randomBytes(SALT_LEN);
      saltKey = salt.toString('hex');
      const trace = sessionTrace(this.opts, 'client', saltKey);
      const cfg: SessionConfig = {
        psk: this.opts.psk, salt,
        sendDirection: Direction.C2S, recvDirection: Direction.S2C,
        role: HandshakeRole.Client,
        d: this.opts.d ?? DEFAULT_D, p: this.opts.p ?? DEFAULT_P,
        mtu: this.opts.mtu ?? DEFAULT_MTU_MIN,
        pmtuMaxMtu: this.opts.pmtuMaxMtu,
        pinnedK: this.opts.pinnedK,
        ack_v2: this.opts.ack_v2, pmtud: this.opts.pmtud, keyUpdate: this.opts.keyUpdate,
        trace: trace?.write,
      };
      session = new Session(cfg, {
        sendWire: (wire) => {
          if (!this.running) return;
          this.dbg(`[${saltKey.slice(0, 8)}] udp tx ${wire.length}B -> ${this.opts.host ?? '127.0.0.1'}:${this.opts.port ?? 4460}`);
          this.bytesTx += wire.length;
          this.udp.send(wire, this.opts.port ?? 4460, this.opts.host ?? '127.0.0.1');
        },
        read: (b) => streamRead(b),
        closed: () => { if (!dead) { dead = true; sock.destroy(); } },
        eof: () => { if (!sock.destroyed) sock.end(); },
        log: this.log,
        debug: this.dbg,
      });
      if (!session.start(nowMs())) { destroy(); return; }
      this.dbg(`[${saltKey.slice(0, 8)}] session+ local conn -> ${target ? targetText(target) : '?'}`);
      this.sessions.set(saltKey, {
        session, cleanup: () => { dead = true; sock.destroy(); }, trace,
      });
      writeConn = (b) => session!.write(b);
      consumedConn = (n) => session!.consumed(n);
      closeWriteConn = () => session!.closeWrite();
      rstConn = () => session!.streamRef.sendRst();
      connClosedNow = () => session!.streamRef.isClosed;
      session.onTick(nowMs());
    };

    const parseEntry = (): void => {
      const kind = detectEntry(entryBuf);
      if (kind === 'need_more') return;
      if (kind === 'unknown') { destroy(); return; }
      entryKind = kind;
      this.dbg(`entry detected kind=${kind} bytes=${entryBuf.length}`);
      if (kind === 'socks5') {
        if (!socksGreeted) {
          const g = socks5ParseGreeting(entryBuf);
          if (g.status === 'need_more') return;
          if (g.status !== 'ok' || !g.value?.noAuth) { destroy(); return; }
          entryBuf = entryBuf.subarray(g.consumed);
          sock.write(socks5GreetingReply(true));
          socksGreeted = true;
          if (!entryBuf.length) return;
        }
        const r = socks5ParseRequest(entryBuf);
        if (r.status === 'need_more') return;
        if (r.status !== 'ok' || !r.value) {
          destroy(socks5Reply(r.status === 'command_not_supported'
            ? Socks5Rep.CommandNotSupported : Socks5Rep.GeneralFailure));
          return;
        }
        target = r.value; firstPayload = entryBuf.subarray(r.consumed);
        entryBuf = Buffer.alloc(0);
      } else if (kind === 'connect') {
        const r = httpParseConnect(entryBuf);
        if (r.status === 'need_more') return;
        if (r.status !== 'ok' || !r.value) {
          destroy(r.status === 'head_too_large' ? HTTP_HEAD_TOO_LARGE :
            r.status === 'method_not_allowed' ? HTTP_METHOD_NOT_ALLOWED : HTTP_BAD_REQUEST);
          return;
        }
        target = r.value; firstPayload = entryBuf.subarray(r.consumed);
        entryBuf = Buffer.alloc(0);
      } else {
        const r = httpParseForward(entryBuf);
        if (r.status === 'need_more') return;
        if (r.status !== 'ok' || !r.value) {
          destroy(r.status === 'head_too_large' ? HTTP_HEAD_TOO_LARGE :
            r.status === 'method_not_allowed' ? HTTP_FORWARD_METHOD_NOT_ALLOWED : HTTP_BAD_REQUEST);
          return;
        }
        target = r.value.target;
        firstPayload = Buffer.concat([r.value.rewrittenHead, entryBuf.subarray(r.consumed)]);
        entryBuf = Buffer.alloc(0);
      }
      openTunnel();
    };

    sock.on('data', (chunk: Buffer) => {
      if (dead) return;
      if (!target) {
        entryBuf = entryBuf.length ? Buffer.concat([entryBuf, chunk]) : chunk;
        if (entryBuf.length > 16384) { destroy(HTTP_HEAD_TOO_LARGE); return; }
        parseEntry();
        return;
      }
      this.dbg(`[${saltKey.slice(0, 8)}] local rx ${chunk.length}B opened=${opened}`);
      // A non-empty pendingLocal means an earlier short write is still waiting
      // for the window; writing this chunk straight into the stream would
      // overtake it and reorder the tunnel byte stream. Queue and drain FIFO.
      if (!opened || !session || pendingLocal.length) {
        queueLocal(chunk);
        if (session) flushPending();
        return;
      }
      const n = writeConn(chunk);
      this.dbg(`[${saltKey.slice(0, 8)}] local->tunnel ${n}/${chunk.length}B`);
      if (n < chunk.length) {
        // Keep the remainder ahead of anything that arrives next; the stream's
        // send window releases it on later ticks/ACKs.
        queueLocal(chunk.subarray(n));
        flushPending();
      }
    });
    sock.on('end', () => {
      endPending = true;
      if (session) flushPending();
    });
    sock.on('error', () => {});
    sock.on('close', () => {
      dead = true;
      if (handshakeWait) clearTimeout(handshakeWait);
      if (drainTimer) { clearInterval(drainTimer); drainTimer = null; }
      if (attachedShared) {
        // The sid frees itself via the stream's closed callback
        // (host.streamClosed). Tell the peer now so its target drains instead
        // of pushing a window into a socket nobody reads.
        if (session && session.established && !connClosedNow()) rstConn();
        else if (attachedEntry) this.releasePoolSid(attachedEntry, connSid);
        return;
      }
      if (saltKey) {
        const b = this.sessions.get(saltKey);
        if (b) {
          // The local app is gone mid-stream (curl --max-time, tab closed, app
          // killed): tell the peer now instead of letting it discover this by
          // accident. A graceful close has already finished the stream, so this
          // only fires on an abort. Without it the peer keeps pushing the rest
          // of its window into a socket nobody reads, and every datagram it
          // sends is answered with a stateless reset — which used to be ignored
          // for 135 s while it retransmitted (544 KB, 1000+ RTO copies).
          if (b.session.established && !b.session.streamRef.isClosed) b.session.streamRef.sendRst();
          this.sessions.delete(saltKey); b.cleanup(); b.trace?.close();
        }
      }
    });
  }
}

// ---------------------------------------------------------------------------
// Server: FCP UDP tunnel -> target TCP
// ---------------------------------------------------------------------------

interface ServerTunnel {
  key: string;
  addr: { host: string; port: number };
  /** The stream this tunnel rides: the session default (sid 0) or a mux sid
   *  stream. Every write/consume/closeWrite goes through it. */
  stream: Stream;
  /** M1 sid this tunnel serves (0 = the session's default tunnel). */
  sid: number;
  parser: PrefixParser<ProxyTarget>;
  targetSock: TcpSocket | null;
  openDone: boolean;
  /** OPEN_OK already crossed the tunnel: an OPEN_ERR frame would then be read
   *  by the client as response bytes, not as a reply. */
  openOkSent: boolean;
  pendingToTarget: Buffer[];
  /** target -> tunnel backlog: bytes the send window could not take yet. */
  pendingToTunnel: Buffer[];
  /** Target hit EOF; the FIN may only go out once the backlog is drained. */
  endFromTarget: boolean;
  paused: boolean;
  pumping: boolean;
  cleanup: () => void;
  writeBuf: (b: Buffer) => number;
  consumeBuf: (n: number) => void;
  closeWriteBuf: () => void;
  callbacks: () => StreamCallbacks;
  trace?: TraceSink;
}

export class TunnelServer {
  private udp: UdpSocket;
  private sessions = new Map<string, Binding>();
  private tunnels = new Map<string, ServerTunnel>();
  private timer: NodeJS.Timeout | null = null;
  private opts: TunnelOptions;
  private running = false;
  private log: (line: string) => void;
  private dbg: (line: string) => void;
  private newSessionsByIp = new Map<string, { count: number; windowStart: number }>();
  private resetReplyByIp = new Map<string, number>();

  constructor(opts: TunnelOptions) {
    this.opts = opts;
    this.log = opts.log ?? (() => {});
    this.dbg = opts.debugLog ?? (() => {});
    this.udp = createSocket('udp4');
    this.udp.on('message', (msg, rinfo) => this.onUdp(msg, rinfo));
    this.udp.on('error', (e) => this.log(`udp error: ${e.message}`));
  }

  async start(): Promise<void> {
    if (this.running) return;
    await new Promise<void>((resolve, reject) => {
      const onErr = (e: Error) => reject(e);
      this.udp.once('error', onErr);
      this.udp.bind(this.opts.port ?? 4460, this.opts.listenHost ?? '0.0.0.0', () => {
        this.udp.off('error', onErr);
        enlargeUdpBuffers(this.udp, this.dbg, this.log);
        resolve();
      });
    });
    this.running = true;
    this.timer = setInterval(() => this.tick(), TICK_MS);
    this.log(`server: udp 0.0.0.0:${this.opts.port ?? 4460}`);
  }

  stop(): void {
    this.running = false;
    if (this.timer) clearInterval(this.timer);
    for (const b of this.sessions.values()) { b.cleanup(); b.trace?.close(); }
    this.sessions.clear();
    this.tunnels.clear();
    this.udp.close();
  }

  get sessionCount(): number { return this.sessions.size; }

  /** S5: per-IP session creation budget. A garbage flood used to pay only
   *  allocation churn per datagram; now it pays at most 64 new sessions per
   *  second per source IP. */
  private allowNewSession(ip: string, now: number): boolean {
    if (this.newSessionsByIp.size > RATE_MAP_MAX) this.pruneRateMaps(now);
    const entry = this.newSessionsByIp.get(ip);
    if (!entry || now - entry.windowStart >= RATE_WINDOW_MS) {
      this.newSessionsByIp.set(ip, { count: 1, windowStart: now });
      return true;
    }
    if (entry.count >= MAX_NEW_SESSIONS_PER_IP) return false;
    entry.count += 1;
    return true;
  }

  /** S5: stateless reset replies at 1 Hz per peer IP — the same reflector
   *  guard the client side already had. */
  private allowResetReply(ip: string, now: number): boolean {
    if (this.resetReplyByIp.size > RATE_MAP_MAX) this.pruneRateMaps(now);
    const last = this.resetReplyByIp.get(ip);
    if (last !== undefined && now - last < RATE_WINDOW_MS) return false;
    this.resetReplyByIp.set(ip, now);
    return true;
  }

  private pruneRateMaps(now: number): void {
    for (const [ip, e] of this.newSessionsByIp) {
      if (now - e.windowStart >= RATE_WINDOW_MS * 10) this.newSessionsByIp.delete(ip);
    }
    for (const [ip, t] of this.resetReplyByIp) {
      if (now - t >= RATE_WINDOW_MS * 10) this.resetReplyByIp.delete(ip);
    }
  }

  private onUdp(msg: Buffer, rinfo: RemoteInfo): void {
    // Anything shorter than an empty data symbol cannot be an FCP datagram;
    // replying to it only turned the server into a reflector for 8-byte junk.
    if (msg.length < DATA_WIRE_OVERHEAD) return;
    const key = msg.subarray(0, SALT_LEN).toString('hex');
    this.dbg(`[${key.slice(0, 8)}] udp rx ${msg.length}B from ${rinfo.address}:${rinfo.port} known=${this.sessions.has(key)}`);
    const b = this.sessions.get(key);
    if (b) {
      const ok = b.session.onWire(msg, nowMs());
      // S1: only an AUTHENTICATED datagram moves the reply address. Forging
      // one requires the PSK, and a spoofed replay is rejected by the nonce
      // window, so following the source cannot be turned into an amplification
      // redirect. Without this a NAT rebinding starved the tunnel: every
      // datagram authenticated fine but every reply flew to the stale address
      // until the 135 s peer_dead clock killed the session.
      if (ok && (b.addr.port !== rinfo.port || b.addr.host !== rinfo.address)) {
        b.addr.host = rinfo.address;
        b.addr.port = rinfo.port;
        this.dbg(`[${key.slice(0, 8)}] peer address moved -> ${rinfo.address}:${rinfo.port}; following`);
      }
      return;
    }
    if (this.sessions.size >= MAX_TUNNEL_SESSIONS) return;
    if (!this.allowNewSession(rinfo.address, nowMs())) return;
    const created = this.createSession(msg.subarray(0, SALT_LEN), rinfo);
    if (!created) return;
    const ok = created.session.onWire(msg, nowMs());
    if (created.session.isClosed) {
      // A reset addressed to a salt we no longer own, or a handshake that
      // failed on its first datagram: never publish a dead session.
      created.cleanup();
      created.trace?.close();
      this.tunnels.delete(key);
      return;
    }
    if (!ok) {
      // #86: authenticated-looking traffic for a salt we do not own. Answer
      // once with a stateless reset under the bootstrap key, at most 1 Hz per
      // peer IP so a flood cannot turn this path into a reflector.
      if (this.allowResetReply(rinfo.address, nowMs())) {
        const reset = created.session.makeReset();
        if (reset) {
          this.dbg(`[${key.slice(0, 8)}] auth failed -> stateless reset tx ${reset.length}B`);
          this.udp.send(reset, rinfo.port, rinfo.address);
        }
      }
      created.cleanup();
      created.trace?.close();
      this.tunnels.delete(key);
      return;
    }
    this.sessions.set(key, created);
  }

  private tick(): void {
    const now = nowMs();
    for (const [key, b] of [...this.sessions]) {
      b.session.onTick(now);
      if (b.session.established && now % 2000 < TICK_MS) {
        const st = b.session.stats();
        this.dbg(`stats inflight=${b.session.inflightBytes}B rwnd=${b.session.peerWindowBytes}B ` +
          `queued=${b.session.queuedBytes}B retx=${b.session.segsRetransmitted}/${b.session.segsSent} ` +
          `retxSplit=${b.session.retxSplit} k=${st.k} loss=${(b.session.fecLoss * 100).toFixed(1)}% srtt=${st.srttMs}ms ` +
          `sendBw=${(b.session.sendRateBytesPerMs * 1000 / 1048576).toFixed(2)}MB/s ` +
          `recvNext=${b.session.recvNext} ` +
          `reorder=${b.session.reorderBytes}B delivPending=${b.session.recvPendingBytes}B`);
      }
      if (b.session.isClosed) {
        this.sessions.delete(key);
        b.cleanup(); b.trace?.close();
        this.tunnels.delete(key);
      }
    }
    // Write window opened (ACKs arrived) or the target already hit EOF: drain
    // the target->tunnel backlog outside of the socket callback.
    for (const t of this.tunnels.values()) {
      if (t.pendingToTunnel.length || t.endFromTarget) this.pumpToTunnel(t);
    }
    for (const b of this.sessions.values()) {
      if (b.sidTunnels) for (const t of b.sidTunnels.values()) {
        if (t.pendingToTunnel.length || t.endFromTarget) this.pumpToTunnel(t);
      }
    }
  }

  /**
   * Move the target->tunnel backlog into the send window. `Stream.write`
   * accepts only what fits in the send window and returns how much it took,
   * so a short return must keep the remainder instead of dropping it, and a
   * FIN must wait until the backlog is empty (otherwise the last bytes of a
   * large response are silently truncated).
   */
  private pumpToTunnel(t: ServerTunnel): void {
    if (t.pumping) return;
    t.pumping = true;
    try {
      while (t.pendingToTunnel.length) {
        const head = t.pendingToTunnel[0];
        const n = t.writeBuf(head);
        if (n <= 0) break;
        if (n < head.length) { t.pendingToTunnel[0] = head.subarray(n); break; }
        t.pendingToTunnel.shift();
      }
    } finally {
      t.pumping = false;
    }
    const sock = t.targetSock;
    if (t.pendingToTunnel.length) {
      if (!t.paused && sock && !sock.destroyed) { t.paused = true; sock.pause(); }
      return;
    }
    if (t.paused && sock && !sock.destroyed) { t.paused = false; sock.resume(); }
    if (t.endFromTarget) {
      t.endFromTarget = false;
      t.closeWriteBuf();
    }
  }

  private createSession(salt: Buffer, rinfo: RemoteInfo): (Binding & { cleanup: () => void }) | null {
    const key = salt.toString('hex');
    const trace = sessionTrace(this.opts, 'server', key);
    const cfg: SessionConfig = {
      psk: this.opts.psk, salt,
      sendDirection: Direction.S2C, recvDirection: Direction.C2S,
      role: HandshakeRole.Server,
      d: this.opts.d ?? DEFAULT_D, p: this.opts.p ?? DEFAULT_P,
      mtu: this.opts.mtu ?? DEFAULT_MTU_MIN,
      pmtuMaxMtu: this.opts.pmtuMaxMtu,
      pinnedK: this.opts.pinnedK,
      ack_v2: this.opts.ack_v2, pmtud: this.opts.pmtud, keyUpdate: this.opts.keyUpdate,
      trace: trace?.write,
    };
    let closed = false;
    let tunnel: ServerTunnel | null = null;
    /** M1: per-sid tunnels on a multiplexed session (the default tunnel stays
     *  in `this.tunnels` under the session key). */
    const sidTunnels = new Map<number, ServerTunnel>();
    const cleanup = () => {
      if (closed) return;
      closed = true;
      const teardown = (t: ServerTunnel) => {
        t.pendingToTarget.length = 0;
        t.pendingToTunnel.length = 0;
        if (t.targetSock && !t.targetSock.destroyed) t.targetSock.destroy();
      };
      if (tunnel) teardown(tunnel);
      for (const t of sidTunnels.values()) teardown(t);
      sidTunnels.clear();
    };
    const addr = { host: rinfo.address, port: rinfo.port };
    const session = new Session(cfg, {
      sendWire: (wire) => {
        if (!this.running || closed) return;
        // Reads `addr`, not the captured rinfo: onUdp updates addr on every
        // authenticated datagram, so a NAT rebinding is followed mid-session.
        this.dbg(`[${key.slice(0, 8)}] udp tx ${wire.length}B -> ${addr.host}:${addr.port}`);
        this.udp.send(wire, addr.port, addr.host);
      },
      read: (bytes) => { if (tunnel) this.onStreamBytes(tunnel, bytes); },
      closed: (reason) => {
        this.log(`session ${key} closed: ${reason}`);
        cleanup();
        this.sessions.delete(key);
        this.tunnels.delete(key);
      },
      eof: () => { if (tunnel?.targetSock && !tunnel.targetSock.destroyed) tunnel.targetSock.end(); },
      streamHost: {
        inboundStream: (sid) => {
          if (closed) return null;
          let t = sidTunnels.get(sid);
          if (t) return { ...t.callbacks() };
          t = this.newSidTunnel(key, sid, addr, trace, cleanup);
          sidTunnels.set(sid, t);
          return { ...t.callbacks() };
        },
        streamReady: (sid, stream) => {
          const t = sidTunnels.get(sid);
          if (t) t.stream = stream;
        },
        streamClosed: (sid) => {
          const t = sidTunnels.get(sid);
          if (t) {
            sidTunnels.delete(sid);
            this.log(`stream ${key}#${sid} closed`);
            this.destroyTunnel(t, key);
          }
        },
      },
      log: this.log,
      debug: this.dbg,
    });
    if (!session.start(nowMs())) { trace?.close(); return null; }
    this.dbg(`[${key.slice(0, 8)}] session+ from ${rinfo.address}:${rinfo.port}`);
    tunnel = this.newDefaultTunnel(session, key, addr, trace, cleanup);
    this.tunnels.set(key, tunnel);
    session.onTick(nowMs());
    return { session, addr, sidTunnels, cleanup, trace };
  }

  /** The session's default tunnel (sid 0): writes route through the session
   *  API, exactly as they did before multiplexing existed. */
  private newDefaultTunnel(session: Session, key: string, addr: { host: string; port: number }, trace: TraceSink | undefined, sessionCleanup: () => void): ServerTunnel {
    const t: ServerTunnel = {
      session, key, addr, stream: session.streamRef, sid: 0,
      parser: new PrefixParser(openParseRequest),
      targetSock: null, openDone: false, openOkSent: false, pendingToTarget: [], pendingToTunnel: [],
      endFromTarget: false, paused: false, pumping: false, cleanup: sessionCleanup, trace,
      writeBuf: (b) => session.write(b),
      consumeBuf: (n) => session.consumed(n),
      closeWriteBuf: () => session.closeWrite(),
      callbacks: () => ({
        send: () => {},
        read: (bytes) => { this.onStreamBytes(t, bytes); },
        closed: () => {},
        eof: () => { if (t.targetSock && !t.targetSock.destroyed) t.targetSock.end(); },
      }),
    };
    return t;
  }

  /** M1: a tunnel for an inbound sid stream on a multiplexed session. */
  private newSidTunnel(key: string, sid: number, addr: { host: string; port: number }, trace: TraceSink | undefined): ServerTunnel {
    let t: ServerTunnel;
    t = {
      key, addr, sid,
      stream: null as unknown as Stream, // streamReady assigns it before any byte
      parser: new PrefixParser(openParseRequest),
      targetSock: null, openDone: false, openOkSent: false, pendingToTarget: [], pendingToTunnel: [],
      endFromTarget: false, paused: false, pumping: false,
      cleanup: () => {
        t.pendingToTarget.length = 0;
        t.pendingToTunnel.length = 0;
        if (t.targetSock && !t.targetSock.destroyed) t.targetSock.destroy();
      },
      writeBuf: (b) => t.stream.write(b, nowMs()),
      consumeBuf: (n) => t.stream.consumed(n),
      closeWriteBuf: () => t.stream.closeWrite(nowMs()),
      callbacks: () => ({
        send: () => {},
        read: (bytes) => { this.onStreamBytes(t, bytes); },
        closed: () => {},
        eof: () => { if (t.targetSock && !t.targetSock.destroyed) t.targetSock.end(); },
      }),
      trace,
    };
    return t;
  }

  private destroyTunnel(t: ServerTunnel, key: string): void {
    t.cleanup();
    if (t.sid === 0) this.tunnels.delete(key);
  }

  /**
   * Drain the tunnel->target FIFO with backpressure. Everything queued here is
   * already consumed (the receive window was released at queue time), so the
   * queue is bounded by the peer's send window; a `false` from write() keeps
   * the rest until the socket drains.
   */
  private pumpToTarget(t: ServerTunnel): void {
    const sock = t.targetSock;
    if (!sock || sock.destroyed || !t.openOkSent) return;
    while (t.pendingToTarget.length) {
      const b = t.pendingToTarget[0]!;
      if (!sock.write(b)) break;
      t.pendingToTarget.shift();
    }
  }

  private onStreamBytes(t: ServerTunnel, bytes: Buffer): void {
    if (t.openDone) {
      const sock = t.targetSock;
      if (!sock || sock.destroyed) {
        // Target is gone (OPEN was refused, connect failed, or the socket was
        // destroyed). Drop rather than queue forever.
        t.consumeBuf(bytes.length);
        return;
      }
      // Before 'connect' fires (or while a backlog is waiting), bytes must not
      // bypass pendingToTarget: Node flushes its connect buffer ahead of any
      // later write, so a direct sock.write() here would overtake the OPEN
      // payload and reorder the stream. Everything goes through the FIFO.
      if (!t.openOkSent || t.pendingToTarget.length) {
        t.pendingToTarget.push(bytes);
        t.consumeBuf(bytes.length);
        this.pumpToTarget(t);
        return;
      }
      // Release the receive window only once the local TCP socket flushed:
      // otherwise a slow target lets Node's writable buffer grow without
      // bound while the peer keeps filling a window we never close.
      sock.write(bytes, () => t.consumeBuf(bytes.length));
      return;
    }
    const rest = t.parser.push(bytes);
    if (!t.parser.done) { t.consumeBuf(bytes.length); return; }
    const r = t.parser.result;
    if (!r || r.status !== 'ok' || !r.value) {
      // Refuse once and stop parsing: every later byte used to re-enter this
      // branch and emit another OPEN_ERR, while the session stayed open.
      t.openDone = true;
      t.consumeBuf(bytes.length);
      t.writeBuf(openWriteErr(OpenError.NotSupported));
      t.closeWriteBuf();
      return;
    }
    t.openDone = true;
    t.consumeBuf(bytes.length);
    if (rest.length) t.pendingToTarget.push(rest);
    const target = r.value;
    this.dbg(`[${t.key.slice(0, 8)}] OPEN rx target=${targetText(target)}:${target.port} firstPayload=${rest.length}B`);
    const host = dialHost(target);
    const sock = connect({ host, port: target.port, family: target.atyp === 0x04 ? 6 : 4 });
    t.targetSock = sock;
    sock.setNoDelay(true);
    sock.setTimeout(10000);
    sock.on('connect', () => {
      sock.setTimeout(0);
      this.log(`target connected: ${targetText(target)}`);
      this.dbg(`[${t.key.slice(0, 8)}] target connected -> OPEN_OK tx`);
      t.openOkSent = true;
      t.writeBuf(openWriteOk());
      // OPEN is followed by the client's first application bytes (e.g. a TLS
      // ClientHello). They belong on the target socket, not back in the tunnel.
      this.pumpToTarget(t);
    });
    sock.on('drain', () => this.pumpToTarget(t));
    sock.on('data', (chunk: Buffer) => {
      t.pendingToTunnel.push(chunk);
      this.pumpToTunnel(t);
      this.dbg(`[${t.key.slice(0, 8)}] target->tunnel ${chunk.length}B backlog=${t.pendingToTunnel.length}`);
    });
    sock.on('end', () => {
      t.endFromTarget = true;
      this.pumpToTunnel(t); // FIN only after the backlog is written
    });
    sock.on('timeout', () => {
      if (!t.openOkSent) t.writeBuf(openWriteErr(OpenError.TargetTimeout));
      t.closeWriteBuf();
      sock.destroy();
    });
    sock.on('error', (e) => {
      this.dbg(`[${t.key.slice(0, 8)}] target error: ${e.message}`);
      this.log(`target error ${targetText(target)}: ${e.message}`);
      // Only a pre-connect failure is still an OPEN reply. After OPEN_OK the
      // client is parsing response bytes, so an OPEN_ERR frame there would be
      // delivered to the local application as garbage; EOF is the signal.
      if (!t.openOkSent) {
        t.writeBuf(openWriteErr(e.message.includes('ENOTFOUND') ? OpenError.Dns : OpenError.Refused));
      }
      // Queue the error and FIN, then let the stream flush on the next ticks.
      // Calling cleanup() here would flip `closed`, and sendWire() drops every
      // datagram once that is set: the error would never reach the client and
      // the session would linger in the map as a send-dead zombie while the
      // peer keeps retrying.
      t.closeWriteBuf();
      sock.destroy();
    });
  }
}

export { OPEN_MAX_BYTES };
