// UDP reactor + local TCP proxy. Port shape of apps/cli (reactor) and
// src/proxy/proxy_engine.{h,cc}: one local TCP connection = one FCP session
// = one target, all sessions sharing a single UDP 5-tuple and keyed by salt.

import { createSocket, type Socket as UdpSocket, type RemoteInfo } from 'node:dgram';
import { createServer, connect, type Socket as TcpSocket, type Server as TcpServer } from 'node:net';
import { randomBytes } from 'node:crypto';
import {
  SALT_LEN, Direction, HandshakeRole, DEFAULT_MTU_MIN, DEFAULT_D, DEFAULT_P,
  OPEN_MAX_BYTES, ATYP_DOMAIN, ATYP_IPV4,
} from '../constants.ts';
import { Session, type SessionConfig } from '../session/session.ts';
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
  rinfo?: RemoteInfo;
  cleanup: () => void;
  trace?: TraceSink;
}

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

  constructor(opts: TunnelOptions) {
    this.opts = opts;
    this.log = opts.log ?? (() => {});
    this.dbg = opts.debugLog ?? (() => {});
    this.udp = createSocket('udp4');
    this.tcp = createServer((sock) => this.onLocalConnection(sock));
    this.udp.on('message', (msg) => this.onUdp(msg));
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

  private onUdp(msg: Buffer): void {
    if (msg.length < SALT_LEN) return;
    this.bytesRx += msg.length;
    const salt = msg.subarray(0, SALT_LEN).toString('hex');
    this.dbg(`[${salt.slice(0, 8)}] udp rx ${msg.length}B known=${this.sessions.has(salt)}`);
    const b = this.sessions.get(salt);
    if (b) b.session.onWire(msg, nowMs());
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
      if (b.session.streamRef.isClosed) { this.sessions.delete(key); b.cleanup(); b.trace?.close(); }
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
    const pendingLocal: Buffer[] = [];
    const replyParser = new PrefixParser(openParseReply);

    const destroy = (buf?: Buffer) => {
      if (dead) return;
      if (buf && !sock.destroyed) sock.write(buf);
      setTimeout(() => sock.destroy(), 30);
    };

    // Same rule as the server side: a short `Stream.write` leaves a remainder
    // behind, and the FIN must not overtake it.
    const flushPending = () => {
      while (pendingLocal.length && session) {
        const b = pendingLocal.shift()!;
        const n = session.write(b);
        if (n < b.length) { pendingLocal.unshift(b.subarray(n)); break; }
      }
      if (session && !pendingLocal.length && endPending) {
        endPending = false;
        session.closeWrite();
      }
    };

    const sendOpen = () => {
      if (!session || !target || opened || dead) return;
      if (!session.established) {
        handshakeWait = setTimeout(sendOpen, 20);
        return;
      }
      if (handshakeWait) { clearTimeout(handshakeWait); handshakeWait = null; }
      const open = openWriteRequest(target);
      if (!open) { destroy(); return; }
      opened = true;
      this.dbg(`[${saltKey.slice(0, 8)}] OPEN tx ${open.length}B -> ${targetText(target)}`);
      session.write(open);
      if (firstPayload && firstPayload.length) session.write(firstPayload);
      flushPending();
      this.log(`open sent -> ${targetText(target)}`);
    };

    streamRead = (bytes: Buffer) => {
      if (replyParser.done) {
        this.dbg(`[${saltKey.slice(0, 8)}] tunnel->local ${bytes.length}B`);
        if (!sock.destroyed) sock.write(bytes);
        session?.consumed(bytes.length);
        return;
      }
      const rest = replyParser.push(bytes);
      session?.consumed(bytes.length);
      if (!replyParser.done) return;
      const r = replyParser.result;
      if (!r || r.status !== 'ok' || !r.value) { destroy(); return; }
      this.dbg(`[${saltKey.slice(0, 8)}] OPEN reply rx ok=${r.value.ok} err=${r.value.ok ? 0 : r.value.err} kind=${entryKind}`);
      if (!r.value.ok) {
        const rep = socks5RepForOpenError(r.value.err);
        destroy(entryKind === 'socks5' ? socks5Reply(rep) : HTTP_BAD_GATEWAY);
        return;
      }
      if (entryKind === 'socks5') sock.write(socks5Reply(Socks5Rep.Succeeded));
      else if (entryKind === 'connect') sock.write(HTTP_OK);
      if (rest.length && !sock.destroyed) sock.write(rest);
      flushPending();
    };

    const setupSession = () => {
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
      session.onTick(nowMs());
      sendOpen();
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
      setupSession();
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
      if (!opened || !session) { pendingLocal.push(Buffer.from(chunk)); return; }
      const n = session.write(chunk);
      this.dbg(`[${saltKey.slice(0, 8)}] local->tunnel ${n}/${chunk.length}B`);
      if (n < chunk.length) {
        pendingLocal.push(Buffer.from(chunk.subarray(n)));
        sock.pause();
        const resume = setInterval(() => {
          flushPending();
          if (!pendingLocal.length || dead) { clearInterval(resume); if (!dead) sock.resume(); }
        }, TICK_MS);
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
  session: Session;
  rinfo: RemoteInfo;
  parser: PrefixParser<ProxyTarget>;
  targetSock: TcpSocket | null;
  openDone: boolean;
  pendingToTarget: Buffer[];
  /** target -> tunnel backlog: bytes the send window could not take yet. */
  pendingToTunnel: Buffer[];
  /** Target hit EOF; the FIN may only go out once the backlog is drained. */
  endFromTarget: boolean;
  paused: boolean;
  pumping: boolean;
  cleanup: () => void;
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

  private onUdp(msg: Buffer, rinfo: RemoteInfo): void {
    if (msg.length < SALT_LEN) return;
    const key = msg.subarray(0, SALT_LEN).toString('hex');
    this.dbg(`[${key.slice(0, 8)}] udp rx ${msg.length}B from ${rinfo.address}:${rinfo.port} known=${this.sessions.has(key)}`);
    const b = this.sessions.get(key);
    if (b) { b.rinfo = rinfo; b.session.onWire(msg, nowMs()); return; }
    const created = this.createSession(msg.subarray(0, SALT_LEN), rinfo);
    if (!created) return;
    const ok = created.session.onWire(msg, nowMs());
    if (!ok) {
      // #86: authenticated-looking traffic for a salt we do not own. Answer
      // once with a stateless reset under the bootstrap key.
      const reset = created.session.makeReset();
      if (reset) {
        this.dbg(`[${key.slice(0, 8)}] auth failed -> stateless reset tx ${reset.length}B`);
        this.udp.send(reset, rinfo.port, rinfo.address);
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
      if (b.session.streamRef.isClosed) {
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
        const n = t.session.write(head);
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
      if (!t.session.streamRef.isClosed) t.session.closeWrite();
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
    const cleanup = () => {
      if (closed) return;
      closed = true;
      if (tunnel) { tunnel.pendingToTarget.length = 0; tunnel.pendingToTunnel.length = 0; }
      if (tunnel?.targetSock && !tunnel.targetSock.destroyed) tunnel.targetSock.destroy();
    };
    const session = new Session(cfg, {
      sendWire: (wire) => {
        if (!this.running || closed) return;
        this.dbg(`[${key.slice(0, 8)}] udp tx ${wire.length}B -> ${rinfo.address}:${rinfo.port}`);
        this.udp.send(wire, rinfo.port, rinfo.address);
      },
      read: (bytes) => { if (tunnel) this.onStreamBytes(tunnel, bytes); tunnel?.session.consumed(bytes.length); },
      closed: (reason) => { this.log(`session ${key} closed: ${reason}`); cleanup(); },
      eof: () => { if (tunnel?.targetSock && !tunnel.targetSock.destroyed) tunnel.targetSock.end(); },
      log: this.log,
      debug: this.dbg,
    });
    if (!session.start(nowMs())) { trace?.close(); return null; }
    this.dbg(`[${key.slice(0, 8)}] session+ from ${rinfo.address}:${rinfo.port}`);
    tunnel = {
      session, rinfo, parser: new PrefixParser(openParseRequest),
      targetSock: null, openDone: false, pendingToTarget: [], pendingToTunnel: [],
      endFromTarget: false, paused: false, pumping: false, cleanup, trace,
    };
    this.tunnels.set(key, tunnel);
    session.onTick(nowMs());
    return { session, rinfo, cleanup, trace };
  }

  private onStreamBytes(t: ServerTunnel, bytes: Buffer): void {
    if (t.openDone) {
      if (t.targetSock && !t.targetSock.destroyed) t.targetSock.write(bytes);
      else t.pendingToTarget.push(Buffer.from(bytes));
      return;
    }
    const rest = t.parser.push(bytes);
    if (!t.parser.done) return;
    const r = t.parser.result;
    if (!r || r.status !== 'ok' || !r.value) {
      t.session.write(openWriteErr(OpenError.NotSupported));
      return;
    }
    t.openDone = true;
    if (rest.length) t.pendingToTarget.push(rest);
    const target = r.value;
    this.dbg(`[${t.session.salt.toString('hex').slice(0, 8)}] OPEN rx target=${targetText(target)}:${target.port} firstPayload=${rest.length}B`);
    const host = dialHost(target);
    const sock = connect({ host, port: target.port, family: target.atyp === 0x04 ? 6 : 4 });
    t.targetSock = sock;
    sock.setNoDelay(true);
    sock.setTimeout(10000);
    sock.on('connect', () => {
      sock.setTimeout(0);
      this.log(`target connected: ${targetText(target)}`);
      this.dbg(`[${t.session.salt.toString('hex').slice(0, 8)}] target connected -> OPEN_OK tx`);
      t.session.write(openWriteOk());
      // OPEN is followed by the client's first application bytes (e.g. a TLS
      // ClientHello). They belong on the target socket, not back in the tunnel.
      while (t.pendingToTarget.length) {
        const b = t.pendingToTarget.shift()!;
        if (!sock.write(b)) { t.pendingToTarget.unshift(b); break; }
      }
    });
    sock.on('drain', () => {
      while (t.pendingToTarget.length) {
        const b = t.pendingToTarget.shift()!;
        if (!sock.write(b)) { t.pendingToTarget.unshift(b); break; }
      }
    });
    sock.on('data', (chunk: Buffer) => {
      t.pendingToTunnel.push(chunk);
      this.pumpToTunnel(t);
      this.dbg(`[${t.session.salt.toString('hex').slice(0, 8)}] target->tunnel ${chunk.length}B backlog=${t.pendingToTunnel.length}`);
    });
    sock.on('end', () => {
      t.endFromTarget = true;
      this.pumpToTunnel(t); // FIN only after the backlog is written
    });
    sock.on('timeout', () => {
      t.session.write(openWriteErr(OpenError.TargetTimeout));
      t.session.closeWrite();
      sock.destroy();
    });
    sock.on('error', (e) => {
      this.dbg(`[${t.session.salt.toString('hex').slice(0, 8)}] target error: ${e.message}`);
      this.log(`target error ${targetText(target)}: ${e.message}`);
      t.session.write(openWriteErr(e.message.includes('ENOTFOUND') ? OpenError.Dns : OpenError.Refused));
      // Queue the error and FIN, then let the stream flush on the next ticks.
      // Calling cleanup() here would flip `closed`, and sendWire() drops every
      // datagram once that is set: the error would never reach the client and
      // the session would linger in the map as a send-dead zombie while the
      // peer keeps retrying.
      t.session.closeWrite();
      sock.destroy();
    });
  }
}

export { OPEN_MAX_BYTES };
