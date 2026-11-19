// UDP reactor + local TCP proxy. Port shape of apps/cli (reactor) and
// src/proxy/proxy_engine.{h,cc}: one local TCP connection = one FCP session
// = one target, all sessions sharing a single UDP 5-tuple and keyed by salt.

import { createSocket, type Socket as UdpSocket, type RemoteInfo } from 'node:dgram';
import { createServer, connect, isIP, type Socket as TcpSocket, type Server as TcpServer } from 'node:net';
import { lookup as dnsLookup } from 'node:dns';
import { randomBytes } from 'node:crypto';
import {
  SALT_LEN, Direction, HandshakeRole, DEFAULT_MTU_MIN, DEFAULT_D, DEFAULT_P,
  OPEN_MAX_BYTES, ATYP_DOMAIN, ATYP_IPV4, DATA_WIRE_OVERHEAD, NONCE_LIMIT,
  MUX_MAX_STREAMS, MUX_SESSION_POOL,
  PROBE_INTERVAL_MS, PROBE_IDLE_MS, PROBE_BUDGET_BYTES, PROBE_RETRY_MS,
} from '../constants.ts';
import { Session, type SessionConfig, type SessionProbeResult } from '../session/session.ts';
import { probeReport, type ProbeReport } from '../probe/pathprobe.ts';
import { Stream, type StreamCallbacks } from '../stream/stream.ts';
import { openBootstrapHello, sealReset } from '../crypto/envelope.ts';
import {
  detectEntry, socks5ParseGreeting, socks5GreetingReply, socks5ParseRequest,
  socks5Reply, socks5RepForOpenError, Socks5Rep,
  httpParseConnect, httpParseForward,
  HTTP_OK, HTTP_BAD_REQUEST, HTTP_BAD_GATEWAY, HTTP_METHOD_NOT_ALLOWED,
  HTTP_HEAD_TOO_LARGE, HTTP_FORWARD_METHOD_NOT_ALLOWED,
  openWriteRequest, openWriteOk, openWriteErr, openParseRequest, openParseReply,
  targetText, parseIpv6Literal, type ProxyTarget, type ParseResult,
} from '../proxy/codec.ts';
import { OpenError } from '../constants.ts';
import { createTraceSink, type TraceSink } from '../util/trace.ts';

const TICK_MS = 10;
/** Stats line cadence: fast enough for a live graph, slow enough not to spam. */
const STATS_PERIOD_MS = 500;

/**
 * One trace row per established session per 2 s: what the current k bought.
 *
 * `fec_k` records the controller's decision and `bbr` its estimate; neither
 * records the counters the decision moves (retransmissions, loss, send rate).
 * Those used to exist only in the debug stats line, and turning debug on to get
 * them also writes two lines per datagram — at 300 KB/s that is megabytes per
 * minute of formatting and disk, enough to change the throughput a benchmark is
 * trying to measure. This costs one small line per session per interval.
 */
function traceStreamInterval(
  sink: TraceSink | undefined,
  s: Session,
  st: ReturnType<Session['stats']>,
): void {
  if (!sink) return;
  sink.write(JSON.stringify({
    t: 'stream',
    k: st.k,
    d: st.d,
    lanes: st.lanes,
    loss: s.fecLoss,
    srtt: st.srttMs,
    retx: s.segsRetransmitted,
    sent: s.segsSent,
    sendBw: Math.round(s.sendRateBytesPerMs * 1000),
    inflight: s.inflightBytes,
    queued: s.queuedBytes,
    rwnd: s.peerWindowBytes,
  }));
}

export interface TunnelOptions {
  psk: Buffer;
  host?: string; port?: number;
  listenHost?: string; listenPort?: number;
  /** PMTUD floor: the probe walk starts here (and stays here with --no-pmtud). */
  mtu?: number;
  /** PMTUD ceiling: the walk never goes above this. */
  pmtuMaxMtu?: number;
  d?: number; p?: number;
  /** Repair groups kept open in parallel (1 = no interleaving). */
  interleave?: number;
  /** Redundant copies of every ACK v2 (1 = off). */
  ackCopies?: number;
  pinnedK?: number;
  ack_v2?: boolean; pmtud?: boolean; keyUpdate?: boolean;
  /** Server only: refuse OPEN targets in private / loopback / link-local /
   *  ULA space (and domains that resolve there). Off by default: the tunnel is
   *  a personal proxy, so dialing your own LAN is the point. Turn it on when
   *  the PSK is shared with people who should reach the internet but not the
   *  server's own network. */
  denyPrivate?: boolean;
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
  /** One idle-time path measurement finished. Client side only: the server
   *  answers trains but never starts one (it cannot know whether the user is
   *  working, and two ends probing each other would double the cost). */
  onProbe?: (r: ProbeReport) => void;
  /** Automatic idle path probe: false stops the periodic scheduler. Manual
   *  probeNow() still works — protocol negotiation is offered independently
   *  via probeNegotiate so the button is never dead. */
  probe?: boolean;
  /** Offer TLV 6 at handshake. Defaults to true; only set false if the peer
   *  cannot speak PROBE (legacy interop). --no-probe does NOT set this. */
  probeNegotiate?: boolean;
  probeIntervalMs?: number;
  probeBudgetBytes?: number;
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
/** Pre-auth CPU budget, per source and global.
 *
 *  Every datagram with an unseen salt is decrypted once under the bootstrap key
 *  before anything else happens (see the gate in onUdp). That is ~36 us of
 *  HKDF + AES-GCM per packet, so an unauthenticated 37-byte flood used to buy
 *  unbounded CPU: ~28k pps saturated a core without the attacker knowing the
 *  PSK. The budget is charged before that decryption, not after, so the cost an
 *  attacker can impose is capped by a number instead of by its packet rate.
 *
 *  The two caps answer different floods. Per-IP stops one host from eating the
 *  whole global budget, which would otherwise lock legitimate clients out while
 *  a single source keeps the counter full. Global bounds the aggregate: at
 *  8192/s the gate can claim ~30% of a core, which leaves the process able to
 *  service established sessions — the traffic that actually matters during an
 *  attack — instead of dying whole.
 *
 *  Per-IP 256 is four times MAX_NEW_SESSIONS_PER_IP, so a browser burst of
 *  session creations plus one HELLO retry each is never throttled; the cost a
 *  single source can still force is 256 x ~36 us, under 1% of a core. */
const MAX_PREAUTH_PER_IP = 256;
const MAX_PREAUTH_GLOBAL = 8192;
/** Bound the bookkeeping maps: a spoofed-source flood must not grow them. */
const RATE_MAP_MAX = 4096;
/** How long one sealed bootstrap datagram is remembered. A replay of a captured
 *  HELLO authenticates (the bootstrap key is static per PSK+salt) and would
 *  otherwise create a fresh server session every time it is replayed from a new
 *  spoofed source. Legitimate HELLO retries seal a fresh nonce each attempt, so
 *  exact duplicates are replays or network duplicates, never retries. */
const BOOT_REPLAY_TTL_MS = 180_000;

/**
 * Wall clock, clamped to be monotonic.
 *
 * Date.now() can step backwards (an NTP correction, a VM snapshot restore, a
 * manual clock change). Every protocol timer is a difference of two
 * timestamps, so a backwards step turns "the RTO expired 200 ms ago" into
 * "the RTO expires in 30 s": the ARQ, the handshake retry and the PMTUD walk
 * all freeze until the wall clock catches up. The clamp advances the clock by
 * exactly the wall-clock delta while the wall clock moves forward, and keeps
 * it where it is while the wall clock is behind — a backwards step then reads
 * as "time stood still" instead of "time ran backwards".
 */
let clockLastWall = 0;
let clockMono = 0;
export function nowMs(): number {
  const wall = Date.now();
  if (clockMono === 0) { clockMono = wall; clockLastWall = wall; }
  else if (wall > clockLastWall) { clockMono += wall - clockLastWall; clockLastWall = wall; }
  return clockMono;
}

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
/** Global rate on Session *creations* per second. The per-IP budget below
 *  bounds one source; a leaked PSK spread across a botnet turns 64/s/IP into
 *  an unbounded sum. With the bootstrap-HELLO pre-gate, only genuinely sealed
 *  HELLOs ever reach creation, so this cap is the last line against
 *  allocation churn rather than the first. */
const MAX_NEW_SESSIONS_GLOBAL = 1000;

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

/**
 * SSRF deny-list, byte-based (--deny-private).
 *
 * The tunnel is a personal proxy, so dialing the server's own LAN is normally
 * the point. When the PSK is shared with people who should reach the internet
 * but not the server's network, this refuses targets that point back into it:
 * loopback, RFC1918 private ranges, link-local (169.254/16 and fe80::/10 —
 * which also covers the cloud metadata endpoints 169.254.169.254 / 100.100.100.200
 * / 169.254.169.254), CGNAT 100.64/10, IPv6 ULA fc00::/7 and IPv4-mapped IPv6.
 * Multicast and the 0/8 + 224+ blocks are refused too. Domain targets are
 * resolved and every answer is checked, so "metadata.google.internal" cannot
 * slip past a literal check.
 *
 * This is defence-in-depth, not a security boundary: the resolver is consulted
 * for the check and then again by connect(), so a fast DNS-rebind attacker who
 * controls the record can race the two lookups. Against that, pin the resolved
 * IP in connect() or run the tunnel on a host with no internal routes worth
 * reaching.
 */
export function ipv4Denied(parts: number[]): boolean {
  const [a, b] = parts;
  if (a === 0 || a === 127 || a === 10) return true;
  if (a === 169 && b === 254) return true;                  // link-local (cloud metadata)
  if (a === 172 && b >= 16 && b <= 31) return true;        // RFC1918
  if (a === 192 && b === 168) return true;                 // RFC1918
  if (a === 100 && b >= 64 && b <= 127) return true;       // CGNAT
  if (a >= 224) return true;                               // multicast / reserved
  return false;
}
export function ipv6Denied(b: Buffer): boolean {
  if (b[0] === 0xff) return true;                          // multicast ff00::/8
  if (b[0] === 0xfe && (b[1] & 0xc0) === 0x80) return true; // link-local fe80::/10
  if (b[0] === 0xfc || b[0] === 0xfd) return true;         // ULA fc00::/7
  // IPv4-mapped ::ffff:a.b.c.d — check the embedded address
  let v4Mapped = true;
  for (let i = 0; i < 10; ++i) if (b[i] !== 0) { v4Mapped = false; break; }
  if (v4Mapped && b[10] === 0xff && b[11] === 0xff) {
    return ipv4Denied([b[12]!, b[13]!, b[14]!, b[15]!]);
  }
  // loopback ::1 and unspecified ::
  let allZero = true;
  for (let i = 0; i < 15; ++i) if (b[i] !== 0) { allZero = false; break; }
  if (allZero && (b[15] === 0 || b[15] === 1)) return true;
  return false;
}
export function ipDenied(family: number, addr: string): boolean {
  if (family === 4) return ipv4Denied(addr.split('.').map(Number));
  if (family === 6) {
    const b = parseIpv6Literal(addr);
    return b === null ? false : ipv6Denied(b);
  }
  return false;
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
  /** M1 应用层字节:下行 = 交付给本地应用(浏览器)的字节;上行 = 本地应用
   *  发来并被接收的字节。与 wire 字节(含 FEC parity/ACK/重传/封套)分开
   *  统计——GUI 的下行/上行卡片按这两个数显示"真实速度"。 */
  private bytesAppRx = 0;
  private bytesAppTx = 0;
  private statsPrevAppRx = 0;
  private statsPrevAppTx = 0;
  private statsPrevTx = 0;
  private statsPrevRx = 0;
  private statsPrevMs = 0;
  private startedMs = 0;
  /** One reset per second for unknown salts: the reply is cheap, but an
   *  unrelated flood must not turn the client into a packet reflector. */
  private lastResetMs = 0;
  /** Cadence of the 2 s per-session stats line. Was `now % 2000 < TICK_MS`,
   *  which only held while the tick was a fixed 10 ms interval; a
   *  deadline-driven tick can straddle the window and skip a whole period. */
  private lastStatsDbgMs = 0;
  /** Idle path probe: when the next one is due (0 = not scheduled yet), whether
   *  one is in flight, and the last time the *application* moved a byte. Raw
   *  wire bytes are useless here — the tunnel's own ACKs and keepalives would
   *  keep a completely idle session looking busy forever. */
  private probeNextMs = 0;
  private probeRunning = false;
  private probeCount = 0;
  private lastAppByteMs = 0;
  /** Manual "measure now" request. Set by probeNow(), consumed on the next
   *  tick; bypasses both the idle gate and the schedule, but still needs a
   *  ready session (one is created if the pool is empty). */
  private probePending = false;

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
    this.armTick();
    this.startedMs = nowMs();
    this.statsPrevMs = this.startedMs;
    // The first probe is due one interval after start, not at start: a user who
    // launches the app and immediately works should never see a train.
    this.lastAppByteMs = this.startedMs;
    if (this.opts.onStats) {
      this.statsTimer = setInterval(() => this.emitStats(), STATS_PERIOD_MS);
    }
    this.log(`client: proxy 127.0.0.1:${this.opts.listenPort ?? 1080} -> udp ${host}:${port}`);
  }

  stop(): void {
    this.running = false;
    if (this.timer) clearTimeout(this.timer);
    if (this.statsTimer) { clearInterval(this.statsTimer); this.statsTimer = null; }
    for (const b of this.sessions.values()) { b.cleanup(); b.trace?.close(); }
    this.sessions.clear();
    this.tcp.close();
    this.udp.close();
  }

  get sessionCount(): number { return this.sessions.size; }

  /**
   * Ask for one path probe immediately, ignoring both the idle-time gate and
   * the schedule. Queued on the next tick so session setup stays on the single
   * reactor thread. Returns false only if a probe is already in flight.
   *
   * The protocol negotiation itself is always offered (see ensurePoolEntry),
   * so an explicit "measure now" works even when automatic probing is off via
   * --no-probe. That is the point: the user disabled *periodic* measurement,
   * not the ability to ask for one.
   */
  probeNow(): boolean {
    if (!this.running || this.probeRunning || this.probePending) return false;
    this.probePending = true;
    this.armTick();
    return true;
  }

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
  private ensurePoolEntry(): SharedClientSession | null {
    const salt = randomBytes(SALT_LEN);
    const key = salt.toString('hex');
    const trace = sessionTrace(this.opts, 'client', key);
    const cfg: SessionConfig = {
      psk: this.opts.psk, salt,
      sendDirection: Direction.C2S, recvDirection: Direction.S2C,
      role: HandshakeRole.Client,
      d: this.opts.d ?? DEFAULT_D, p: this.opts.p ?? DEFAULT_P,
      interleave: this.opts.interleave, ackCopies: this.opts.ackCopies,
      // Negotiation stays on for --no-probe so an explicit probeNow() can run;
      // only the automatic scheduler reads opts.probe.
      probe: this.opts.probeNegotiate !== false,
      mtu: this.opts.mtu ?? DEFAULT_MTU_MIN,
      pmtuMaxMtu: this.opts.pmtuMaxMtu,
      pinnedK: this.opts.pinnedK,
      ack_v2: this.opts.ack_v2, pmtud: this.opts.pmtud, keyUpdate: this.opts.keyUpdate,
      probeBudgetBytes: this.opts.probeBudgetBytes,
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
      // Only pool sessions are probed: they outlive any single connection, which
      // is exactly the state the probe needs (established, no user traffic).
      pathProbe: (r) => this.onPathProbe(r),
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
    // A failed start (invalid MTU, refused handshake) must not throw into the
    // socket data handler — that would crash the whole proxy. Return null and
    // let the connection fall back to its own session, whose start() failure
    // is handled locally with destroy().
    if (!session.start(nowMs())) { trace?.close(); return null; }
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
    // Grow the pool toward the cap on the first MUX_SESSION_POOL attaches so
    // even a simultaneous burst disperses across sessions deterministically.
    const want = Math.min(MUX_SESSION_POOL, this.poolNext + 1);
    while (this.pool.length < want) {
      const created = this.ensurePoolEntry();
      if (!created) return null;
    }
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
    // 应用层速率:交付给浏览器/从浏览器接收的真实字节(不含 FEC/ACK/封套开销)
    const appRxRate = Math.round((this.bytesAppRx - this.statsPrevAppRx) / dt);
    const appTxRate = Math.round((this.bytesAppTx - this.statsPrevAppTx) / dt);
    let up = 0;
    for (const b of this.sessions.values()) if (b.session.established) up += 1;
    const uptime = ((now - this.startedMs) / 1000).toFixed(1);
    this.opts.onStats?.(
      `stats ${uptime}s live=${this.sessions.size} up=${up} tunnels=${this.sessions.size} ` +
        `tx=${this.bytesTx}B rx=${this.bytesRx}B tx_rate=${txRate}B/s rx_rate=${rxRate}B/s ` +
        `app_rx=${this.bytesAppRx}B app_tx=${this.bytesAppTx}B ` +
        `app_rx_rate=${appRxRate}B/s app_tx_rate=${appTxRate}B/s ` +
        `probe_run=${this.probeRunning ? 1 : 0} probe_next=${this.probeDueSec(now)}s probe_n=${this.probeCount}`,
    );
    this.statsPrevTx = this.bytesTx;
    this.statsPrevRx = this.bytesRx;
    this.statsPrevAppRx = this.bytesAppRx;
    this.statsPrevAppTx = this.bytesAppTx;
    this.statsPrevMs = now;
  }

  /** Seconds until the next idle probe, or -1 when the feature is off. */
  private probeDueSec(now: number): number {
    if (this.opts.probe === false) return -1;
    if (this.probeRunning) return 0;
    if (this.probeNextMs === 0) return Math.round((this.opts.probeIntervalMs ?? PROBE_INTERVAL_MS) / 1000);
    return Math.max(0, Math.round((this.probeNextMs - now) / 1000));
  }

  /**
   * One idle-time measurement, on a cadence.
   *
   * The gate is application bytes, not wire bytes: a session that is only
   * exchanging keepalives and ACKs is idle by any measure a user cares about, and
   * gating on wire traffic would mean the probe never runs. The probe is also
   * skipped while any stream has bytes in flight or queued — measuring a path
   * that is already carrying data reports the user's traffic, and adds a
   * megabyte to it.
   *
   * If no session is established at all (fresh start, or the pool idled out
   * after five minutes of silence) one is created: "idle" is precisely the state
   * in which the user has nothing connected, so a probe that required a live
   * session would never run when it matters.
   */
  private maybeProbe(now: number): void {
    // Manual request bypasses both the feature switch and the idle/schedule
    // gates. Automatic probing still respects all three.
    const manual = this.probePending;
    if (manual) this.probePending = false;
    if (!manual && this.opts.probe === false) return;
    if (this.probeRunning) {
      // The session carrying the run can die mid-train; without this the flag
      // would stay set and no later probe would ever start.
      let live = false;
      for (const entry of this.pool) if (entry.session.pathProbeRunning) { live = true; break; }
      if (live) return;
      this.probeRunning = false;
    }
    const interval = this.opts.probeIntervalMs ?? PROBE_INTERVAL_MS;
    if (!manual) {
      if (this.probeNextMs === 0) {
        this.probeNextMs = Math.max(now, this.lastAppByteMs) + interval;
        return;
      }
      if (now < this.probeNextMs) return;
      if (now - this.lastAppByteMs < PROBE_IDLE_MS) {
        // Busy: do not consume the schedule, come back when it might be idle.
        this.probeNextMs = now + Math.min(interval, PROBE_RETRY_MS * 6);
        return;
      }
    }
    let target: Session | null = null;
    for (const entry of this.pool) {
      const s = entry.session;
      if (!s.pathProbeReady || s.pathProbeRunning) continue;
      if (!manual && (s.inflightBytes > 0 || s.queuedBytes > 0)) continue;
      target = s;
      break;
    }
    if (!target) {
      // A manual ask with no live session creates one and retries on the next
      // tick, once the handshake has had a chance to complete.
      if (this.pool.length === 0) this.ensurePoolEntry();
      if (manual) this.probePending = true;
      this.probeNextMs = now + PROBE_RETRY_MS;
      return;
    }
    const budget = this.opts.probeBudgetBytes ?? PROBE_BUDGET_BYTES;
    if (!target.startPathProbe(budget)) {
      if (manual) this.probePending = true;
      this.probeNextMs = now + PROBE_RETRY_MS;
      return;
    }
    this.probeRunning = true;
    this.probeNextMs = now + interval;
    this.log(`path probe: ${Math.round(budget / 1024)} KiB train, ${manual ? 'manual' : `idle ${Math.round((now - this.lastAppByteMs) / 1000)}s`}, mtu=${target.mtuLimits.mtu}`);
  }

  private onPathProbe(r: SessionProbeResult): void {
    this.probeRunning = false;
    ++this.probeCount;
    const report = probeReport(r, { mtu: r.mtu, d: r.d, k: r.k });
    this.opts.onProbe?.(report);
    const pct = (v: number): string => (v < 0 ? '—' : `${(v * 100).toFixed(1)}%`);
    const mbs = (v: number): string => (v <= 0 ? '—' : `${(v / 1048576).toFixed(2)} MB/s`);
    this.log(`path probe: up ${mbs(report.up?.ramp ?? 0)} loss ${pct(report.up?.lossRx ?? -1)} · ` +
      `down ${mbs(report.down?.ramp ?? 0)} loss ${pct(report.down?.lossRx ?? -1)} · ` +
      `rtt ${report.up?.rttMin ?? -1}/${report.up?.rttAvg ?? -1}ms · ${Math.round(report.ms / 1000 * 10) / 10}s ` +
      `(${Math.round(report.used / 1024)} KiB)`);
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

  /**
   * Arm the next tick.
   *
   * TICK_MS is the fallback cadence, not the resolution: every session reports
   * its earliest self-driven deadline (delayed ack, partial repair group, TLP,
   * RTO) and the tick is armed for whichever comes first. With nothing pending
   * this collapses to a plain 10 ms interval, so idle sessions cost exactly what
   * they did before.
   */
  private armTick(): void {
    if (!this.running) return;
    this.timer = setTimeout(() => this.tick(), this.nextTickDelayMs());
  }

  private nextTickDelayMs(): number {
    const now = nowMs();
    let delay = TICK_MS;
    for (const b of this.sessions.values()) {
      const d = b.session.nextTimerMs(now);
      if (d > 0 && d < delay) delay = d;
    }
    return Math.max(1, delay);
  }

  private tick(): void {
    const now = nowMs();
    const statsDue = now - this.lastStatsDbgMs >= 2000;
    if (statsDue) this.lastStatsDbgMs = now;
    for (const [key, b] of [...this.sessions]) {
      b.session.onTick(now);
      if (b.session.established && statsDue) {
        const st = b.session.stats();
        traceStreamInterval(b.trace, b.session, st);
        this.dbg(`stats inflight=${b.session.inflightBytes}B rwnd=${b.session.peerWindowBytes}B ` +
          `queued=${b.session.queuedBytes}B retx=${b.session.segsRetransmitted}/${b.session.segsSent} ` +
          `retxSplit=${b.session.retxSplit} k=${st.k} d=${st.d} L=${st.lanes} loss=${(b.session.fecLoss * 100).toFixed(1)}% srtt=${st.srttMs}ms ` +
          `sendBw=${(b.session.sendRateBytesPerMs * 1000 / 1048576).toFixed(2)}MB/s ` +
          `recvNext=${b.session.recvNext} ` +
          `reorder=${b.session.reorderBytes}B delivPending=${b.session.recvPendingBytes}B ` +
          `retxLat=${b.session.retxLatencyP50Ms}/${b.session.retxLatencyP95Ms}ms(n=${b.session.retxLatencyCount}) ` +
          `ackTrunc=${b.session.ackRangesTruncated}/${b.session.ackRangesDropped} ` +
          `authFail=${st.authFail} structFail=${st.structFail}`);
      }
      // Session-level isClosed only: on a shared mux session the default
      // stream may idle out while sid streams live — that must not tear the
      // session down (the default stream's close callback already guards).
      if (b.session.isClosed) { this.sessions.delete(key); b.cleanup(); b.trace?.close(); }
    }
    this.maybeProbe(now);
    // Armed last: onTick is what creates most deadlines (delayed ack, repair
    // group close, TLP), so computing the delay before the loop would always
    // schedule against the previous round's state and miss them.
    this.armTick();
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
    let pendingLocal: Buffer[] = [];
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
    const queueLocal = (b: Buffer, front = false) => {
      if (front) pendingLocal.unshift(Buffer.from(b));
      else pendingLocal.push(Buffer.from(b));
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
      // The FIN is sticky until it has actually reached the tunnel stream:
      // while the pool session is still handshaking, closeWriteConn is still
      // the empty placeholder and connStream is null, so consuming the flag
      // here dropped the local application's half-close on the floor — the
      // target never saw the EOF, and an origin that only answers after EOF
      // never answered at all (the local app hung until the idle timeout).
      // C++ proxy_engine.cc keeps want_fin until the stream exists.
      if (session && connStream && !pendingLocal.length && endPending) {
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
        // The handshake landed: allocate this connection's sid stream. Between
        // 0.0.3 peers mux always negotiates (both ends offer TLV 5); a null
        // here means the peer broke the TLV contract — drop the connection.
        connStream = session.openStream(connSid, streamCallbacks);
        if (!connStream) { destroy(); return; }
        // 应用层上行的唯一计数点:隧道接受的字节恰好在此经过一次
        writeConn = (b) => {
          const n = connStream!.write(b, nowMs());
          this.bytesAppTx += n;
          this.lastAppByteMs = nowMs();
          return n;
        };
        consumedConn = (n) => connStream!.consumed(n);
        closeWriteConn = () => connStream!.closeWrite(nowMs());
        rstConn = () => connStream!.sendRst();
        connClosedNow = () => connStream!.isClosed;
      }
      const open = openWriteRequest(target);
      if (!open) { destroy(); return; }
      opened = true;
      this.dbg(`[${saltKey.slice(0, 8)}] OPEN tx ${open.length}B -> ${targetText(target)} (sid ${attachedShared ? connSid : 0})`);
      // The OPEN must be the FIRST byte of the tunnel stream. The local app can
      // already have delivered its body while the handshake was still in
      // flight — a client that pipelines greeting + request + body in one write
      // does exactly that, and `pendingLocal` then holds the body before this
      // function ever runs. Appending the OPEN behind it sent the peer a body
      // with no OPEN in front: its PrefixParser failed, it answered OPEN_ERR
      // NotSupported, and the upload was lost. Unshift instead of push so the
      // OPEN stays first no matter what the backlog already contains.
      queueLocal(open, true);
      if (firstPayload && firstPayload.length) {
        // The OPEN is already at pendingLocal[0] (queueLocal unshifted it).
        // Insert the coalesced first payload right AFTER it, keeping whatever
        // the app queued during the handshake behind both. Rebuilding the array
        // from `rest = pendingLocal` duplicated the OPEN (rest already held it)
        // and leaked a raw FCPO frame into the origin's byte stream. Also count
        // these bytes in the backlog so the 1 MiB pause gate stays accurate.
        pendingLocal.splice(1, 0, Buffer.from(firstPayload));
        pendingLocalBytes += firstPayload.length;
      }
      flushPending();
      this.log(`open sent -> ${targetText(target)}`);
    };

    streamRead = (bytes: Buffer) => {
      // 应用层下行:交付给本地应用(浏览器)的字节,不含任何隧道开销。
      this.bytesAppRx += bytes.length;
      this.lastAppByteMs = nowMs();
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

    /** M1: attach round-robin across the session pool. No per-conn fallback:
     *  both ends are 0.0.3+, mux always negotiates, and the pool's
     *  2 x 255 stream capacity is far beyond realistic concurrency. */
    const openTunnel = (): void => {
      const attached = this.tryAttachPool(sock, streamCallbacks, killConn);
      if (!attached) { destroy(); return; }
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
      this.dbg(`[${saltKey.slice(0, 8)}] session+ (pool${attached.stream ? ' established' : ', awaiting handshake'}) local conn -> ${targetText(target)}`);
      session.onTick(nowMs());
      sendOpen();
    };

    const parseEntry = (): boolean => {
      const kind = detectEntry(entryBuf);
      if (kind === 'need_more') return true;
      if (kind === 'unknown') { destroy(); return false; }
      entryKind = kind;
      this.dbg(`entry detected kind=${kind} bytes=${entryBuf.length}`);
      if (kind === 'socks5') {
        if (!socksGreeted) {
          const g = socks5ParseGreeting(entryBuf);
          if (g.status === 'need_more') return true;
          if (g.status !== 'ok' || !g.value?.noAuth) { destroy(); return false; }
          entryBuf = entryBuf.subarray(g.consumed);
          sock.write(socks5GreetingReply(true));
          socksGreeted = true;
          if (!entryBuf.length) return true;
        }
        const r = socks5ParseRequest(entryBuf);
        if (r.status === 'need_more') return true;
        if (r.status !== 'ok' || !r.value) {
          destroy(socks5Reply(r.status === 'command_not_supported'
            ? Socks5Rep.CommandNotSupported : Socks5Rep.GeneralFailure));
          return false;
        }
        target = r.value; firstPayload = entryBuf.subarray(r.consumed);
        entryBuf = Buffer.alloc(0);
      } else if (kind === 'connect') {
        const r = httpParseConnect(entryBuf);
        if (r.status === 'need_more') return true;
        if (r.status !== 'ok' || !r.value) {
          destroy(r.status === 'head_too_large' ? HTTP_HEAD_TOO_LARGE :
            r.status === 'method_not_allowed' ? HTTP_METHOD_NOT_ALLOWED : HTTP_BAD_REQUEST);
          return false;
        }
        target = r.value; firstPayload = entryBuf.subarray(r.consumed);
        entryBuf = Buffer.alloc(0);
      } else {
        const r = httpParseForward(entryBuf);
        if (r.status === 'need_more') return true;
        if (r.status !== 'ok' || !r.value) {
          destroy(r.status === 'head_too_large' ? HTTP_HEAD_TOO_LARGE :
            r.status === 'method_not_allowed' ? HTTP_FORWARD_METHOD_NOT_ALLOWED : HTTP_BAD_REQUEST);
          return false;
        }
        target = r.value.target;
        firstPayload = Buffer.concat([r.value.rewrittenHead, entryBuf.subarray(r.consumed)]);
        entryBuf = Buffer.alloc(0);
      }
      openTunnel();
      return false;
    };

    sock.on('data', (chunk: Buffer) => {
      if (dead) return;
      if (!target) {
        entryBuf = entryBuf.length ? Buffer.concat([entryBuf, chunk]) : chunk;
        // The head-length limits belong to the parsers: HTTP caps the head at
        // 8 KiB and answers 'head_too_large' itself, SOCKS5 caps its request at
        // 262 B. This guard used to cap the *whole first chunk* at 16 KiB,
        // which is not the same thing — any client that pipelines request +
        // body in one write (curl -T, nc with a here-doc, a browser POST whose
        // body is already in the socket buffer) was killed with a bogus 431
        // before the parser ever ran, and the upload never reached the target.
        // Now the guard only fires when a parser is still asking for more after
        // 16 KiB, which no valid head can do: a complete head always parses and
        // everything after it becomes firstPayload.
        const needMore = parseEntry();
        if (needMore && entryBuf.length > 16384) { destroy(HTTP_HEAD_TOO_LARGE); return; }
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
      if (attachedShared && attachedEntry && connSid) {
        // The local app is gone mid-stream: tell the peer now so its target
        // drains instead of pushing a window into a socket nobody reads. An
        // abort RSTs the sid stream; a graceful close already finished it (the
        // stream's closed callback frees the sid via host.streamClosed).
        if (session && session.established && !connClosedNow()) rstConn();
        else this.releasePoolSid(attachedEntry, connSid);
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
  /** The OPEN passed parsing but the target is still being vetted (the
   *  --deny-private DNS lookup). Bytes that arrive in that window belong to the
   *  OPEN's payload and must be queued, not dropped: consuming them would tell
   *  the peer they were delivered, so nothing would ever resend them. */
  openPending: boolean;
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
  private timer: NodeJS.Timeout | null = null;
  private opts: TunnelOptions;
  private running = false;
  private log: (line: string) => void;
  private dbg: (line: string) => void;
  private newSessionsByIp = new Map<string, { count: number; windowStart: number }>();
  private newSessionsGlobal = { count: 0, windowStart: 0 };
  private preAuthByIp = new Map<string, { count: number; windowStart: number }>();
  private preAuthGlobal = { count: 0, windowStart: 0 };
  private resetReplyByIp = new Map<string, number>();
  /** salt|nonce of bootstrap datagrams already accepted, with their arrival
   *  time. Bounded; see rememberBootstrap(). */
  private seenBootstrap = new Map<string, number>();
  /** See TunnelClient.lastStatsDbgMs: elapsed-time cadence, not modulo. */
  private lastStatsDbgMs = 0;

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
    this.armTick();
    this.log(`server: udp 0.0.0.0:${this.opts.port ?? 4460}`);
  }

  stop(): void {
    this.running = false;
    if (this.timer) clearTimeout(this.timer);
    for (const b of this.sessions.values()) { b.cleanup(); b.trace?.close(); }
    this.sessions.clear();
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

  /** S5 companion: global session-creation budget per second. Per-IP limits do
   *  not bound a distributed flood from spoofed or distinct source addresses;
   *  this one does. HELLOs rejected here are simply dropped — a real client
   *  that is being rate-limited just reconnects a second later, while a flood
   *  gets nothing but a silent hole. */
  private allowNewSessionGlobal(now: number): boolean {
    if (now - this.newSessionsGlobal.windowStart >= RATE_WINDOW_MS) {
      this.newSessionsGlobal = { count: 0, windowStart: now };
    }
    if (this.newSessionsGlobal.count >= MAX_NEW_SESSIONS_GLOBAL) return false;
    this.newSessionsGlobal.count += 1;
    return true;
  }

  /** Charge one datagram against the pre-auth CPU budget. Consumed before the
   *  bootstrap-key decryption, so a rejected packet costs a map lookup and
   *  nothing else. Both windows are 1 s, same as the session budgets. */
  private allowPreAuth(ip: string, now: number): boolean {
    if (now - this.preAuthGlobal.windowStart >= RATE_WINDOW_MS) {
      this.preAuthGlobal = { count: 0, windowStart: now };
    }
    if (this.preAuthGlobal.count >= MAX_PREAUTH_GLOBAL) return false;
    if (this.preAuthByIp.size > RATE_MAP_MAX) this.pruneRateMaps(now);
    const entry = this.preAuthByIp.get(ip);
    if (!entry || now - entry.windowStart >= RATE_WINDOW_MS) {
      this.preAuthByIp.set(ip, { count: 1, windowStart: now });
      this.preAuthGlobal.count += 1;
      return true;
    }
    if (entry.count >= MAX_PREAUTH_PER_IP) return false;
    entry.count += 1;
    this.preAuthGlobal.count += 1;
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
    for (const [ip, e] of this.preAuthByIp) {
      if (now - e.windowStart >= RATE_WINDOW_MS * 10) this.preAuthByIp.delete(ip);
    }
    for (const [ip, t] of this.resetReplyByIp) {
      if (now - t >= RATE_WINDOW_MS * 10) this.resetReplyByIp.delete(ip);
    }
    // Time-based pruning cannot bound a flood of *fresh* spoofed IPs (nothing
    // is old enough to expire), so the map used to grow with the spoofable
    // address space. Evict from the front — Map iterates in insertion order —
    // down to half the cap so the next eviction is amortised.
    while (this.newSessionsByIp.size > RATE_MAP_MAX / 2) {
      const oldest = this.newSessionsByIp.keys().next().value;
      if (oldest === undefined) break;
      this.newSessionsByIp.delete(oldest);
    }
    while (this.preAuthByIp.size > RATE_MAP_MAX / 2) {
      const oldest = this.preAuthByIp.keys().next().value;
      if (oldest === undefined) break;
      this.preAuthByIp.delete(oldest);
    }
    while (this.resetReplyByIp.size > RATE_MAP_MAX / 2) {
      const oldest = this.resetReplyByIp.keys().next().value;
      if (oldest === undefined) break;
      this.resetReplyByIp.delete(oldest);
    }
  }

  /** Identity of one sealed bootstrap datagram: salt (8) | nonce (8). */
  private bootstrapId(msg: Buffer): string | null {
    if (msg.length < SALT_LEN + 8) return null;
    return msg.subarray(0, SALT_LEN + 8).toString('hex');
  }

  private isBootstrapReplay(id: string, now: number): boolean {
    const seen = this.seenBootstrap.get(id);
    return seen !== undefined && now - seen < BOOT_REPLAY_TTL_MS;
  }

  private rememberBootstrap(id: string, now: number): void {
    if (this.seenBootstrap.size >= RATE_MAP_MAX) {
      for (const [k, t] of this.seenBootstrap) {
        if (now - t >= BOOT_REPLAY_TTL_MS) this.seenBootstrap.delete(k);
      }
      while (this.seenBootstrap.size >= RATE_MAP_MAX) {
        const oldest = this.seenBootstrap.keys().next().value;
        if (oldest === undefined) break;
        this.seenBootstrap.delete(oldest);
      }
    }
    this.seenBootstrap.set(id, now);
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
    // A sealed bootstrap datagram (normally a HELLO) carries its salt and nonce
    // in the clear. One recorded by an on-path observer authenticates forever,
    // and each replay from a spoofed source would create a fresh session and
    // reflect a HELLO_ACK to that victim. The replay window is per session, so
    // it cannot catch this; drop exact duplicate datagrams globally instead.
    const bootId = this.bootstrapId(msg);
    if (bootId && this.isBootstrapReplay(bootId, nowMs())) {
      this.dbg(`[${key.slice(0, 8)}] bootstrap replay dropped (${rinfo.address}:${rinfo.port})`);
      return;
    }
    const salt = msg.subarray(0, SALT_LEN);
    // CPU budget for the unknown-salt path, charged before the decryption below
    // rather than after it. Placed here so both outcomes — the gate rejecting
    // junk and the gate accepting a HELLO — cost one budget unit, which is the
    // only way the crypto work an unauthenticated sender can force is bounded.
    if (!this.allowPreAuth(rinfo.address, nowMs())) return;
    // Pre-auth gate. Building a Session costs two Envelopes, the KDF, a Stream,
    // a PathProbe and three controllers — and every 37-byte datagram with an
    // unseen salt used to buy all of it before the ciphertext was even looked
    // at a second time. A real client's first datagram for a new salt is always
    // its HELLO (Session.start() puts nothing else on the wire until it
    // establishes), so decrypting once under the bootstrap key and checking for
    // that shape is the cheapest sufficient test. Anything else is either junk
    // or a v7 session-key packet from a client that outlived our state, and
    // both get the same answer a Session would have produced — a stateless
    // reset — at the cost of one GCM open and zero allocation.
    if (openBootstrapHello(this.opts.psk, salt, msg) === null) {
      if (this.allowResetReply(rinfo.address, nowMs())) {
        const reset = sealReset(this.opts.psk, salt, Direction.S2C, Direction.C2S,
          NONCE_LIMIT - 1n - BigInt(randomBytes(2).readUInt16LE(0)));
        if (reset) {
          this.dbg(`[${key.slice(0, 8)}] no session for salt -> stateless reset tx ${reset.length}B`);
          this.udp.send(reset, rinfo.port, rinfo.address);
        }
      }
      return;
    }
    // Per-IP first: a single source that is already at its own cap must not
    // also drain the global budget, or one flooding host would deny new
    // sessions to every other client while never exceeding its per-IP share.
    if (!this.allowNewSession(rinfo.address, nowMs())) return;
    if (!this.allowNewSessionGlobal(nowMs())) return;
    const created = this.createSession(salt, rinfo);
    if (!created) return;
    const ok = created.session.onWire(msg, nowMs());
    if (created.session.isClosed) {
      // A reset addressed to a salt we no longer own, or a handshake that
      // failed on its first datagram: never publish a dead session.
      created.cleanup();
      created.trace?.close();
      return;
    }
    if (!ok) {
      // The gate above already proved this datagram is a HELLO shape, so a
      // failure here is a bootstrap-key problem the reset path cannot fix.
      created.cleanup();
      created.trace?.close();
      return;
    }
    if (bootId) this.rememberBootstrap(bootId, nowMs());
    this.sessions.set(key, created);
  }

  private armTick(): void {
    if (!this.running) return;
    this.timer = setTimeout(() => this.tick(), this.nextTickDelayMs());
  }

  private nextTickDelayMs(): number {
    const now = nowMs();
    let delay = TICK_MS;
    for (const b of this.sessions.values()) {
      const d = b.session.nextTimerMs(now);
      if (d > 0 && d < delay) delay = d;
    }
    return Math.max(1, delay);
  }

  private tick(): void {
    const now = nowMs();
    const statsDue = now - this.lastStatsDbgMs >= 2000;
    if (statsDue) this.lastStatsDbgMs = now;
    for (const [key, b] of [...this.sessions]) {
      b.session.onTick(now);
      if (b.session.established && statsDue) {
        const st = b.session.stats();
        traceStreamInterval(b.trace, b.session, st);
        this.dbg(`stats inflight=${b.session.inflightBytes}B rwnd=${b.session.peerWindowBytes}B ` +
          `queued=${b.session.queuedBytes}B retx=${b.session.segsRetransmitted}/${b.session.segsSent} ` +
          `retxSplit=${b.session.retxSplit} k=${st.k} d=${st.d} L=${st.lanes} loss=${(b.session.fecLoss * 100).toFixed(1)}% srtt=${st.srttMs}ms ` +
          `sendBw=${(b.session.sendRateBytesPerMs * 1000 / 1048576).toFixed(2)}MB/s ` +
          `recvNext=${b.session.recvNext} ` +
          `reorder=${b.session.reorderBytes}B delivPending=${b.session.recvPendingBytes}B ` +
          `retxLat=${b.session.retxLatencyP50Ms}/${b.session.retxLatencyP95Ms}ms(n=${b.session.retxLatencyCount}) ` +
          `ackTrunc=${b.session.ackRangesTruncated}/${b.session.ackRangesDropped} ` +
          `authFail=${st.authFail} structFail=${st.structFail}`);
      }
      if (b.session.isClosed) {
        this.sessions.delete(key);
        b.cleanup(); b.trace?.close();
        }
    }
    // Write window opened (ACKs arrived) or the target already hit EOF: drain
    // the target->tunnel backlog outside of the socket callback.
    for (const b of this.sessions.values()) {
      if (b.sidTunnels) for (const t of b.sidTunnels.values()) {
        if (t.pendingToTunnel.length || t.endFromTarget) this.pumpToTunnel(t);
      }
    }
    // Armed last: see the client's tick().
    this.armTick();
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
      interleave: this.opts.interleave, ackCopies: this.opts.ackCopies,
      // Negotiation stays on for --no-probe so an explicit probeNow() can run;
      // only the automatic scheduler reads opts.probe.
      probe: this.opts.probeNegotiate !== false,
      mtu: this.opts.mtu ?? DEFAULT_MTU_MIN,
      pmtuMaxMtu: this.opts.pmtuMaxMtu,
      pinnedK: this.opts.pinnedK,
      ack_v2: this.opts.ack_v2, pmtud: this.opts.pmtud, keyUpdate: this.opts.keyUpdate,
      probeBudgetBytes: this.opts.probeBudgetBytes,
      trace: trace?.write,
    };
    let closed = false;
    /** M1: per-sid tunnels on a multiplexed session. */
    const sidTunnels = new Map<number, ServerTunnel>();
    const cleanup = () => {
      if (closed) return;
      closed = true;
      const teardown = (t: ServerTunnel) => {
        t.pendingToTarget.length = 0;
        t.pendingToTunnel.length = 0;
        if (t.targetSock && !t.targetSock.destroyed) t.targetSock.destroy();
      };
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
      read: () => { /* sid 0 carries no connection: pool clients open sids >= 1 */ },
      closed: (reason) => {
        this.log(`session ${key} closed: ${reason}`);
        cleanup();
        this.sessions.delete(key);
        },
      streamHost: {
        inboundStream: (sid) => {
          if (closed) return null;
          let t = sidTunnels.get(sid);
          if (t) return { ...t.callbacks() };
          t = this.newSidTunnel(key, sid, addr, trace);
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
            this.destroyTunnel(t);
          }
        },
      },
      log: this.log,
      debug: this.dbg,
    });
    if (!session.start(nowMs())) { trace?.close(); return null; }
    this.dbg(`[${key.slice(0, 8)}] session+ from ${rinfo.address}:${rinfo.port}`);
    // Deliberately no onTick() here. Ticking before the first datagram has been
    // authenticated made the server emit its own HELLO in response to *any*
    // well-formed 36-byte garbage, i.e. ~3x amplification to a spoofed source.
    // A real client's HELLO is answered by onWire() -> onHello() -> ACK; any
    // other authenticated first packet is followed by a server HELLO on the
    // normal 10 ms tick, after the session has been published.
    return { session, addr, sidTunnels, cleanup, trace };
  }

  /** M1: a tunnel for an inbound sid stream on a multiplexed session. */
  private newSidTunnel(key: string, sid: number, addr: { host: string; port: number }, trace: TraceSink | undefined): ServerTunnel {
    let t: ServerTunnel;
    t = {
      key, addr, sid,
      stream: null as unknown as Stream, // streamReady assigns it before any byte
      parser: new PrefixParser(openParseRequest),
      targetSock: null, openDone: false, openOkSent: false, openPending: false,
      pendingToTarget: [], pendingToTunnel: [],
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
        // Fire-and-forget: the path is async only for the optional DNS check,
        // and a rejection here must not become an unhandled rejection.
        read: (bytes) => { void this.onStreamBytes(t, bytes).catch((e: Error) => {
          this.log(`target handling failed: ${e.message}`);
          t.closeWriteBuf();
        }); },
        closed: () => {},
        eof: () => { if (t.targetSock && !t.targetSock.destroyed) t.targetSock.end(); },
      }),
      trace,
    };
    return t;
  }

  private destroyTunnel(t: ServerTunnel): void {
    t.cleanup();
  }

  /**
   * Drain the tunnel->target FIFO with backpressure. The queued bytes are
   * still charged to the receive window: they are consumed only once the
   * target socket has actually flushed them, so a target that never accepts
   * the connection closes the window instead of letting the peer pile up
   * megabytes here.
   */
  private pumpToTarget(t: ServerTunnel): void {
    const sock = t.targetSock;
    if (!sock || sock.destroyed || !t.openOkSent) return;
    while (t.pendingToTarget.length) {
      // write() returning false means "queued, but above the high-water mark",
      // not "rejected". Keeping the chunk and writing it again on 'drain'
      // duplicated every upload chunk that crossed the 16 KB buffer: the target
      // received the same bytes twice and the request stream was corrupted.
      const b = t.pendingToTarget.shift()!;
      // The window is released when the bytes reach the target socket, not
      // when they are queued.
      const flushed = sock.write(b, () => t.consumeBuf(b.length));
      if (!flushed) break;
    }
  }

  /**
   * --deny-private check for one OPEN target.
   *
   * A literal target is judged directly (no DNS in the path). A domain target
   * is resolved first and EVERY answer must pass — one private record in a
   * round-robin set is a way in. A resolution failure is not a refusal: it
   * will surface as ENOTFOUND on connect(), which is the honest answer, and
   * refusing here would hide it behind a misleading "refused".
   */
  private async targetAllowed(target: ProxyTarget, host: string): Promise<boolean> {
    if (target.atyp === ATYP_IPV4) return !ipv4Denied([...target.addr]);
    if (target.atyp === ATYP_IPV6) return !ipv6Denied(target.addr);
    // family: 4 to match the dial below (a domain target connects with
    // family: 4, so the process never reaches the AAAA records). Resolving
    // with `all: true` alone pulled AAAA in as well and refused any public
    // host that happens to publish a private IPv6 answer, even though that
    // address could not have been dialled — a false refusal, logged as
    // "target refused (private address space)" with no way to tell why.
    const answers = await new Promise<Array<{ address: string; family: number }>>((resolve) => {
      dnsLookup(host, { all: true, family: 4 }, (err, addrs) => {
        if (err || !addrs) { resolve([]); return; }
        resolve(addrs as Array<{ address: string; family: number }>);
      });
    });
    if (answers.length === 0) return true; // let connect() report the real error
    // One private answer in a round-robin set is a way in.
    return answers.every((a) => !ipDenied(a.family, a.address));
  }

  private async onStreamBytes(t: ServerTunnel, bytes: Buffer): Promise<void> {
    if (t.openDone) {
      const sock = t.targetSock;
      if (!sock || sock.destroyed) {
        // Still being vetted (--deny-private does a DNS lookup before connect):
        // the bytes are part of the OPEN payload, so queue them in the FIFO and
        // keep them charged to the window. Dropping them here was silent data
        // loss — consumeBuf() marks them "taken" and the peer never resends.
        if (t.openPending) { t.pendingToTarget.push(bytes); return; }
        // Target is gone (OPEN was refused, connect failed, or the socket was
        // destroyed). Drop rather than queue forever.
        t.consumeBuf(bytes.length);
        return;
      }
      // Before 'connect' fires (or while a backlog is waiting), bytes must not
      // bypass pendingToTarget: Node flushes its connect buffer ahead of any
      // later write, so a direct sock.write() here would overtake the OPEN
      // payload and reorder the stream. Everything goes through the FIFO.
      //
      // The bytes are NOT consumed here. consumeBuf() is the "the target
      // application took these bytes" signal, and releasing it at queue time
      // threw the receive window away: a target whose TCP connect hangs (a
      // black-holed address keeps connect() pending for the full 10 s) then
      // buffered every byte the peer sent — 42.7 MB measured, with the peer's
      // window never closing because deliveryPending stayed at 0. C++
      // proxy_engine.cc counts the queued bytes towards the window for
      // exactly this reason ("counting only app_in there would keep the
      // window open and let the peer grow stream_in without bound").
      if (!t.openOkSent || t.pendingToTarget.length) {
        t.pendingToTarget.push(bytes);
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
    // Only the OPEN header is protocol overhead. The coalesced first payload
    // is application data: it stays charged to the receive window until the
    // target socket has flushed it (see onStreamBytes / pumpToTarget).
    t.consumeBuf(bytes.length - rest.length);
    if (rest.length) t.pendingToTarget.push(rest);
    const target = r.value;
    this.dbg(`[${t.key.slice(0, 8)}] OPEN rx target=${targetText(target)}:${target.port} firstPayload=${rest.length}B`);
    const host = dialHost(target);
    // --deny-private: refuse before connect() when the target points into the
    // server's own network. openDone is already set, so bytes that arrive while
    // the lookup runs land in pendingToTarget (see the openPending branch in
    // onStreamBytes) and wait for OPEN_OK, the same path they take before
    // 'connect' fires.
    if (this.opts.denyPrivate) {
      t.openPending = true;
      let allowed = false;
      try { allowed = await this.targetAllowed(target, host); }
      finally { t.openPending = false; }
      if (!allowed) {
        this.log(`target refused (private address space): ${targetText(target)}`);
        t.pendingToTarget.length = 0;
        t.writeBuf(openWriteErr(OpenError.Refused));
        t.closeWriteBuf();
        return;
      }
    }
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

export { OPEN_MAX_BYTES, MAX_PREAUTH_PER_IP };
