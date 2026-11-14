// FCP Node CLI. Mirrors apps/cli/cli.cc Usage: same defaults (UDP 4460,
// local proxy 1080, MTU 1400, FEC 10:4), same key sources, same long flags.
// Zero runtime dependencies; run with `node src/app/cli.ts server|client ...`.

import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { createServer, connect } from 'node:net';
import { randomBytes } from 'node:crypto';
import {
  PRODUCT_VERSION, DEFAULT_MTU_MIN, DEFAULT_PMTU_MAX_MTU, DEFAULT_D, DEFAULT_P,
} from '../constants.ts';
import { TunnelClient, TunnelServer, type TunnelOptions } from './tunnel.ts';
import {
  flushTraces, normaliseTracePrefix, resolveTraceFiles, summariseTrace,
} from '../util/trace.ts';
import { makeLogger } from '../util/log.ts';

const USAGE = `FCP ${PRODUCT_VERSION} (Node.js port)
Usage:
  node cli.ts server [options]
  node cli.ts client [options]
  node cli.ts speedtest [--seconds=N] [options]
  node cli.ts metrics-report --metrics=PREFIX

Key (required, both ends equal):
  --key=HEX32           16-byte pre-shared key, 32 hex chars.
                        (--key-file / --psk-file / -k / --key-env / FCP_PSK were
                        all removed: one inline value, nothing left to resolve)

Server:
  -b, --bind=IP[:P]     UDP listen address (default 0.0.0.0:4460)

Client:
  --peer=IP[:P]         FCP server to connect to (required; port defaults to 4460)
  -b, --bind=IP[:P]     local proxy listen address (default 127.0.0.1:1080)
                        one port speaks SOCKS5, HTTP CONNECT and absolute-form HTTP

  (-p/--port was removed: the address already carries its port, so the flag only
  offered a second, conflicting way to say the same thing. Write :P instead.)

  -b always means "bind locally" and --peer always means "connect there", on
  both ends. (-H/--host and -l/--listen/--local-port were removed: they named
  the same two concepts twice.)

speedtest:
  --seconds=N           seconds per direction, 3..30 (default 8)
                        (--speedtest-seconds=N is accepted as the old spelling)

MTU (PMTUD is ON by default):
  --mtu-min=N           datagram bytes incl. the 20B IP + 8B UDP headers where the
                        probe walk STARTS (default 1040; 128..9000). It is a FLOOR,
                        not a cap: the tunnel grows past it as the path proves it.
                        With --no-pmtud this becomes the fixed budget.
                        (--packet-size / --mtu / -m were removed; they are rejected)
  --mtu-max=N           ceiling for the walk (default 1500, raised to --mtu-min when
                        that is higher; 128..9000, >= --mtu-min).
                        Probes step up by 100B until the path answers or this is hit.
  --no-pmtud            disable probing and pin the datagram budget at --mtu-min
                        (--pmtud is gone: probing is already the default)

Common:
  --fec=D:P             frame geometry (default 10:4); P is the per-set parity
                        CEILING, and it is also the ceiling the adaptive
                        controller may raise k to. The sender starts at
                        min(3,P) and adjusts k itself from loss feedback, so
                        there is no --parity / --k / --fec-budget knob any more
                        (all three are rejected).
  --metrics=PREFIX      per-session controller metrics, one JSONL file per
                        session: <PREFIX>-client-<salt>.jsonl (and -server-).
                        Records the adaptive controllers' decisions (fec_k)
                        and estimates (bbr). The directory is created if
                        missing; read the files back with:
                        metrics-report --metrics=PREFIX
  --log-level=LEVEL     debug|info|warn|error|off (default info)
                        debug adds per-datagram / per-segment / per-connection traces
                        (--log was removed; it is rejected, not ignored)
  --log-file=PATH       also append every log line to PATH (creates parent dirs)
  -h, --help            print this help and exit; the first line carries the version
                        (--version was removed: -h already prints it)

Boolean switches (--no-pmtud --help) never consume the next argument;
write --name=value for options that take a value. Numeric options are
range-checked and fail loudly instead of silently falling back to the default.

ACK v2 (the wide ACK carrying up to 64 SACK blocks instead of one rotating
block) is offered unconditionally; --ack-v2 / --tlv were removed because there
was no longer anything to choose. An older peer that offers no TLV still
negotiates down to the classic ACK on its own.

The #84 epoch key roll is likewise always offered (TLV type=4) and only
switches on when BOTH ends offer it, so a peer that cannot roll simply keeps
the session key. --key-update was removed: it had no off-state worth keeping,
and one-sided use is settled by the TLV handshake rather than by a flag.

Node.js-only differences from the C++ CLI: speedtest uses an in-process
loopback; metrics-report summarises --metrics JSONL instead of replaying it.
See docs/移植对照与差异.md for the full delta list.
`;

// Boolean switches never take a value. The whitelist matters: without it the
// parser used "the next token does not start with -" to decide, so `--no-pmtud 3`
// silently swallowed the 3 and every later positional shifted.
const BOOL_FLAGS = new Set([
  'help', 'no-pmtud',
]);

const ALIASES: Record<string, string> = {
  b: 'bind', h: 'help',
};

// Everything the parser is allowed to produce. Anything else is a typo, and a
// typo used to be dropped in silence (e.g. `--speedtest`, which no code path
// ever reached because the client branch matched first).
const KNOWN_OPTS = new Set([
  'key', 'bind', 'peer', 'mtu-min', 'mtu-max', 'fec', 'metrics',
  'log-level', 'log-file', 'seconds', 'speedtest-seconds', 'positional',
]);

// Renamed knobs that must fail loudly instead of being dropped as "unknown".
// Silence would be worse than the error: an ignored `-m 1040` reverts to 1400
// (peer budget mismatch, every oversize symbol silently dropped) and an
// ignored `--log=debug` reverts to info (the traces you asked for vanish).
const REMOVED_OPTS: Record<string, { use: string; why: string; short?: boolean }> = {
  mtu: { use: '--mtu-min=N (and --mtu-max=N)', why: 'the budget is now a probe floor, the old fixed cap would pin the path' },
  m: { use: '--mtu-min=N (and --mtu-max=N)', why: 'the budget is now a probe floor, the old fixed cap would pin the path', short: true },
  'packet-size': { use: '--mtu-min=N (and --mtu-max=N)', why: 'packet-size was a hard cap; the budget now starts at a floor and grows by PMTUD' },
  log: { use: '--log-level=LEVEL', why: 'the default info level would silently drop the debug traces' },
  parity: { use: '--fec=D:P to raise the P ceiling; k itself is automatic', why: 'a pinned k disables the loss-driven adaptation, which is the whole point of the controller' },
  'fec-budget': { use: '--fec=D:P: P is the ceiling k may climb to', why: 'the ratio never bounded anything (the default 0.8 mapped to k=7, above the agreed P, so the extra parity was dropped by the peer as IndexPastS); the agreed P is the only honest ceiling' },
  k: { use: '--fec=D:P to raise the P ceiling; k itself is automatic', why: 'the old C++ spelling of --parity; pinning k disables loss-driven adaptation' },
  pmtud: { use: '--no-pmtud, and only if you want probing OFF', why: 'probing is already the default, so the switch only restated it and invited the opposite reading' },
  'key-file': { use: '--key=HEX32', why: 'a file only wrapped the same 32 hex chars in a path that could fail with ENOENT' },
  'psk-file': { use: '--key=HEX32', why: 'a file only wrapped the same 32 hex chars in a path that could fail with ENOENT' },
  'key-env': { use: '--key=HEX32', why: 'the key is now one inline value, so there is no env lookup to resolve or get wrong' },
  host: { use: '--peer=IP[:P]', why: 'the client needs one name for the remote address, and -b now means "bind locally" on both ends' },
  H: { use: '--peer=IP[:P]', why: 'the client needs one name for the remote address, and -b now means "bind locally" on both ends', short: true },
  listen: { use: '-b/--bind=IP[:P]', why: 'the local listen address is the same concept on both ends, so it gets the same flag' },
  l: { use: '-b/--bind=IP[:P]', why: 'the local listen address is the same concept on both ends, so it gets the same flag', short: true },
  'local-port': { use: '-b/--bind=IP:P', why: 'one bind address already carries its port, so a second port flag was a redundant way to say the same thing' },
  port: { use: '-b/--bind=IP:P or --peer=IP:P', why: 'the address already carries its port; a separate flag could contradict it, and silently won over the address' },
  p: { use: '-b/--bind=IP:P or --peer=IP:P', why: 'the address already carries its port; a separate flag could contradict it, and silently won over the address', short: true },
  tlv: { use: 'nothing: the always-on ACK v2 offer sets CAP_TLV by itself', why: 'the switch advertised no TLV type of its own, so it could not change the wire' },
  'ack-v2': { use: 'nothing: the wide ACK is always offered now', why: 'keeping it as a flag implied the classic ACK was still a real choice, and one forgotten flag silently halved SACK coverage' },
  version: { use: '-h (the first line prints the version)', why: 'a second way to ask for the same string only created room for the two to disagree' },
  trace: { use: '--metrics=PREFIX', why: 'it records controller decisions/estimates (fec_k, bbr), not packet traces; --metrics says so' },
  'key-update': { use: 'nothing: the epoch key roll is always offered, and engages only when both ends offer TLV type 4', why: 'the flag had no useful off-state; whether the session key can roll is a fact about the peer, settled in the handshake' },
};

function parseArgs(argv: string[]): { mode: string; opts: Map<string, string>; flags: Set<string> } {
  const mode = argv[0] && !argv[0].startsWith('-') ? argv[0] : 'help';
  const rest = mode === 'help' ? argv : argv.slice(1);
  const opts = new Map<string, string>();
  const flags = new Set<string>();
  for (let i = 0; i < rest.length; ++i) {
    const a = rest[i];
    if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      if (eq >= 0) { opts.set(a.slice(2, eq), a.slice(eq + 1)); continue; }
      const name = a.slice(2);
      if (BOOL_FLAGS.has(name)) { flags.add(name); continue; }
      const next = rest[i + 1];
      if (next !== undefined && !next.startsWith('-')) { opts.set(name, next); ++i; }
      else flags.add(name);
      continue;
    }
    if (a.startsWith('-') && a.length > 1) {
      // `-k` was a file argument that nobody needs any more: the key is 32 hex
      // chars, so the short form only added a path and an ENOENT.
      if (a[1] === 'k') {
        throw new Error('-k is no longer accepted; use --key=HEX32 (32 hex chars); ' +
          'reading a key from a file was dropped');
      }
      const key = ALIASES[a[1]] ?? a[1];
      const inline = a.length > 2 ? a.slice(2).replace(/^=/, '') : '';
      const next = rest[i + 1];
      if (inline) opts.set(key, inline);
      else if (BOOL_FLAGS.has(key)) flags.add(key);
      else if (next !== undefined && !next.startsWith('-')) { opts.set(key, next); ++i; }
      else flags.add(key);
      continue;
    }
    opts.set('positional', a);
  }
  return { mode, opts, flags };
}

function splitHostPort(value: string | undefined, defaultHost: string, defaultPort: number): { host: string; port: number } {
  if (!value) return { host: defaultHost, port: defaultPort };
  const v = value.trim();
  if (!v) return { host: defaultHost, port: defaultPort };
  let hostPart = v;
  let portPart = '';
  if (v.startsWith('[')) {
    // Bracketed IPv6 literal: [::1]:4460. The brackets are URL syntax, not
    // part of the address, and Node's bind/connect want the bare form.
    const close = v.indexOf(']');
    if (close < 0) throw new Error(`invalid address "${v}": missing ']'`);
    hostPart = v.slice(1, close);
    const rest = v.slice(close + 1);
    if (rest) {
      if (rest[0] !== ':') throw new Error(`invalid address "${v}": expected ":port" after ']'`);
      portPart = rest.slice(1);
    }
  } else {
    const first = v.indexOf(':');
    const last = v.lastIndexOf(':');
    if (first >= 0 && first === last) {
      hostPart = v.slice(0, first);
      portPart = v.slice(first + 1);
    }
    // More than one colon is a bare IPv6 literal: keep it whole and use the
    // default port instead of reading its last group as a port.
  }
  if (!hostPart) hostPart = defaultHost;
  if (!portPart) return { host: hostPart, port: defaultPort };
  const port = Number(portPart);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`invalid port "${portPart}" in "${v}": expected 1..65535`);
  }
  return { host: hostPart, port };
}

function loadKey(opts: Map<string, string>): Buffer {
  const hex = opts.get('key');
  if (hex === undefined) {
    throw new Error('--key is required: 32 hex chars (16-byte PSK), identical on both ends');
  }
  const clean = hex.replace(/\s+/g, '').replace(/^0x/i, '');
  if (!/^[0-9a-fA-F]{32}$/.test(clean)) {
    // Never echo the value: a malformed key is still a secret.
    throw new Error(`--key expects exactly 32 hex chars (16 bytes), got ${hex.length} char(s)`);
  }
  return Buffer.from(clean, 'hex');
}

/** Integer option with an explicit range; bad input fails instead of defaulting. */
function intOpt(opts: Map<string, string>, name: string, def: number, min: number, max: number): number {
  const raw = opts.get(name);
  if (raw === undefined) return def;
  const n = Number(raw);
  if (!Number.isInteger(n) || n < min || n > max) {
    throw new Error(`--${name} expects an integer in ${min}..${max}, got "${raw}"`);
  }
  return n;
}

function parseFec(v: string | undefined): { d: number; p: number } {
  if (!v) return { d: DEFAULT_D, p: DEFAULT_P };
  const m = /^(\d+):(\d+)$/.exec(v);
  if (!m) throw new Error(`--fec expects D:P, got ${v}`);
  const d = Number(m[1]), p = Number(m[2]);
  if (d < 1 || d > 256 || p < 0 || p > 7 || d + p > 256) throw new Error(`--fec out of range: ${v}`);
  return { d, p };
}

async function speedtest(base: TunnelOptions, seconds: number): Promise<void> {
  // In-process loopback: a real FCP tunnel (handshake + envelope + FEC +
  // FCP-STREAM) carrying a local TCP echo, measured over the proxy port.
  const echo = createServer((s) => s.pipe(s));
  await new Promise<void>((r) => echo.listen(0, '127.0.0.1', r));
  const echoPort = (echo.address() as { port: number }).port;
  const udpPort = 40000 + Math.floor(Math.random() * 10000);
  const proxyPort = 30000 + Math.floor(Math.random() * 10000);
  const server = new TunnelServer({ ...base, port: udpPort, log: () => {} });
  const client = new TunnelClient({ ...base, host: '127.0.0.1', port: udpPort, listenPort: proxyPort, log: () => {} });
  await server.start();
  await client.start();

  const greeting = Buffer.from([0x05, 0x01, 0x00]);
  const req = Buffer.concat([
    Buffer.from([0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1]),
    Buffer.from([(echoPort >>> 8) & 0xff, echoPort & 0xff]),
  ]);
  const sock = connect(proxyPort, '127.0.0.1');
  let phase: 'greeting' | 'reply' | 'data' = 'greeting';
  let sent = 0, received = 0;
  const chunk = randomBytes(1024);
  const start = Date.now();
  const endAt = start + seconds * 1000;
  let resolveDone: () => void = () => {};
  const done = new Promise<void>((r) => { resolveDone = r; });
  sock.on('connect', () => sock.write(greeting));
  sock.on('data', (b: Buffer) => {
    if (phase === 'greeting') { phase = 'reply'; sock.write(req); return; }
    if (phase === 'reply') {
      if (b.length < 10 || b[1] !== 0) { sock.destroy(); resolveDone(); return; }
      phase = 'data';
      for (let i = 0; i < 16; ++i) { sock.write(chunk); sent += chunk.length; }
      return;
    }
    received += b.length;
    if (Date.now() < endAt) { sock.write(chunk); sent += chunk.length; }
    else { sock.destroy(); resolveDone(); }
  });
  sock.on('error', () => resolveDone());
  sock.on('close', () => resolveDone());
  await Promise.race([done, new Promise<void>((r) => setTimeout(r, (seconds + 5) * 1000))]);
  // The timeout branch used to leave this socket open, which kept the event
  // loop alive after the report and made `speedtest` hang until killed.
  sock.destroy();
  const elapsed = Math.max(1, Date.now() - start) / 1000;
  process.stdout.write(
    `FCP speedtest (in-process loopback, ${seconds}s):\n` +
    `  tx ${sent} B  rx ${received} B  ${(received * 8 / elapsed / 1e6).toFixed(2)} Mbit/s rx\n` +
    `  sessions: client=${client.sessionCount} server=${server.sessionCount}\n`,
  );
  client.stop(); server.stop(); echo.close();
}

async function metricsReport(prefix: string): Promise<void> {
  // The directory comes from the prefix. It used to come from the working
  // directory, which reported "0 files" for every absolute --metrics path.
  const files = resolveTraceFiles(prefix);
  if (files.length === 0) {
    throw new Error(`metrics-report ${prefix}: no ${normaliseTracePrefix(prefix)}-client-*.jsonl ` +
      'or -server-*.jsonl found (tracing writes one file per session)');
  }
  const s = summariseTrace(files);
  process.stdout.write(
    `metrics-report ${prefix}: ${s.files} file(s), ${s.events} events` +
    `${s.malformed ? `, ${s.malformed} malformed line(s)` : ''}\n`,
  );
  for (const [k, v] of [...s.kinds].sort((a, b) => b[1] - a[1])) {
    process.stdout.write(`  ${k}: ${v}\n`);
  }
}

/**
 * Fail fast on a bad --metrics prefix: create its directory now instead of
 * letting the first handshake find out. The old writer opened the file lazily
 * and an unhandled 'error' from that open killed the server at handshake time.
 */
function prepareTracePrefix(raw: string): string {
  const prefix = normaliseTracePrefix(raw);
  mkdirSync(dirname(prefix), { recursive: true });
  return prefix;
}

async function main(): Promise<void> {
  const { mode, opts, flags } = parseArgs(process.argv.slice(2));
  // Removed-knob check runs before the help shortcut on purpose: `--version`
  // would otherwise be parsed as mode "help" (argv[0] starts with -) and print
  // the usage instead of saying why it is gone.
  for (const name of [...opts.keys(), ...flags]) {
    const removed = REMOVED_OPTS[name];
    if (removed) {
      // `short` marks the entries that really were single-dash options; `k` is the
      // long `--k`, so a blanket "length === 1" test would mislabel it.
      const shown = removed.short ? `-${name}` : `--${name}`;
      throw new Error(`${shown} is no longer accepted; use ${removed.use} ` +
        `(the old spelling is rejected on purpose: ${removed.why})`);
    }
  }
  if (flags.has('help') || opts.has('help') || mode === 'help') { process.stdout.write(USAGE); return; }
  const logLevel = opts.get('log-level') ?? 'info';
  if (!['debug', 'info', 'warn', 'error', 'off'].includes(logLevel)) {
    throw new Error(`--log-level expects debug|info|warn|error|off, got "${logLevel}"`);
  }
  const log = makeLogger(logLevel, opts.get('log-file'));
  for (const name of opts.keys()) {
    if (!KNOWN_OPTS.has(name)) log(`WRN unknown option --${name} ignored (see --help)`);
  }
  for (const name of flags) {
    if (!BOOL_FLAGS.has(name)) {
      log(`WRN unknown switch --${name} ignored (see --help; speedtest is a subcommand, not a flag)`);
    }
  }

  // The wide ACK is no longer a choice: offering it costs 1 TLV byte in the
  // handshake and a peer that cannot speak it negotiates down by itself, so the
  // only thing the old flag did was let one end forget it and halve SACK
  // coverage without any visible symptom. The epoch key roll is offered on the
  // same terms — one extra empty TLV, gated by the peer's answer.
  const fecGeo = parseFec(opts.get('fec'));
  const debugLog = logLevel === 'debug' ? (l: string) => log(`DBG ${l}`) : undefined;
  const mtuMin = intOpt(opts, 'mtu-min', DEFAULT_MTU_MIN, 128, 9000);
  // A floor above the default ceiling is a legal configuration, not an error:
  // default the ceiling to the floor instead of demanding a redundant
  // --mtu-max on the command line. An explicit --mtu-max below the floor is
  // still rejected below.
  const mtuMax = intOpt(opts, 'mtu-max', Math.max(DEFAULT_PMTU_MAX_MTU, mtuMin), 128, 9000);
  if (mtuMax < mtuMin) {
    throw new Error(`--mtu-max=${mtuMax} is below --mtu-min=${mtuMin}; the probe walk needs a ceiling at or above its floor`);
  }
  const common: TunnelOptions = {
    psk: Buffer.alloc(16),
    mtu: mtuMin,
    pmtuMaxMtu: mtuMax,
    ...fecGeo,
    // PMTUD is ON by default now. CAP_PMTUD (bit4) used to be a hard caps gate
    // against C++ 0.0.19 peers, but the tunnel is Node<->Node only, so the
    // negotiation risk is gone and the path can grow itself.
    pmtud: !flags.has('no-pmtud'),
    ack_v2: true,
    keyUpdate: true,
    log,
    debugLog,
  };
  if (mode === 'metrics-report') {
    if (!opts.has('metrics')) throw new Error('metrics-report requires --metrics=PREFIX');
    await metricsReport(opts.get('metrics')!);
    return;
  }
  if (opts.has('metrics')) common.tracePrefix = prepareTracePrefix(opts.get('metrics')!);
  common.psk = loadKey(opts);

  let tunnel: TunnelClient | TunnelServer;
  if (mode === 'server') {
    const bind = splitHostPort(opts.get('bind'), '0.0.0.0', 4460);
    tunnel = new TunnelServer({
      ...common, listenHost: bind.host, port: bind.port,
      onStats: (line) => process.stdout.write(line + '\n'),
    });
  } else if (mode === 'client') {
    const remote = splitHostPort(opts.get('peer'), '', 4460);
    if (!remote.host) throw new Error('client requires --peer=IP[:P] (the FCP server address)');
    const listen = splitHostPort(opts.get('bind'), '127.0.0.1', 1080);
    tunnel = new TunnelClient({
      ...common, host: remote.host, port: remote.port,
      listenHost: listen.host,
      listenPort: listen.port,
      // Machine channel for the desktop shell: stdout, not `log`, so
      // --log-level=error still reports throughput.
      onStats: (line) => process.stdout.write(line + '\n'),
    });
  } else if (mode === 'speedtest') {
    // --speedtest used to be advertised as a client flag, but the client branch
    // matched first so the flag was unreachable: the subcommand is the only way.
    const raw = opts.get('seconds') ?? opts.get('speedtest-seconds') ?? '8';
    const seconds = Math.min(30, Math.max(3, Number(raw) || 8));
    await speedtest(common, seconds);
    return;
  } else if (mode === 'replay') {
    throw new Error('replay was renamed: use metrics-report --metrics=PREFIX');
  } else {
    throw new Error(`unknown mode "${mode}"; use server | client | speedtest | metrics-report`);
  }

  await tunnel.start();
  let stopping = false;
  const shutdown = () => {
    if (stopping) return; // a second Ctrl-C must not re-enter the flush
    stopping = true;
    tunnel.stop();
    // Trace files are buffered: process.exit() straight after stop() truncated
    // the tail of every file. Wait for the streams to reach 'close' (capped).
    void flushTraces().then(() => process.exit(0), () => process.exit(0));
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
  log(`${mode} started`);
}

main().catch((e: Error) => {
  process.stderr.write(`fcp: ${e.message}\n`);
  process.exitCode = 1;
});
