// Node server <-> Node client self-interop probe.
//
// Starts TWO independent OS processes via the real CLI entry points, over real
// UDP sockets, and proves:
//   1. both sides reach "FCP established" (handshake + key agreement);
//   2. SOCKS5 / HTTP CONNECT / absolute-form HTTP all carry traffic;
//   3. a 320 KiB body crosses FEC + ARQ byte-for-byte intact;
//   4. a client with the wrong PSK never establishes and never gets a reply;
//   5. PMTUD actually raises the datagram budget (a probe gets ACKed and the
//      sender's payloadMax grows) — a receive limit tied to the local send
//      budget would silently kill this.
//
// This is the acceptance line for fcp-node. No C++ binary is involved.
// Usage: node scripts/self-interop.mjs [--json] [--log-dir=DIR]
//   --log-dir writes server.log / client.log / bad.log with full --log-level=debug traces.
import { spawn } from 'node:child_process';
import { createServer, connect } from 'node:net';
import { createSocket } from 'node:dgram';
import { mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const JSON_OUT = process.argv.includes('--json');
const LOG_DIR_ARG = process.argv.find((a) => a.startsWith('--log-dir='));
const LOG_DIR = LOG_DIR_ARG ? LOG_DIR_ARG.slice('--log-dir='.length) : null;
if (LOG_DIR) mkdirSync(LOG_DIR, { recursive: true });
const KEY = '00112233445566778899aabbccddeeff';
const WRONG_KEY = 'ffeeddccbbaa99887766554433221100';
const MARKER = 'FCP-NODE-SELF-OK';
// Deliberately larger than the 256 KiB FCP-STREAM send window: a short
// Stream.write must keep the remainder (and the FIN must not overtake it),
// otherwise the tail of the body is truncated.
const BIG = 320 * 1024;

const children = [];
const logs = { server: [], client: [], bad: [] };
const results = [];
let origin = null;

function log(tag, line) {
  logs[tag].push(line);
  if (!JSON_OUT) process.stderr.write(`[${tag}] ${line}\n`);
}
function add(name, ok, detail) { results.push({ name, ok, detail }); }

function freeUdpPort() {
  return new Promise((res, rej) => {
    const s = createSocket('udp4');
    s.once('error', rej);
    s.bind(0, '127.0.0.1', () => {
      const p = s.address().port;
      s.close(() => res(p));
    });
  });
}
function freeTcpPort() {
  return new Promise((res, rej) => {
    const s = createServer();
    s.once('error', rej);
    s.listen(0, '127.0.0.1', () => {
      const p = s.address().port;
      s.close(() => res(p));
    });
  });
}

function run(tag, args) {
  if (LOG_DIR) args.push(`--log-file=${join(LOG_DIR, `${tag}.log`)}`);
  const c = spawn(process.execPath, args, { cwd: root, stdio: ['ignore', 'pipe', 'pipe'] });
  const feed = (b) => String(b).split(/\r?\n/).filter(Boolean).forEach((l) => log(tag, l));
  c.stdout.on('data', feed);
  c.stderr.on('data', feed);
  c.on('error', (e) => log(tag, `spawn error: ${e.message}`));
  children.push(c);
  return c;
}

function waitFor(predicate, ms, label) {
  return new Promise((res, rej) => {
    const started = Date.now();
    const t = setInterval(() => {
      if (predicate()) { clearInterval(t); res(Date.now() - started); }
      else if (Date.now() - started > ms) {
        clearInterval(t);
        rej(new Error(`timeout (${ms}ms): ${label}`));
      }
    }, 25);
  });
}

// Read an HTTP response (with Content-Length) from a proxy socket after the
// entry handshake has already been performed by the caller.
function collect(sock, expectedLength) {
  return new Promise((res, rej) => {
    const chunks = [];
    let total = 0;
    let done = false;
    const timer = setTimeout(() => finish(new Error('response timeout')), 10000);
    const finish = (err) => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      sock.destroy();
      if (err) return rej(err);
      const all = Buffer.concat(chunks);
      const i = all.indexOf('\r\n\r\n');
      if (i < 0) return rej(new Error('no HTTP header terminator'));
      res({ head: all.subarray(0, i).toString('latin1'), body: all.subarray(i + 4) });
    };
    sock.on('data', (b) => {
      chunks.push(b); total += b.length;
      const all = Buffer.concat(chunks);
      const i = all.indexOf('\r\n\r\n');
      if (i >= 0) {
        const m = /Content-Length:\s*(\d+)/i.exec(all.subarray(0, i).toString('latin1'));
        if (m && total >= i + 4 + Number(m[1])) finish();
        else if (!m && expectedLength === undefined && /Connection:\s*close/i.test(all.subarray(0, i).toString('latin1'))) {
          // no length: rely on 'end'
        }
      }
    });
    sock.on('end', () => finish());
    sock.on('close', () => finish(new Error('socket closed before a complete response')));
    sock.on('error', (e) => finish(e));
  });
}

function httpRequest(path) {
  return Buffer.from(`GET ${path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n`, 'latin1');
}

function socks5(proxyPort, targetPort, path) {
  return new Promise((res, rej) => {
    const sock = connect(proxyPort, '127.0.0.1');
    let phase = 0;
    sock.setTimeout(10000, () => { sock.destroy(); rej(new Error('socks5 timeout')); });
    sock.on('error', rej);
    sock.on('connect', () => sock.write(Buffer.from([5, 1, 0])));
    sock.on('data', (b) => {
      if (phase === 0) {
        if (b[0] !== 5 || b[1] !== 0) { sock.destroy(); rej(new Error(`socks5 greeting rep=${b[1]}`)); return; }
        phase = 1;
        sock.write(Buffer.concat([
          Buffer.from([5, 1, 0, 1, 127, 0, 0, 1]),
          Buffer.from([(targetPort >>> 8) & 0xff, targetPort & 0xff]),
        ]));
      } else if (phase === 1) {
        if (b.length < 2 || b[1] !== 0) { sock.destroy(); rej(new Error(`socks5 connect rep=${b[1]}`)); return; }
        phase = 2;
        sock.removeAllListeners('data');
        collect(sock).then(res, rej);
        sock.write(httpRequest(path));
      }
    });
  });
}

function httpConnect(proxyPort, targetPort, path) {
  return new Promise((res, rej) => {
    const sock = connect(proxyPort, '127.0.0.1');
    let phase = 0;
    sock.setTimeout(10000, () => { sock.destroy(); rej(new Error('CONNECT timeout')); });
    sock.on('error', rej);
    sock.on('connect', () => sock.write(Buffer.from(
      `CONNECT 127.0.0.1:${targetPort} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n`, 'latin1')));
    sock.on('data', (b) => {
      if (phase) return;
      const s = b.toString('latin1');
      if (!s.startsWith('HTTP/1.1 200')) { sock.destroy(); rej(new Error(`CONNECT reply: ${s.split('\r\n')[0]}`)); return; }
      phase = 1;
      sock.removeAllListeners('data');
      collect(sock).then(res, rej);
      sock.write(httpRequest(path));
    });
  });
}

function httpForward(proxyPort, targetPort, path) {
  return new Promise((res, rej) => {
    const sock = connect(proxyPort, '127.0.0.1');
    sock.setTimeout(10000, () => { sock.destroy(); rej(new Error('forward timeout')); });
    sock.on('error', rej);
    sock.on('connect', () => sock.write(Buffer.from(
      `GET http://127.0.0.1:${targetPort}${path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n`, 'latin1')));
    sock.removeAllListeners('data');
    collect(sock).then(res, rej);
  });
}

// Drives a SOCKS5 entry just far enough to prove the local proxy accepted the
// connection, then checks whether a success reply ever arrives. Used for the
// wrong-PSK case: a refused TCP connect must not be mistaken for a rejection.
function probeEntry(port, targetPort) {
  return new Promise((res) => {
    const sock = connect(port, '127.0.0.1');
    let phase = 0;
    const out = { greeted: false, replied: false };
    const finish = () => { sock.destroy(); res(out); };
    const timer = setTimeout(finish, 3000);
    sock.on('error', finish);
    sock.on('close', () => { clearTimeout(timer); finish(); });
    sock.on('connect', () => sock.write(Buffer.from([5, 1, 0])));
    sock.on('data', (b) => {
      if (phase === 0) {
        out.greeted = b[0] === 5 && b[1] === 0;
        phase = 1;
        sock.write(Buffer.concat([
          Buffer.from([5, 1, 0, 1, 127, 0, 0, 1]),
          Buffer.from([(targetPort >>> 8) & 0xff, targetPort & 0xff]),
        ]));
      } else {
        out.replied = true;
        clearTimeout(timer);
        finish();
      }
    });
  });
}

function verifyReply(reply, path, size) {
  if (!reply.head.startsWith('HTTP/1.1 200')) throw new Error(`bad status: ${reply.head.split('\r\n')[0]}`);
  if (!reply.head.includes(`X-FCP-Path: ${path}`)) throw new Error(`wrong path echoed: ${reply.head.split('\r\n')[0]}`);
  if (reply.body.length !== size) throw new Error(`body length ${reply.body.length}, want ${size}`);
  if (size === BIG) {
    for (let i = 0; i < size; ++i) if (reply.body[i] !== (i & 0xff)) throw new Error(`byte mismatch at ${i}`);
  } else if (reply.body.toString() !== MARKER) {
    throw new Error(`bad body: ${reply.body.toString('latin1').slice(0, 40)}`);
  }
  return true;
}

async function shutdown() {
  for (const c of children) if (c.exitCode === null && c.signalCode === null) c.kill();
  await Promise.all(children.map((c) => new Promise((r) => {
    if (c.exitCode !== null || c.signalCode !== null) return r();
    const t = setTimeout(r, 1500);
    c.once('exit', () => { clearTimeout(t); r(); });
  })));
  if (origin) {
    origin.closeAllConnections?.();
    await new Promise((r) => origin.close(r));
  }
}

try {
  const udpPort = await freeUdpPort();
  const proxyPort = await freeTcpPort();
  const badProxyPort = await freeTcpPort();
  const originPort = await freeTcpPort();

  origin = createServer((sock) => {
    let head = Buffer.alloc(0);
    sock.on('data', (b) => {
      head = Buffer.concat([head, b]);
      if (!head.includes('\r\n\r\n')) return;
      const path = head.toString('latin1').split('\r\n')[0].split(' ')[1] ?? '/';
      const size = path.startsWith('/big') ? BIG : MARKER.length;
      const body = path.startsWith('/big')
        ? Buffer.from(Uint8Array.from({ length: size }, (_, i) => i & 0xff))
        : Buffer.from(MARKER);
      sock.write(Buffer.concat([
        Buffer.from(`HTTP/1.1 200 OK\r\nContent-Length: ${size}\r\nConnection: close\r\nX-FCP-Path: ${path}\r\n\r\n`, 'latin1'),
        body,
      ]));
      sock.end();
    });
  });
  await new Promise((r) => origin.listen(originPort, '127.0.0.1', r));

  const common = ['--fec=10:3', '--log-level=debug'];
  run('server', ['src/app/server.ts', `--key=${KEY}`, '-b', `127.0.0.1:${udpPort}`, ...common]);
  run('client', ['src/app/client.ts', `--key=${KEY}`, `--peer=127.0.0.1:${udpPort}`,
    '-b', `127.0.0.1:${proxyPort}`, ...common]);
  // Wrong-PSK peer: same server, different local proxy port.
  run('bad', ['src/app/client.ts', `--key=${WRONG_KEY}`, `--peer=127.0.0.1:${udpPort}`,
    '-b', `127.0.0.1:${badProxyPort}`, ...common]);

  // Wait for both CLI processes to actually bind their sockets. Spawning is
  // async: connecting before "client started" is logged gets ECONNREFUSED and
  // no session (hence no handshake) is ever created.
  await waitFor(() =>
    logs.server.some((l) => l.includes('server started')) &&
    logs.client.some((l) => l.includes('client started')) &&
    logs.bad.some((l) => l.includes('client started')),
  10000, 'CLI processes ready');

  // A session is created lazily, on the first local proxy connection. Kick
  // one off (without awaiting) so the handshake actually starts, then wait for
  // both processes to log "FCP established" and reuse that request as the
  // SOCKS5 test case.
  const kickoff = socks5(proxyPort, originPort, '/socks').catch((e) => e);
  const hasEstablished = (tag) => logs[tag].some((l) => l.includes('FCP established'));
  let hsMs = -1;
  try {
    hsMs = await waitFor(() => hasEstablished('client') && hasEstablished('server'), 12000,
      'client+server FCP handshake');
    add('handshake (2 processes, real UDP)', true, `${hsMs} ms; both sides logged "FCP established"`);
  } catch (e) {
    add('handshake (2 processes, real UDP)', false, e.message);
  }

  if (hsMs >= 0) {
    const cases = [
      ['SOCKS5', () => kickoff, '/socks', MARKER.length],
      ['HTTP CONNECT', () => httpConnect(proxyPort, originPort, '/connect'), '/connect', MARKER.length],
      ['absolute-form HTTP', () => httpForward(proxyPort, originPort, '/forward'), '/forward', MARKER.length],
      ['320 KiB payload', () => socks5(proxyPort, originPort, '/big'), '/big', BIG],
    ];
    for (const [name, fn, path, size] of cases) {
      try {
        const reply = await fn();
        if (reply instanceof Error) throw reply;
        verifyReply(reply, path, size);
        add(name, true, `${reply.body.length} B, X-FCP-Path ${path}`);
      } catch (e) { add(name, false, e.message); }
    }
  } else {
    await kickoff;
    for (const n of ['SOCKS5', 'HTTP CONNECT', 'absolute-form HTTP', '320 KiB payload']) {
      add(n, false, 'skipped: handshake did not complete');
    }
  }

  // Negative: the wrong-PSK peer must accept the local TCP connection (so the
  // probe is meaningful) but never reach "FCP established" and never return a
  // SOCKS5 success reply.
  const badProbe = await probeEntry(badProxyPort, originPort);
  const badEstablished = hasEstablished('bad');
  add('wrong PSK rejected', badProbe.greeted && !badEstablished && !badProbe.replied,
    `local-entry=${badProbe.greeted} established=${badEstablished} socks5-success=${badProbe.replied}`);

  // Scope rejections to the *good* client's salt: the wrong-PSK probe's
  // datagrams are deliberately rejected and would otherwise mask a real
  // failure (and the old /auth_fail|authentication failed|struct fail/ regex
  // matched nothing at all, so the check always passed).
  const goodTag = (logs.client.find((l) => /session start/.test(l))?.match(/\[([0-9a-f]{8})\]/) ?? [])[1];
  const scoped = [
    ...logs.server.filter((l) => !goodTag || l.includes(`[${goodTag}]`)),
    ...logs.client,
  ];
  const authNoise = scoped.filter((l) => /REJECT auth-fail/.test(l));
  const structHigh = [...logs.server, ...logs.client]
    .map((l) => /structFail=(\d+)/.exec(l))
    .filter(Boolean)
    .map((m) => Number(m[1]))
    .filter((n) => n > 0);
  add('no auth/structure failures on the good path',
    authNoise.length === 0 && structHigh.length === 0,
    authNoise.length ? authNoise.slice(0, 3).join(' | ')
      : structHigh.length ? `structFail=${Math.max(...structHigh)}` : 'clean');

  // PMTUD must actually move the budget upward: a probe is sent, the peer
  // accepts it (its receive limit is decoupled from its own send budget) and
  // answers, and the sender raises payloadMax. Without the ACK this is dead.
  const pmtuAcks = [...logs.server, ...logs.client].filter((l) => /PMTU ack mtu=/.test(l));
  // An ACK alone proves nothing: require payloadMax to actually grow from the
  // session-start value (a no-op raiseLimits() used to pass this check).
  const payloadMax = [...logs.client, ...logs.server]
    .map((l) => /payloadMax=(\d+)/.exec(l))
    .filter(Boolean)
    .map((m) => Number(m[1]));
  const grew = payloadMax.length >= 2 && Math.max(...payloadMax) > Math.min(...payloadMax);
  add('PMTUD raises the datagram budget', pmtuAcks.length > 0 && grew,
    pmtuAcks.length
      ? `${pmtuAcks[pmtuAcks.length - 1].trim()} (payloadMax ${Math.min(...payloadMax)} -> ${Math.max(...payloadMax)})`
      : 'no PMTU ack in either log');
} catch (e) {
  add('probe itself', false, e.stack ?? e.message);
} finally {
  await shutdown();
}

const passed = results.filter((r) => r.ok).length;
const failed = results.length - passed;
if (JSON_OUT) {
  process.stdout.write(JSON.stringify({ total: results.length, passed, failed, results }) + '\n');
} else {
  console.log('\nFCP-Node self-interop (Node server <-> Node client)');
  console.log('------------------------------------------- ------ --------------------------------');
  for (const r of results) {
    console.log(`${r.name.padEnd(43)} ${(r.ok ? 'PASS' : 'FAIL').padEnd(6)} ${r.detail}`);
  }
  console.log(`\n${failed === 0 ? 'SELF-INTEROP PASSED' : `${failed} CHECK(S) FAILED`}`);
  if (failed || process.argv.includes('--verbose')) {
    console.log('\n--- full process logs ---');
    for (const [tag, lines] of Object.entries(logs)) {
      console.log(`[${tag}] (${lines.length} lines)`);
      for (const l of lines) console.log(`    ${l}`);
    }
  }
}
process.exit(failed === 0 ? 0 : 1);
