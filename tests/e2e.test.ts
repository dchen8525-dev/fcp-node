// End-to-end tests over real UDP + TCP sockets: start a TunnelServer, a
// TunnelClient and a local HTTP origin, then drive all three local proxy
// entry protocols through the encrypted FCP tunnel.
// Run: node --test tests/e2e.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, connect, type Server } from 'node:net';
import { createSocket } from 'node:dgram';
import { randomBytes } from 'node:crypto';
import { TunnelClient, TunnelServer } from '../src/app/tunnel.ts';
import { DATA_WIRE_OVERHEAD } from '../src/constants.ts';

const PSK = randomBytes(16);
const MARKER = 'FCP-NODE-E2E-OK';

function freePort(): number { return 20000 + Math.floor(Math.random() * 20000); }
function listen(s: Server, port: number): Promise<void> {
  return new Promise((resolve, reject) => {
    s.once('error', reject);
    s.listen(port, '127.0.0.1', () => { s.off('error', reject); resolve(); });
  });
}
function portOf(s: Server): number { return (s.address() as { port: number }).port; }

interface Reply { head: string; body: Buffer; }
function withTimeout<T>(p: Promise<T>, ms: number, label: string): Promise<T> {
  return Promise.race([
    p,
    new Promise<T>((_, reject) => setTimeout(() => reject(new Error(`timeout: ${label}`)), ms)),
  ]);
}

function socks5RoundTrip(proxyPort: number, targetPort: number, request: Buffer): Promise<Reply> {
  return withTimeout(new Promise<Reply>((resolve, reject) => {
    const sock = connect(proxyPort, '127.0.0.1');
    const chunks: Buffer[] = [];
    let phase: 'greeting' | 'reply' | 'data' = 'greeting';
    sock.setTimeout(8000, () => { sock.destroy(); reject(new Error('socks5 socket timeout')); });
    sock.on('connect', () => sock.write(Buffer.from([5, 1, 0])));
    sock.on('error', reject);
    sock.on('data', (b: Buffer) => {
      if (phase === 'greeting') {
        assert.equal(b[0], 5); assert.equal(b[1], 0);
        phase = 'reply';
        sock.write(Buffer.concat([
          Buffer.from([5, 1, 0, 1, 127, 0, 0, 1]),
          Buffer.from([(targetPort >>> 8) & 0xff, targetPort & 0xff]),
        ]));
        return;
      }
      if (phase === 'reply') {
        assert.equal(b.length, 10);
        assert.equal(b[1], 0, `socks5 reply rep=${b[1]}`);
        phase = 'data';
        sock.write(request);
        return;
      }
      chunks.push(b);
    });
    sock.on('end', () => {
      const all = Buffer.concat(chunks);
      const idx = all.indexOf('\r\n\r\n');
      resolve({ head: all.subarray(0, idx).toString('latin1'), body: all.subarray(idx + 4) });
    });
    sock.on('close', () => {
      if (chunks.length) {
        const all = Buffer.concat(chunks);
        const idx = all.indexOf('\r\n\r\n');
        resolve({ head: all.subarray(0, idx).toString('latin1'), body: all.subarray(idx + 4) });
      }
    });
  }), 12000, 'socks5 round trip');
}

function connectRoundTrip(proxyPort: number, targetPort: number, request: Buffer): Promise<Reply> {
  return withTimeout(new Promise<Reply>((resolve, reject) => {
    const sock = connect(proxyPort, '127.0.0.1');
    const chunks: Buffer[] = [];
    let phase: 'connect' | 'data' = 'connect';
    sock.setTimeout(8000, () => { sock.destroy(); reject(new Error('CONNECT socket timeout')); });
    sock.on('connect', () => sock.write(
      Buffer.from(`CONNECT 127.0.0.1:${targetPort} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n`, 'latin1')));
    sock.on('error', reject);
    sock.on('data', (b: Buffer) => {
      if (phase === 'connect') {
        const s = b.toString('latin1');
        assert.ok(s.startsWith('HTTP/1.1 200'), s);
        phase = 'data';
        sock.write(request);
        return;
      }
      chunks.push(b);
    });
    const finish = () => {
      const all = Buffer.concat(chunks);
      const idx = all.indexOf('\r\n\r\n');
      resolve({ head: all.subarray(0, idx).toString('latin1'), body: all.subarray(idx + 4) });
    };
    sock.on('end', finish);
    sock.on('close', () => { if (chunks.length) finish(); });
  }), 12000, 'CONNECT round trip');
}

function forwardRoundTrip(proxyPort: number, targetPort: number, path: string): Promise<Reply> {
  return withTimeout(new Promise<Reply>((resolve, reject) => {
    const sock = connect(proxyPort, '127.0.0.1');
    const chunks: Buffer[] = [];
    sock.setTimeout(8000, () => { sock.destroy(); reject(new Error('forward socket timeout')); });
    sock.on('connect', () => sock.write(Buffer.from(
      `GET http://127.0.0.1:${targetPort}${path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\n\r\n`, 'latin1')));
    sock.on('error', reject);
    sock.on('data', (b: Buffer) => chunks.push(b));
    const finish = () => {
      const all = Buffer.concat(chunks);
      const idx = all.indexOf('\r\n\r\n');
      resolve({ head: all.subarray(0, idx).toString('latin1'), body: all.subarray(idx + 4) });
    };
    sock.on('end', finish);
    sock.on('close', () => { if (chunks.length) finish(); });
  }), 12000, 'absolute-form round trip');
}

test('e2e: SOCKS5 / HTTP CONNECT / absolute-form all work through the FCP tunnel', async (t) => {
  const origin = createServer((sock) => {
    let head = Buffer.alloc(0);
    sock.on('data', (b: Buffer) => {
      head = Buffer.concat([head, b]);
      if (head.includes('\r\n\r\n')) {
        const line = head.toString('latin1').split('\r\n')[0];
        const path = line.split(' ')[1] ?? '/';
        const size = path.startsWith('/big') ? 64 * 1024 : MARKER.length;
        const body = path.startsWith('/big')
          ? Buffer.alloc(size).map((_, i) => i & 0xff)
          : Buffer.from(MARKER);
        sock.write(Buffer.concat([
          Buffer.from(`HTTP/1.1 200 OK\r\nContent-Length: ${size}\r\nConnection: close\r\nX-FCP-Path: ${path}\r\n\r\n`, 'latin1'),
          body,
        ]));
        sock.end();
      }
    });
  });
  await listen(origin, 0);
  const targetPort = portOf(origin);
  const udpPort = freePort(), proxyPort = freePort();
  const logs: string[] = [];
  const log = (line: string) => logs.push(line);
  const server = new TunnelServer({ psk: PSK, port: udpPort, log });
  const client = new TunnelClient({ psk: PSK, host: '127.0.0.1', port: udpPort, listenPort: proxyPort, log });
  await server.start();
  await client.start();
  t.after(() => { client.stop(); server.stop(); origin.close(); });

  const req = (p: string) => Buffer.from(`GET ${p} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n`, 'latin1');

  const socks = await socks5RoundTrip(proxyPort, targetPort, req('/socks'));
  assert.ok(socks.head.startsWith('HTTP/1.1 200'), socks.head);
  assert.ok(socks.head.includes('X-FCP-Path: /socks'));
  assert.equal(socks.body.toString(), MARKER);

  const conn = await connectRoundTrip(proxyPort, targetPort, req('/connect'));
  assert.ok(conn.head.startsWith('HTTP/1.1 200'), conn.head);
  assert.equal(conn.body.toString(), MARKER);

  const fwd = await forwardRoundTrip(proxyPort, targetPort, '/forward');
  assert.ok(fwd.head.startsWith('HTTP/1.1 200'), fwd.head);
  assert.ok(fwd.head.includes('X-FCP-Path: /forward'), 'absolute-form was rewritten to origin-form');
  assert.equal(fwd.body.toString(), MARKER);

  const big = await socks5RoundTrip(proxyPort, targetPort, req('/big'));
  assert.ok(big.head.startsWith('HTTP/1.1 200'), big.head);
  assert.equal(big.body.length, 64 * 1024, '64 KiB crosses FEC + ARQ intact');
  for (let i = 0; i < big.body.length; ++i) assert.equal(big.body[i], i & 0xff);

  assert.equal(client.sessionCount >= 1, true);
  assert.equal(server.sessionCount >= 1, true);
  const authErrors = logs.filter((l) => /auth|fail/i.test(l));
  assert.deepEqual(authErrors, [], 'no authentication or structural failures');
});

test('e2e: wrong PSK cannot establish a tunnel', async (t) => {
  const origin = createServer((sock) => {
    sock.on('data', () => { sock.write('HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok'); sock.end(); });
  });
  await listen(origin, 0);
  const udpPort = freePort(), proxyPort = freePort();
  const server = new TunnelServer({ psk: PSK, port: udpPort, log: () => {} });
  const client = new TunnelClient({ psk: randomBytes(16), host: '127.0.0.1', port: udpPort, listenPort: proxyPort, log: () => {} });
  await server.start();
  await client.start();
  t.after(() => { client.stop(); server.stop(); origin.close(); });
  const sock = connect(proxyPort, '127.0.0.1');
  let greeting = false;
  const result = await withTimeout(new Promise<string>((resolve) => {
    sock.on('connect', () => sock.write(Buffer.from([5, 1, 0])));
    sock.on('data', (b: Buffer) => {
      if (!greeting) { greeting = true; sock.write(Buffer.concat([
        Buffer.from([5, 1, 0, 1, 127, 0, 0, 1]), Buffer.from([0, 80]),
      ])); return; }
      resolve('unexpected-reply');
    });
    sock.on('error', () => resolve('error'));
    sock.on('close', () => resolve('closed'));
    setTimeout(() => resolve('timeout'), 1500);
  }), 3000, 'wrong-PSK probe');
  assert.notEqual(result, 'unexpected-reply', 'a wrong PSK must never get a SOCKS5 success reply');
  assert.equal(server.sessionCount, 0,
    'an unauthenticated datagram is answered with #86 reset and leaves no session behind');
  sock.destroy();
});

test('e2e: sealed bootstrap datagrams are remembered so replays expire', () => {
  // Replaying a captured HELLO after its session is gone authenticates under
  // the static bootstrap key and would create a fresh session (and reflect a
  // HELLO_ACK). The per-session nonce window cannot see this, so the server
  // keeps a bounded global salt|nonce cache.
  const srv = new TunnelServer({ psk: PSK, port: 0, log: () => {} });
  const api = srv as unknown as {
    bootstrapId(b: Buffer): string | null;
    isBootstrapReplay(id: string, now: number): boolean;
    rememberBootstrap(id: string, now: number): void;
  };
  const wire = Buffer.concat([randomBytes(8), Buffer.alloc(8), Buffer.alloc(40)]);
  const id = api.bootstrapId(wire);
  assert.ok(id, 'salt+nonce identifies the datagram');
  assert.equal(api.isBootstrapReplay(id!, 1000), false, 'unseen');
  api.rememberBootstrap(id!, 1000);
  assert.equal(api.isBootstrapReplay(id!, 1000 + 179_000), true, 'still inside the TTL');
  assert.equal(api.isBootstrapReplay(id!, 1000 + 180_001), false, 'forgotten after the TTL');
});

test('e2e: an unauthenticated datagram never produces more bytes than it carried', async (t) => {
  // Creating the session used to tick it once before authenticating anything,
  // so one well-formed 36-byte datagram with a random salt made the server
  // emit its own HELLO (~70 B) *plus* the stateless reset (36 B) to the source
  // address - a ~3x UDP reflector for a spoofed source. A reset is still
  // allowed: it is at most as large as the request.
  const udpPort = freePort();
  const server = new TunnelServer({ psk: PSK, port: udpPort, log: () => {} });
  await server.start();
  t.after(() => server.stop());
  const sock = createSocket('udp4');
  await new Promise<void>((r) => sock.bind(0, '127.0.0.1', () => r()));
  t.after(() => sock.close());
  const replies: Buffer[] = [];
  sock.on('message', (m) => replies.push(Buffer.from(m)));

  const req = Buffer.concat([randomBytes(8), Buffer.alloc(DATA_WIRE_OVERHEAD - 8, 0x41)]);
  assert.equal(req.length, DATA_WIRE_OVERHEAD, 'shaped like the smallest FCP datagram');
  sock.send(req, udpPort, '127.0.0.1');
  await new Promise((r) => setTimeout(r, 250));

  const replyBytes = replies.reduce((n, b) => n + b.length, 0);
  assert.ok(replyBytes <= req.length,
    `replied ${replyBytes}B to a ${req.length}B unauthenticated datagram (amplification)`);
  assert.equal(server.sessionCount, 0, 'an unauthenticated datagram leaves no session behind');
});

test('e2e: window-pressure integrity — bursty upload + paced download stay byte-exact', async (t) => {
  // Both reorder traps live under backpressure: a short Stream.write leaves a
  // remainder queued at the tunnel, and the next local data event must never
  // overtake it (client side), just as pre-connect stream bytes must never
  // overtake the OPEN payload (server side). This test saturates the windows
  // in both directions and checks every byte at the far end.
  const UPLOAD = 3 * 1024 * 1024;
  const DOWNLOAD = 2 * 1024 * 1024;
  let uploadBad = false;
  const origin = createServer((sock) => {
    let rx = 0;
    sock.on('data', (b: Buffer) => {
      for (let i = 0; i < b.length; ++i) {
        if (b[i] !== ((rx + i) & 0xff)) { uploadBad = true; sock.destroy(); return; }
      }
      rx += b.length;
      // Read slower than the tunnel delivers: the server's tunnel->target
      // write backpressures, the advertised rwnd collapses, and the client's
      // session.write starts returning short (residue lands in pendingLocal).
      sock.pause();
      setTimeout(() => sock.resume(), 40);
    });
    sock.on('end', () => {
      if (uploadBad || rx !== UPLOAD) { sock.destroy(); return; }
      let off = 0;
      const writeChunk = () => {
        while (off < DOWNLOAD) {
          const len = Math.min(64 * 1024, DOWNLOAD - off);
          const body = Buffer.alloc(len).map((_, i) => (off + i) & 0xff);
          off += len;
          if (!sock.write(body)) { setTimeout(writeChunk, 4); return; }
        }
        sock.end();
      };
      writeChunk();
    });
  });
  await listen(origin, 0);
  const targetPort = portOf(origin);
  const udpPort = freePort(), proxyPort = freePort();
  const server = new TunnelServer({ psk: PSK, port: udpPort, log: () => {} });
  const client = new TunnelClient({ psk: PSK, host: '127.0.0.1', port: udpPort, listenPort: proxyPort, log: () => {} });
  await server.start();
  await client.start();
  t.after(() => { client.stop(); server.stop(); origin.close(); });

  const outcome = await withTimeout(new Promise<{ downBad: boolean; down: number }>((resolve, reject) => {
    const sock = connect(proxyPort, '127.0.0.1');
    let stage: 'greet' | 'req' | 'stream' = 'greet';
    let sentUp = 0;
    let rxDown = 0;
    let downBad = false;
    const upload = Buffer.alloc(UPLOAD).map((_, i) => i & 0xff);
    const fail = (e: Error) => { sock.destroy(); reject(e); };
    sock.setTimeout(25000, () => fail(new Error(`stress timeout up=${sentUp} down=${rxDown}`)));
    sock.on('error', fail);
    const sendNext = () => {
      if (sentUp >= UPLOAD) { sock.end(); return; }
      // Many mid-size data events with 1 ms gaps: between two of them an ACK
      // opens the send window, which is exactly the interleaving that used to
      // let a direct write overtake the queued remainder.
      const len = Math.min(16384 + Math.floor(Math.random() * 16384), UPLOAD - sentUp);
      sock.write(upload.subarray(sentUp, sentUp + len));
      sentUp += len;
      setTimeout(sendNext, 1);
    };
    sock.on('connect', () => sock.write(Buffer.from([5, 1, 0])));
    sock.on('data', (b: Buffer) => {
      if (stage === 'greet') {
        if (b[0] !== 5 || b[1] !== 0) return fail(new Error('greeting rejected'));
        stage = 'req';
        sock.write(Buffer.concat([
          Buffer.from([5, 1, 0, 1, 127, 0, 0, 1]),
          Buffer.from([(targetPort >>> 8) & 0xff, targetPort & 0xff]),
        ]));
        return;
      }
      if (stage === 'req') {
        if (b[1] !== 0) return fail(new Error('socks connect refused'));
        stage = 'stream';
        sendNext();
        return;
      }
      for (let i = 0; i < b.length; ++i) {
        if (b[i] !== ((rxDown + i) & 0xff)) { downBad = true; break; }
      }
      rxDown += b.length;
      // Read slower than the tunnel delivers so the server->client direction
      // also runs with a closed window and a pending backlog.
      sock.pause();
      setTimeout(() => sock.resume(), 10);
    });
    sock.on('end', () => { sock.destroy(); resolve({ downBad, down: rxDown }); });
    sock.on('close', () => resolve({ downBad, down: rxDown }));
  }), 40000, 'stress round trip');

  assert.equal(uploadBad, false, 'client->tunnel bytes arrived in order at the origin');
  assert.equal(outcome.downBad, false, 'tunnel->client bytes arrived in order at the local app');
  assert.equal(outcome.down, DOWNLOAD, `full download crossed the tunnel (${outcome.down}/${DOWNLOAD})`);
});

test('e2e: concurrent connections multiplex over a single session', async (t) => {
  // M1: N local TCP connections ride ONE shared FCP session (sid streams).
  // Five concurrent echo downloads of distinct patterns must all stay
  // byte-exact, and the client must end with exactly one session.
  const N = 5, SIZE = 96 * 1024;
  const origin = createServer((sock) => {
    sock.on('data', (b: Buffer) => sock.write(b)); // echo
    sock.on('end', () => sock.end());
  });
  await listen(origin, 0);
  const targetPort = portOf(origin);
  const udpPort = freePort(), proxyPort = freePort();
  const server = new TunnelServer({ psk: PSK, port: udpPort, log: () => {} });
  const client = new TunnelClient({ psk: PSK, host: '127.0.0.1', port: udpPort, listenPort: proxyPort, log: () => {} });
  await server.start();
  await client.start();
  t.after(() => { client.stop(); server.stop(); origin.close(); });

  const oneConn = (n: number) => new Promise<void>((resolve, reject) => {
    const sock = connect(proxyPort, '127.0.0.1');
    let stage = 'greet';
    const sent: Buffer[] = [];
    const got: Buffer[] = [];
    let gotBytes = 0;
    sock.setTimeout(15000, () => { sock.destroy(); reject(new Error(`conn ${n} timeout`)); });
    sock.on('error', reject);
    const sendNext = () => {
      // one 16 KB write per event, pattern = n*16 + (byte & 0x3f) so the five
      // streams' payloads are distinguishable
      if (sent.length >= SIZE / 16384) { sock.end(); return; }
      const chunk = Buffer.alloc(16384).map((_, i) => (n * 16 + ((sent.length * 16384 + i) & 0x3f)) & 0xff);
      sent.push(chunk);
      sock.write(chunk);
      setTimeout(sendNext, 1);
    };
    sock.on('connect', () => sock.write(Buffer.from([5, 1, 0])));
    sock.on('data', (b: Buffer) => {
      if (stage === 'greet') {
        if (b[1] !== 0) return reject(new Error('greeting refused'));
        stage = 'req';
        sock.write(Buffer.concat([
          Buffer.from([5, 1, 0, 1, 127, 0, 0, 1]),
          Buffer.from([(targetPort >>> 8) & 0xff, targetPort & 0xff]),
        ]));
        return;
      }
      if (stage === 'req') {
        if (b[1] !== 0) return reject(new Error(`conn ${n} refused`));
        stage = 'echo';
        sendNext();
        return;
      }
      got.push(b);
      gotBytes += b.length;
      if (gotBytes >= SIZE) {
        const all = Buffer.concat(got).subarray(0, SIZE);
        for (let i = 0; i < SIZE; ++i) {
          if (all[i] !== (n * 16 + (i & 0x3f)) & 0xff) {
            return reject(new Error(`conn ${n} corrupt at ${i}`));
          }
        }
        sock.destroy();
        resolve();
      }
    });
    sock.on('close', () => { if (gotBytes < SIZE) reject(new Error(`conn ${n} closed early at ${gotBytes}`)); });
  });

  await Promise.all([0, 1, 2, 3, 4].map((n) => oneConn(n)));
  // M1 round-robin pool: 5 connections disperse across the 2-session cap,
  // each session an independent window and loss domain.
  assert.equal(client.sessionCount, 2, `round-robin pool disperses connections across 2 sessions (got ${client.sessionCount})`);
});
