// End-to-end tests over real UDP + TCP sockets: start a TunnelServer, a
// TunnelClient and a local HTTP origin, then drive all three local proxy
// entry protocols through the encrypted FCP tunnel.
// Run: node --test tests/e2e.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, connect, type Server } from 'node:net';
import { randomBytes } from 'node:crypto';
import { TunnelClient, TunnelServer } from '../src/app/tunnel.ts';

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
