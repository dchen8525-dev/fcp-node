// Adversarial regression tests for the tunnel layer (client half-close, server
// backpressure). Both need real sockets: the bug they pin down lives in the
// wiring between the local TCP socket, the FCP session and the target socket.
//
// Run: node --test tests/tunnel.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer, connect, type Server } from 'node:net';
import { randomBytes } from 'node:crypto';

import { TunnelClient, TunnelServer } from '../src/app/tunnel.ts';

const PSK = randomBytes(16);
const port = (base: number): number => base + Math.floor(Math.random() * 2000);

interface Pair {
  server: TunnelServer;
  client: TunnelClient;
  udpPort: number;
  proxyPort: number;
}

async function pair(): Promise<Pair> {
  const udpPort = port(45000);
  const proxyPort = port(47000);
  const server = new TunnelServer({ psk: PSK, port: udpPort });
  const client = new TunnelClient({ psk: PSK, host: '127.0.0.1', port: udpPort, listenPort: proxyPort });
  await server.start();
  await client.start();
  return { server, client, udpPort, proxyPort };
}

const socksConnect = (targetPort: number): Buffer => Buffer.concat([
  Buffer.from([5, 1, 0, 1, 127, 0, 0, 1]),
  Buffer.from([(targetPort >>> 8) & 0xff, targetPort & 0xff]),
]);

test('TUNNEL: the local half-close reaches the target even while the handshake is in flight', async () => {
  // The client's FIN was consumed by the "the queue is empty" check while the
  // pool session was still handshaking — closeWriteConn was still the empty
  // placeholder, so the FIN evaporated. The target never saw the EOF, and an
  // origin that only answers after EOF never answered: the local application
  // hung until the 300 s idle timeout. C++ proxy_engine.cc keeps want_fin
  // until the stream exists.
  let sawFin = 0;
  const origin: Server = createServer({ allowHalfOpen: true }, (s) => {
    s.on('data', () => {});
    s.on('end', () => { ++sawFin; s.write('BYE'); s.end(); });
  });
  await new Promise<void>((r) => origin.listen(0, '127.0.0.1', () => r()));
  const targetPort = (origin.address() as { port: number }).port;
  const p = await pair();
  try {
    // The first connections of a fresh client ride a pool session whose
    // handshake is still in flight, which is exactly the window where the
    // FIN was lost.
    for (let i = 0; i < 5; ++i) {
      const out = await new Promise<string>((resolve) => {
        const s = connect(p.proxyPort, '127.0.0.1');
        const timer = setTimeout(() => { s.destroy(); resolve('timeout'); }, 2000);
        s.on('connect', () => s.write(Buffer.from([5, 1, 0])));
        s.on('data', (b: Buffer) => {
          if (b.length === 2) {                 // the SOCKS5 greeting reply
            s.write(socksConnect(targetPort));
            s.end();                            // request sent, half-close now
            return;
          }
          if (b.length === 10 && b[0] === 5) return;   // the SOCKS5 connect reply
          clearTimeout(timer);
          const text = b.toString();
          s.destroy();
          resolve(text);
        });
        s.on('error', () => { clearTimeout(timer); resolve('error'); });
      });
      assert.equal(out, 'BYE', `connection ${i}: the origin never saw the EOF`);
    }
    assert.equal(sawFin, 5, 'every target must have received the FIN');
  } finally {
    p.client.stop(); p.server.stop(); origin.close();
  }
});

test('TUNNEL: a target whose connect hangs must not make the server buffer without bound', async () => {
  // The queued bytes were consumed (the receive window released) at queue
  // time, so the peer's window never closed: a black-holed target kept the
  // server buffering everything the peer sent — 42.7 MB measured, delivery
  // pending still 0 — which is a remote memory-exhaustion lever for anyone
  // who can reach the local proxy. C++ proxy_engine.cc counts the queued
  // bytes towards the window for exactly this reason.
  const p = await pair();
  try {
    const s = connect(p.proxyPort, '127.0.0.1');
    await new Promise<void>((r) => s.once('connect', () => r()));
    s.write(Buffer.from([5, 1, 0]));
    await new Promise<void>((r) => s.once('data', () => r()));
    // 192.0.2.1 is TEST-NET-1: the SYN goes nowhere, so connect() hangs for
    // the full 10 s timeout.
    s.write(Buffer.concat([
      Buffer.from([5, 1, 0, 1, 192, 0, 2, 1]),
      Buffer.from([0, 80]),
    ]));
    const chunk = Buffer.alloc(65536, 0x43);
    let sent = 0;
    const pump = (): void => {
      while (sent < 32 * 1024 * 1024) {
        sent += chunk.length;
        if (!s.write(chunk)) { s.once('drain', pump); return; }
      }
    };
    pump();
    await new Promise((r) => setTimeout(r, 3000));

    let backlog = 0;
    let deliveryPending = 0;
    for (const b of (p.server as unknown as {
      sessions: Map<string, { sidTunnels?: Map<number, { pendingToTarget: Buffer[]; stream: { deliveryPendingBytes: number } }> }>;
    }).sessions.values()) {
      if (!b.sidTunnels) continue;
      for (const t of b.sidTunnels.values()) {
        for (const c of t.pendingToTarget) backlog += c.length;
        deliveryPending += t.stream.deliveryPendingBytes;
      }
    }
    assert.ok(backlog < 8 * 1024 * 1024,
      `the server buffered ${backlog} B for a target that never accepted the connection`);
    assert.ok(deliveryPending > 0,
      'the un-flushed bytes must stay charged to the receive window');
    s.destroy();
  } finally {
    p.client.stop(); p.server.stop();
  }
});
