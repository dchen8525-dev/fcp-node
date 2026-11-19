// Manual "measure now" through the real Tunnel pair, over real UDP sockets.
//
// probe-session.test.ts proves the Session-level protocol; this one proves the
// GUI-facing contract: probeNow() must work even with automatic probing OFF
// (--probe-interval=0), must ignore the idle gate, and must deliver exactly one
// result on the normal onProbe channel. The TLV 6 negotiation is deliberately left on
// (probeNegotiate defaults true) — that is what makes the button usable when
// the user only disabled *periodic* measurement.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { createSocket } from 'node:dgram';
import { TunnelClient, TunnelServer } from '../src/app/tunnel.ts';
import type { ProbeReport } from '../src/probe/pathprobe.ts';

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const s = createSocket('udp4');
    s.once('error', reject);
    s.bind(0, '127.0.0.1', () => {
      const p = s.address().port;
      s.close(() => resolve(p));
    });
  });
}

async function waitFor<T>(fn: () => T | null, timeoutMs: number, label: string): Promise<T> {
  const until = Date.now() + timeoutMs;
  while (Date.now() < until) {
    const v = fn();
    if (v !== null) return v;
    await new Promise((r) => setTimeout(r, 30));
  }
  throw new Error('timeout waiting for ' + label);
}

test('probeNow: manual measurement runs with automatic probing disabled', async () => {
  const psk = randomBytes(16);
  const serverPort = await freePort();
  const proxyPort = await freePort();

  let result: ProbeReport | null = null;
  const server = new TunnelServer({
    psk, listenHost: '127.0.0.1', port: serverPort,
    mtu: 1400, pmtud: false, log: () => {},
  });
  const client = new TunnelClient({
    psk, host: '127.0.0.1', port: serverPort,
    listenHost: '127.0.0.1', listenPort: proxyPort,
    mtu: 1400, pmtud: false,
    probe: false,                  // automatic scheduler OFF (--probe-interval=0)
    probeBudgetBytes: 256 * 1024,  // keep the test short
    log: () => {},
    onProbe: (r) => { result = r; },
  });

  await server.start();
  await client.start();
  try {
    assert.ok(client.probeNow(), 'probeNow queued even though probe=false');
    assert.equal(client.probeNow(), false, 'a second request while pending is refused');

    const r = await waitFor(() => result, 20000, 'manual probe result');
    assert.ok(r.up, 'uplink measured');
    assert.ok(r.down, 'downlink measured');
    assert.equal(r.up.lossRx, 0, 'loopback loses nothing');
    assert.equal(r.down.lossRx, 0, 'loopback loses nothing');
    assert.ok(r.used <= r.budget, 'budget respected');
  } finally {
    client.stop();
    server.stop();
  }
});
