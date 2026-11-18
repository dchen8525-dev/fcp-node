// The idle path probe through a real Session pair over real UDP sockets.
//
// tests/probe.test.ts drives the state machine against a simulated link; this one
// checks the wiring that the simulation cannot: that both ends offer TLV 6, that
// probe frames survive the envelope + oob dispatch, and that a run reports both
// directions with the session's own geometry attached.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createSocket } from 'node:dgram';
import { randomBytes } from 'node:crypto';
import { Session, type SessionProbeResult } from '../src/session/session.ts';
import { Direction, HandshakeRole } from '../src/constants.ts';

const now = () => Date.now();

function bind(): Promise<{ sock: ReturnType<typeof createSocket>; port: number }> {
  return new Promise((resolve, reject) => {
    const sock = createSocket('udp4');
    sock.once('error', reject);
    sock.bind(0, '127.0.0.1', () => {
      sock.off('error', reject);
      resolve({ sock, port: (sock.address() as { port: number }).port });
    });
  });
}

test('path probe: TLV negotiation, oob dispatch, both directions reported', async () => {
  const psk = randomBytes(16);
  const salt = randomBytes(8);
  const A = await bind();
  const B = await bind();

  let client: Session | null = null;
  let server: Session | null = null;
  let result: SessionProbeResult | null = null;

  client = new Session({
    psk, salt,
    sendDirection: Direction.C2S, recvDirection: Direction.S2C,
    role: HandshakeRole.Client,
    d: 10, p: 6,
    mtu: 1400, pmtud: false,
  }, {
    sendWire: (wire) => A.sock.send(wire, B.port, '127.0.0.1'),
    read: () => {},
    closed: () => {},
    pathProbe: (r) => { result = r; },
  });
  server = new Session({
    psk, salt,
    sendDirection: Direction.S2C, recvDirection: Direction.C2S,
    role: HandshakeRole.Server,
    d: 10, p: 6,
    mtu: 1400, pmtud: false,
  }, {
    sendWire: (wire) => B.sock.send(wire, A.port, '127.0.0.1'),
    read: () => {},
    closed: () => {},
  });

  A.sock.on('message', (m) => client?.onWire(m, now()));
  B.sock.on('message', (m) => server?.onWire(m, now()));

  assert.ok(client.start(now()), 'client starts');
  assert.ok(server.start(now()), 'server starts');

  const timer = setInterval(() => { client?.onTick(now()); server?.onTick(now()); }, 10);
  const cleanup = () => { clearInterval(timer); A.sock.close(); B.sock.close(); };

  try {
    // Handshake.
    const t0 = now();
    while (!(client.established && server.established)) {
      if (now() - t0 > 5000) throw new Error('handshake did not complete');
      await new Promise((r) => setTimeout(r, 20));
    }
    assert.ok(client.pathProbeReady, 'both ends offered TLV 6');
    assert.ok(server.pathProbeReady, 'server side offers TLV 6 too');

    // 256 KiB keeps the test short; the pacing ramp is the same.
    assert.ok(client.startPathProbe(256 * 1024), 'probe starts');
    assert.ok(client.pathProbeRunning, 'run is in flight');
    assert.equal(client.startPathProbe(256 * 1024), false, 'a second run is refused');

    const t1 = now();
    while (!result) {
      if (now() - t1 > 20000) throw new Error('no probe result');
      await new Promise((r) => setTimeout(r, 50));
    }

    assert.ok(result!.up, 'uplink measured');
    assert.ok(result!.down, 'downlink measured');
    assert.equal(result!.up!.lossRx, 0, 'loopback loses nothing');
    assert.equal(result!.down!.lossRx, 0, 'loopback loses nothing');
    assert.ok(result!.up!.rttMin >= 0, 'rtt measured');
    assert.ok(result!.usedBytes <= result!.budgetBytes, 'budget respected');
    assert.ok(result!.usedBytes > result!.budgetBytes * 0.8, 'most of the budget was used');
    // The geometry is stamped from the session, so a reader can price the loss.
    assert.equal(result!.mtu, 1400);
    assert.equal(result!.d, 10);
    assert.ok(result!.k >= 1);
  } finally {
    cleanup();
  }
});
