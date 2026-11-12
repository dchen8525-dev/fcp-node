// The desktop shell draws its throughput graph from the `stats` line, so its
// shape is a contract, not a debug convenience: it must be emitted on a timer
// regardless of --log-level, carry monotonically non-decreasing byte totals, and
// stay parseable without a session present.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TunnelClient } from '../src/app/tunnel.ts';

const STATS_RE =
  /^stats ([\d.]+)s live=(\d+) up=(\d+) tunnels=(\d+) tx=(\d+)B rx=(\d+)B tx_rate=(-?\d+)B\/s rx_rate=(-?\d+)B\/s$/;

test('stats line is emitted on a timer and parses', async () => {
  const lines: string[] = [];
  const client = new TunnelClient({
    psk: Buffer.alloc(16, 0x2a),
    host: '127.0.0.1',
    port: 4499,
    listenHost: '127.0.0.1',
    listenPort: 0,           // let the kernel pick a free port
    log: () => {},
    onStats: (line) => lines.push(line),
  });
  await client.start();
  await new Promise((r) => setTimeout(r, 1250));
  client.stop();

  assert.ok(lines.length >= 2, `expected >=2 stats lines in 1.25s, got ${lines.length}`);
  for (const line of lines) {
    const m = STATS_RE.exec(line);
    assert.ok(m, `unparseable stats line: ${line}`);
    assert.equal(Number(m[2]), 0, 'no sessions on an idle tunnel');
    assert.equal(Number(m[3]), 0, 'no established sessions on an idle tunnel');
    assert.ok(Number(m[5]) >= 0, 'tx is non-negative');
    assert.ok(Number(m[6]) >= 0, 'rx is non-negative');
  }

  // Uptime advances monotonically: the graph's x-axis depends on it.
  const first = Number(STATS_RE.exec(lines[0])![1]);
  const last = Number(STATS_RE.exec(lines[lines.length - 1])![1]);
  assert.ok(last > first, `uptime must advance (${first} -> ${last})`);

  const c = client.counters;
  assert.equal(c.sessions, 0);
  assert.ok(c.tx === 0 && c.rx === 0, 'nothing crossed the wire');
});

test('stats timer stops with the tunnel', async () => {
  const lines: string[] = [];
  const client = new TunnelClient({
    psk: Buffer.alloc(16, 0x2a),
    host: '127.0.0.1',
    port: 4499,
    listenHost: '127.0.0.1',
    listenPort: 0,
    log: () => {},
    onStats: (line) => lines.push(line),
  });
  await client.start();
  await new Promise((r) => setTimeout(r, 650));
  client.stop();
  const atStop = lines.length;
  await new Promise((r) => setTimeout(r, 700));
  assert.equal(lines.length, atStop, 'no stats line may be emitted after stop()');
});
