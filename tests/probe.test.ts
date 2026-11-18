// Idle-time path probe: wire codec, and the measurement loop over a virtual path.
//
// The interesting failures are all timing ones — the ramp settling on the wrong
// rate, the receiver's summary never arriving, the tail loss being invisible — so
// these tests run the real state machine against a simulated link (one-way delay,
// drop predicate, tick clock) rather than asserting that functions were called.

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  PathProbe, encodeProbe, decodeProbe, isProbeFrame,
  type ProbeResult, type ProbeHost,
} from '../src/probe/pathprobe.ts';
import {
  PROBE_HDR_LEN, PROBE_TYPE_DAT, PROBE_TYPE_ECHO, PROBE_TYPE_SUM,
  PROBE_MAGIC, PROBE_RATE_CAP_BPS,
} from '../src/constants.ts';

const SIZE = 1335;              // oob payload that fills a 1400 B MTU
const OWD = 50;                 // one-way delay, ms
const BUDGET = 1024 * 1024;

interface Endpoint {
  probe: PathProbe;
  result: ProbeResult | null;
  /** Datagrams this end put on the wire, drained by the simulation each slot. */
  out: Buffer[];
  sent: number;
}

function endpoint(): Endpoint {
  const out: Buffer[] = [];
  const ep: Endpoint = {
    probe: null as unknown as PathProbe, result: null, out, sent: 0,
  };
  const host: ProbeHost = {
    send: (payload) => { ++ep.sent; out.push(payload); },
    srttMs: () => 2 * OWD,
    dgramSize: () => SIZE,
    onResult: (r) => { ep.result = r; },
  };
  ep.probe = new PathProbe(host);
  return ep;
}

/** Wrap the two endpoints with the simulated path and run until both are idle. */
function simulate(opts: {
  drop?: (dir: 'a2b' | 'b2a', seq: number, payload: Buffer) => boolean;
  untilMs?: number;
  /** Token bucket on the a->b direction: a datagram that arrives while the
   *  bucket is empty is lost, which is what "pacing above capacity" looks like. */
  capacityBps?: number;
} = {}) {
  const a = endpoint();
  const b = endpoint();
  const wire: { at: number; to: 'a' | 'b'; payload: Buffer }[] = [];
  const drop = opts.drop ?? (() => false);
  const until = opts.untilMs ?? 30000;
  let now = 0;
  let started = false;
  let tokens = 0;
  let lastRefill = 0;

  const pump = () => {
    // Anything either end put on the wire in this slot is queued with the delay.
    const drain = (from: Endpoint, to: 'a' | 'b', dir: 'a2b' | 'b2a') => {
      while (from.out.length) {
        const payload = from.out.shift()!;
        const seq = payload.length >= PROBE_HDR_LEN ? (decodeProbe(payload)?.seq ?? -1) : -1;
        if (drop(dir, seq, payload)) continue;
        if (opts.capacityBps && dir === 'a2b' && payload.length >= PROBE_HDR_LEN) {
          // Token bucket with a small burst allowance, so pacing at exactly the
          // capacity is clean and pacing at twice it loses about half.
          tokens = Math.min(opts.capacityBps / 250, tokens + (opts.capacityBps * (now - lastRefill)) / 1000);
          lastRefill = now;
          if (tokens < payload.length) continue;
          tokens -= payload.length;
        }
        wire.push({ at: now + OWD, to, payload });
      }
    };
    drain(a, 'b', 'a2b');
    drain(b, 'a', 'b2a');
  };

  for (now = 0; now <= until; now += 2) {
    for (let i = 0; i < wire.length; ) {
      if (wire[i].at <= now) {
        const item = wire.splice(i, 1)[0]!;
        (item.to === 'a' ? a : b).probe.onFrame(item.payload, now);
      } else ++i;
    }
    if (!started && now === 0) { started = a.probe.start(0, BUDGET); }
    a.probe.onTick(now);
    b.probe.onTick(now);
    pump();
    if (started && a.result) break;
  }
  return { a, b };
}

test('probe frame: encode/decode round trip and rejection', () => {
  const f = {
    type: PROBE_TYPE_DAT, flags: 1, token: 0xdeadbeef, seq: 7, total: 431,
    got: 0, sentMs: 123456, size: SIZE, aux: 0,
  };
  const buf = encodeProbe(f, SIZE);
  assert.equal(buf.length, SIZE);
  assert.ok(isProbeFrame(buf));
  const back = decodeProbe(buf)!;
  assert.equal(back.type, PROBE_TYPE_DAT);
  assert.equal(back.token, 0xdeadbeef);
  assert.equal(back.seq, 7);
  assert.equal(back.total, 431);
  assert.equal(back.sentMs, 123456);
  assert.equal(back.size, SIZE);
  // Bulk must not leak heap: everything past the header is zero.
  assert.equal(buf.subarray(PROBE_HDR_LEN).reduce((m, v) => m | v, 0), 0);

  const short = encodeProbe(f).subarray(0, PROBE_HDR_LEN - 1);
  assert.equal(decodeProbe(short), null);
  const wrong = Buffer.from(encodeProbe(f));
  wrong[0] ^= 0xff;
  assert.equal(decodeProbe(wrong), null);
  assert.ok(PROBE_MAGIC.length === 8);
});

test('clean path: both directions measured, budget respected, RTT is the path RTT', () => {
  const { a } = simulate();
  const r = a.result;
  assert.ok(r, 'run produced a result');
  assert.ok(r!.up, 'uplink half ran');
  assert.ok(r!.down, 'downlink half ran');

  const up = r!.up!;
  const down = r!.down!;
  // No loss anywhere: the receiver's own count is exact.
  assert.equal(up.lossRx, 0);
  assert.equal(down.lossRx, 0);
  assert.equal(up.maxRun, 0);
  assert.equal(down.maxRun, 0);
  // RTT comes back from the echoed sentMs, so it is the round trip, not a guess.
  assert.ok(up.rttMin >= 2 * OWD - 4 && up.rttMin <= 2 * OWD + 4, `rttMin=${up.rttMin}`);
  // A clean path must ramp to the ceiling and settle below it.
  assert.ok(up.rampBps >= PROBE_RATE_CAP_BPS * 0.9, `ramp=${up.rampBps}`);

  // Never more than the budget of DAT payload, and both halves actually spent it.
  assert.ok(r!.usedBytes <= r!.budgetBytes, `used=${r!.usedBytes} budget=${r!.budgetBytes}`);
  assert.ok(r!.usedBytes > r!.budgetBytes * 0.9, `used=${r!.usedBytes}`);
});

test('uniform 20% loss is reported from both ends and they agree', () => {
  let n = 0;
  const { a } = simulate({
    drop: (dir, _seq, payload) => {
      // Only drop DATA datagrams; echoes and summaries are small and, on a real
      // path, not what the link is losing at 20%. The test then checks the two
      // independent counts of the same loss.
      if (payload[8] !== PROBE_TYPE_DAT) return false;
      return n++ % 5 === 0;
    },
  });
  const r = a.result!;
  const up = r.up!;
  const down = r.down!;
  // Sender's view (missing echoes) and receiver's view (its own summary) must
  // both land near 20%; the receiver's number is the authoritative one.
  assert.ok(up.lossRx > 0.12 && up.lossRx < 0.28, `up.lossRx=${up.lossRx}`);
  assert.ok(up.lossTx > 0.12 && up.lossTx < 0.28, `up.lossTx=${up.lossTx}`);
  assert.ok(down.lossRx > 0.12 && down.lossRx < 0.28, `down.lossRx=${down.lossRx}`);
  assert.ok(up.maxRun >= 1, 'consecutive misses are counted');
});

test('a lost tail still produces a loss number', () => {
  // Everything from 80% of the train onwards is dropped: the LAST datagram never
  // arrives, so the receiver has to end the train on silence. Without that the
  // run would hang until the timeout and report nothing.
  const { a } = simulate({
    drop: (dir, seq, payload) => {
      if (payload[8] !== PROBE_TYPE_DAT) return false;
      const total = decodeProbe(payload)?.total ?? 0;
      return total > 0 && seq > total * 0.8;
    },
  });
  const up = a.result!.up!;
  assert.ok(up.lossRx > 0.1, `up.lossRx=${up.lossRx}`);
  assert.ok(up.lossTx > 0.1, `up.lossTx=${up.lossTx}`);
});

test('a dead peer ends the run instead of probing forever', () => {
  const { a } = simulate({ drop: () => true, untilMs: 40000 });
  const r = a.result;
  assert.ok(r, 'run still terminates');
  assert.equal(r!.up!.lossRx, -1, 'no summary means no receiver-side number');
  assert.equal(r!.up!.lossTx, 1);
  assert.equal(r!.up!.reason, 'ok');
});

test('interleaved bursts show up as a run, not as scattered single drops', () => {
  const { a } = simulate({
    drop: (dir, seq, payload) => {
      if (payload[8] !== PROBE_TYPE_DAT) return false;
      const total = decodeProbe(payload)?.total ?? 1;
      // Compare against the *sequence within the train*, not a global counter.
      const window = Math.floor(seq / 40);
      const pos = seq % 40;
      return pos >= 10 && pos < 16 && window >= 0 && seq < total;
    },
  });
  const up = a.result!.up!;
  assert.ok(up.maxRun >= 5, `maxRun=${up.maxRun}`);
  assert.ok(up.lossRx > 0.05, `loss=${up.lossRx}`);
});

test('a lossy but fast path is not mistaken for a congested one', () => {
  // The deployed path loses ~2% at random and carried 2.1 MB/s. A ramp that
  // stopped at the first chunk exceeding an absolute loss threshold would report
  // the *start* rate there and hide a path twenty times faster — which is why the
  // stop rule is "loss jumped above the baseline", not "loss is non-zero".
  const CAP = 2 * 1024 * 1024;
  let n = 0;
  const { a } = simulate({
    capacityBps: CAP,
    drop: (dir, _seq, payload) => {
      if (payload[8] !== PROBE_TYPE_DAT) return false;
      return n++ % 5 === 0;   // 20% random, independent of pacing
    },
  });
  const up = a.result!.up!;
  assert.ok(up.rampBps > CAP * 0.6, `ramp=${up.rampBps} should be near ${CAP}`);
  assert.ok(up.rampBps < CAP * 1.6, `ramp=${up.rampBps} should not exceed the path`);
  // Loss above the 20% floor is what the training above capacity costs.
  assert.ok(up.lossRx >= 0.2, `loss=${up.lossRx}`);
});
