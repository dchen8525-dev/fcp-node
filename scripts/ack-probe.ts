// Measure what the SACK truncation costs.
//
// The ACK v2 carries the received runs as ranges, but the datagram budget only
// holds so many of them (maxRanges = floor((payloadMax - 10) / 10): five at a
// 128 B MTU, twenty-two at 300 B, sixty-four at 1400 B). The runs are sorted by
// offset, so the ones that get dropped are the newest holes — and a hole the
// peer never heard about is a hole the sender can only find by RTO.
//
// This probe runs the same seeded loss/reorder pattern twice: once with the
// current order (keep the lowest offsets) and once keeping the highest, and
// prints what each costs.
//
// Usage: node scripts/ack-probe.ts [--json] [--mtu=N] [--loss=N]
import { Stream } from '../src/stream/stream.ts';

interface Args {
  json: boolean;
  mtu: number | null;
  loss: number | null;
  seeds: number;
}

function parseArgs(argv: string[]): Args {
  const out: Args = { json: false, mtu: null, loss: null, seeds: 5 };
  for (const a of argv) {
    if (a === '--json') out.json = true;
    else if (a.startsWith('--mtu=')) out.mtu = Number(a.slice(6));
    else if (a.startsWith('--loss=')) out.loss = Number(a.slice(7));
    else if (a.startsWith('--seeds=')) out.seeds = Math.max(1, Number(a.slice(8)));
  }
  return out;
}

/** xorshift32: the same seed gives the same loss pattern, so the two runs of
 *  one cell are comparable down to the packet. */
function rng(seed: number): () => number {
  let s = seed >>> 0 || 1;
  return () => {
    s ^= s << 13; s >>>= 0;
    s ^= s >>> 17;
    s ^= s << 5; s >>>= 0;
    return s / 0x100000000;
  };
}

/** One direction of the path: a fixed delay plus jitter (so packets reorder)
 *  and an independent drop chance per packet. */
class Link {
  private queue: Array<{ at: number; buf: Buffer }> = [];
  private lossPct: number;
  private delayMs: number;
  private jitterMs: number;
  private rand: () => number;

  constructor(lossPct: number, delayMs: number, jitterMs: number, rand: () => number) {
    this.lossPct = lossPct;
    this.delayMs = delayMs;
    this.jitterMs = jitterMs;
    this.rand = rand;
  }

  send(buf: Buffer, now: number): void {
    if (this.rand() * 100 < this.lossPct) return;   // dropped
    const at = now + this.delayMs + Math.floor(this.rand() * (this.jitterMs + 1));
    this.queue.push({ at, buf: Buffer.from(buf) });
  }

  /** Deliver everything due at `now`. */
  deliver(now: number, to: (b: Buffer) => void): void {
    let i = 0;
    while (i < this.queue.length) {
      if (this.queue[i]!.at <= now) {
        const p = this.queue.splice(i, 1)[0]!;
        to(p.buf);
      } else ++i;
    }
  }
}

type Order = 'lowest' | 'highest' | 'both' | 'all' | 'fit';

interface Cell {
  mtu: number; lossPct: number; order: Order;
  /** Median completion time over the seeds, and the totals of the counters. */
  doneMs: number; ok: boolean;
  fastRetx: number; rtoRetx: number; fastRounds: number;
  truncatedAcks: number; droppedRuns: number;
  received: number; samples: number;
  /** ACK bytes the receiver actually put on the wire (sum / worst). */
  ackBytes: number; ackMax: number; ackCount: number;
  /** Bandwidth cost of the extra retransmissions a weaker SACK list causes:
   *  bytes the receiver had already seen when they arrived again. */
  dupBytes: number; retxAll: number;
}

const TOTAL = 512 * 1024;
const BASE_DELAY = 40;      // ms one way
const JITTER = 20;          // ms of spread, so packets reorder
const DEADLINE_MS = 120_000;

/** Run one cell of the grid with the given truncation order. */
function run(mtu: number, lossPct: number, order: Order, seed: number): Cell {
  const proto = Stream.prototype as unknown as {
    keepAckRanges: (runs: unknown[], cum: number, budget: number, rotate: number)
      => { picked: unknown[]; nextRotate: number };
  };
  const original = proto.keepAckRanges;
  const list = (runs: unknown[]): unknown[] => runs;
  const keep = (picked: unknown[], rotate: number): { picked: unknown[]; nextRotate: number } =>
    ({ picked, nextRotate: rotate });
  if (order !== 'fit') {
    // "fit" is not patched: it is the real implementation in stream.ts.
    proto.keepAckRanges = order === 'lowest'
      // The old behaviour: the budget is estimated at 10 B per range, so only
      // the lowest ranges fit and the newest holes are dropped.
      ? (runs, _cum, budget, rotate) => {
        const max = Math.max(0, Math.min(64, Math.floor((budget - 10) / 10)));
        return keep(list(runs).slice(0, max), rotate);
      }
      : order === 'highest'
        ? (runs, _cum, budget, rotate) => {
          const max = Math.max(0, Math.min(64, Math.floor((budget - 10) / 10)));
          return keep(list(runs).slice(-max), rotate);
        }
        : order === 'all'
          // Oracle: the datagram budget stops mattering and the ACK carries the
          // newest 64 runs -- the most the v2 format can encode. The gap
          // against "fit" is what carrying *more* ranges would buy on top of
          // the real implementation; the ackAvg/ackMax columns show the price.
          ? (runs, _cum, _budget, rotate) => keep(list(runs).slice(-64), rotate)
          : (runs, _cum, budget, rotate) => {
            // Static "both": half at the bottom (near cum), half at the top,
            // with the same worst-case budget as the old code.
            const r = list(runs);
            const max = Math.max(0, Math.min(64, Math.floor((budget - 10) / 10)));
            if (r.length <= max) return keep(r, rotate);
            const half = Math.floor(max / 2);
            return keep(r.slice(0, half).concat(r.slice(r.length - (max - half))), rotate);
          };
  }

  try {
    const payloadMax = mtu - 62;          // mtu - ip(20) - udp(8) - envelope(34)
    const rand = rng(seed);
    const up = new Link(lossPct, BASE_DELAY, JITTER, rand);
    const down = new Link(lossPct, BASE_DELAY, JITTER, rand);

    let received = 0;
    let sent = 0;
    let ackBytes = 0; let ackMax = 0; let ackCount = 0;
    const a = new Stream(
      { maxSegment: payloadMax, initialSrttMs: 2 * BASE_DELAY, sendWindowBytes: 256 * 1024,
        rcvBufBytes: 256 * 1024, idleTimeoutMs: 1e9, ackV2: true },
      { send: (b) => up.send(b, now), read: () => {}, closed: () => {}, eof: () => {} },
    );
    const b = new Stream(
      { maxSegment: payloadMax, initialSrttMs: 2 * BASE_DELAY, sendWindowBytes: 256 * 1024,
        rcvBufBytes: 256 * 1024, idleTimeoutMs: 1e9, ackV2: true },
      { send: (seg) => { ackBytes += seg.length; ++ackCount; if (seg.length > ackMax) ackMax = seg.length; down.send(seg, now); },
        read: (bytes) => { received += bytes.length; b.consumed(bytes.length); },
        closed: () => {}, eof: () => {} },
    );
    if (order === 'all') {
      // Oracle: the ACK is never cut short by the datagram budget. The
      // receiver is given a budget large enough for the whole list, which is
      // what an ACK that reports everything would look like -- at the cost of
      // an ACK that no longer fits the link (see the ackAvg/ackMax columns).
      // encodeAckV2 still caps the list at 64 ranges, so this is the ceiling
      // of the v2 format.
      b.setMaxSegment(1 << 20);
    }

    const chunk = Buffer.alloc(16 * 1024, 0x5a);
    let now = 0;
    let doneMs = -1;
    while (now < DEADLINE_MS) {
      ++now;
      up.deliver(now, (buf) => b.onSegment(buf, now));
      down.deliver(now, (buf) => a.onSegment(buf, now));
      if (sent < TOTAL) sent += a.write(chunk, now);
      a.onTick(now);
      b.onTick(now);
      if (received >= TOTAL && doneMs < 0) doneMs = now;
      if (doneMs >= 0) break;
    }
    return {
      mtu, lossPct, order,
      doneMs, ok: received >= TOTAL,
      fastRetx: a.retxFast, rtoRetx: a.retxRto, fastRounds: a.fastRounds,
      truncatedAcks: b.ackRangesTruncated, droppedRuns: b.ackRangesDropped,
      received, samples: 1,
      ackBytes, ackMax, ackCount,
      dupBytes: b.dupBytes, retxAll: a.retransmits,
    };
  } finally {
    proto.keepAckRanges = original;
  }
}

/** Run one cell over several seeds and aggregate: the median completion time
 *  (a single sample is too noisy to compare two orders) and the summed
 *  counters. */
function runCell(mtu: number, lossPct: number, order: Order, seeds: number): Cell {
  const runs: Cell[] = [];
  for (let i = 0; i < seeds; ++i) {
    runs.push(run(mtu, lossPct, order, 0x5eed ^ (mtu * 31 + lossPct * 7 + i * 0x9e37)));
  }
  const times = runs.map((r) => r.doneMs).sort((a, b) => a - b);
  const mid = times[Math.floor(times.length / 2)] ?? 0;
  const sum = (f: (c: Cell) => number): number => runs.reduce((a, c) => a + f(c), 0);
  return {
    mtu, lossPct, order,
    doneMs: mid, ok: runs.every((r) => r.ok),
    fastRetx: sum((c) => c.fastRetx), rtoRetx: sum((c) => c.rtoRetx), fastRounds: sum((c) => c.fastRounds),
    truncatedAcks: sum((c) => c.truncatedAcks), droppedRuns: sum((c) => c.droppedRuns),
    received: sum((c) => c.received), samples: seeds,
    ackBytes: sum((c) => c.ackBytes),
    ackMax: Math.max(...runs.map((c) => c.ackMax)),
    ackCount: sum((c) => c.ackCount),
    dupBytes: sum((c) => c.dupBytes), retxAll: sum((c) => c.retxAll),
  };
}

const args = parseArgs(process.argv.slice(2));
const mtus = args.mtu ? [args.mtu] : [1400, 576, 300, 128];
const losses = args.loss !== null ? [args.loss] : [1, 3, 5, 10];
const orders: Order[] = ['lowest', 'highest', 'both', 'all', 'fit'];

const cells: Cell[] = [];
for (const mtu of mtus) {
  for (const lossPct of losses) {
    for (const order of orders) {
      cells.push(runCell(mtu, lossPct, order, args.seeds));
    }
  }
}

if (args.json) {
  process.stdout.write(JSON.stringify(cells, null, 2) + '\n');
} else {
  const pad = (s: string, n: number): string => s.padEnd(n);
  const num = (v: number, n: number): string => String(v).padStart(n);
  console.log(`seeds=${args.seeds}  (done = median completion time over the seeds)`);
  console.log('MTU  loss  order     done(ms)  fast   rto  rounds  truncACK  dropRuns  ackAvg  ackMax  dupKB');
  console.log('--- ----- ---------- --------  -----  ----  ------  --------  --------  ------  ------  -----');
  for (let i = 0; i < cells.length; i += orders.length) {
    const base = cells[i]!;                       // "lowest" is the baseline
    for (const c of cells.slice(i, i + orders.length)) {
      const avg = c.ackCount > 0 ? Math.round(c.ackBytes / c.ackCount) : 0;
      console.log(
        `${num(c.mtu, 3)}  ${num(c.lossPct, 4)}%  ${pad(c.order, 10)}  ${num(c.doneMs, 8)}  ` +
        `${num(c.fastRetx, 5)}  ${num(c.rtoRetx, 4)}  ${num(c.fastRounds, 6)}  ${num(c.truncatedAcks, 8)}  ` +
        `${num(c.droppedRuns, 8)}  ${num(avg, 6)}  ${num(c.ackMax, 6)}  ${num(Math.round(c.dupBytes / 1024), 5)}`,
      );
    }
    for (const c of cells.slice(i + 1, i + orders.length)) {
      const dDone = c.doneMs - base.doneMs;
      const dRto = c.rtoRetx - base.rtoRetx;
      const pct = base.doneMs > 0 ? (100 * dDone / base.doneMs) : 0;
      console.log(
        `${pad('', 3)}  ${pad('', 4)}  ${pad(c.order, 10)}  ${num(dDone, 8)}  ${pad('', 5)}  ${num(dRto, 4)}  ` +
        `${pad('', 6)}  ${pad('', 8)}  ${pad('', 8)}   (${pct >= 0 ? '+' : ''}${pct.toFixed(1)}% time, ` +
        `${dRto >= 0 ? '+' : ''}${dRto} rto vs lowest)`,
      );
    }
  }
  console.log('\n"lowest"  = current order (keep the lowest offsets, drop the newest holes)');
  console.log('"highest" = keep the highest offsets (drop the oldest holes)');
  console.log('"both"    = half at the bottom (near cum), half at the top');
  console.log('"fit"     = the real implementation: both ends + a rotating middle window');
  console.log('"all"     = oracle: the ACK is never cut short (v2 still caps at 64 ranges)');
  console.log('deltas    = against "lowest"');
  console.log('ackAvg/ackMax = bytes the receiver put on the wire per ACK');
}
