// "How many bytes moved in the last N ms", without a timestamp per byte.
//
// The tunnel uses this for the path probe's idle gate. Asking "when did the
// application last move a byte" answers the wrong question: a browser that
// polls an analytics endpoint every few seconds keeps that timestamp fresh for
// hours while carrying no throughput at all, and the probe then never runs.
// Counting bytes per second answers what the gate actually wants to know — was
// there traffic — and a few KB of beacons is not traffic.

/** One bucket per second; four times the widest window the tunnel asks for. */
const BUCKETS = 64;

const idx = (sec: number): number => ((sec % BUCKETS) + BUCKETS) % BUCKETS;

export class ByteWindow {
  private buckets = new Float64Array(BUCKETS);
  /** Newest second written; 0 means "nothing recorded yet". Wall-clock seconds
   *  are ~1.7e9, so 0 is never a real bucket. */
  private sec = 0;

  add(bytes: number, nowMs: number): void {
    if (!(bytes > 0)) return;
    const sec = Math.floor(nowMs / 1000);
    if (sec !== this.sec) {
      // Clear every bucket the gap crossed. A gap wider than the ring clears
      // all of them, and the span is clamped so an hour of silence costs 64
      // writes rather than 3600.
      const span = this.sec === 0 ? BUCKETS : Math.min(BUCKETS, sec - this.sec);
      for (let i = 1; i <= span; ++i) this.buckets[idx(this.sec + i)] = 0;
      this.sec = sec;
    }
    this.buckets[idx(sec)] += bytes;
  }

  /** Bytes added in the `windowMs` ending at `nowMs`. Windows wider than the
   *  ring (64 s) are only as exact as the ring is old. */
  total(nowMs: number, windowMs: number): number {
    if (this.sec === 0) return 0;
    const nowSec = Math.floor(nowMs / 1000);
    if (nowSec - this.sec >= BUCKETS) return 0; // the whole ring is stale
    const first = Math.max(Math.floor((nowMs - windowMs) / 1000), this.sec - BUCKETS + 1);
    let sum = 0;
    for (let s = first; s <= nowSec; ++s) {
      // Buckets past the newest write still hold values from one ring lap ago;
      // they are not "zero bytes in that second", they are unknown.
      if (s > this.sec) break;
      sum += this.buckets[idx(s)];
    }
    return sum;
  }
}
