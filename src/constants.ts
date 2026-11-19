// FCP wire constants. Single source of truth for the TypeScript port.
// Mirrors D:\work\fcp\src\fcp\{envelope,hdr,handshake,fecstat,defaults,limits,gf256,rs,gcm}.h
// 效力顺序（docs/文档索引.md §2）：C++ 代码 > 详细设计 > 协议规格 > README。
// 与规格文档冲突处以代码为准，差异登记在 docs/兼容矩阵与差异.md。

// FEC header v2 (7 bytes):
//   offset 0  set_id u32 LE
//   offset 4  index  u8
//   offset 5  d      u8   data shards this set was built with
//   offset 6  type_k = (k << 5) | (j << 2) | type
//
// `d` used to be a session constant, so both ends had to agree on it for the
// whole session and the receiver could only validate against the negotiated
// ceiling. Carrying it per symbol makes every set self-describing: the sender
// may resize groups while a session is running (adaptive d) and the decoder
// still knows the exact geometry of the set in front of it, instead of
// inferring it from how many data indices happened to show up.
export const FEC_HDR_LEN = 7;
export const MAX_S = 256;
export const MAX_PARITY = 7;

export const SymbolType = {
  Data: 0,
  Parity: 1,
  Oob: 2,
} as const;
export type SymbolTypeValue = (typeof SymbolType)[keyof typeof SymbolType];

// Envelope (envelope.h)
export const SALT_LEN = 8;
export const NONCE_LEN = 8;
export const TAG_LEN = 12;
export const ENVELOPE_OVERHEAD = 28;
export const RESET_MAGIC_LEN = 8;
export const NONCE_LIMIT = 1n << 32n;
export const REPLAY_WINDOW = 1024; // #84：代码为 1024，规格 §4.1 仍写 256
export const EPOCH_SPAN = 1n << 24n;
export const EPOCH_SPACE_END = 65536n * EPOCH_SPAN;
export const FIRST_ROLL_AT = 100n;
export const GCM_IV_LEN = 12;
export const RESET_MAGIC = Buffer.from([0x46, 0x43, 0x50, 0x52, 0x53, 0x54, 0x31, 0x00]); // "FCPRST1\0"

export const Direction = {
  C2S: 0x01,
  S2C: 0x02,
} as const;
export type DirectionValue = (typeof Direction)[keyof typeof Direction];

// Handshake (handshake.h)
export const CAPS_LEN = 4;
export const CAPS_VERSION = 1;
export const CAP_FRAMING = 1 << 0;
export const CAP_FECSTAT = 1 << 1;
export const CAP_PER_SET_K = 1 << 2;
export const CAP_DEADLINE = 1 << 3;
export const CAP_PMTUD = 1 << 4;
export const CAP_TLV = 1 << 5;
export const CAP_KNOWN_MASK = 0x3f;
export const LOCAL_FLAGS_M1 = CAP_FRAMING | CAP_FECSTAT | CAP_PER_SET_K;

export const HELLO_MAGIC = Buffer.from('FCP_HELLO_V1\0\0\0\0', 'latin1');
export const HELLO_ACK_MAGIC = Buffer.from('FCP_HELLO_ACK_V1', 'latin1');
export const HELLO_MAGIC_LEN = 16;
export const HELLO_ACK_MAGIC_LEN = 16;
export const HANDSHAKE_NONCE_LEN = 16;
export const HELLO_LEN = HELLO_MAGIC_LEN + HANDSHAKE_NONCE_LEN + CAPS_LEN; // 36
export const HELLO_ACK_LEN = HELLO_ACK_MAGIC_LEN + 2 * HANDSHAKE_NONCE_LEN + CAPS_LEN; // 52
export const TLV_BLOCK_LEN_BYTES = 2;
export const TLV_OVERHEAD = 2;
export const TLV_MAX_VALUE_LEN = 255;
export const TLV_BLOCK_MAX_LEN = 1024;
export const TLV_TYPE_ERROR = 1;
export const TLV_TYPE_ACK_V2 = 2;
export const TLV_TYPE_PREWARM = 3;
// #84 epoch key roll. Empty value: the only thing it says is "I can roll too".
// The roll itself is derived from the counter, so there is nothing else to carry;
// what this buys is knowing that turning it on will not desync the peer.
export const TLV_TYPE_KEY_UPDATE = 4;
/** Session multiplexing (M1): both ends offer → every DATA symbol payload
 *  gains a 1-byte stream id prefix (0 = the session's default stream), and
 *  each id carries its own FCP-STREAM byte stream. Old peers never offer it
 *  and see today's single-stream wire, byte for byte. */
export const TLV_TYPE_MULTIPLEX = 5;
/** Idle-time path probe. Offered unconditionally; a probe only runs when both
 *  ends offered it, so a peer that never heard of it is simply never probed
 *  (one lost probe train would otherwise look like 100% loss). */
export const TLV_TYPE_PATH_PROBE = 6;
export const MUX_MAX_STREAMS = 255; // stream ids 1..255; 0 = default stream
/** Client-side session pool: eligible local connections round-robin across
 *  this many shared sessions (each an independent window and loss domain).
 *  4 windows aggregate 4x the in-flight capacity and disperse loss bursts
 *  across independent recovery domains; measured +51-69% aggregate on the
 *  4-range download vs a single stream. */
export const MUX_SESSION_POOL = 4;
export const HANDSHAKE_MAX_RETRIES = 9;
export const HANDSHAKE_RETRY_MS = 250;
export const HANDSHAKE_RETRY_CAP_MS = 8000;
export const HANDSHAKE_MAX_CACHED_SEGMENTS = 512;
export const HANDSHAKE_MAX_CACHED_BYTES = 512 * 1024;

export const HandshakeRole = { Client: 0, Server: 1 } as const;
export type HandshakeRoleValue = (typeof HandshakeRole)[keyof typeof HandshakeRole];
export const SessionMode = { FramedRepair: 0, FramedStats: 1 } as const;
export const HandshakeState = { Idle: 0, HelloSent: 1, Established: 2, Failed: 3 } as const;
export const HandshakeError = {
  None: 0, NoAck: 1, BadCaps: 2, MissingCapability: 3, CacheOverflow: 4, BadNonce: 5,
} as const;
export type HandshakeErrorValue = (typeof HandshakeError)[keyof typeof HandshakeError];

// FECSTAT (fecstat.h)
export const FECSTAT_LEN = 128;
export const FECSTAT_VERSION = 1;
export const FECSTAT_MAX_FORWARD_SETS = 1 << 20;
export const MIN_SAMPLE_PACKETS = 256;
export const FECSTAT_MAGIC = Buffer.from('FCP_FECSTAT_V1\0\0', 'latin1');
export const FLG_LEDGER = 0x08;
export const FLG_DIRECTION = 0x01;
export const FLG_TAIL_DROPPED = 0x02;
export const FLG_LATE_RECOVERY = 0x04;

// GF(256) / RS (gf256.h, rs.h)
export const GF256_POLY = 0x11d;
export const RS_MAX_SHARDS = 256;
export const RS_MAX_PARITY = 7;

// FEC interleaving / adaptive group size
/** Interleave depth ceiling: the sender keeps this many repair groups open and
 *  round-robins segments across them, so a burst of B consecutive datagram
 *  losses lands B/L in each group instead of B in one. */
export const MAX_INTERLEAVE = 8;
/** Smallest group the adaptive controller may pick. Below this the parity
 *  granularity gets coarse (k/d jumps by 1/d per step) and the set rate climbs. */
export const D_FLOOR = 4;
/** Ceiling on full groups per second, used to reject a d so small that the
 *  receiver would evict unaccounted sets faster than it settles them.
 *
 *  A set occupies a slot for 2 s (frame.ts settles at 1 s and deletes at 2 s),
 *  so a sustained rate of P groups/s keeps 2P sets resident, and MAX_ACTIVE_SETS
 *  = 256 (declared below, in the FEC section) allows at most 128/s. This used
 *  to be 150, which its own comment disproved: 150 x 2 = 300 resident sets,
 *  i.e. exactly the eviction path the bound exists to avoid. The 256 is written
 *  out because MAX_ACTIVE_SETS is declared later in this file; the invariant
 *  `2 x this <= MAX_ACTIVE_SETS` is pinned by tests/geom.test.ts. */
export const MAX_SETS_PER_SECOND = 256 / 2;
/** A d change is only applied when it moves by at least this much, so the
 *  controller cannot chatter between two adjacent values every tick. */
export const D_STEP_MIN = 2;
/** Minimum spacing between d changes. One FECSTAT interval of evidence. */
export const D_ADAPT_INTERVAL_MS = 2000;

// ACK redundancy
/** Copies of every ACK put on the wire. 1 disables the feature.
 *
 *  Off by default, and that is a measured choice, not caution. Each copy costs
 *  the *receiver* one more encrypt+send per ACK, so the price scales with the
 *  ACK rate: on a loopback run at 7-10k datagrams/s, --ack-copies=2 cut
 *  goodput from 11-15 MB/s to 5.6-8.7 MB/s and three copies to 6.6-7.0 MB/s,
 *  with interleaving at 4 lanes costing nothing on the same runs. The path this
 *  is deployed on loses 1.6% and already retransmits ~0, so there is nothing to
 *  win there. It stays a knob for a link whose *uplink* is the lossy side. */
export const MAX_ACK_COPIES = 4;
/** Bit 7 of the ACK v2 range-count byte marks a redundant copy. The count
 *  itself never exceeds 64, so the bit is free. */
export const ACK_V2_FLAG_COPY = 0x80;
/** How many recent ACK signatures the receiver remembers, so a copy that
 *  arrives after a newer ACK still cannot be mistaken for fresh loss evidence. */
export const ACK_SIG_RING = 4;

// Idle path probe (probe/pathprobe.ts)
//
// The tunnel only learns the shape of its path while it is carrying data: FECSTAT
// needs 256 delivered shards per report, so an idle session measures nothing at
// all, and the first thing a user does after a long idle period starts from a k/d
// chosen for a path that may have changed. A probe train is a bounded burst of
// un-repaired datagrams on the same 5-tuple, so it measures the raw path (which is
// exactly what k has to cover) without touching stream or ARQ state.
export const PROBE_MAGIC = Buffer.from('FCPPRB01', 'latin1');
/** magic8 | type1 | flags1 | token4 | seq2 | total2 | got2 | sentMs4 | size2 |
 *  reserve4 | aux2 ... = 32 bytes, then zero padding for DAT. */
export const PROBE_HDR_LEN = 32;
export const PROBE_TYPE_DAT = 0;
export const PROBE_TYPE_ECHO = 1;
export const PROBE_TYPE_SUM = 2;
export const PROBE_TYPE_DOWN = 3;
export const PROBE_FLAG_LAST = 0x01;
/** Set on the DOWN request, so one frame type can never be mistaken for a DAT
 *  even if a future field changes shape. */
export const PROBE_FLAG_DOWN = 0x02;
/** Total DAT payload one measurement may put on the wire, both directions
 *  together. Echoes are ~67 bytes each on top (see PROBE_HDR_LEN + overhead). */
export const PROBE_BUDGET_BYTES = 1024 * 1024;
export const PROBE_INTERVAL_MS = 5 * 60_000;
/** No application byte in either direction for this long counts as idle. */
export const PROBE_IDLE_MS = 20_000;
/** Ramp start. Below this a 512 KiB half-budget finishes before the rate has
 *  moved at all, so a fresh probe would report the pacing rate, not the path. */
export const PROBE_RATE_START_BPS = 256 * 1024;
/** Above this the probe is measuring its own pacing granularity (a 10 ms tick
 *  cannot space datagrams finer than ~80 KiB/s of burst), so the result is
 *  reported as "at least this" instead of pretending to resolve more. */
export const PROBE_RATE_CAP_BPS = 8 * 1024 * 1024;
/** Datagrams per ramp chunk: 48 x ~1.3 KiB = 63 KiB, which gives a loss
 *  estimate whose standard error at a 20% baseline is ~5 points — small enough
 *  to tell "the path loses 20% anyway" from "the path loses 20% because I am
 *  pacing above capacity", and small enough that 5-6 chunks fit in half the
 *  budget. */
export const PROBE_RAMP_ROUND = 48;
/** A chunk above `baseline + max(this, 2.5 sigma)` ends the ramp. The sigma term
 *  matters on a lossy path: with 48 datagrams at a 20% baseline, a 20-point jump
 *  is inside the noise, and a fixed 2-point threshold would stop the ramp at the
 *  first chunk every single time. */
export const PROBE_LOSS_LIMIT = 0.02;
/** Settle pacing as a fraction of the last clean round, so the settle phase
 *  measures the path instead of re-running the experiment that just failed. */
export const PROBE_SETTLE_FRACTION = 0.85;
/** Hard stop for one phase. A 512 KiB half-budget on a 100 KB/s path needs 5 s;
 *  past this the result is reported with whatever was measured. */
export const PROBE_TIMEOUT_MS = 15000;
/** Quiet time after the last datagram before the receiver's summary is built
 *  and sent: stragglers that arrive inside it are counted, not lost. */
export const PROBE_DRAIN_MS = 250;
/** The summary is oob and never retransmitted, so it goes out three times. */
export const PROBE_SUM_COPIES = 3;
/** Retry spacing when a probe could not start (no established session yet). */
export const PROBE_RETRY_MS = 5000;

// Defaults (defaults.h)
export const DEFAULT_D = 10;
export const DEFAULT_P = 6;
export const DEFAULT_MTU = 1400;
// PMTUD is on by default: the datagram budget starts at a conservative floor
// and walks upward toward the ceiling. 1040 is deliberately below the IPv6
// minimum (1280) because it is the value already proved on the deployed path.
export const DEFAULT_MTU_MIN = 1040;
export const DEFAULT_IP_HEADER_LEN = 20;
export const DEFAULT_PMTU_MAX_MTU = 1500;
/** Probe step in bytes; 1040 -> 1500 is 5 acknowledged steps. */
export const PMTU_PROBE_STEP = 100;
/** Exponential backoff after a probe is declared a black hole. */
export const PMTU_BACKOFF_MAX_MS = 60000;
export const DEFAULT_SRTT_MS = 200;
export const DEFAULT_FLUSH_MS = 200;
export const QUEUE_GUARDRAIL_GAP_MS = 40;
export const DEFAULT_SEND_WINDOW_BYTES = 512 * 1024;
export const DEFAULT_RCV_BUF_BYTES = 256 * 1024;
/** Floor for the BDP-derived window. It used to be 512 KiB because the window
 *  was sized from the *receive*-direction estimate, which knows nothing about
 *  the send path; a floor that high only hid the bad estimate and inflated
 *  in-flight bytes on a 1 MB/s link. With an honest send-side rate the floor
 *  only has to cover ACK-clock jitter. */
export const DEFAULT_WINDOW_MIN_BYTES = 128 * 1024;
/** The receive buffer is not a bandwidth knob. It must hold every byte that
 *  arrived out of order until the hole in front of them is repaired, and on a
 *  path dropping 16% of datagrams that is most of a window: measured reorder
 *  occupancy reached 257 KB against a 256 KiB buffer, at which point the
 *  receiver started dropping segments it had already been sent, the sender
 *  could only retransmit, and retransmits were 40% of all traffic. Sizing it
 *  at a fixed generous floor costs memory and nothing else. */
export const DEFAULT_RCV_BUF_FLOOR_BYTES = 1024 * 1024;
/** Receive buffer = this x BDP, never below the floor above. Four, not two:
 *  the buffer has to cover a whole sender window (2 x BDP) plus the hole. */
export const RCV_BUF_BDP_FACTOR = 4;
export const DEFAULT_WINDOW_MAX_BYTES = 1024 * 1024;
export const DEFAULT_WINDOW_CEILING_BYTES = 4 * 1024 * 1024;

/** Bytes one pump() pass may emit. A whole window emitted inside a single
 *  synchronous loop is exactly what overran the path and stalled the peer;
 *  the remainder continues on the next tick or ACK. Measured on the VPS link:
 *  44 KiB bursts gave 32 KB/s, 5.5 KiB bursts gave 81 KB/s, and 1.4 KiB gave
 *  45 KB/s (too small to fill the RTT). A byte budget keeps small control
 *  segments from being counted as if they were full-size ones. */
export const PUMP_BURST_BYTES = 6 * 1024;
/** Zero-window probe cadence. The old `nowMs % 1000 < 30` test could miss its
 *  slot entirely on a 10 ms tick and stall a full second. */
export const ZERO_WINDOW_PROBE_MS = 50;
/** In-flight target = WINDOW_BDP_FACTOR x BDP, clamped to [floor, ceiling].
 *  Two, not four: the estimate below is already the achieved delivery rate, so
 *  2xBDP is the standard BBR headroom. Four doubled the standing queue and made
 *  every loss event cost twice as much in-flight data. */
export const WINDOW_BDP_FACTOR = 2;
/** Bandwidth estimate is the max over this window, not the last epoch. Bursty
 *  delivery makes a single epoch read 10x low and collapses the window. */
export const BBR_BW_WINDOW_MS = 2000;
/** Re-evaluate the window at most this often; bbr settles once per srtt. */
export const WINDOW_UPDATE_INTERVAL_MS = 250;
/** Only resize when the target moves this far, so rwnd advertisements do not
 *  flap on every estimate wobble. */
export const WINDOW_CHANGE_RATIO = 1.25;
/** Recovery ratio at or above which a sample counts as "no loss at all".
 *  Deprecated: the FEC controller now works from the directly measured shard
 *  loss rate instead of a recovery ratio, which always sat in a dead band. */
export const CLEAN_RECOVERY = 0.99;
/** Consecutive clean samples required before FEC drops one step. */
export const CLEAN_EVIDENCE = 2;
/** Consecutive low-loss samples before k steps down. Each FECSTAT is 2 s, so
 *  four samples is 8 s of evidence against one loss event — enough to stop k
 *  from flapping on a path whose loss rate sits right on a step boundary. */
export const FEC_DROP_STREAK = 4;
/** Multiplier on the expected number of lost shards per group when choosing k.
 *  `k` must cover the mean plus variance: 3 x d x loss covers the bursty
 *  losses this path produces without paying for worst case every group.
 *
 *  1.5 covered the MEAN of the per-group loss distribution and nothing else.
 *  Measured on the live path at 19-20% shard loss with d=10: the formula picked
 *  k=3, where P(a group loses more than k) = 12.1%, so one group in eight could
 *  not be repaired and waited an ARQ round on a ~400 ms path. Pinning k=6
 *  (tail 0.09%) on the same path, same 19-20% loss, doubled goodput: 1.88-2.36
 *  MB/s against 0.90-1.00 MB/s, with retransmissions down from 6.5-7.0% to
 *  1.3-2.4% of segments and the wire rate still only 3.0-3.8 MB/s (loss did not
 *  rise with it, so the link was never the limit — recovery was). 3.0 puts
 *  k=6 at 20% loss, 3 at 10%, 2 at 5% and the floor at <=2%, so a clean path
 *  still pays the minimum. Above ~22% loss the ceiling P is what binds. */
export const FEC_HEADROOM = 3.0;
/** Minimum delivered data shards in one FECSTAT before its loss rate is used.
 *  1000 was too high: a 0.3 MB/s stream produces ~600 shards per 2 s report,
 *  so the controller simply never engaged on a slow path. At 256 the standard
 *  error on a 5% estimate is about 1.4 percentage points. */
export const FEC_LOSS_MIN_SHARDS = 256;
export const DEFAULT_IDLE_TIMEOUT_MS = 300000;

// Log levels (log_level.h)
export const LogSeverity = { Debug: 10, Info: 20, Warn: 30, Error: 40, Off: 100 } as const;

// Frame / MTU (frame_tx.h)
export const FRAME_ENVELOPE_OVERHEAD = 28;
export const DATA_WIRE_OVERHEAD = 37;   // 28 + 7 + 2
export const PARITY_WIRE_OVERHEAD = 35; // 28 + 7
export const KCP_HEADER_RESERVE = 24;   // legacy reserve, no KCP implementation exists
export const MIN_FLUSH_MS = 25;
export const MAX_FLUSH_MS = 200;
/** A partial repair group may not sit longer than this multiple of the time it
 *  needs to fill up. Waiting a full sRTT (the old fixed flushMs = srtt) for a
 *  group that would have closed in 14 ms delays the parity for its tail by
 *  ~190 ms on a fast path — and parity is the only thing that repairs that tail
 *  without an ARQ round trip. On a slow path the same formula is *larger* than
 *  sRTT, so the cap stays at sRTT and nothing changes there: this only ever
 *  shortens the wait where waiting bought nothing. */
export const FLUSH_DRAIN_FACTOR = 1.5;

// FrameRx (frame_rx.h)
export const MAX_ACTIVE_SETS = 256;
export const MAX_GAP_PLACEHOLDERS = 64;
export const AHEAD_CONFIRM_TIMEOUT_MS = 2000;
export const SN_WINDOW = 4096;
/** Byte ceiling on the symbols all active sets hold together (frame_rx.h).
 *  Without it a peer may pin the heap by filling every set with full-size
 *  symbols; the sender's ARQ retransmits whatever this drops. */
export const MAX_RX_SYMBOL_BYTES = 8 * 1024 * 1024;

// Session (session.cc)
export const KEEPALIVE_MAGIC = Buffer.from('FCPKAL1\0', 'latin1');
export const KEEPALIVE_LEN = 8;
export const HANDSHAKE_SEND_BUDGET = 1 << 16;
export const BOOTSTRAP_PROBES_PER_SECOND = 64;
export const NAT_KEEPALIVE_MS = 45000;
export const PEER_ALIVE_GRACE_MS = 3 * 45000;

// FCP-STREAM (stream.h)
export const STREAM_TYPE_DATA = 1;
export const STREAM_TYPE_ACK = 2;
export const STREAM_TYPE_RST = 3;
export const STREAM_TYPE_ACK_V2 = 4;
export const STREAM_DATA_HDR_LEN = 6;
export const STREAM_ACK_LEN = 17;
export const STREAM_ACK_V2_MIN_LEN = 10;
export const STREAM_ACK_V2_MAX_RANGES = 64;
export const STREAM_RST_LEN = 2;
export const STREAM_FLAG_FIN = 1 << 0;
/** Duplicate acks required to arm the fast-retransmit pass. The SACK ranges
 *  already carry the loss evidence; the threshold only filters reordered ACK
 *  arrivals, and 2 fires one ack-cycle (~40 ms) sooner than 3.
 *
 *  1: on a stalled window the receiver has nothing left to send, so its only
 *  duplicate acks come from the HOLE_DUP_ACK timer. Waiting for a second one
 *  cost a full repeat interval (50 ms before, 10-50 ms now) *before* the age
 *  gate was even consulted, and the gate then still had to be satisfied by a
 *  later ack. fastRetransmit() re-arms on every duplicate ack and is idempotent
 *  — the proof (sackedHigh past the segment), the age gate and the per-segment
 *  repeat interval all still have to pass — so a lower threshold only makes the
 *  evaluation happen sooner, it does not send more copies. */
export const DUP_ACK_THRESH = 1;
export const STREAM_RST_ABORT = 1;
export const ACK_DELAY_MS = 4;
/** Data segments per acknowledgement. One ack per segment turned the uplink
 *  into a 97-byte burst per received datagram; the path drops bursts, so most
 *  acks never arrived and the sender's window only crept forward. 6 was the
 *  measured sweet spot for coalescing, but evidence latency then cost the
 *  sender ~1.5 RTT per hole (the dup-ack counter fills 2x slower); 3 halves
 *  that while keeping ack volume at a level the lossy uplink tolerated. */
export const ACK_EVERY_SEGMENTS = 3;
/** While a sequence hole is open the receiver must keep answering, otherwise
 *  the sender sits on a full window waiting for an ack that will never come
 *  until its RTO expires (seconds). Repeated acks drive fast retransmit.
 *  50 ms: with DUP_ACK_THRESH at 2 the fast-retransmit trigger lands within
 *  ~1 RTT of the hole forming. Same ack, no extra wire state.
 *
 *  This is a *ceiling*: the live interval is clamp(srtt / HOLE_DUP_ACK_DIVISOR,
 *  HOLE_DUP_ACK_MIN_MS, HOLE_DUP_ACK_MS). A fixed 50 ms is a fifth of a RTT on
 *  a 250 ms path but two and a half RTTs on a 20 ms one, so the hole was
 *  reported at wildly different rates depending on where the peer happened to
 *  be. Scaling it to the path keeps the repeat inside the same round. */
export const HOLE_DUP_ACK_MS = 50;
export const HOLE_DUP_ACK_MIN_MS = 10;
export const HOLE_DUP_ACK_DIVISOR = 8;
/** Segments repaired per duplicate-ack round. Retransmitting only the oldest
 *  hole makes a 20-segment gap take 20 rounds; the rest are provably missing
 *  because they were sent before the sacked block that produced the dup ack.
 *  Six is a full pump burst worth (6 x 976 B), not an arbitrary count. */
export const FAST_RETX_SEGMENTS = 6;
/** Minimum age before a segment is retransmitted for the first time. Three dup
 *  acks already prove the segment is missing, so this only guards against
 *  reordering, where "later data arrived" is not proof of loss. */
export const FAST_RETX_MIN_AGE_MS = 30;
/** The age gate above is `min(minRtt x 1.25, srtt)` — a full round trip — and it
 *  was the dominant term in single-hole recovery: the hole was proven missing
 *  one RTT after the evidence arrived, so the copy landed ~1.75 RTT after the
 *  loss. Keeping the full RTT always was the reaction to reordering (rounds that
 *  sent copies nobody needed). Both directions now exist: a round that recovers
 *  real loss narrows the gate by TIGHTEN_STEP down to TIGHTEN_FLOOR, a round
 *  that turns out to have been reordering snaps it back to 1.
 *  0.25 of a 200 ms path leaves the 30 ms floor in charge, which is the smallest
 *  wait that is still meaningful. */
export const FAST_RETX_TIGHTEN_STEP = 0.85;
export const FAST_RETX_TIGHTEN_FLOOR = 0.25;
/** How long the worst legitimate RTT sample stays in force before a smaller
 *  one may replace it. The reorder gate is derived from that sample, so without
 *  decay a single 400 ms blip would keep every later retransmit waiting 400 ms.
 *  10 s outlives a burst of reordering and still forgets a one-off queue spike. */
export const RTT_PEAK_DECAY_MS = 10000;
/** Ceiling on the RTT peak the reorder gate may learn. Beyond this the sample
 *  is a hole-delayed segment (already filtered in onAck) or a queue so deep
 *  that one hole is not the problem worth optimising for. */
export const RTT_PEAK_MAX_MS = 1000;
/** rttvar below this is measurement noise, not path jitter: on a clean link the
 *  estimator settles at 1-3 ms, and letting that widen the reorder gate would
 *  trade real recovery latency for a spread that does not exist. */
export const RTTVAR_NOISE_FLOOR_MS = 5;
/** Do not resend a segment that went out less than this long ago. Duplicate
 *  acks arrive every ~100 ms; without the guard the same three segments were
 *  re-emitted every round, pushing the retransmit ratio past 80% while the
 *  copies were still in flight. */
export const MIN_RETX_INTERVAL_MS = 120;
/** A retransmission needs a full RTT before its ACK can arrive. Re-sending
 *  sooner is guaranteed waste: the copy is still in flight. This is the real
 *  ceiling on the retransmit ratio — the fixed 120 ms floor was shorter than
 *  the 200-400 ms path RTT, so every copy was duplicated at least once. */
export const RETX_RTT_FACTOR = 1.0;
export const MIN_RTT_EXPIRY_MS = 10000;
export const TLP_MIN_PTO_MS = 60;
export const TLP_MAX_PROBES = 2;
/** Retransmit-recovery latency ring size. Bounded on purpose: a proxy runs
 *  thousands of sessions and an unbounded sample list is a leak, while 256
 *  samples give a p95 that is stable to a few ms. */
export const RETX_LAT_SAMPLES = 256;
/** Receive-side chunk-count ceiling (stream.h kMinOobChunks/kMaxOobChunks).
 *  The byte ceiling alone does not bound memory: a peer can put one byte in
 *  each run, so 256 KiB of reorder data becomes 128 k Buffer objects. */
export const MIN_OOB_CHUNKS = 1024;
export const MAX_OOB_CHUNKS = 8192;
/** Session-wide ceiling on reorder + delivered-but-unconsumed bytes, summed
 *  over the default stream and every live sid stream. Each stream's own
 *  ceiling is its rcvBufBytes (up to 4 MiB once the BDP walk grows it), and a
 *  mux session can carry 255 of them — a peer holding one hole per stream
 *  pins rcvBuf × 255 of heap until the idle timeout, which on a small VPS is
 *  an OOM lever. The per-stream windows are untouched; over-budget streams
 *  are trimmed largest-first and their window is re-shrunk each tick until
 *  the aggregate drains. 16 MiB is far above any legitimate page load and far
 *  below the per-stream worst case multiplied out. */
export const SESSION_STREAM_BUDGET_BYTES = 16 * 1024 * 1024;

// PMTUD (pmtu.h)
export const PMTU_MAGIC = Buffer.from('FCP_PMTU', 'latin1');
export const PMTU_HEADER_LEN = 16;
export const PMTU_TYPE_PROBE = 0;
export const PMTU_TYPE_ACK = 1;
export const PMTU_ABSOLUTE_MAX_MTU = 9000;

// Proxy (proxy_proto.h)
export const ATYP_IPV4 = 0x01;
export const ATYP_DOMAIN = 0x03;
export const ATYP_IPV6 = 0x04;
export const SOCKS5_VERSION = 0x05;
export const SOCKS5_METHOD_NO_AUTH = 0x00;
export const SOCKS5_METHOD_NONE = 0xff;
export const SOCKS5_CMD_CONNECT = 0x01;
export const SOCKS5_GREETING_REPLY_LEN = 2;
export const SOCKS5_REPLY_LEN = 10;
export const SOCKS5_MAX_DOMAIN_LEN = 255;
export const SOCKS5_MAX_GREETING_BYTES = 257;
export const SOCKS5_MAX_REQUEST_BYTES = 262;
export const HTTP_HEAD_MAX_BYTES = 8192;
export const HTTP_MAX_HOST_LEN = 255;
export const HTTP_FORWARD_DEFAULT_PORT = 80;
export const OPEN_MAGIC = Buffer.from('FCPO', 'latin1');
export const OPEN_VERSION = 1;
export const OPEN_KIND_OK = 0x01;
export const OPEN_KIND_ERR = 0xff;
export const OPEN_MAX_ADDR_LEN = 255;
export const OPEN_OK_LEN = 8;
export const OPEN_ERR_LEN = 7;
export const OPEN_MAX_BYTES = 264;

export const OpenError = {
  Refused: 1, Dns: 2, TargetTimeout: 3, NotSupported: 4, TooManySessions: 5,
} as const;
export type OpenErrorValue = (typeof OpenError)[keyof typeof OpenError];

// Control (strategy.h / reporter / defaults)
export const TARGET_RECOVERY = 0.80;
/** Controller feedback cadence. 1 s: the adaptive k must track loss spikes
 *  within one RTT-scale window; the 128 B report costs nothing even doubled.
 *  Both ends must run the same cadence (a mixed pair still works — the
 *  receiver dedups by the monotonic set id — but adapts at the slower end). */
export const FECSTAT_INTERVAL_MS = 1000;
export const FECSTAT_MAX_INTERVAL_MS = 60000;

export const PRODUCT_VERSION = '0.0.24';
