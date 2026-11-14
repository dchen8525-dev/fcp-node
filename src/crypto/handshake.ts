// FCP v7 handshake. Port of src/fcp/handshake.{h,cc}.
//
// Wire (oob symbol payload):
//   HELLO     = magic16 "FCP_HELLO_V1\0\0\0\0" | sender_nonce16 | caps4  [+ TLV block]
//   HELLO_ACK = magic16 "FCP_HELLO_ACK_V1" | client_nonce16 | server_nonce16 | caps4 [+ TLV]
//   caps      = ver(1) | data(1) | parity(1) | flags(1)
//   TLV block = block_len(2 LE) | [type(1) | len(1) | value]...
//
// Role is fixed by Direction (C2S = client), not by who spoke first, so a
// simultaneous open converges on the same key. The 16-byte magic doubles as
// the version gate: a byte mismatch means "not a handshake at all".

import { randomBytes } from 'node:crypto';
import {
  HELLO_MAGIC, HELLO_ACK_MAGIC, HELLO_LEN, HELLO_ACK_LEN, HELLO_MAGIC_LEN,
  HELLO_ACK_MAGIC_LEN, HANDSHAKE_NONCE_LEN, CAPS_LEN, CAPS_VERSION,
  CAP_KNOWN_MASK, CAP_TLV, CAP_FRAMING, CAP_FECSTAT, LOCAL_FLAGS_M1,
  TLV_BLOCK_LEN_BYTES, TLV_OVERHEAD, TLV_MAX_VALUE_LEN, TLV_BLOCK_MAX_LEN,
  TLV_TYPE_ERROR, TLV_TYPE_ACK_V2, TLV_TYPE_PREWARM,
  HANDSHAKE_MAX_RETRIES, HANDSHAKE_RETRY_MS, HANDSHAKE_RETRY_CAP_MS,
  HANDSHAKE_MAX_CACHED_SEGMENTS, HANDSHAKE_MAX_CACHED_BYTES,
  HandshakeRole, SessionMode, HandshakeState, HandshakeError,
  type HandshakeRoleValue, type HandshakeErrorValue,
} from '../constants.ts';
import { putLe16, getLe16, bytesEqual } from '../wire.ts';

export interface HandshakeCaps { ver: number; data: number; parity: number; flags: number; }
export interface HandshakeTlv { type: number; value: Buffer; }
export interface NegotiatedParams { d: number; p: number; flags: number; mode: number; }

export const HandshakeStatus = {
  NotHandshake: 0, Consumed: 1, ProtocolFailure: 2,
} as const;
export type HandshakeStatusValue = (typeof HandshakeStatus)[keyof typeof HandshakeStatus];

export function writeCaps(c: HandshakeCaps, out: Uint8Array, off = 0): void {
  out[off] = c.ver; out[off + 1] = c.data; out[off + 2] = c.parity; out[off + 3] = c.flags;
}
export function parseCaps(b: Uint8Array, off = 0): HandshakeCaps {
  return { ver: b[off], data: b[off + 1], parity: b[off + 2], flags: b[off + 3] };
}
export function capsValid(c: HandshakeCaps): boolean {
  if (c.ver !== CAPS_VERSION || c.data < 1 || c.parity > 7) return false;
  if (c.data + c.parity > 256) return false;
  return (c.flags & ~CAP_KNOWN_MASK) === 0;
}
export function nonceValid(n: Uint8Array): boolean {
  let acc = 0;
  for (let i = 0; i < HANDSHAKE_NONCE_LEN; ++i) acc |= n[i];
  return acc !== 0;
}

export function tlvEncode(tlvs: HandshakeTlv[], out: Uint8Array, off = 0): number {
  let total = 0;
  for (const t of tlvs) {
    if (t.type === 0 || t.value.length > TLV_MAX_VALUE_LEN) return 0;
    total += TLV_OVERHEAD + t.value.length;
  }
  if (total > TLV_BLOCK_MAX_LEN || out.length - off < TLV_BLOCK_LEN_BYTES + total) return 0;
  putLe16(total, out, off);
  let p = off + TLV_BLOCK_LEN_BYTES;
  for (const t of tlvs) {
    out[p++] = t.type;
    out[p++] = t.value.length;
    Buffer.from(t.value).copy(out as Buffer, p);
    p += t.value.length;
  }
  return p - off;
}

export function tlvParse(block: Uint8Array, len = block.length): HandshakeTlv[] | null {
  const out: HandshakeTlv[] = [];
  let off = 0;
  while (off < len) {
    if (len - off < TLV_OVERHEAD) return null;
    const type = block[off], vlen = block[off + 1];
    if (type === 0 || len - off - TLV_OVERHEAD < vlen) return null;
    out.push({ type, value: Buffer.from(block.subarray(off + TLV_OVERHEAD, off + TLV_OVERHEAD + vlen)) });
    off += TLV_OVERHEAD + vlen;
  }
  return out;
}

/** Returns the TLV list (possibly empty) or null when the claimed block is malformed. */
export function helloTlvs(data: Uint8Array, len = data.length, isAck = false): HandshakeTlv[] | null {
  const fixed = isAck ? HELLO_ACK_LEN : HELLO_LEN;
  if (len < fixed || (data[fixed - 1] & CAP_TLV) === 0) return [];
  if (len === fixed) return null;
  const block = getLe16(data, fixed);
  if (block > TLV_BLOCK_MAX_LEN || len !== fixed + TLV_BLOCK_LEN_BYTES + block) return null;
  return tlvParse(data.subarray(fixed + TLV_BLOCK_LEN_BYTES), block);
}

function msgOk(data: Uint8Array, len: number, fixedLen: number, magic: Buffer): boolean {
  if (len < fixedLen || !bytesEqual(magic, data, HELLO_MAGIC_LEN)) return false;
  if ((data[fixedLen - 1] & CAP_TLV) === 0) return len === fixedLen;
  if (len === fixedLen) return true; // claimed but absent -> caps error later
  if (len < fixedLen + TLV_BLOCK_LEN_BYTES) return false;
  return len === fixedLen + TLV_BLOCK_LEN_BYTES + getLe16(data, fixedLen);
}
export function isHello(d: Uint8Array, len = d.length): boolean { return msgOk(d, len, HELLO_LEN, HELLO_MAGIC); }
export function isHelloAck(d: Uint8Array, len = d.length): boolean { return msgOk(d, len, HELLO_ACK_LEN, HELLO_ACK_MAGIC); }

export function buildHello(caps: HandshakeCaps, senderNonce: Uint8Array, tlvs: HandshakeTlv[] = []): Buffer {
  const out = Buffer.alloc(HELLO_LEN + (tlvs.length ? TLV_BLOCK_LEN_BYTES + TLV_BLOCK_MAX_LEN : 0));
  HELLO_MAGIC.copy(out, 0);
  Buffer.from(senderNonce).copy(out, HELLO_MAGIC_LEN);
  writeCaps(caps, out, HELLO_MAGIC_LEN + HANDSHAKE_NONCE_LEN);
  if (!tlvs.length) return out.subarray(0, HELLO_LEN);
  const n = tlvEncode(tlvs, out, HELLO_LEN);
  if (n === 0) throw new Error('buildHello: TLV block unencodable');
  return out.subarray(0, HELLO_LEN + n);
}

// `withEmptyBlock` mirrors the C++ build_hello_ack_ext: when we echo the
// peer's kCapTlv bit but have no TLV of our own, the block must still be
// present with block_len = 0. A bare 52-byte ACK carrying the bit is rejected
// by the peer as "block claimed but absent" (BadCaps).
export function buildHelloAck(
  caps: HandshakeCaps, clientNonce: Uint8Array, serverNonce: Uint8Array,
  tlvs: HandshakeTlv[] = [], withEmptyBlock = false,
): Buffer {
  const block = tlvs.length > 0 || withEmptyBlock;
  const out = Buffer.alloc(HELLO_ACK_LEN + (block ? TLV_BLOCK_LEN_BYTES + TLV_BLOCK_MAX_LEN : 0));
  HELLO_ACK_MAGIC.copy(out, 0);
  Buffer.from(clientNonce).copy(out, HELLO_ACK_MAGIC_LEN);
  Buffer.from(serverNonce).copy(out, HELLO_ACK_MAGIC_LEN + HANDSHAKE_NONCE_LEN);
  writeCaps(caps, out, HELLO_ACK_MAGIC_LEN + 2 * HANDSHAKE_NONCE_LEN);
  if (!block) return out.subarray(0, HELLO_ACK_LEN);
  const n = tlvEncode(tlvs, out, HELLO_ACK_LEN);
  if (n === 0) throw new Error('buildHelloAck: TLV block unencodable');
  return out.subarray(0, HELLO_ACK_LEN + n);
}

export function encodePrewarmTlv(ticket: {
  initialK: number; srttMs: number; windowKb: number; bwKbps: number; minRttMs: number;
}): Buffer {
  const v = Buffer.alloc(12);
  v[0] = 1;
  v[1] = ticket.initialK;
  v.writeUInt16LE(ticket.srttMs & 0xffff, 2);
  v[4] = ticket.windowKb & 0xff; v[5] = (ticket.windowKb >>> 8) & 0xff; v[6] = (ticket.windowKb >>> 16) & 0xff;
  v[7] = ticket.bwKbps & 0xff; v[8] = (ticket.bwKbps >>> 8) & 0xff; v[9] = (ticket.bwKbps >>> 16) & 0xff;
  v.writeUInt16LE(ticket.minRttMs & 0xffff, 10);
  return v;
}
export function decodePrewarmTlv(v: Uint8Array): { initialK: number; srttMs: number; windowKb: number; bwKbps: number; minRttMs: number } | null {
  if (v.length !== 12 || v[0] !== 1) return null;
  const initialK = v[1];
  if (initialK >= 8 && initialK <= 14) return null;
  return {
    initialK: initialK === 0x0f ? 0 : initialK,
    srttMs: getLe16(v, 2),
    windowKb: v[4] | (v[5] << 8) | (v[6] << 16),
    bwKbps: v[7] | (v[8] << 8) | (v[9] << 16),
    minRttMs: getLe16(v, 10),
  };
}

export interface HandshakeOptions {
  localD: number;
  localP: number;
  role: HandshakeRoleValue;
  send: (msg: Uint8Array) => void;
  localNonce?: Uint8Array;
  localFlags?: number;
  maxCachedSegments?: number;
  maxCachedBytes?: number;
  rttSeedMs?: number;
  localTlvs?: HandshakeTlv[];
}

export class Handshake {
  readonly role: HandshakeRoleValue;
  private localD: number;
  private localP: number;
  private localFlags: number;
  private sendFn: (msg: Uint8Array) => void;
  private localNonce: Buffer;
  private peerNonce: Buffer = Buffer.alloc(HANDSHAKE_NONCE_LEN);
  private havePeer = false;
  private localTlvs: HandshakeTlv[];
  private peerTlvs: HandshakeTlv[] = [];
  private peerTlvHello = false;
  private tlvOffered = false;

  state: number = HandshakeState.Idle;
  error: HandshakeErrorValue = HandshakeError.None;
  params: NegotiatedParams = { d: 0, p: 0, flags: 0, mode: SessionMode.FramedRepair };
  retries = 0;
  nextRetryMs = 0;
  private firstGapMs: number = HANDSHAKE_RETRY_MS;
  private maxCachedSegments: number;
  private maxCachedBytes: number;
  private cached: Buffer[] = [];
  private cachedBytes = 0;
  nonceMismatch = 0;
  helloRefused = 0;
  peerError: HandshakeErrorValue = HandshakeError.None;

  constructor(opts: HandshakeOptions) {
    this.role = opts.role;
    this.localD = opts.localD;
    this.localP = opts.localP;
    this.localFlags = opts.localFlags ?? LOCAL_FLAGS_M1;
    this.sendFn = opts.send;
    this.maxCachedSegments = opts.maxCachedSegments ?? HANDSHAKE_MAX_CACHED_SEGMENTS;
    this.maxCachedBytes = opts.maxCachedBytes ?? HANDSHAKE_MAX_CACHED_BYTES;
    this.localTlvs = opts.localTlvs ?? [];
    if (opts.rttSeedMs && opts.rttSeedMs > 0) {
      this.firstGapMs = Math.min(Math.max(2 * opts.rttSeedMs, HANDSHAKE_RETRY_MS), HANDSHAKE_RETRY_CAP_MS);
    }
    this.localNonce = opts.localNonce ? Buffer.from(opts.localNonce) : Buffer.from(randomBytes(HANDSHAKE_NONCE_LEN));
    if (!nonceValid(this.localNonce)) this.fail(HandshakeError.BadNonce);
  }

  get established(): boolean { return this.state === HandshakeState.Established; }
  get failed(): boolean { return this.state === HandshakeState.Failed; }
  get clientNonce(): Buffer { return this.role === HandshakeRole.Client ? this.localNonce : this.peerNonce; }
  get serverNonce(): Buffer { return this.role === HandshakeRole.Server ? this.localNonce : this.peerNonce; }
  get bufferingData(): boolean { return this.state === HandshakeState.Idle || this.state === HandshakeState.HelloSent; }
  get havePeerNonce(): boolean { return this.havePeer; }
  tlvNegotiated(): boolean { return (this.params.flags & CAP_TLV) !== 0; }
  tlvAgreed(type: number): boolean {
    if (!this.tlvNegotiated()) return false;
    return this.localTlvs.some((t) => t.type === type) && this.peerTlvs.some((t) => t.type === type);
  }
  peerTlv(type: number): Buffer | null {
    const t = this.peerTlvs.find((x) => x.type === type);
    return t ? t.value : null;
  }
  setLocalTlvs(tlvs: HandshakeTlv[]): void { this.localTlvs = tlvs; }

  private fail(err: HandshakeErrorValue): void {
    this.state = HandshakeState.Failed;
    this.error = err;
    this.cached = [];
    this.cachedBytes = 0;
  }

  start(nowMs: number): void {
    if (this.state !== HandshakeState.Idle || this.error === HandshakeError.BadNonce) return;
    this.state = HandshakeState.HelloSent;
    this.retries = 0;
    this.nextRetryMs = nowMs;
  }

  onTick(nowMs: number): void {
    if (this.state !== HandshakeState.HelloSent || nowMs < this.nextRetryMs) return;
    if (this.retries >= HANDSHAKE_MAX_RETRIES) { this.fail(HandshakeError.NoAck); return; }
    // The #77 plain-v7 downgrade used to fire after two unanswered HELLOs. It
    // was removed: this proxy's data path is multiplexed and the server only
    // serves sid streams (its default stream is intentionally unwired), so a
    // downgraded session can never carry a connection. Worse, on the client it
    // poisons the shared session pool: after one lossy handshake the entry is
    // established without mux and every later connection is refused. A session
    // with no TLVs of its own still sends the plain shape (see sendHello).
    this.sendHello();
    ++this.retries;
    this.nextRetryMs = nowMs + Math.min(this.firstGapMs * (2 ** (this.retries - 1)), HANDSHAKE_RETRY_CAP_MS);
  }

  private sendHello(): void {
    const offer = this.localTlvs.length > 0;
    const flags = offer ? (this.localFlags | CAP_TLV) & 0xff : (this.localFlags & ~CAP_TLV) & 0xff;
    const caps: HandshakeCaps = { ver: CAPS_VERSION, data: this.localD, parity: this.localP, flags };
    if (offer) this.tlvOffered = true;
    this.sendFn(buildHello(caps, this.localNonce, offer ? this.localTlvs : []));
  }

  private sendHelloAck(): void {
    if (!this.havePeer) return;
    const offer = this.peerTlvHello;
    const flags = offer ? (this.localFlags | CAP_TLV) & 0xff : (this.localFlags & ~CAP_TLV) & 0xff;
    const caps: HandshakeCaps = { ver: CAPS_VERSION, data: this.localD, parity: this.localP, flags };
    this.sendFn(buildHelloAck(caps, this.clientNonce, this.serverNonce,
      offer ? this.localTlvs : [], offer));
  }

  private sendErrorAck(err: HandshakeErrorValue, clientNonce: Uint8Array): void {
    if (this.role !== HandshakeRole.Server) return;
    const caps: HandshakeCaps = {
      ver: CAPS_VERSION, data: this.localD, parity: this.localP,
      flags: ((this.localFlags & ~CAP_TLV) | CAP_TLV) & 0xff,
    };
    this.sendFn(buildHelloAck(caps, clientNonce, this.localNonce,
      [{ type: TLV_TYPE_ERROR, value: Buffer.from([err]) }]));
  }

  cacheData(segment: Uint8Array): boolean {
    if (!this.bufferingData) return false;
    if (this.cached.length + 1 > this.maxCachedSegments ||
        this.cachedBytes + segment.length > this.maxCachedBytes) {
      this.fail(HandshakeError.CacheOverflow);
      return false;
    }
    this.cachedBytes += segment.length;
    this.cached.push(Buffer.from(segment));
    return true;
  }
  takeCachedData(): Buffer[] {
    if (this.state !== HandshakeState.Established) return [];
    const out = this.cached;
    this.cached = [];
    this.cachedBytes = 0;
    return out;
  }

  private negotiate(peer: HandshakeCaps): boolean {
    const flags = (this.localFlags & peer.flags) & 0xff;
    const required = CAP_FRAMING | CAP_FECSTAT;
    if ((flags & required) !== required) { this.fail(HandshakeError.MissingCapability); return false; }
    const bothTlv = (peer.flags & CAP_TLV) !== 0 &&
      (this.role === HandshakeRole.Client ? this.tlvOffered : this.peerTlvHello);
    this.params = {
      d: Math.min(this.localD, peer.data),
      p: Math.min(this.localP, peer.parity),
      flags: (flags | (bothTlv ? CAP_TLV : 0)) & 0xff,
      mode: Math.min(this.localP, peer.parity) === 0 ? SessionMode.FramedStats : SessionMode.FramedRepair,
    };
    this.state = HandshakeState.Established;
    this.error = HandshakeError.None;
    return true;
  }

  /** Dispatch an oob payload. Returns NotHandshake when it is not ours. */
  onOob(data: Uint8Array, len = data.length): HandshakeStatusValue {
    if (isHello(data, len)) return this.onHello(data, len);
    if (isHelloAck(data, len)) return this.onHelloAck(data, len);
    return HandshakeStatus.NotHandshake;
  }

  private onHello(data: Uint8Array, len: number): HandshakeStatusValue {
    if (this.state === HandshakeState.Failed) return HandshakeStatus.Consumed;
    const senderNonce = data.subarray(HELLO_MAGIC_LEN, HELLO_MAGIC_LEN + HANDSHAKE_NONCE_LEN);
    const tlvs = helloTlvs(data, len, false);
    const peer = parseCaps(data, HELLO_MAGIC_LEN + HANDSHAKE_NONCE_LEN);
    const knowsTlv = (peer.flags & CAP_TLV) !== 0;
    if (!capsValid(peer) || tlvs === null) {
      if (knowsTlv) this.sendErrorAck(HandshakeError.BadCaps, senderNonce);
      this.fail(HandshakeError.BadCaps);
      return HandshakeStatus.ProtocolFailure;
    }
    if (!nonceValid(senderNonce)) {
      if (knowsTlv) this.sendErrorAck(HandshakeError.BadNonce, senderNonce);
      this.fail(HandshakeError.BadNonce);
      return HandshakeStatus.ProtocolFailure;
    }
    if (this.state === HandshakeState.Established) {
      if (this.havePeer && bytesEqual(this.peerNonce, senderNonce, HANDSHAKE_NONCE_LEN)) {
        this.sendHelloAck(); // our ACK was lost -> idempotent re-ACK
      } else {
        ++this.helloRefused; // R3-24: a different nonce cannot restart a live session
      }
      return HandshakeStatus.Consumed;
    }
    if (this.havePeer) {
      if (!bytesEqual(this.peerNonce, senderNonce, HANDSHAKE_NONCE_LEN)) { ++this.helloRefused; return HandshakeStatus.Consumed; }
    } else {
      this.peerNonce = Buffer.from(senderNonce);
      this.havePeer = true;
      this.peerTlvHello = knowsTlv;
      if (knowsTlv) this.peerTlvs = tlvs;
    }
    if (!this.negotiate(peer)) return HandshakeStatus.ProtocolFailure;
    this.sendHelloAck();
    return HandshakeStatus.Consumed;
  }

  private onHelloAck(data: Uint8Array, len: number): HandshakeStatusValue {
    if (this.state !== HandshakeState.HelloSent) return HandshakeStatus.Consumed;
    const cNonce = data.subarray(HELLO_ACK_MAGIC_LEN, HELLO_ACK_MAGIC_LEN + HANDSHAKE_NONCE_LEN);
    const sNonce = data.subarray(HELLO_ACK_MAGIC_LEN + HANDSHAKE_NONCE_LEN, HELLO_ACK_MAGIC_LEN + 2 * HANDSHAKE_NONCE_LEN);
    const ownEcho = this.role === HandshakeRole.Client ? cNonce : sNonce;
    const peerDraw = this.role === HandshakeRole.Client ? sNonce : cNonce;
    if (!bytesEqual(ownEcho, this.localNonce, HANDSHAKE_NONCE_LEN)) {
      ++this.nonceMismatch;
      return HandshakeStatus.Consumed;
    }
    const tlvs = helloTlvs(data, len, true);
    if (tlvs !== null) {
      for (const t of tlvs) {
        if (t.type === TLV_TYPE_ERROR && t.value.length === 1) {
          const code = t.value[0];
          this.peerError = code === HandshakeError.BadCaps || code === HandshakeError.BadNonce
            ? code : HandshakeError.BadCaps;
          this.fail(this.peerError);
          return HandshakeStatus.ProtocolFailure;
        }
      }
    }
    const peer = parseCaps(data, HELLO_ACK_MAGIC_LEN + 2 * HANDSHAKE_NONCE_LEN);
    if (!capsValid(peer) || tlvs === null) { this.fail(HandshakeError.BadCaps); return HandshakeStatus.ProtocolFailure; }
    if (!nonceValid(cNonce) || !nonceValid(sNonce)) { this.fail(HandshakeError.BadNonce); return HandshakeStatus.ProtocolFailure; }
    if (this.havePeer) {
      if (!bytesEqual(this.peerNonce, peerDraw, HANDSHAKE_NONCE_LEN)) { ++this.helloRefused; return HandshakeStatus.Consumed; }
    } else {
      this.peerNonce = Buffer.from(peerDraw);
      this.havePeer = true;
    }
    if (peer.flags & CAP_TLV) this.peerTlvs = tlvs;
    if (!this.negotiate(peer)) return HandshakeStatus.ProtocolFailure;
    return HandshakeStatus.Consumed;
  }
}

export { HELLO_LEN, HELLO_ACK_LEN, CAP_TLV, TLV_TYPE_ACK_V2, TLV_TYPE_PREWARM, CAPS_LEN };
