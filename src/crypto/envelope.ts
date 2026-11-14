// AEAD envelope. Port of src/fcp/envelope.h / envelope.cc.
//
// Wire: salt(8) | nonce_ctr(8 LE) | AES-128-GCM ciphertext | tag(12).
// IV (12B, local expansion): counter(8 LE) | direction(1) | 0x00 x 3.
// AAD is empty. Two direction keys from SP 800-108 counter KDF, 1024-slot
// anti-replay window, optional #84 epoch key update, #86 stateless reset.

import { gcmSeal, gcmOpen, cspRandomU64 } from './aes.ts';
import { deriveSessionKey, deriveDirectionKeys, deriveEpochDirectionKey } from './keys.ts';
import {
  SALT_LEN, NONCE_LEN, TAG_LEN, ENVELOPE_OVERHEAD, RESET_MAGIC_LEN, RESET_MAGIC,
  NONCE_LIMIT, REPLAY_WINDOW, EPOCH_SPAN, EPOCH_SPACE_END, FIRST_ROLL_AT,
  GCM_IV_LEN, Direction, type DirectionValue,
} from '../constants.ts';
import { bytesEqual, getLe64, putLe64 } from '../wire.ts';

const U64_MAX = 0xffffffffffffffffn;

function makeIv(counter: bigint, direction: DirectionValue): Buffer {
  const iv = Buffer.alloc(GCM_IV_LEN);
  putLe64(counter, iv, 0);
  iv[8] = direction;
  return iv; // bytes 9..11 already zero
}

interface RecvEpoch {
  hasNonce: boolean;
  highest: bigint;
  seen: Uint8Array;
}
function newRecvEpoch(): RecvEpoch {
  return { hasNonce: false, highest: 0n, seen: new Uint8Array(REPLAY_WINDOW) };
}

// Port of std::bitset <<= delta: bit i moves to i + delta, high bits drop.
function shiftSeen(seen: Uint8Array, delta: bigint): void {
  if (delta >= BigInt(seen.length)) {
    seen.fill(0);
    return;
  }
  const d = Number(delta);
  for (let i = seen.length - 1; i >= d; --i) seen[i] = seen[i - d];
  seen.fill(0, 0, d);
}

export class Envelope {
  readonly salt: Buffer;
  private sendDirection: DirectionValue;
  private recvDirection: DirectionValue;
  private sendKey: Buffer;
  private recvKey: Buffer;
  private prevRecvKey: Buffer;
  private sessionKey: Buffer;

  private counterCeiling: bigint = NONCE_LIMIT;
  private sendLimit: bigint = NONCE_LIMIT;
  private sendNonceValue: bigint = 0n;
  private recvHasNonce = false;
  private recvHighest = 0n;
  private recvSeen = new Uint8Array(REPLAY_WINDOW);

  private keyUpdateEnabled = false;
  private sendEpoch = 0n;
  private rolledOnce = false;
  private recvEpochSeen = 0n;
  private recvCur = newRecvEpoch();
  private recvPrev = newRecvEpoch();

  constructor(psk: Uint8Array, salt: Uint8Array, sendDir: DirectionValue, recvDir: DirectionValue) {
    if (psk.length !== 16 || salt.length !== SALT_LEN) throw new Error('Envelope: bad key/salt length');
    this.salt = Buffer.from(salt);
    this.sendDirection = sendDir;
    this.recvDirection = recvDir;
    this.installKeys(deriveSessionKey(psk, salt));
  }

  private installKeys(sessionKey: Buffer): void {
    const { c2s, s2c } = deriveDirectionKeys(sessionKey);
    this.sendKey = Buffer.from(this.sendDirection === Direction.C2S ? c2s : s2c);
    this.recvKey = Buffer.from(this.recvDirection === Direction.C2S ? c2s : s2c);
    this.sessionKey = Buffer.from(sessionKey);
    this.prevRecvKey = Buffer.alloc(16);
    this.sendNonceValue = 0n;
    this.counterCeiling = NONCE_LIMIT;
    this.sendLimit = NONCE_LIMIT;
    this.recvHasNonce = false;
    this.recvHighest = 0n;
    this.recvSeen.fill(0);
    this.sendEpoch = 0n;
    this.rolledOnce = false;
    this.recvEpochSeen = 0n;
    this.recvCur = newRecvEpoch();
    this.recvPrev = newRecvEpoch();
  }

  /** R3-1: replace data-plane keys after the handshake produced both nonces. */
  rekey(sessionKey: Buffer): void {
    this.installKeys(sessionKey);
  }

  setKeyUpdate(enabled: boolean): void {
    this.keyUpdateEnabled = enabled;
    const limit = enabled ? EPOCH_SPACE_END : NONCE_LIMIT;
    this.counterCeiling = limit;
    this.sendLimit = limit;
  }
  get keyUpdate(): boolean { return this.keyUpdateEnabled; }
  get sendEpochValue(): bigint { return this.sendNonceValue / EPOCH_SPAN; }
  get nonce(): bigint { return this.sendNonceValue; }
  get exhausted(): boolean { return this.sendNonceValue >= this.sendLimit; }

  setSendNonce(value: bigint): boolean {
    if (value >= this.counterCeiling || value >= this.sendLimit) return false;
    this.sendNonceValue = value;
    return true;
  }

  /** Bootstrap envelope: random 64-bit counter start, full receive range. */
  initBootstrapNonce(budget: number): boolean {
    const draw = cspRandomU64();
    const span = BigInt(budget) + 1n;
    this.sendNonceValue = draw % (U64_MAX - span);
    this.sendLimit = this.sendNonceValue + span;
    this.counterCeiling = U64_MAX;
    return true;
  }

  private rollSendEpoch(): boolean {
    const epochNum = this.sendEpoch / EPOCH_SPAN + 1n;
    if (epochNum > 65535n) return false;
    this.sendKey = deriveEpochDirectionKey(this.sessionKey, this.sendDirection, Number(epochNum));
    this.sendEpoch = epochNum * EPOCH_SPAN;
    this.sendNonceValue = this.sendEpoch;
    this.rolledOnce = true;
    return true;
  }

  /** Seal one datagram and advance the send counter. Returns null on exhaustion. */
  seal(plain: Uint8Array): Buffer | null {
    if (this.keyUpdateEnabled) {
      const inEpoch = this.sendNonceValue - this.sendEpoch;
      const threshold = this.rolledOnce ? EPOCH_SPAN : FIRST_ROLL_AT;
      if (inEpoch >= threshold && !this.rollSendEpoch()) return null;
    }
    if (this.sendNonceValue >= this.sendLimit) return null;
    const wire = this.sealUnchecked(this.sendNonceValue, plain);
    if (wire === null) return null;
    this.sendNonceValue += 1n;
    return wire;
  }

  /** Test/replay primitive: explicit counter, does not advance send state. */
  sealAt(counter: bigint, plain: Uint8Array): Buffer | null {
    if (counter >= this.counterCeiling) return null;
    return this.sealUnchecked(counter, plain);
  }

  private sealUnchecked(counter: bigint, plain: Uint8Array): Buffer | null {
    const sealed = gcmSeal(this.sendKey, makeIv(counter, this.sendDirection), plain);
    if (sealed === null) return null;
    const wire = Buffer.allocUnsafe(ENVELOPE_OVERHEAD + plain.length); // fully written below
    this.salt.copy(wire, 0);
    putLe64(counter, wire, SALT_LEN);
    sealed.cipher.copy(wire, SALT_LEN + NONCE_LEN);
    sealed.tag.copy(wire, SALT_LEN + NONCE_LEN + plain.length);
    return wire;
  }

  private nonceWindowMayAccept(counter: bigint): boolean {
    if (!this.recvHasNonce) return true;
    if (counter > this.recvHighest) return true;
    const delta = this.recvHighest - counter;
    return delta < BigInt(this.recvSeen.length) && this.recvSeen[Number(delta)] === 0;
  }

  private acceptNonce(counter: bigint): boolean {
    if (!this.recvHasNonce) {
      this.recvHasNonce = true;
      this.recvHighest = counter;
      this.recvSeen.fill(0);
      this.recvSeen[0] = 1;
      return true;
    }
    if (counter > this.recvHighest) {
      shiftSeen(this.recvSeen, counter - this.recvHighest);
      this.recvSeen[0] = 1;
      this.recvHighest = counter;
      return true;
    }
    const delta = this.recvHighest - counter;
    if (delta >= BigInt(this.recvSeen.length) || this.recvSeen[Number(delta)] !== 0) return false;
    this.recvSeen[Number(delta)] = 1;
    return true;
  }

  private epochWindowMayAccept(win: RecvEpoch, counter: bigint): boolean {
    if (!win.hasNonce) return true;
    if (counter > win.highest) return true;
    const delta = win.highest - counter;
    return delta < BigInt(win.seen.length) && win.seen[Number(delta)] === 0;
  }

  private epochAccept(win: RecvEpoch, counter: bigint): boolean {
    if (!win.hasNonce) {
      win.hasNonce = true;
      win.highest = counter;
      win.seen.fill(0);
      win.seen[0] = 1;
      return true;
    }
    if (counter > win.highest) {
      shiftSeen(win.seen, counter - win.highest);
      win.seen[0] = 1;
      win.highest = counter;
      return true;
    }
    const delta = win.highest - counter;
    if (delta >= BigInt(win.seen.length) || win.seen[Number(delta)] !== 0) return false;
    win.seen[Number(delta)] = 1;
    return true;
  }

  /** Authenticate + decrypt. null on auth failure, replay, bad salt, bad counter. */
  open(wire: Uint8Array): Buffer | null {
    if (wire.length < ENVELOPE_OVERHEAD) return null;
    if (!bytesEqual(this.salt, wire, SALT_LEN)) return null;
    const counter = getLe64(wire, SALT_LEN);
    if (counter >= this.counterCeiling) return null;
    if (this.keyUpdateEnabled) return this.openEpoch(counter, wire);
    if (!this.nonceWindowMayAccept(counter)) return null;
    const iv = makeIv(counter, this.recvDirection);
    const cipherLen = wire.length - ENVELOPE_OVERHEAD;
    const cipher = wire.subarray(SALT_LEN + NONCE_LEN, SALT_LEN + NONCE_LEN + cipherLen);
    const tag = wire.subarray(SALT_LEN + NONCE_LEN + cipherLen);
    const plain = gcmOpen(this.recvKey, iv, cipher, tag);
    if (plain === null) return null;
    if (!this.acceptNonce(counter)) return null;
    return plain;
  }

  private openEpoch(nonce: bigint, wire: Uint8Array): Buffer | null {
    const epoch = nonce / EPOCH_SPAN;
    const counter = nonce % EPOCH_SPAN;
    let key: Buffer;
    let win: RecvEpoch;
    let commitNext = false;
    if (epoch === this.recvEpochSeen) {
      key = this.recvKey;
      win = this.recvCur;
    } else if (epoch + 1n === this.recvEpochSeen) {
      key = this.prevRecvKey;
      win = this.recvPrev;
    } else if (epoch === this.recvEpochSeen + 1n) {
      key = deriveEpochDirectionKey(this.sessionKey, this.recvDirection, Number(epoch));
      commitNext = true;
      win = newRecvEpoch(); // replaced with recvCur after the tag verifies
    } else {
      return null;
    }
    if (counter >= this.counterCeiling) return null;
    if (!commitNext && !this.epochWindowMayAccept(win, counter)) return null;
    const iv = makeIv(nonce, this.recvDirection);
    const cipherLen = wire.length - ENVELOPE_OVERHEAD;
    const cipher = wire.subarray(SALT_LEN + NONCE_LEN, SALT_LEN + NONCE_LEN + cipherLen);
    const tag = wire.subarray(SALT_LEN + NONCE_LEN + cipherLen);
    const plain = gcmOpen(key, iv, cipher, tag);
    if (plain === null) return null;
    if (commitNext) {
      this.recvPrev = this.recvCur;
      this.prevRecvKey = this.recvKey;
      this.recvEpochSeen = epoch;
      this.recvKey = key;
      this.recvCur = newRecvEpoch();
      win = this.recvCur;
    }
    if (!this.epochAccept(win, counter)) return null;
    return plain;
  }

  /** #86: stateless reset bypasses the replay window (any nonce is allowed). */
  openReset(wire: Uint8Array): Buffer | null {
    if (wire.length !== ENVELOPE_OVERHEAD + RESET_MAGIC_LEN) return null;
    if (!bytesEqual(this.salt, wire, SALT_LEN)) return null;
    const iv = makeIv(getLe64(wire, SALT_LEN), this.recvDirection);
    const cipher = wire.subarray(SALT_LEN + NONCE_LEN, SALT_LEN + NONCE_LEN + RESET_MAGIC_LEN);
    const tag = wire.subarray(SALT_LEN + NONCE_LEN + RESET_MAGIC_LEN);
    const plain = gcmOpen(this.recvKey, iv, cipher, tag);
    if (plain === null || !bytesEqual(RESET_MAGIC, plain, RESET_MAGIC_LEN)) return null;
    return Buffer.from(RESET_MAGIC);
  }

  /** Wipe key material. JS cannot guarantee physical erasure; best effort. */
  destroy(): void {
    for (const k of [this.sendKey, this.recvKey, this.prevRecvKey, this.sessionKey]) k.fill(0);
  }
}

/** Build a sealed stateless-reset datagram for a peer that lost its session. */
export function sealReset(psk: Uint8Array, salt: Uint8Array, sendDir: DirectionValue, recvDir: DirectionValue, counter: bigint): Buffer | null {
  const env = new Envelope(psk, salt, sendDir, recvDir);
  const wire = env.sealAt(counter, RESET_MAGIC);
  env.destroy();
  return wire;
}

export { SALT_LEN, NONCE_LEN, TAG_LEN, ENVELOPE_OVERHEAD };
