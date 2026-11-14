// Byte-level wire helpers. Port of src/fcp/wire.h (little-endian protocol
// fields, network order for proxy codecs). All offsets validated by callers.

export function getLe16(b: Uint8Array, off = 0): number {
  return b[off] | (b[off + 1] << 8);
}
export function putLe16(v: number, out: Uint8Array, off = 0): void {
  out[off] = v & 0xff;
  out[off + 1] = (v >>> 8) & 0xff;
}
export function getLe24(b: Uint8Array, off = 0): number {
  return b[off] | (b[off + 1] << 8) | (b[off + 2] << 16);
}
export function putLe24(v: number, out: Uint8Array, off = 0): void {
  out[off] = v & 0xff;
  out[off + 1] = (v >>> 8) & 0xff;
  out[off + 2] = (v >>> 16) & 0xff;
}
export function getLe32(b: Uint8Array, off = 0): number {
  return (b[off] | (b[off + 1] << 8) | (b[off + 2] << 16) | (b[off + 3] << 24)) >>> 0;
}
export function putLe32(v: number, out: Uint8Array, off = 0): void {
  out[off] = v & 0xff;
  out[off + 1] = (v >>> 8) & 0xff;
  out[off + 2] = (v >>> 16) & 0xff;
  out[off + 3] = (v >>> 24) & 0xff;
}
export function getLe64(b: Uint8Array, off = 0): bigint {
  let v = 0n;
  for (let i = 7; i >= 0; --i) v = (v << 8n) | BigInt(b[off + i]);
  return v;
}
export function putLe64(v: bigint, out: Uint8Array, off = 0): void {
  let x = v & 0xffffffffffffffffn;
  for (let i = 0; i < 8; ++i) {
    out[off + i] = Number(x & 0xffn);
    x >>= 8n;
  }
}
export function getBe16(b: Uint8Array, off = 0): number {
  return (b[off] << 8) | b[off + 1];
}
export function putBe16(v: number, out: Uint8Array, off = 0): void {
  out[off] = (v >>> 8) & 0xff;
  out[off + 1] = v & 0xff;
}
export function getBe32(b: Uint8Array, off = 0): number {
  return ((b[off] * 0x1000000) + (b[off + 1] << 16) + (b[off + 2] << 8) + b[off + 3]) >>> 0;
}
export function putBe32(v: number, out: Uint8Array, off = 0): void {
  out[off] = (v >>> 24) & 0xff;
  out[off + 1] = (v >>> 16) & 0xff;
  out[off + 2] = (v >>> 8) & 0xff;
  out[off + 3] = v & 0xff;
}

// LEB128 unsigned varint (#78 FCP-STREAM ACK v2). At most 5 bytes for u32.
export function putUvarint(v: number, out: Uint8Array, off = 0): number {
  let x = v >>> 0;
  let n = 0;
  while (x >= 0x80) {
    out[off + n++] = (x & 0x7f) | 0x80;
    x >>>= 7;
  }
  out[off + n++] = x;
  return n;
}
export function getUvarint(b: Uint8Array, cap: number, state: { off: number }): number | null {
  let v = 0;
  let shift = 0;
  for (let i = 0; i < 5; ++i) {
    if (state.off >= cap) return null;
    const byte = b[state.off++];
    // The fifth byte of a u32 LEB128 may only carry 4 significant bits. Without
    // this check `0x7f << 28` overflowed the 32-bit accumulator and wrapped,
    // so non-canonical encodings decoded to a small value instead of failing -
    // a value that could then disagree with the encoder's canonical form.
    if (i === 4 && (byte & 0x7f) > 0x0f) return null;
    v |= (byte & 0x7f) << shift;
    if ((byte & 0x80) === 0) return v >>> 0;
    shift += 7;
  }
  return null;
}

// Wrap-safe modular half-window comparison (src/fcp/seq.h).
export function seqAfter(a: number, b: number): boolean {
  return (((a - b) >>> 0) | 0) > 0;
}
export function seqAtOrAfter(a: number, b: number): boolean {
  return !seqAfter(b, a);
}
export function seqDist(a: number, b: number): number {
  return ((a - b) >>> 0) | 0;
}

export function bytesEqual(a: Uint8Array, b: Uint8Array, len = a.length): boolean {
  if (b.length < len) return false;
  for (let i = 0; i < len; ++i) if (a[i] !== b[i]) return false;
  return true;
}
export function secureZero(b: Uint8Array): void {
  b.fill(0);
}
export function concat(parts: Uint8Array[]): Buffer {
  return Buffer.concat(parts.map((p) => Buffer.from(p)));
}
