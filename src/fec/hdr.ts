// FCP 7-byte FEC header (v2).
//   offset 0  set_id u32 LE
//   offset 4  index  u8
//   offset 5  d      u8   data shards this set was cut with
//   offset 6  type_k = (k << 5) | (j << 2) | type
//
// v1 had no `d`: the group size was a session constant agreed in the
// handshake, so a sender could not change it, and the receiver could only
// validate an index against the negotiated ceiling instead of the geometry the
// set was actually built with. One byte buys self-describing sets, which is
// what makes interleaved groups with different sizes decode correctly.

import { FEC_HDR_LEN, MAX_S, SymbolType, type SymbolTypeValue } from '../constants.ts';
import { getLe32, putLe32, seqAfter } from '../wire.ts';

export interface FecHdr { setId: number; index: number; d: number; typeK: number; }

export const HdrStatus = {
  Ok: 0, IndexPastS: 1, DataIndexPastD: 2, JNotBelowK: 3,
  BadN: 4, DataPastKnownN: 5, InvalidType: 6, BadD: 7,
} as const;
export type HdrStatusValue = (typeof HdrStatus)[keyof typeof HdrStatus];

export function packTypeK(k: number, j: number, type: number): number {
  return (((k & 0x07) << 5) | ((j & 0x07) << 2) | (type & 0x03)) & 0xff;
}
export function hdrType(typeK: number): number { return typeK & 0x03; }
export function hdrK(typeK: number): number { return (typeK >>> 5) & 0x07; }
export function hdrJ(typeK: number): number { return (typeK >>> 2) & 0x07; }
export function isParity(typeK: number): boolean { return (typeK & 0x03) === SymbolType.Parity; }
export function validSymbolType(t: number): boolean {
  return t === SymbolType.Data || t === SymbolType.Parity || t === SymbolType.Oob;
}

export function packHdr(hdr: FecHdr): Buffer {
  const out = Buffer.alloc(FEC_HDR_LEN);
  putLe32(hdr.setId, out, 0);
  out[4] = hdr.index & 0xff;
  out[5] = hdr.d & 0xff;
  out[6] = hdr.typeK & 0xff;
  return out;
}
export function parseHdr(input: Uint8Array, len = input.length): FecHdr | null {
  if (len < FEC_HDR_LEN) return null;
  return { setId: getLe32(input, 0), index: input[4], d: input[5], typeK: input[6] };
}

/**
 * Validate one symbol header against the geometry it declares.
 *
 * `p` is the negotiated parity ceiling, not the k in this header: j must stay
 * below the k the header carries, but the index bound is set by the header's
 * own d, so a set cut with a smaller group than the session agreed still
 * validates — that is the whole point of carrying d per symbol.
 */
export function validateHdr(hdr: FecHdr, p: number, nKnown: boolean, n: number): HdrStatusValue {
  const type = hdrType(hdr.typeK);
  if (type === SymbolType.Oob) return HdrStatus.Ok;
  if (!validSymbolType(type)) return HdrStatus.InvalidType;
  if (hdr.d < 1 || hdr.d + p > MAX_S) return HdrStatus.BadD;
  const s = hdr.d + p;
  if (hdr.index >= s) return HdrStatus.IndexPastS;
  if (type === SymbolType.Data) {
    if (hdr.index >= hdr.d) return HdrStatus.DataIndexPastD;
    if (nKnown && hdr.index >= n) return HdrStatus.DataPastKnownN;
    return HdrStatus.Ok;
  }
  const k = hdrK(hdr.typeK);
  const j = hdrJ(hdr.typeK);
  if (j >= k) return HdrStatus.JNotBelowK;
  const parityN = hdr.index - j;
  if (parityN < 1 || parityN > hdr.d) return HdrStatus.BadN;
  return HdrStatus.Ok;
}

/** True when b is strictly after a (src/fcp/seq.h half-window). */
export function setIdAfter(a: number, b: number): boolean { return seqAfter(b, a); }
