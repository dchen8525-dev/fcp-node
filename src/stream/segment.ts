// FCP-STREAM v1 segment codec. Port of src/fcp/stream.h, stream.cc,
// stream_recv.cc, stream_send.cc. All integers little-endian; ACK v2 ranges
// are LEB128 uvarints relative to cum (hence wrap-safe).

import {
  STREAM_TYPE_DATA, STREAM_TYPE_ACK, STREAM_TYPE_RST, STREAM_TYPE_ACK_V2,
  STREAM_DATA_HDR_LEN, STREAM_ACK_LEN, STREAM_ACK_V2_MIN_LEN,
  STREAM_ACK_V2_MAX_RANGES, STREAM_RST_LEN, STREAM_FLAG_FIN, STREAM_RST_ABORT,
} from '../constants.ts';
import { getLe32, putLe32, putUvarint, getUvarint, seqAfter, seqAtOrAfter, seqDist } from '../wire.ts';

export type Segment =
  | { type: typeof STREAM_TYPE_DATA; seq: number; flags: number; payload: Buffer }
  | { type: typeof STREAM_TYPE_ACK; cum: number; rwnd: number; sackStart: number; sackEnd: number }
  | { type: typeof STREAM_TYPE_ACK_V2; cum: number; rwnd: number; ranges: Array<{ start: number; end: number }> }
  | { type: typeof STREAM_TYPE_RST; code: number };

export function encodeData(seq: number, flags: number, payload: Uint8Array): Buffer {
  const out = Buffer.alloc(STREAM_DATA_HDR_LEN + payload.length);
  out[0] = STREAM_TYPE_DATA;
  putLe32(seq, out, 1);
  out[5] = flags & 0xff;
  Buffer.from(payload).copy(out, STREAM_DATA_HDR_LEN);
  return out;
}
export function encodeAck(cum: number, rwnd: number, sackStart: number, sackEnd: number): Buffer {
  const out = Buffer.alloc(STREAM_ACK_LEN);
  out[0] = STREAM_TYPE_ACK;
  putLe32(cum, out, 1);
  putLe32(rwnd, out, 5);
  putLe32(sackStart, out, 9);
  putLe32(sackEnd, out, 13);
  return out;
}
export function encodeAckV2(cum: number, rwnd: number, blocks: Array<{ start: number; end: number }>): Buffer {
  const out = Buffer.alloc(STREAM_ACK_V2_MIN_LEN + STREAM_ACK_V2_MAX_RANGES * 10);
  out[0] = STREAM_TYPE_ACK_V2;
  putLe32(cum, out, 1);
  putLe32(rwnd, out, 5);
  let off = STREAM_ACK_V2_MIN_LEN;
  let n = 0;
  let prevEnd = cum;
  for (const b of blocks) {
    if (n >= STREAM_ACK_V2_MAX_RANGES) break;
    const gap = seqDist(b.start, prevEnd);
    if (gap < 0) continue;
    off += putUvarint(gap >>> 0, out, off);
    off += putUvarint(seqDist(b.end, b.start) >>> 0, out, off);
    prevEnd = b.end;
    ++n;
  }
  out[9] = n;
  return out.subarray(0, off);
}
export function encodeRst(code = STREAM_RST_ABORT): Buffer {
  return Buffer.from([STREAM_TYPE_RST, code & 0xff]);
}

export function parseSegment(input: Uint8Array, len = input.length): Segment | null {
  if (len < 1) return null;
  const type = input[0];
  if (type === STREAM_TYPE_DATA) {
    if (len < STREAM_DATA_HDR_LEN) return null;
    return {
      type, seq: getLe32(input, 1), flags: input[5],
      payload: Buffer.from(input.subarray(STREAM_DATA_HDR_LEN, len)),
    };
  }
  if (type === STREAM_TYPE_ACK) {
    if (len !== STREAM_ACK_LEN) return null;
    return {
      type, cum: getLe32(input, 1), rwnd: getLe32(input, 5),
      sackStart: getLe32(input, 9), sackEnd: getLe32(input, 13),
    };
  }
  if (type === STREAM_TYPE_RST) {
    if (len !== STREAM_RST_LEN) return null;
    return { type, code: input[1] };
  }
  if (type === STREAM_TYPE_ACK_V2) {
    if (len < STREAM_ACK_V2_MIN_LEN) return null;
    const cum = getLe32(input, 1), rwnd = getLe32(input, 5);
    const declared = Math.min(input[9], STREAM_ACK_V2_MAX_RANGES);
    const state = { off: STREAM_ACK_V2_MIN_LEN };
    const ranges: Array<{ start: number; end: number }> = [];
    let prevEnd = cum;
    for (let i = 0; i < declared; ++i) {
      const gap = getUvarint(input, len, state);
      const blen = getUvarint(input, len, state);
      if (gap === null || blen === null || blen === 0) return null;
      const start = (prevEnd + gap) >>> 0;
      const end = (start + blen) >>> 0;
      if (!seqAtOrAfter(start, cum) || !seqAfter(end, start) ||
          (i > 0 && !seqAfter(start, ranges[ranges.length - 1].end))) return null;
      ranges.push({ start, end });
      prevEnd = end;
    }
    if (state.off !== len) return null;
    return { type, cum, rwnd, ranges };
  }
  return null; // unknown type: ignored, counted as bad_segs
}

export { STREAM_TYPE_DATA, STREAM_TYPE_ACK, STREAM_TYPE_ACK_V2, STREAM_TYPE_RST, STREAM_FLAG_FIN };
