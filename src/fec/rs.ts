// Systematic Cauchy Reed-Solomon codec. Port of src/fcp/rs.cc.
// data indices [0, n), parity indices [n, n + k). All symbols are zero-extended
// to symbolMax bytes by the caller before encoding/decoding.

import { cauchyCoeff, cauchyInvertMatrix } from './cauchy.ts';
import { gfMulRow } from './gf256.ts';
import { RS_MAX_SHARDS } from '../constants.ts';

function xorScaled(dst: Uint8Array, src: Uint8Array, len: number, coeff: number): void {
  if (coeff === 0) return;
  const row = gfMulRow(coeff);
  for (let i = 0; i < len; ++i) dst[i] ^= row[src[i]];
}

export function rsEncode(data: Uint8Array[], n: number, k: number, symbolMax: number): Buffer[] | null {
  if (k === 0 || n === 0 || n + k > RS_MAX_SHARDS) return null;
  const parity: Buffer[] = [];
  for (let r = 0; r < k; ++r) parity.push(Buffer.alloc(symbolMax));
  for (let c = 0; c < n; ++c) {
    for (let r = 0; r < k; ++r) {
      xorScaled(parity[r], data[c], symbolMax, cauchyCoeff(r, c, k));
    }
  }
  return parity;
}

/**
 * `symbols` has n + k entries; null marks an erasure.
 * Returns an array of length n where recovered[i] is non-null for reconstructed
 * data symbols, or null when the system is unsolvable.
 */
export function rsDecode(symbols: (Uint8Array | null)[], n: number, k: number, symbolMax: number): (Buffer | null)[] | null {
  if (n === 0 || k === 0 || n + k > RS_MAX_SHARDS) return null;
  const recovered: (Buffer | null)[] = new Array(n).fill(null);
  const missing: number[] = [];
  for (let i = 0; i < n; ++i) if (symbols[i] === null) missing.push(i);
  if (missing.length === 0) return recovered;
  if (missing.length > k) return null;

  const rows: number[] = [];
  for (let r = 0; r < k && rows.length < missing.length; ++r) {
    if (symbols[n + r] !== null) rows.push(r);
  }
  if (rows.length < missing.length) return null;

  const t = missing.length;
  const matrix = new Uint8Array(t * t);
  for (let i = 0; i < t; ++i) {
    for (let j = 0; j < t; ++j) matrix[i * t + j] = cauchyCoeff(rows[i], missing[j], k);
  }
  if (!cauchyInvertMatrix(matrix, t)) return null;

  const rhs: Buffer[] = [];
  for (let i = 0; i < t; ++i) {
    const row = Buffer.from(symbols[n + rows[i]]!);
    for (let c = 0; c < n; ++c) {
      if (symbols[c] === null) continue;
      xorScaled(row, symbols[c], symbolMax, cauchyCoeff(rows[i], c, k));
    }
    rhs.push(row);
  }
  for (let j = 0; j < t; ++j) {
    const out = Buffer.alloc(symbolMax);
    for (let i = 0; i < t; ++i) xorScaled(out, rhs[i], symbolMax, matrix[j * t + i]);
    recovered[missing[j]] = out;
  }
  return recovered;
}
