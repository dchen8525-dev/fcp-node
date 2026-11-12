// Cauchy matrix over GF(2^8). Port of src/fcp/cauchy.cc.

import { gfInv, gfMul } from './gf256.ts';

// C++ truncates (r ^ (k + c)) to uint8_t.
export function cauchyCoeff(r: number, c: number, k: number): number {
  return gfInv((r ^ (k + c)) & 0xff);
}

/** Row-major k x n matrix. */
export function cauchyMatrix(n: number, k: number): Uint8Array {
  const m = new Uint8Array(n * k);
  for (let r = 0; r < k; ++r) {
    for (let c = 0; c < n; ++c) m[r * n + c] = cauchyCoeff(r, c, k);
  }
  return m;
}

/** Gauss-Jordan inversion in GF(2^8); mutates matrix to its inverse. */
export function cauchyInvertMatrix(matrix: Uint8Array, dim: number): boolean {
  const inverse = new Uint8Array(dim * dim);
  for (let i = 0; i < dim; ++i) inverse[i * dim + i] = 1;
  for (let col = 0; col < dim; ++col) {
    let pivot = col;
    while (pivot < dim && matrix[pivot * dim + col] === 0) ++pivot;
    if (pivot === dim) return false;
    if (pivot !== col) {
      for (let j = 0; j < dim; ++j) {
        const a = matrix[pivot * dim + j];
        matrix[pivot * dim + j] = matrix[col * dim + j];
        matrix[col * dim + j] = a;
        const b = inverse[pivot * dim + j];
        inverse[pivot * dim + j] = inverse[col * dim + j];
        inverse[col * dim + j] = b;
      }
    }
    const pivotInv = gfInv(matrix[col * dim + col]);
    for (let j = 0; j < dim; ++j) {
      matrix[col * dim + j] = gfMul(matrix[col * dim + j], pivotInv);
      inverse[col * dim + j] = gfMul(inverse[col * dim + j], pivotInv);
    }
    for (let row = 0; row < dim; ++row) {
      if (row === col) continue;
      const factor = matrix[row * dim + col];
      if (factor === 0) continue;
      for (let j = 0; j < dim; ++j) {
        matrix[row * dim + j] ^= gfMul(factor, matrix[col * dim + j]);
        inverse[row * dim + j] ^= gfMul(factor, inverse[col * dim + j]);
      }
    }
  }
  matrix.set(inverse);
  return true;
}
