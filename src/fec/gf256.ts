// GF(2^8) arithmetic. Port of src/fcp/gf256.cc.
// Reduction polynomial 0x11D, generator 2. Wire-visible through parity bytes.

const poly = 0x11d;
const exp = new Uint8Array(512);
const log = new Uint8Array(256);
const mul = new Uint8Array(256 * 256);

{
  let x = 1;
  for (let i = 0; i < 255; ++i) {
    exp[i] = x;
    log[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= poly;
  }
  for (let i = 255; i < 512; ++i) exp[i] = exp[i - 255];
  for (let a = 0; a < 256; ++a) {
    for (let b = 0; b < 256; ++b) {
      mul[a * 256 + b] = (a === 0 || b === 0) ? 0 : exp[log[a] + log[b]];
    }
  }
}

export function gfMul(a: number, b: number): number { return mul[a * 256 + b]; }
export function gfInv(a: number): number { return a === 0 ? 0 : exp[255 - log[a]]; }
export function gfDiv(a: number, b: number): number { return a === 0 ? 0 : mul[a * 256 + gfInv(b)]; }
export function gfPow(a: number, e: number): number {
  if (e === 0) return 1;
  if (a === 0) return 0;
  return exp[(log[a] * (e % 255)) % 255];
}
export function gfExp(i: number): number { return exp[i % 255]; }
export function gfLog(a: number): number { return log[a]; }
export function gfMulRow(coeff: number): Uint8Array { return mul.subarray(coeff * 256, coeff * 256 + 256); }

export const expTable = exp;
export const logTable = log;
