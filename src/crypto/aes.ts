// AES-128 primitives. Port of src/fcp/aes.cc / gcm.cc / ghash.cc, but using
// Node's built-in OpenSSL implementation (node:crypto) instead of a hand-rolled
// AES. The wire result is identical: standard AES-128-ECB single-block and
// AES-128-GCM with a 12-byte IV, empty AAD and a 12-byte tag.
//
// No third-party dependency. Zero runtime deps.

import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { GCM_IV_LEN, TAG_LEN } from '../constants.ts';

export function aes128EncryptBlock(key: Uint8Array, block: Uint8Array): Buffer {
  if (key.length !== 16) throw new Error('aes128: key must be 16 bytes');
  if (block.length !== 16) throw new Error('aes128: block must be 16 bytes');
  const c = createCipheriv('aes-128-ecb', Buffer.from(key), null);
  c.setAutoPadding(false);
  return Buffer.concat([c.update(Buffer.from(block)), c.final()]);
}

export function gcmSeal(key: Uint8Array, iv: Uint8Array, plain: Uint8Array, aad?: Uint8Array): { cipher: Buffer; tag: Buffer } | null {
  if (key.length !== 16 || iv.length !== GCM_IV_LEN) return null;
  try {
    const c = createCipheriv('aes-128-gcm', Buffer.from(key), Buffer.from(iv), { authTagLength: TAG_LEN });
    if (aad && aad.length) c.setAAD(Buffer.from(aad));
    const cipher = Buffer.concat([c.update(Buffer.from(plain)), c.final()]);
    return { cipher, tag: c.getAuthTag() };
  } catch {
    return null;
  }
}

export function gcmOpen(key: Uint8Array, iv: Uint8Array, cipher: Uint8Array, tag: Uint8Array, aad?: Uint8Array): Buffer | null {
  if (key.length !== 16 || iv.length !== GCM_IV_LEN || tag.length !== TAG_LEN) return null;
  try {
    const d = createDecipheriv('aes-128-gcm', Buffer.from(key), Buffer.from(iv), { authTagLength: TAG_LEN });
    if (aad && aad.length) d.setAAD(Buffer.from(aad));
    d.setAuthTag(Buffer.from(tag));
    return Buffer.concat([d.update(Buffer.from(cipher)), d.final()]);
  } catch {
    return null; // authentication failure: caller counts auth_fail
  }
}

export function cspRandomBytes(len: number): Buffer {
  return randomBytes(len);
}

// Fails loudly when the OS CSPRNG is unavailable (src/fcp/random.h contract).
// Node's randomBytes throws rather than returning weak bytes, so this is a
// deliberate rethrow with a protocol-level message.
export function cspRandomU64(): bigint {
  return cspRandomBytes(8).readBigUInt64LE(0);
}
