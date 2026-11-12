// Session key derivation. Port of src/fcp/envelope.cc:
//   derive_session_key       (v6 bootstrap / handshake envelope)
//   derive_session_key_v7    (CBC-MAC over salt, client nonce, server nonce)
//   derive_direction_keys    (SP 800-108 counter-mode KDF, AES-128 PRF)
//   derive_epoch_direction_key (#84)

import { aes128EncryptBlock } from './aes.ts';
import { SALT_LEN, Direction, type DirectionValue } from '../constants.ts';

function xor16(a: Uint8Array, b: Uint8Array): Buffer {
  const out = Buffer.alloc(16);
  for (let i = 0; i < 16; ++i) out[i] = a[i] ^ b[i];
  return out;
}

// session_key = AES128(psk, salt(8) || 0x00 x 8)
export function deriveSessionKey(psk: Uint8Array, salt: Uint8Array): Buffer {
  if (psk.length !== 16 || salt.length !== SALT_LEN) throw new Error('deriveSessionKey: bad lengths');
  const block = Buffer.alloc(16);
  Buffer.from(salt).copy(block, 0);
  return aes128EncryptBlock(psk, block);
}

// NIST SP 800-108 Rev.1 §4.1 counter KDF:
//   K(i) = AES(K_mr, [i]1 | label | 0x00 | [L]8)   with L in BITS, big endian
// FCP uses 6-byte labels "fcp-c2" / "fcp-s2" and asks for 128 bits (16 bytes).
function kdfCtrAes128(key: Uint8Array, label: string, outLen: number): Buffer {
  const labelBytes = Buffer.from(label, 'latin1');
  if (labelBytes.length !== 6) throw new Error('kdf: label must be 6 bytes');
  const lBe = Buffer.alloc(8);
  lBe.writeBigUInt64BE(BigInt(outLen) * 8n, 0);
  const parts: Buffer[] = [];
  let counter = 1;
  for (let done = 0; done < outLen; done += 16, ++counter) {
    const block = Buffer.alloc(16);
    block[0] = counter & 0xff;
    labelBytes.copy(block, 1);
    block[7] = 0x00;
    lBe.copy(block, 8);
    parts.push(aes128EncryptBlock(key, block));
  }
  return Buffer.concat(parts).subarray(0, outLen);
}

export function deriveDirectionKeys(sessionKey: Uint8Array): { c2s: Buffer; s2c: Buffer } {
  return {
    c2s: Buffer.from(kdfCtrAes128(sessionKey, 'fcp-c2', 16)),
    s2c: Buffer.from(kdfCtrAes128(sessionKey, 'fcp-s2', 16)),
  };
}

// #84: epoch >= 1 keys, out = AES128(session_key, label(2) | epoch(2 LE) | 0^12)
export function deriveEpochDirectionKey(sessionKey: Uint8Array, dir: DirectionValue, epoch: number): Buffer {
  const block = Buffer.alloc(16);
  block[0] = dir === Direction.C2S ? 0x63 : 0x73; // 'c' / 's'
  block[1] = 0x32; // '2'
  block[2] = epoch & 0xff;
  block[3] = (epoch >>> 8) & 0xff;
  return aes128EncryptBlock(sessionKey, block);
}

// R3-1: three fixed-size AES blocks, CBC-MAC style.
//   X0 = AES(psk, salt || 0^8)
//   X1 = AES(psk, X0 xor client_nonce)
//   X2 = AES(psk, X1 xor server_nonce)
export function deriveSessionKeyV7(
  psk: Uint8Array, salt: Uint8Array, clientNonce: Uint8Array, serverNonce: Uint8Array,
): Buffer {
  if (psk.length !== 16 || salt.length !== SALT_LEN ||
      clientNonce.length !== 16 || serverNonce.length !== 16) {
    throw new Error('deriveSessionKeyV7: bad lengths');
  }
  const x0 = deriveSessionKey(psk, salt);
  const x1 = aes128EncryptBlock(psk, xor16(x0, clientNonce));
  return aes128EncryptBlock(psk, xor16(x1, serverNonce));
}
