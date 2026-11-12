// Golden vectors copied byte-for-byte from the C++ test suite in
// D:\work\fcp\tests. They guard against transcription errors in the Node
// port's wire constants (endianness, GCM tag length, GF tables, RS matrix),
// NOT against cross-implementation interop. Per the acceptance decision of
// 2026-11-11, no C++ peer is required; see scripts/self-interop.mjs.
//
// Sources:
//   tests/aes_test.cc:9-13       FIPS-197 AES-128 single block
//   tests/gcm_test.cc:20-68      NIST GCM tc1/tc2/tc3 (12-byte tag, AAD)
//   tests/hdr_test.cc:9-27       pack_type_k + pack_hdr golden
//   tests/rs_test.cc:24-50       Reed-Solomon parity golden (n=4,k=2,len=6)
//   tests/envelope_test.cc:12-14 PSK/salt used by the envelope tests
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { aes128EncryptBlock, gcmSeal, gcmOpen } from '../src/crypto/aes.ts';
import { Envelope } from '../src/crypto/envelope.ts';
import { Direction } from '../src/constants.ts';
import { packTypeK, packHdr, parseHdr, hdrType, hdrK, hdrJ } from '../src/fec/hdr.ts';
import { rsEncode, rsDecode } from '../src/fec/rs.ts';

const hex = (b: Uint8Array): string => Buffer.from(b).toString('hex');
const bin = (s: string): Buffer => Buffer.from(s.replace(/\s+/g, ''), 'hex');

test('golden: FIPS-197 AES-128 (tests/aes_test.cc:9-13)', () => {
  const key = bin('000102030405060708090a0b0c0d0e0f');
  const plain = bin('00112233445566778899aabbccddeeff');
  assert.equal(hex(aes128EncryptBlock(key, plain)), '69c4e0d86a7b0430d8cdb78070b4c55a');
});

test('golden: NIST GCM tc1/tc2/tc3 including AAD (tests/gcm_test.cc:20-68)', () => {
  // tc1: empty message, all-zero key/IV
  const t1 = gcmSeal(new Uint8Array(16), new Uint8Array(12), new Uint8Array(0))!;
  assert.equal(hex(t1.cipher), '');
  assert.equal(hex(t1.tag), '58e2fccefa7e3061367f1d57');

  // tc2: one zero block
  const t2 = gcmSeal(new Uint8Array(16), new Uint8Array(12), new Uint8Array(16))!;
  assert.equal(hex(t2.cipher), '0388dace60b6a392f328c2b971b2fe78');
  assert.equal(hex(t2.tag), 'ab6e47d42cec13bdf53a67b2');

  // tc3: 60-byte plaintext, 20-byte AAD
  const key3 = bin('feffe9928665731c6d6a8f9467308308');
  const iv3 = bin('cafebabefacedbaddecaf888');
  const aad3 = bin('feedfacedeadbeeffeedfacedeadbeefabaddad2');
  const plain3 = bin(
    'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c' +
    '95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39',
  );
  const t3 = gcmSeal(key3, iv3, plain3, aad3)!;
  assert.equal(hex(t3.cipher),
    '42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b2' +
    '5466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091');
  assert.equal(hex(t3.tag), '5bc94fbc3221a5db94fae95a');
  assert.equal(hex(gcmOpen(key3, iv3, t3.cipher, t3.tag, aad3)!), hex(plain3));
  assert.equal(gcmOpen(key3, iv3, t3.cipher, t3.tag), null, 'AAD is authenticated');
});

test('golden: pack_type_k and FEC header (tests/hdr_test.cc:9-27)', () => {
  assert.equal(packTypeK(1, 0, 0), 0x20);
  assert.equal(packTypeK(1, 0, 1), 0x21);
  assert.equal(packTypeK(1, 1, 1), 0x25);
  assert.equal(packTypeK(4, 2, 1), 0x89);
  assert.equal(packTypeK(7, 7, 1), 0xfd);
  assert.equal(packTypeK(0, 0, 2), 0x02);
  assert.equal(packTypeK(0, 0, 3), 0x03);
  const bytes = packHdr({ setId: 0x04030201, index: 5, typeK: packTypeK(1, 0, 0) });
  assert.equal(hex(bytes), '010203040520');
  const parsed = parseHdr(bytes)!;
  assert.equal(parsed.setId, 0x04030201);
  assert.equal(parsed.index, 5);
  assert.equal(parsed.typeK, 0x20);
  assert.equal(hdrType(parsed.typeK), 0);
  assert.equal(hdrK(parsed.typeK), 1);
  assert.equal(hdrJ(parsed.typeK), 0);
  assert.equal(parseHdr(bytes.subarray(0, 5)), null);
});

test('golden: Reed-Solomon parity bytes (tests/rs_test.cc:24-50)', () => {
  const data = [
    bin('000102030405'), bin('101112131415'),
    bin('202122232425'), bin('303132333435'),
  ];
  const parity = rsEncode(data, 4, 2, 6)!;
  assert.equal(hex(parity[0]), '089221bb5ac0');
  assert.equal(hex(parity[1]), '5dc774ee0f95');
  // The same vectors must decode back after erasing two data symbols.
  const rec = rsDecode([null, data[1], null, data[3], parity[0], parity[1]], 4, 2, 6)!;
  assert.equal(hex(rec[0]!), hex(data[0]));
  assert.equal(hex(rec[2]!), hex(data[2]));
});

test('golden: envelope direction separation at a pinned nonce (tests/envelope_test.cc:38-52)', () => {
  const key = bin('00112233445566778899aabbccddeeff');
  const salt = bin('0102030405060708');
  const payload = bin('a0a1a2a3a4');
  const client = new Envelope(key, salt, Direction.C2S, Direction.S2C);
  const server = new Envelope(key, salt, Direction.S2C, Direction.C2S);
  const cw = client.sealAt(100n, payload)!;
  const sw = server.sealAt(100n, payload)!;
  assert.equal(cw.length, 33);
  assert.notEqual(hex(cw), hex(sw), 'the direction byte is part of the IV');
  assert.equal(hex(new Envelope(key, salt, Direction.S2C, Direction.C2S).open(cw)!), hex(payload));
  assert.equal(hex(new Envelope(key, salt, Direction.C2S, Direction.S2C).open(sw)!), hex(payload));
});
