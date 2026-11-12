// Byte-level tests. Golden vectors come from D:\work\fcp\tests\{gcm,aes,envelope}_test.cc
// and from docs/协议格式.md. Run: node --test tests/bytes.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { aes128EncryptBlock, gcmSeal, gcmOpen } from '../src/crypto/aes.ts';
import { deriveSessionKey, deriveSessionKeyV7, deriveDirectionKeys, deriveEpochDirectionKey } from '../src/crypto/keys.ts';
import { Envelope } from '../src/crypto/envelope.ts';
import { Direction, FECSTAT_LEN, RESET_MAGIC } from '../src/constants.ts';
import { gfMul, gfInv, gfMulRow } from '../src/fec/gf256.ts';
import { cauchyCoeff } from '../src/fec/cauchy.ts';
import { rsEncode, rsDecode } from '../src/fec/rs.ts';
import { packHdr, parseHdr, validateHdr, HdrStatus, packTypeK, hdrType, hdrK, hdrJ } from '../src/fec/hdr.ts';
import { encodeFecstat, decodeFecstat, makeFecstatPacket, FecstatStatus, FecstatValidator } from '../src/fec/fecstat.ts';
import { computeMtuLimits, packOobFrame } from '../src/fec/frame.ts';
import { putUvarint, getUvarint, getLe32, putLe32, seqAfter, seqDist } from '../src/wire.ts';
import { encodeData, encodeAck, encodeAckV2, encodeRst, parseSegment } from '../src/stream/segment.ts';

const hex = (b: Uint8Array): string => Buffer.from(b).toString('hex');
const PSK = Buffer.from('00112233445566778899aabbccddeeff', 'hex');
const SALT = Buffer.from('0102030405060708', 'hex');

test('AES-128 FIPS-197 single block', () => {
  assert.equal(
    hex(aes128EncryptBlock(Buffer.from('000102030405060708090a0b0c0d0e0f', 'hex'), Buffer.from('00112233445566778899aabbccddeeff', 'hex'))),
    '69c4e0d86a7b0430d8cdb78070b4c55a',
  );
});

test('AES-128-GCM 12-byte tag matches C++ tests/gcm_test.cc:27-29', () => {
  const r = gcmSeal(new Uint8Array(16), new Uint8Array(12), new Uint8Array(0));
  assert.equal(hex(r.tag), '58e2fccefa7e3061367f1d57');
  assert.equal(hex(gcmOpen(new Uint8Array(16), new Uint8Array(12), new Uint8Array(0), r.tag)), '');
});

test('GF(256) field axioms and Cauchy coefficients', () => {
  assert.equal(gfMul(0x53, gfInv(0x53)), 1);
  assert.equal(gfMul(0x57, 0x83), gfMul(0x83, 0x57)); // commutativity
  assert.equal(gfMul(0x57, 0x12 ^ 0x34), gfMul(0x57, 0x12) ^ gfMul(0x57, 0x34)); // distributivity
  assert.equal(gfMulRow(1)[0x42], 0x42);
  for (let r = 0; r < 7; ++r) for (let c = 0; c < 10; ++c) {
    const v = cauchyCoeff(r, c, 7);
    assert.ok(v >= 0 && v <= 255);
    assert.equal(v, gfInv((r ^ (7 + c)) & 0xff));
  }
});

test('key derivation: determinism, direction separation, epoch separation', () => {
  const k0 = deriveSessionKey(PSK, SALT);
  assert.equal(hex(k0), hex(deriveSessionKey(PSK, SALT)));
  const dk = deriveDirectionKeys(k0);
  assert.notEqual(hex(dk.c2s), hex(dk.s2c));
  const cn = Buffer.alloc(16, 1), sn = Buffer.alloc(16, 2);
  const k7 = deriveSessionKeyV7(PSK, SALT, cn, sn);
  assert.notEqual(hex(k7), hex(k0));
  assert.equal(hex(k7), hex(deriveSessionKeyV7(PSK, SALT, cn, sn)));
  assert.notEqual(hex(k7), hex(deriveSessionKeyV7(PSK, SALT, sn, cn)));
  assert.notEqual(hex(deriveEpochDirectionKey(k7, Direction.C2S, 1)), hex(dk.c2s));
});

test('envelope: seal/open, replay, wrong salt, tamper', () => {
  const client = new Envelope(PSK, SALT, Direction.C2S, Direction.S2C);
  const server = new Envelope(PSK, SALT, Direction.S2C, Direction.C2S);
  const wire = client.seal(Buffer.from('hello fcp'))!;
  assert.equal(wire.length, 28 + 9);
  assert.equal(server.open(wire)!.toString(), 'hello fcp');
  assert.equal(server.open(wire), null, 'replay must be rejected');
  assert.equal(new Envelope(PSK, Buffer.alloc(8), Direction.S2C, Direction.C2S).open(wire), null);
  const tampered = Buffer.from(wire); tampered[30] ^= 1;
  assert.equal(new Envelope(PSK, SALT, Direction.S2C, Direction.C2S).open(tampered), null);
});

test('envelope: 1024-slot replay window accepts out-of-order, rejects old', () => {
  const a = new Envelope(PSK, SALT, Direction.C2S, Direction.S2C);
  const b = new Envelope(PSK, SALT, Direction.S2C, Direction.C2S);
  const w = [];
  for (let i = 0; i < 1100; ++i) w.push(a.seal(Buffer.from([i & 0xff]))!);
  // Deliver 0..1000 except 500; the hole is 500 counters behind the highest.
  for (let i = 0; i <= 1000; ++i) if (i !== 500) assert.ok(b.open(w[i]));
  assert.ok(b.open(w[500]), 'a hole 500 back is inside the 1024-slot window');
  assert.equal(b.open(w[500]), null, 'a second copy is a replay');
  for (let i = 1001; i < 1100; ++i) assert.ok(b.open(w[i]));
  assert.equal(b.open(w[0]), null, 'a counter 1099 back is stale');
});

test('stateless reset bypasses the replay window', () => {
  const a = new Envelope(PSK, SALT, Direction.C2S, Direction.S2C);
  const b = new Envelope(PSK, SALT, Direction.S2C, Direction.C2S);
  const wire = a.sealAt(123456789n, RESET_MAGIC)!;
  assert.equal(hex(b.openReset(wire)), hex(RESET_MAGIC));
  assert.equal(hex(b.openReset(wire)), hex(RESET_MAGIC), 'reset is replay-tolerant by design');
});

test('FEC header: pack/parse/validate', () => {
  const h = packHdr({ setId: 0x12345678, index: 3, typeK: (3 << 5) | (1 << 2) | 1 });
  assert.equal(hex(h), '785634120365');
  const p = parseHdr(h)!;
  assert.deepEqual(p, { setId: 0x12345678, index: 3, typeK: 0x65 });
  assert.equal(hdrType(p.typeK), 1);
  assert.equal(hdrK(p.typeK), 3);
  assert.equal(hdrJ(p.typeK), 1);
  assert.equal(validateHdr(p, 10, 13, true, 3), HdrStatus.Ok);
  assert.equal(validateHdr(parseHdr(packHdr({ setId: 1, index: 3, typeK: packTypeK(3, 0, 0) }))!, 10, 13, true, 3), HdrStatus.DataPastKnownN);
  assert.equal(validateHdr(parseHdr(packHdr({ setId: 1, index: 0, typeK: packTypeK(0, 0, 3) }))!, 10, 13, false, 0), HdrStatus.InvalidType);
});

test('RS systematic codec recovers up to k erasures', () => {
  const data = Array.from({ length: 10 }, (_, i) => Buffer.alloc(64, i + 1));
  const par = rsEncode(data, 10, 3, 64)!;
  assert.equal(par.length, 3);
  const shards = [...data, ...par];
  shards[2] = null; shards[7] = null;
  shards[10] = null;
  const rec = rsDecode(shards, 10, 3, 64)!;
  assert.equal(hex(rec[2]!), hex(data[2]));
  assert.equal(hex(rec[7]!), hex(data[7]));
});

test('FECSTAT: 128-byte layout round-trip and validator', () => {
  const p = makeFecstatPacket(SALT);
  p.accountedThroughSetId = 0xfffffff0;
  p.dataExpected = 1234; p.dataRxOrig = 1000; p.parityRx = 7;
  p.ledgerGroups = 64; p.ledgerMeta = (0x1234 << 16) | 3;
  const wire = encodeFecstat(p);
  assert.equal(wire.length, FECSTAT_LEN);
  assert.equal(wire.subarray(0, 16).toString('latin1'), 'FCP_FECSTAT_V1\0\0');
  assert.equal(wire[24], 1);
  assert.equal(getLe32(wire, 28), 0xfffffff0);
  const r = decodeFecstat(wire, SALT);
  assert.equal(r.status, FecstatStatus.Ok);
  assert.equal(r.packet!.dataExpected, 1234);
  assert.equal(r.packet!.ledgerMeta, p.ledgerMeta);
  assert.equal(decodeFecstat(wire.subarray(0, 127), SALT).status, FecstatStatus.BadLength);
  assert.equal(decodeFecstat(wire, Buffer.alloc(8)).status, FecstatStatus.BadSalt);
  const v = new FecstatValidator();
  assert.equal(v.validate(wire, SALT).status, FecstatStatus.Ok);
  assert.equal(v.validate(wire, SALT).status, FecstatStatus.Duplicate);
  const older = makeFecstatPacket(SALT); older.accountedThroughSetId = 0xffffffe0;
  assert.equal(v.validate(encodeFecstat(older), SALT).status, FecstatStatus.Stale);
  const future = makeFecstatPacket(SALT); future.accountedThroughSetId = 0xfffffff0 + (1 << 21);
  assert.equal(v.validate(encodeFecstat(future), SALT).status, FecstatStatus.Stale);
});

test('MTU limits match frame_tx.h static_assert', () => {
  const a = computeMtuLimits(1400, 20);
  assert.equal(a.payloadMax, 1336);
  assert.equal(a.symbolMax, 1338);
  assert.equal(a.mss, 1312);
  const b = computeMtuLimits(1400, 40);
  assert.equal(b.payloadMax, 1316);
  assert.equal(b.mss, 1292);
  assert.equal(computeMtuLimits(80, 20).valid, false);
  const oob = packOobFrame(Buffer.from('FCPKAL1\0', 'latin1'));
  assert.equal(oob.length, 6 + 8);
  assert.equal(oob[0], 0); assert.equal(oob[4], 0); assert.equal(oob[5], 2);
});

test('wire: uvarint, LE/BE, modular sequence', () => {
  const b = Buffer.alloc(16);
  let off = 0;
  off += putUvarint(0, b, off);
  off += putUvarint(127, b, off);
  off += putUvarint(128, b, off);
  off += putUvarint(0xffffffff, b, off);
  const st = { off: 0 };
  assert.equal(getUvarint(b, off, st), 0);
  assert.equal(getUvarint(b, off, st), 127);
  assert.equal(getUvarint(b, off, st), 128);
  assert.equal(getUvarint(b, off, st), 0xffffffff);
  assert.equal(st.off, off);
  // C++ seq.h: seq_after(a,b) means "a is strictly after b".
  assert.equal(seqAfter(2, 0xfffffffe), true);
  assert.equal(seqAfter(0xfffffffe, 2), false);
  assert.equal(seqDist(2, 0xfffffffe), 4);
  const le = Buffer.alloc(4); putLe32(0x12345678, le, 0);
  assert.equal(getLe32(le, 0), 0x12345678);
});

test('FCP-STREAM segment codec: DATA / ACK / ACK v2 / RST', () => {
  const d = encodeData(0x12345678, 1, Buffer.from('abc'));
  assert.equal(hex(d.subarray(0, 6)), '017856341201');
  assert.deepEqual(parseSegment(d), { type: 1, seq: 0x12345678, flags: 1, payload: Buffer.from('abc') });
  const a = encodeAck(100, 4096, 120, 140);
  assert.equal(a.length, 17);
  assert.deepEqual(parseSegment(a), { type: 2, cum: 100, rwnd: 4096, sackStart: 120, sackEnd: 140 });
  const v2 = encodeAckV2(100, 4096, [{ start: 120, end: 140 }, { start: 200, end: 260 }]);
  assert.equal(v2[9], 2);
  const pv2 = parseSegment(v2)!;
  assert.equal(pv2.type, 4);
  if (pv2.type === 4) assert.deepEqual(pv2.ranges, [{ start: 120, end: 140 }, { start: 200, end: 260 }]);
  const r = encodeRst();
  assert.equal(hex(r), '0301');
  assert.equal(parseSegment(Buffer.from([9, 0, 0])), null);
  const bad = Buffer.from(v2); bad[9] = 9;
  assert.equal(parseSegment(bad), null, 'malformed range set is discarded whole');
});
