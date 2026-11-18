// Protocol-level tests: handshake state machine, FEC frame repair,
// FCP-STREAM ARQ, proxy codecs and an in-memory client/server Session pair
// (no sockets, deterministic clock). Run: node --test tests/protocol.test.ts
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  Handshake, HandshakeStatus, isHello, isHelloAck, buildHello, buildHelloAck,
  capsValid, parseCaps, helloTlvs, tlvEncode, tlvParse,
  encodePrewarmTlv, decodePrewarmTlv,
} from '../src/crypto/handshake.ts';
import {
  HELLO_LEN, HELLO_ACK_LEN, CAPS_VERSION, LOCAL_FLAGS_M1, CAP_TLV, CAP_FRAMING,
  CAP_FECSTAT, TLV_TYPE_ACK_V2, TLV_TYPE_PREWARM, TLV_TYPE_ERROR,
  HandshakeRole, HandshakeState, HandshakeError, Direction, SymbolType,
  TLV_BLOCK_LEN_BYTES, ENVELOPE_OVERHEAD, FEC_HDR_LEN, PMTU_HEADER_LEN,
  STREAM_TYPE_ACK_V2,
} from '../src/constants.ts';
import { deriveSessionKeyV7 } from '../src/crypto/keys.ts';
import { computeMtuLimits, FrameTx, FrameRx, packTxFrame, type TxSymbol } from '../src/fec/frame.ts';
import { Stream } from '../src/stream/stream.ts';
import { parseSegment, encodeAckV2, encodeAck } from '../src/stream/segment.ts';
import { Session, type SessionConfig } from '../src/session/session.ts';
import {
  socks5ParseGreeting, socks5GreetingReply, socks5ParseRequest, socks5Reply,
  httpParseConnect, httpParseForward, openWriteRequest, openWriteOk, openWriteErr,
  openParseRequest, openParseReply, detectEntry, targetText,
} from '../src/proxy/codec.ts';
import { OPEN_OK_LEN, OPEN_ERR_LEN, ATYP_DOMAIN, ATYP_IPV4, ATYP_IPV6, OpenError } from '../src/constants.ts';
import { bytesEqual, getLe16 } from '../src/wire.ts';

const PSK = Buffer.from('00112233445566778899aabbccddeeff', 'hex');
const SALT = Buffer.from('0102030405060708', 'hex');
const NONCE_C = Buffer.alloc(16, 0x11);
const NONCE_S = Buffer.alloc(16, 0x22);

test('HELLO / HELLO_ACK wire shapes are 36 / 52 bytes with exact magic', () => {
  const caps = { ver: CAPS_VERSION, data: 10, parity: 3, flags: LOCAL_FLAGS_M1 };
  const hello = buildHello(caps, NONCE_C);
  assert.equal(hello.length, HELLO_LEN);
  assert.equal(hello.subarray(0, 16).toString('latin1'), 'FCP_HELLO_V1\0\0\0\0');
  assert.equal(hex(hello.subarray(16, 32)), hex(NONCE_C));
  assert.deepEqual(parseCaps(hello, 32), caps);
  assert.equal(isHello(hello), true);
  assert.equal(isHelloAck(hello), false);
  const ack = buildHelloAck(caps, NONCE_C, NONCE_S);
  assert.equal(ack.length, HELLO_ACK_LEN);
  assert.equal(ack.subarray(0, 16).toString('latin1'), 'FCP_HELLO_ACK_V1');
  assert.equal(hex(ack.subarray(16, 32)), hex(NONCE_C));
  assert.equal(hex(ack.subarray(32, 48)), hex(NONCE_S));
  assert.equal(isHelloAck(ack), true);
  assert.equal(capsValid(caps), true);
  assert.equal(capsValid({ ...caps, ver: 2 }), false);
  assert.equal(capsValid({ ...caps, flags: 0x80 }), false, 'bits 6..7 are reserved');
  assert.equal(capsValid({ ...caps, flags: CAP_TLV | LOCAL_FLAGS_M1 }), true, 'bit5 = TLV is known');
});

test('TLV block: encode/parse, malformed rejection, prewarm ticket', () => {
  const tlvs = [
    { type: TLV_TYPE_ACK_V2, value: Buffer.alloc(0) },
    { type: TLV_TYPE_PREWARM, value: encodePrewarmTlv({ initialK: 3, srttMs: 120, windowKb: 256, bwKbps: 4096, minRttMs: 40 }) },
  ];
  const caps = { ver: 1, data: 10, parity: 3, flags: LOCAL_FLAGS_M1 | CAP_TLV };
  const ext = buildHello(caps, NONCE_C, tlvs);
  assert.equal(ext.length, HELLO_LEN + 2 + 2 + 14);
  assert.equal(getLe16(ext, HELLO_LEN), 16);
  const parsed = helloTlvs(ext, ext.length, false)!;
  assert.equal(parsed.length, 2);
  assert.equal(parsed[0].type, TLV_TYPE_ACK_V2);
  const t = decodePrewarmTlv(parsed[1].value)!;
  assert.equal(t.initialK, 3); assert.equal(t.srttMs, 120); assert.equal(t.minRttMs, 40);
  assert.equal(helloTlvs(ext.subarray(0, ext.length - 1), ext.length - 1, false), null);
  const buf = Buffer.alloc(64);
  assert.equal(tlvEncode([{ type: 0, value: Buffer.alloc(0) }], buf), 0);
  assert.equal(tlvParse(Buffer.from([1, 5, 0, 0])), null);
});

test('handshake: client/server converge on the same v7 session key', () => {
  const toServer: Buffer[] = [], toClient: Buffer[] = [];
  const client = new Handshake({
    localD: 10, localP: 3, role: HandshakeRole.Client,
    localNonce: NONCE_C,
    send: (m) => toServer.push(Buffer.from(m)),
    localTlvs: [{ type: TLV_TYPE_ACK_V2, value: Buffer.alloc(0) }],
  });
  const server = new Handshake({
    localD: 10, localP: 3, role: HandshakeRole.Server,
    localNonce: NONCE_S,
    send: (m) => toClient.push(Buffer.from(m)),
    localTlvs: [{ type: TLV_TYPE_ACK_V2, value: Buffer.alloc(0) }],
  });
  client.start(0); server.start(0);
  client.onTick(0);
  assert.equal(toServer.length, 1);
  assert.equal(server.onOob(toServer[0]), HandshakeStatus.Consumed);
  assert.equal(toClient.length, 1);
  assert.equal(client.onOob(toClient[0]), HandshakeStatus.Consumed);
  assert.equal(client.established, true);
  assert.equal(server.established, true);
  assert.equal(hex(client.clientNonce), hex(server.clientNonce));
  assert.equal(hex(client.serverNonce), hex(server.serverNonce));
  assert.equal(hex(deriveSessionKeyV7(PSK, SALT, client.clientNonce, client.serverNonce)),
    hex(deriveSessionKeyV7(PSK, SALT, server.clientNonce, server.serverNonce)));
  assert.equal(client.tlvAgreed(TLV_TYPE_ACK_V2), true);
  assert.equal(server.tlvAgreed(TLV_TYPE_ACK_V2), true);
  assert.equal(client.params.d, 10);
  assert.equal(client.params.p, 3);
});

test('handshake: plain v7 shape, ACK echo check, duplicate HELLO re-ACK, restart refused', () => {
  const out: Buffer[] = [];
  const server = new Handshake({
    localD: 10, localP: 3, role: HandshakeRole.Server, localNonce: NONCE_S,
    send: (m) => out.push(Buffer.from(m)),
  });
  server.start(0);
  const caps = { ver: 1, data: 10, parity: 3, flags: LOCAL_FLAGS_M1 };
  const hello = buildHello(caps, NONCE_C);
  assert.equal(hello.length, 36);
  assert.equal(server.onOob(hello), HandshakeStatus.Consumed);
  assert.equal(out.length, 1);
  assert.equal(out[0].length, HELLO_ACK_LEN, 'plain HELLO -> plain ACK (no TLV bit)');
  assert.equal(server.onOob(hello), HandshakeStatus.Consumed);
  assert.equal(out.length, 2, 'duplicate HELLO is idempotently re-ACKed');
  const other = buildHello(caps, Buffer.alloc(16, 0x33));
  assert.equal(server.onOob(other), HandshakeStatus.Consumed);
  assert.equal(out.length, 2, 'R3-24: a different nonce cannot restart a live session');
  assert.equal(server.helloRefused, 1);
  // The client rejects an ACK that echoes somebody else's nonce.
  const client = new Handshake({ localD: 10, localP: 3, role: HandshakeRole.Client, localNonce: NONCE_C, send: () => {} });
  client.start(0);
  const badAck = buildHelloAck(caps, Buffer.alloc(16, 0x99), NONCE_S);
  assert.equal(client.onOob(badAck), HandshakeStatus.Consumed);
  assert.equal(client.established, false);
  assert.equal(client.nonceMismatch, 1);
});

test('handshake: TLV-offering client vs plain server gets a valid empty-block ACK', () => {
  // The ACK echoes the peer's kCapTlv bit even when we have no TLV of our own.
  // Sending a bare 52-byte ACK with that bit set is read as "block claimed but
  // absent" and kills the handshake with BadCaps, so the empty block must be
  // on the wire (C++ build_hello_ack_ext does the same).
  const out: Buffer[] = [];
  const server = new Handshake({
    localD: 10, localP: 3, role: HandshakeRole.Server, localNonce: NONCE_S,
    send: (m) => out.push(Buffer.from(m)),
  });
  server.start(0);
  out.length = 0;
  const hello = buildHello(
    { ver: 1, data: 10, parity: 3, flags: LOCAL_FLAGS_M1 | CAP_TLV },
    NONCE_C, [{ type: TLV_TYPE_ACK_V2, value: Buffer.alloc(0) }],
  );
  assert.equal(server.onOob(hello), HandshakeStatus.Consumed);
  assert.equal(out.length, 1);
  assert.equal(out[0].length, HELLO_ACK_LEN + TLV_BLOCK_LEN_BYTES);
  assert.equal(getLe16(out[0], HELLO_ACK_LEN), 0, 'block_len = 0');
  assert.deepEqual(helloTlvs(out[0], out[0].length, true), []);

  const client = new Handshake({
    localD: 10, localP: 3, role: HandshakeRole.Client, localNonce: NONCE_C,
    send: () => {},
    localTlvs: [{ type: TLV_TYPE_ACK_V2, value: Buffer.alloc(0) }],
  });
  client.start(0);
  client.onTick(0); // sends the TLV HELLO, which is what sets tlvOffered
  assert.equal(client.onOob(out[0]), HandshakeStatus.Consumed);
  assert.equal(client.established, true, 'empty block must not be treated as BadCaps');
  assert.equal(client.tlvNegotiated(), true);
  assert.equal(client.tlvAgreed(TLV_TYPE_ACK_V2), false, 'peer offered no TLV type');
});

test('handshake: 9-send retry schedule never drops the TLV block', () => {
  // Retries used to downgrade to the plain v7 shape after two unanswered
  // HELLOs. Between current peers that produced a session without multiplexing,
  // which the proxy cannot serve at all (and which poisoned the whole client
  // session pool). Loss must not change the offered capabilities.
  const out: Buffer[] = [];
  const c = new Handshake({
    localD: 10, localP: 3, role: HandshakeRole.Client, localNonce: NONCE_C,
    send: (m) => out.push(Buffer.from(m)),
    localTlvs: [{ type: TLV_TYPE_ACK_V2, value: Buffer.alloc(0) }],
  });
  c.start(0);
  let t = 0;
  for (let i = 0; i < 9; ++i) { c.onTick(t); t = c.nextRetryMs; }
  assert.equal(out.length, 9);
  for (const [i, h] of out.entries()) {
    assert.equal(h.length > HELLO_LEN, true, `retry ${i + 1} still offers its TLV block`);
  }
  c.onTick(t);
  assert.equal(c.failed, true);
  assert.equal(c.error, HandshakeError.NoAck);
});

test('FrameTx/FrameRx: D=10 k=3 repairs two lost data symbols', () => {
  const limits = computeMtuLimits(1400, 20);
  const emitted: TxSymbol[] = [];
  const tx = new FrameTx(10, limits, (s) => emitted.push(s));
  tx.setK(3);
  const payloads = Array.from({ length: 10 }, (_, i) => Buffer.alloc(100, i + 1));
  for (const p of payloads) tx.onSegment(p, 0);
  assert.equal(emitted.length, 13, '10 data + 3 parity');
  assert.equal(tx.closedFull, 1);
  assert.equal(tx.currentSetId, 1);

  const delivered: Buffer[] = [];
  const rx = new FrameRx({
    d: 10, p: 3, maxSymbolLen: limits.symbolMax,
    deliver: (b, info) => delivered.push(Buffer.concat([Buffer.from([info.recovered ? 1 : 0]), b])),
    oob: () => {},
  });
  // Drop data indices 2 and 7; shuffle the rest to exercise reordering.
  // Data first, then parity: a deterministic order so the repair count is
  // exactly the two dropped indices (an early parity may legitimately
  // reconstruct a third index that later arrives as a late duplicate).
  const frames = emitted
    .filter((s) => !(s.index === 2 || s.index === 7))
    .map((s) => packTxFrame(s));
  for (const f of frames) rx.onDatagram(f, 0);
  assert.equal(delivered.length, 10, 'all ten payloads delivered');
  assert.equal(rx.counters.recovered, 2);
  const got = new Set(delivered.map((b) => b.subarray(1).toString('hex')));
  for (const p of payloads) assert.ok(got.has(p.toString('hex')));
  assert.equal(delivered.filter((b) => b[0] === 1).length, 2, 'the two repairs are marked recovered');
});

test('FrameRx: oob symbols are dispatched, malformed headers rejected', () => {
  const oobs: Buffer[] = [];
  const delivered: Buffer[] = [];
  const rx = new FrameRx({ d: 10, p: 3, deliver: (b) => delivered.push(b), oob: (b) => oobs.push(b) });
  const oobFrame = Buffer.concat([
    Buffer.from([0, 0, 0, 0, 0, 0, 2]), Buffer.from('FCPKAL1\0', 'latin1'),
  ]);
  rx.onDatagram(oobFrame, 0);
  assert.equal(oobs.length, 1);
  assert.equal(oobs[0].toString('latin1'), 'FCPKAL1\0');
  rx.onDatagram(Buffer.from([0, 0, 0]), 0);
  assert.equal(rx.counters.structFail, 1);
});

test('FrameRx: the FECSTAT accounted-through key stays monotonic after retirement', () => {
  // The key used to be recomputed from the live set map. Retirement deletes a
  // set 2 s after its first symbol, so after a quiet interval the key fell back
  // to 0 and the peer's validator classified every later report as stale.
  const rx = new FrameRx({ d: 10, p: 3, deliver: () => {}, oob: () => {} });
  const dataFrame = (setId: number): Buffer => packTxFrame({
    setId, index: 0, d: 10, typeK: 0x60, symbol: Buffer.from([3, 0, 0xab]),
  });
  rx.onDatagram(dataFrame(5), 0);
  rx.onTick(1001);
  assert.equal(rx.accountedThroughSetId(), 5);
  rx.onTick(2001); // set 5 retired and removed from the map
  assert.equal(rx.accountedThroughSetId(), 5, 'retirement must not reset the key');
  rx.onTick(4000);
  assert.equal(rx.accountedThroughSetId(), 5);
  rx.onDatagram(dataFrame(6), 4000);
  rx.onTick(5001);
  assert.equal(rx.accountedThroughSetId(), 6, 'a newer settled set advances it');
});

test('FCP-STREAM: ordered delivery across loss/reorder/duplicates + FIN', () => {
  const aToB: Buffer[] = [], bToA: Buffer[] = [];
  let aRead = Buffer.alloc(0), bRead = Buffer.alloc(0);
  let bEof = 0;
  const a = new Stream(
    { maxSegment: 8, ackEvery: 1, initialSrttMs: 50, idleTimeoutMs: 100000 },
    { send: (s) => aToB.push(s), read: (b) => { aRead = Buffer.concat([aRead, b]); }, closed: () => {} },
  );
  const b = new Stream(
    { maxSegment: 8, ackEvery: 1, initialSrttMs: 50, idleTimeoutMs: 100000 },
    { send: (s) => bToA.push(s), read: (b2) => { bRead = Buffer.concat([bRead, b2]); }, closed: () => {}, eof: () => { ++bEof; } },
  );
  const msg = Buffer.from('the quick brown fox jumps over the lazy dog');
  a.write(msg, 0);
  a.closeWrite(0);
  assert.ok(aToB.length >= 6, 'payload is chunked into maxSegment-sized DATA segments');

  // Deliver in a scrambled order with one segment duplicated; drop one and
  // let the RTO retransmit it from the sender's timer.
  const order = aToB.map((_, i) => i);
  const scrambled = [order[0], order[2], order[1], order[1], order[4], order[3], ...order.slice(5)];
  for (let t = 1; t <= 40; ++t) {
    for (const i of scrambled) {
      if (t === 1 || (t > 20 && parseSegment(aToB[i])?.type === 1)) b.onSegment(aToB[i], t);
    }
    while (bToA.length) a.onSegment(bToA.shift()!, t);
    a.onTick(t); b.onTick(t);
  }
  assert.equal(bRead.toString(), msg.toString(), 'reassembly is byte-exact');
  assert.equal(bEof, 1, 'FIN delivered once');
  assert.equal(b.eofReceived, true);
});

test('proxy codecs: SOCKS5, CONNECT, absolute-form, FCP OPEN', () => {
  const g = socks5ParseGreeting(Buffer.from([5, 2, 0, 2]));
  assert.equal(g.status, 'ok'); assert.equal(g.value!.noAuth, true);
  assert.equal(hex(socks5GreetingReply(true)), '0500');
  const req = Buffer.concat([
    Buffer.from([5, 1, 0, 3, 11]), Buffer.from('example.com', 'latin1'), Buffer.from([0x00, 0x50]),
  ]);
  const r = socks5ParseRequest(req);
  assert.equal(r.status, 'ok');
  assert.equal(targetText(r.value!), 'example.com:80');
  assert.equal(socks5Reply(0).length, 10);

  const conn = httpParseConnect(Buffer.from('CONNECT example.com:443 HTTP/1.1\r\nHost: x\r\n\r\n', 'latin1'));
  assert.equal(conn.status, 'ok');
  assert.equal(targetText(conn.value!), 'example.com:443');
  assert.equal(conn.consumed, 45);

  const fwd = httpParseForward(Buffer.from('GET http://example.com/a/b?q=1 HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive\r\n\r\n', 'latin1'));
  assert.equal(fwd.status, 'ok');
  assert.equal(targetText(fwd.value!.target), 'example.com:80');
  const head = fwd.value!.rewrittenHead.toString('latin1');
  assert.ok(head.startsWith('GET /a/b?q=1 HTTP/1.1\r\n'));
  assert.ok(head.includes('Connection: close'));
  assert.ok(!head.includes('keep-alive'));
  assert.equal(httpParseForward(Buffer.from('GET https://example.com/ HTTP/1.1\r\n\r\n', 'latin1')).status, 'bad_request');

  const chunked = httpParseForward(Buffer.from(
    'POST http://example.com/up HTTP/1.1\r\nHost: example.com\r\n' +
    'Transfer-Encoding: chunked\r\nConnection: keep-alive, X-Hop\r\nX-Hop: 1\r\n\r\n', 'latin1'));
  assert.equal(chunked.status, 'ok');
  const ch = chunked.value!.rewrittenHead.toString('latin1');
  assert.ok(ch.includes('Transfer-Encoding: chunked'), 'chunked framing must be preserved');
  assert.ok(!/^X-Hop:/im.test(ch), 'headers named by Connection are hop-by-hop');
  assert.ok(ch.includes('Host: example.com'), 'Host is rebuilt from the absolute-form URL');
  assert.equal(httpParseForward(Buffer.from(
    'GET http://example.com/ HTTP/1.1\r\nHost: other.example\r\n\r\n', 'latin1')).status, 'bad_request');
  const frag = httpParseForward(Buffer.from(
    'GET http://example.com/a#frag HTTP/1.1\r\nHost: example.com\r\n\r\n', 'latin1'));
  assert.equal(frag.status, 'ok');
  assert.ok(frag.value!.rewrittenHead.toString('latin1').startsWith('GET /a HTTP/1.1\r\n'));

  for (const t of [
    { atyp: ATYP_DOMAIN, addr: Buffer.from('example.com', 'latin1'), port: 443 },
    { atyp: ATYP_IPV4, addr: Buffer.from([127, 0, 0, 1]), port: 8080 },
  ]) {
    const open = openWriteRequest(t)!;
    assert.equal(open.subarray(0, 4).toString('latin1'), 'FCPO');
    const parsed = openParseRequest(open);
    assert.equal(parsed.status, 'ok');
    assert.equal(targetText(parsed.value!), targetText(t));
    assert.equal(parsed.consumed, open.length);
  }
  const ok = openParseReply(openWriteOk());
  assert.equal(ok.status, 'ok'); assert.equal(ok.consumed, OPEN_OK_LEN); assert.equal(ok.value!.ok, true);
  const err = openParseReply(openWriteErr(OpenError.Dns));
  assert.equal(err.status, 'ok'); assert.equal(err.consumed, OPEN_ERR_LEN); assert.equal(err.value!.ok, false);
  assert.equal(err.value!.err, OpenError.Dns);
  assert.equal(detectEntry(Buffer.from([5, 1, 0])), 'socks5');
  assert.equal(detectEntry(Buffer.from('CONNECT x:1 HTTP/1.1', 'latin1')), 'connect');
  assert.equal(detectEntry(Buffer.from('GET http://x/ HTTP/1.1', 'latin1')), 'forward');
});

// ---------------------------------------------------------------------------
// In-memory full-stack pair: handshake -> AEAD -> FEC -> FCP-STREAM
// ---------------------------------------------------------------------------

function makePair(opts: {
  ack_v2?: boolean; k?: number; keyUpdate?: 'none' | 'both' | 'client' | 'server';
} = {}) {
  const toServer: Buffer[] = [], toClient: Buffer[] = [];
  const cRead: Buffer[] = [], sRead: Buffer[] = [];
  const cClosed: string[] = [], sClosed: string[] = [];
  const ku = opts.keyUpdate ?? 'none';
  const base = {
    psk: PSK, salt: SALT, d: 10, p: 3, mtu: 1400,
    ack_v2: opts.ack_v2 ?? false,
    pinnedK: opts.k ?? 0,
  };
  const cCfg: SessionConfig = {
    ...base, sendDirection: Direction.C2S, recvDirection: Direction.S2C, role: HandshakeRole.Client,
    keyUpdate: ku === 'both' || ku === 'client',
  };
  const sCfg: SessionConfig = {
    ...base, sendDirection: Direction.S2C, recvDirection: Direction.C2S, role: HandshakeRole.Server,
    keyUpdate: ku === 'both' || ku === 'server',
  };
  const clock = { now: 0 };
  const sReadBySid = new Map<number, Buffer[]>();
  const sStreamsBySid = new Map<number, { write: (b: Buffer) => number; closeWrite: () => void; isClosed: boolean }>();
  const client = new Session(cCfg, {
    sendWire: (w) => toServer.push(Buffer.from(w)),
    read: (b) => cRead.push(Buffer.from(b)),
    closed: (r) => cClosed.push(r),
  });
  const server = new Session(sCfg, {
    sendWire: (w) => toClient.push(Buffer.from(w)),
    read: (b) => sRead.push(Buffer.from(b)),
    closed: (r) => sClosed.push(r),
    streamHost: {
      inboundStream: (sid) => ({
        send: () => {},
        read: (b) => { const a = sReadBySid.get(sid) ?? []; a.push(Buffer.from(b)); sReadBySid.set(sid, a); },
        closed: () => {},
        eof: () => {
          // Echo a marker when the peer's FIN lands: proves the FIN crossed
          // the multiplexed session and the sid stream saw it.
          const st = sStreamsBySid.get(sid);
          if (st && !st.isClosed) st.write(Buffer.from('EOF-' + sid));
        },
      }),
      streamReady: (sid, stream) => {
        sStreamsBySid.set(sid, {
          write: (b) => stream.write(b, clock.now),
          closeWrite: () => stream.closeWrite(clock.now),
          get isClosed() { return stream.isClosed; },
        });
      },
      streamClosed: (sid) => { sReadBySid.delete(sid); sStreamsBySid.delete(sid); },
    },
  });
  client.start(0); server.start(0);
  let now = 0;
  const pump = (ms = 5, rounds = 1): void => {
    for (let n = 0; n < rounds; ++n) {
      now += ms;
      clock.now = now;
      client.onTick(now); server.onTick(now);
      let guard = 0;
      while ((toServer.length || toClient.length) && guard++ < 100) {
        while (toServer.length) server.onWire(toServer.shift()!, now);
        while (toClient.length) client.onWire(toClient.shift()!, now);
      }
    }
  };
  return {
    client, server, cRead, sRead, cClosed, sClosed, pump, now: () => now,
    sReadBySid, sStreamsBySid,
    // Raw queues let a test step exactly one datagram instead of draining.
    toServer, toClient,
  };
}

test('full stack: handshake + AEAD + FEC carry bidirectional stream bytes', () => {
  const p = makePair();
  p.pump(5, 12);
  assert.equal(p.client.established, true, 'client established');
  assert.equal(p.server.established, true, 'server established');
  assert.equal(p.client.authFail + p.server.authFail, 0, 'every datagram authenticated');
  const up = Buffer.from('client-to-server-payload');
  const down = Buffer.from('server-to-client-payload');
  assert.equal(p.client.write(up), up.length);
  assert.equal(p.server.write(down), down.length);
  p.pump(5, 20);
  assert.equal(Buffer.concat(p.sRead).toString(), up.toString());
  assert.equal(Buffer.concat(p.cRead).toString(), down.toString());
});

test('full stack: large payload (> one symbol) and FIN half-close', () => {
  const p = makePair({ k: 3 });
  p.pump(5, 12);
  const big = Buffer.alloc(9000);
  for (let i = 0; i < big.length; ++i) big[i] = i & 0xff;
  let off = 0;
  while (off < big.length) off += p.client.write(big.subarray(off));
  p.client.closeWrite();
  p.pump(5, 120);
  const got = Buffer.concat(p.sRead);
  assert.equal(got.length, big.length);
  assert.equal(hex(got), hex(big), '9000 bytes survive FEC framing + ARQ byte-exact');
});

test('full stack: FECSTAT reports are accepted by the peer validator', () => {
  const p = makePair();
  p.pump(5, 12);
  p.pump(50, 60); // 3 s of controller ticks
  assert.equal(p.client.fecstatDropped, 0);
  assert.equal(p.server.fecstatDropped, 0);
});

test('full stack: a server that gets a stateless reset drops the session instead of retransmitting', () => {
  // Measured on the VPS: after a curl --max-time abort the client had no
  // session for the salt and answered every datagram with a sealed reset, but
  // only the *client* role honoured resets. The server kept a full window
  // (544 KB queued) and 1000+ RTO copies alive until peer_dead, 135 s later,
  // burning the uplink the whole time.
  const p = makePair({ k: 3 });
  p.pump(5, 12);
  assert.equal(p.server.established, true, 'server established');
  const reset = p.client.makeReset();
  assert.ok(reset, 'client can seal a reset under the bootstrap key');
  assert.equal(p.server.onWire(reset!, p.now() + 1), true, 'reset is accepted, not an auth failure');
  assert.deepEqual(p.sClosed, ['stateless_reset'], 'server closes as stateless_reset');
  assert.equal(p.server.authFail, 0, 'and does not count it as a wrong-PSK datagram');
});


test('full stack: TLV + ACK v2 negotiation and #84 key update are symmetric', () => {
  const p = makePair({ ack_v2: true, keyUpdate: 'both' });
  p.pump(5, 12);
  assert.equal(p.client.established, true);
  assert.equal(p.server.established, true);
  assert.equal(p.client.keyUpdateActive, true);
  assert.equal(p.server.keyUpdateActive, true);
  assert.equal(p.client.streamRef.cumAcked >= 0, true);
  const msg = Buffer.from('ack-v2-path');
  p.client.write(msg);
  p.pump(5, 20);
  assert.equal(Buffer.concat(p.sRead).toString(), msg.toString());
});

test('#84 key update stays off unless BOTH ends offer TLV type 4', () => {
  // Regression guard: the roll used to be gated on "TLV negotiated", which is
  // always true now that ACK v2 is offered unconditionally. One end would roll
  // its key after FIRST_ROLL_AT packets while the other kept the session key,
  // so every packet after that was dropped with no error on either side.
  for (const side of ['client', 'server'] as const) {
    const p = makePair({ ack_v2: true, keyUpdate: side });
    p.pump(5, 12);
    assert.equal(p.client.established, true, `established (${side} only)`);
    assert.equal(p.client.keyUpdateActive, false, `client must not roll (${side} only)`);
    assert.equal(p.server.keyUpdateActive, false, `server must not roll (${side} only)`);
    const msg = Buffer.from(`no-roll-${side}`);
    p.client.write(msg);
    p.pump(5, 20);
    assert.equal(Buffer.concat(p.sRead).toString(), msg.toString(), `bytes still flow (${side} only)`);
  }
});

function hex(b: Uint8Array): string { return Buffer.from(b).toString('hex'); }

// --- M1: session multiplexing ----------------------------------------------

test('M1: mux negotiates between modern peers and sid streams stay independent', () => {
  const p = makePair();
  p.pump(5, 12);
  assert.equal(p.client.muxActive, true, 'both ends offer TLV 5');
  assert.equal(p.server.muxActive, true);

  const got1: Buffer[] = [], got2: Buffer[] = [], closed: string[] = [];
  const s1 = p.client.openStream(1, {
    send: () => {}, read: (b) => got1.push(b), closed: (r) => closed.push('1:' + r), eof: () => {},
  });
  const s2 = p.client.openStream(2, {
    send: () => {}, read: (b) => got2.push(b), closed: (r) => closed.push('2:' + r), eof: () => {},
  });
  assert.ok(s1 && s2, 'both sids open');
  assert.equal(p.client.openStream(1, { send: () => {}, read: () => {}, closed: () => {} }), null,
    'a taken sid is refused');
  assert.equal(p.client.openStream(0, { send: () => {}, read: () => {}, closed: () => {} }), null,
    'sid 0 is the default stream, never opened through openStream');

  // Interleaved writes keep the streams independent.
  s1!.write(Buffer.from('one-aaa'));
  s2!.write(Buffer.from('two-bbb'));
  s1!.write(Buffer.from('-ccc'));
  p.pump(5, 20);
  assert.equal(Buffer.concat(p.sReadBySid.get(1) ?? []).toString(), 'one-aaa-ccc');
  assert.equal(Buffer.concat(p.sReadBySid.get(2) ?? []).toString(), 'two-bbb');
  assert.equal(p.sRead.join(''), '', 'the default stream stays empty while sid streams run');

  // Closing one sid stream leaves the other fully functional.
  s1!.closeWrite();
  p.pump(5, 30);
  s2!.write(Buffer.from('-more'));
  p.pump(5, 30);
  assert.equal(Buffer.concat(p.sReadBySid.get(2) ?? []).toString(), 'two-bbb-more');
});

test('M1: per-sid streams carry their own FIN and the default stream coexists', () => {
  const p = makePair();
  p.pump(5, 12);
  const gotBack: Buffer[] = [];
  const s1 = p.client.openStream(3, {
    send: () => {}, read: (b) => gotBack.push(b), closed: () => {}, eof: () => {},
  });
  const big = Buffer.alloc(5000);
  for (let i = 0; i < big.length; ++i) big[i] = i & 0xff;
  let off = 0;
  while (off < big.length) off += s1!.write(big.subarray(off));
  s1!.closeWrite();
  // The default stream keeps carrying data alongside.
  const msg = Buffer.from('default-stream-still-works');
  assert.equal(p.client.write(msg), msg.length);
  p.pump(5, 120);
  const gotSid = Buffer.concat(p.sReadBySid.get(3) ?? []);
  assert.equal(gotSid.length, big.length, '5000 bytes cross the sid stream');
  const back = Buffer.concat(gotBack).toString();
  assert.ok(back.includes('EOF-3'), 'server observed the sid FIN and answered through the same sid stream');
  assert.equal(Buffer.concat(p.sRead).toString(), msg.toString(), 'default stream unaffected');
  // The server closes its half too: only then is the sid freed for reuse.
  p.sStreamsBySid.get(3)?.closeWrite();
  p.pump(5, 60);
  assert.equal(p.client.openStream(3, { send: () => {}, read: () => {}, closed: () => {} }) !== null, true,
    'both halves closed: the sid is freed for reuse');
});

test('M1: sid control segments inherit ACK v2 and are flushed immediately', () => {
  const p = makePair({ ack_v2: true });
  p.pump(5, 12);
  assert.equal(p.client.muxActive, true, 'mux negotiated');

  // Every sid stream must use the wide ack that was negotiated for the
  // session; makeStream() used to leave ackV2 at its default false.
  const s1 = p.client.openStream(1, { send: () => {}, read: () => {}, closed: () => {} });
  assert.ok(s1, 'sid 1 opened');
  assert.equal(s1!.ackV2Enabled, true, 'sid stream inherits ACK v2');
  assert.equal(p.client.streamRef.ackV2Enabled, true, 'default stream keeps it too');

  // Drain setup traffic, then deliver exactly one repair group of three DATA
  // symbols from the server's default stream. Two ack-coalescing slots plus
  // the third segment is what makes the receiver emit an ACK.
  p.pump(5, 20);
  p.toServer.length = 0;
  p.toClient.length = 0;
  p.server.write(Buffer.from('aaa'));
  p.server.write(Buffer.from('bbb'));
  p.server.write(Buffer.from('ccc'));
  const t = p.now() + 300; // past the ~srtt flush timer, before any TLP
  p.server.onTick(t);
  // Three DATA symbols plus the scaled repair symbol for a short group
  // (ceil(k*n/d) = 1 at D=10, k=3, n=3).
  assert.equal(p.toClient.length, 4, 'one repair group carried the three segments');

  const before = p.toServer.length;
  for (const w of p.toClient.splice(0)) p.client.onWire(w, t);
  // In mux mode the 1-byte sid prefixes every segment, so the stream type is
  // at offset 1. Reading offset 0 read the sid (0 here), the ACK was treated
  // as data, and it sat in the repair group until the flush timer.
  // The ACK leaves immediately: it gets the dedicated control lane, which
  // closes on arrival, so it is one DATA symbol plus the one scaled repair
  // symbol a 1-symbol group gets at D=10, P=3. (With --ack-copies>1 the extra
  // copies ride the data lanes, so this would be one datagram per copy more.)
  assert.equal(p.toServer.length, before + 2, 'the ACK left immediately');
});

test('M1: bytes queued during the handshake are framed with sid 0', () => {
  // Data written before the handshake is cached unframed because mux is not
  // known yet. configure() used to replay it raw, so the peer read the stream
  // type as a sid: a phantom sid 1 stream got the OPEN parser's garbage and
  // the default stream never ACKed those bytes (retransmitted until idle).
  const p = makePair();
  assert.equal(p.client.established, false);
  assert.equal(p.client.streamRef.write(Buffer.from('early'), 0), 5,
    'the pre-handshake cache accepts data');
  p.pump(5, 12);
  assert.equal(p.client.muxActive, true, 'mux negotiated after the write');
  p.pump(5, 80); // past the ~srtt flush timer so the repair group goes out
  assert.equal(Buffer.concat(p.sRead).toString(), 'early',
    'the server default stream received the bytes');
  assert.equal(p.sStreamsBySid.size, 0, 'no phantom sid stream was created');
});

test('M1: a zero-length mux symbol cannot fabricate a stream id', () => {
  const p = makePair();
  p.pump(5, 12);
  assert.equal(p.client.muxActive, true);
  // An empty payload has no room for the sid byte. This must be accounted as
  // a structural failure, not routed with sid === undefined.
  const before = p.server.structFail;
  (p.server as unknown as { deliverStreamFrame: (b: Buffer) => void }).deliverStreamFrame(Buffer.alloc(0));
  assert.equal(p.server.structFail, before + 1, 'empty payload rejected as structFail');
});

test('FrameRx: evicting an accounted set retires its id (no late re-settle)', () => {
  // REGRESSION: capacity eviction of an already-accounted set used to drop it
  // from `sets` without adding the id to `retired`. A late symbol for that id
  // then re-created the set and settled it a SECOND time (double-counted
  // FECSTAT + duplicate delivery). C++ frame_rx.cc:415 explicitly inserts the
  // evicted accounted id into retired_ here.
  const delivered: Buffer[] = [];
  const rx = new FrameRx({ d: 10, p: 3, deliver: (b) => delivered.push(b), oob: () => {} });
  const dataFrame = (setId: number): Buffer => packTxFrame({
    setId, index: 0, d: 10, typeK: 0x60, symbol: Buffer.from([3, 0, 0xab]),
  });
  // Fill the set map to capacity with data symbols.
  for (let id = 0; id < 256; ++id) rx.onDatagram(dataFrame(id), 0);
  rx.onTick(1000); // every set becomes accounted (1 s gate), none yet retired (2 s)
  const before = rx.counters.setsExpected;
  assert.equal(before, 256);

  // A new set id forces eviction of the first (accounted) set, id 0.
  rx.onDatagram(dataFrame(256), 1000);
  assert.equal(rx.view(0), undefined, 'set 0 was evicted');

  // A late symbol for the evicted, accounted set must be rejected by the
  // retired-id guard — it must NOT re-create the set.
  rx.onDatagram(dataFrame(0), 1001);
  assert.equal(rx.view(0), undefined, 'retired id must not be re-created by a late symbol');
  assert.equal(rx.counters.retiredDropped, 1, 'late symbol counted as retiredDropped');
  rx.onTick(2200);
  assert.equal(rx.counters.setsExpected, before + 1,
    'only set 256 settles; the evicted set 0 must not be counted twice');
});

test('FrameRx: a reconstructed symbol obeys the session byte budget', () => {
  // REGRESSION: storeRecovered added bytes to symbolBytes without the
  // MAX_RX_SYMBOL_BYTES ceiling that arriving symbols (and C++ store_symbol)
  // enforce. Under sustained loss, recovery could push the counter past the
  // only heap guard and leave it negative after settle.
  const rx = new FrameRx({ d: 10, p: 3, deliver: () => {}, oob: () => {} });
  const r = rx as unknown as {
    symbolBytes: number;
    storeRecovered: (set: { data: Map<number, Buffer> }, idx: number, symbol: Buffer) => void;
  };
  const CEILING = 8 * 1024 * 1024;
  r.symbolBytes = CEILING - 10;
  const fakeSet = { data: new Map<number, Buffer>() };
  const big = Buffer.alloc(100, 0x7b);

  r.storeRecovered(fakeSet, 0, big); // would exceed by 90 bytes
  assert.equal(r.symbolBytes, CEILING - 10, 'budget refusal must not grow symbolBytes');
  assert.equal(fakeSet.data.size, 0, 'budget refusal must not cache the row');
  assert.equal(rx.counters.symbolBudgetDrops, 1, 'refusal is counted');

  // A row that fits is still stored and counted.
  const small = Buffer.alloc(8, 0x5a);
  r.storeRecovered(fakeSet, 1, small);
  assert.equal(r.symbolBytes, CEILING - 2);
  assert.equal(fakeSet.data.get(1)?.length, 8);
});

test('HTTP CONNECT and forward accept a bracketed IPv6 literal target', () => {
  // REGRESSION: parseAuthority stripped the brackets but httpParseConnect /
  // httpParseForward always encoded the result as ATYP_DOMAIN. The peer's
  // openParseRequest rejects ':' in a domain (hostCharOk), so every CONNECT
  // [IPv6] and absolute-form GET http://[IPv6]/ failed with bad_address.
  const con = httpParseConnect(Buffer.from(
    'CONNECT [::1]:443 HTTP/1.1\r\nHost: [::1]:443\r\n\r\n', 'latin1'));
  assert.equal(con.status, 'ok');
  const open = openWriteRequest(con.value!);
  assert.ok(open);
  assert.equal(openParseRequest(open!).status, 'ok', 'a CONNECT [IPv6] must produce a FCP OPEN the peer accepts');
  assert.equal(con.value!.atyp, ATYP_IPV6, 'IPv6 literal encoded as ATYP_IPV6, not ATYP_DOMAIN');

  const fwd = httpParseForward(Buffer.from(
    'GET http://[2001:db8::1]:8080/x HTTP/1.1\r\nHost: [2001:db8::1]:8080\r\n\r\n', 'latin1'));
  assert.equal(fwd.status, 'ok');
  assert.equal(fwd.value!.target.atyp, ATYP_IPV6);
  assert.equal(openParseRequest(openWriteRequest(fwd.value!.target)!).status, 'ok');

  // Byte-level correctness of the expansion (compressed, mapped, mixed, full).
  const bytesFor = (lit: string): string => {
    const r = httpParseConnect(Buffer.from(
      `CONNECT [${lit}]:443 HTTP/1.1\r\nHost: x\r\n\r\n`, 'latin1'));
    assert.equal(r.status, 'ok', `${lit} must parse`);
    return Buffer.from(r.value!.addr).toString('hex');
  };
  assert.equal(bytesFor('::1'), '00000000000000000000000000000001');
  assert.equal(bytesFor('2001:db8::1'), '20010db8000000000000000000000001');
  assert.equal(bytesFor('::ffff:192.0.2.1'), '00000000000000000000ffffc0000201');
  assert.equal(bytesFor('::192.0.2.1'), '000000000000000000000000c0000201');
  for (const bad of ['2001::1::2', 'gggg::1', 'fe80::1%eth0']) {
    const r = httpParseConnect(Buffer.from(
      `CONNECT [${bad}]:443 HTTP/1.1\r\nHost: x\r\n\r\n`, 'latin1'));
    assert.equal(r.status, 'bad_request', `${bad} must be rejected`);
  }
});

test('FrameRx: set-id gap placeholders count as setsKUnknown, not tailDropped', () => {
  // C++ settle.cc:127-129 counts a fully-lost set (seen only as an id jump,
  // no symbol ever arrived) as sets_k_unknown. The TS accountSet used to bump
  // setsTailDropped instead, and setsKUnknown was never incremented at all —
  // FECSTAT reported the wrong field and mis-set FLG_TAIL_DROPPED.
  const rx = new FrameRx({ d: 10, p: 3, deliver: () => {}, oob: () => {} });
  const dataFrame = (setId: number): Buffer => packTxFrame({
    setId, index: 0, d: 10, typeK: 0x60, symbol: Buffer.from([3, 0, 0xab]),
  });
  rx.onDatagram(dataFrame(0), 0);
  rx.onDatagram(dataFrame(5), 0); // jump 0 -> 5 creates placeholders 1..4
  rx.onTick(1000);
  assert.equal(rx.counters.setsKUnknown, 4, 'four gap placeholders counted as kUnknown');
  assert.equal(rx.counters.setsTailDropped, 0, 'gap placeholders are not tail drops');
});

test('FrameRx: a late in-bound original counts as dataLateRx, not lateDup', () => {
  // FECSTAT dataLateRx must be a distinct signal from lateDup. It used to be
  // wired to lateDup in snapshotCounters, so real late originals never showed
  // up and the peer's data_lost() under-counted loss.
  const rx = new FrameRx({ d: 5, p: 3, deliver: () => {}, oob: () => {} });
  const dataFrame = (idx: number): Buffer => packTxFrame({
    setId: 7, index: idx, d: 5, typeK: 0x60, symbol: Buffer.from([3, 0, 0xab]),
  });
  rx.onDatagram(dataFrame(0), 0);
  rx.onDatagram(dataFrame(2), 0); // maxDataIndex=2 -> nUsed/boundary=3, hole at 1
  rx.onTick(1000);                // set 7 accounted
  rx.onDatagram(dataFrame(1), 1001); // late original inside the boundary
  assert.equal(rx.counters.dataLateRx, 1, 'late in-bound original counted');
  assert.equal(rx.counters.lateDup, 0, 'not a duplicate');
});

test('FrameRx: a symbol with a conflicting k is rejected as structFail', () => {
  // C++ note_k() (frame_rx.cc:435) is first-wins but returns false when a later
  // symbol in the same set declares a different clamped k; the caller drops it
  // with struct_fail. TS silently kept the first k, so a peer with a wrong k
  // field could drive RS decode with mismatched geometry.
  const rx = new FrameRx({ d: 5, p: 3, deliver: () => {}, oob: () => {} });
  const frame = (k: number, idx: number): Buffer => packTxFrame({
    setId: 9, index: idx, d: 5, typeK: (k << 5) | 0, symbol: Buffer.from([3, 0, 0xab]),
  });
  rx.onDatagram(frame(1, 0), 0); // set 9 k=1 first-wins
  assert.equal(rx.counters.structFail, 0);
  const before = rx.view(9)!.orig.size;
  rx.onDatagram(frame(2, 1), 0); // conflicting k=2 -> rejected
  assert.equal(rx.counters.structFail, 1, 'conflicting k counted as structFail');
  assert.equal(rx.view(9)!.orig.size, before, 'conflicting symbol not absorbed into the set');
});

// ---------------------------------------------------------------------------
// PMTUD: the probe walk must survive a lost probe answer
// ---------------------------------------------------------------------------

/** A PMTU ACK is the only 16-byte oob payload on the wire, so its wire length
 *  is unique: FEC header + envelope overhead + the 16-byte PMTU header. */
const PMTU_ACK_WIRE_LEN = ENVELOPE_OVERHEAD + FEC_HDR_LEN + PMTU_HEADER_LEN;

/**
 * A client that walks its MTU up while the peer answers every probe it
 * receives. `dropAcks` says how many of the peer's answers never arrive, and
 * `silentPeer` makes the peer answer nothing at all.
 */
function pmtudWalk(opts: { dropAcks?: number; silentPeer?: boolean } = {}) {
  const toServer: Buffer[] = [];
  const toClient: Buffer[] = [];
  const base = {
    psk: PSK, salt: SALT, d: 10, p: 3, mtu: 576, pmtuMaxMtu: 1500,
  };
  const client = new Session(
    { ...base, sendDirection: Direction.C2S, recvDirection: Direction.S2C, role: HandshakeRole.Client, pmtud: true },
    { sendWire: (w) => toServer.push(Buffer.from(w)), read: () => {}, closed: () => {} },
  );
  const server = new Session(
    { ...base, sendDirection: Direction.S2C, recvDirection: Direction.C2S, role: HandshakeRole.Server, pmtud: false },
    { sendWire: (w) => toClient.push(Buffer.from(w)), read: () => {}, closed: () => {} },
  );
  client.start(0);
  server.start(0);
  let now = 0;
  let dropped = 0;
  const step = (): void => {
    now += 20;
    client.onTick(now);
    server.onTick(now);
    while (toServer.length) server.onWire(toServer.shift()!, now);
    while (toClient.length) {
      const d = toClient.shift()!;
      // Only the probe answers are silenced; the handshake still goes through.
      if (d.length === PMTU_ACK_WIRE_LEN &&
          (opts.silentPeer || dropped < (opts.dropAcks ?? 0))) { ++dropped; continue; }
      client.onWire(d, now);
    }
  };
  for (let i = 0; i < 25; ++i) step();                  // handshake
  assert.equal(client.established, true, 'the pair established');
  for (let i = 0; i < 1200; ++i) step();                // 24 s of probing
  return { client, server, dropped };
}

test('PMTUD: a probe answer that was lost does not freeze the MTU walk', () => {
  // Symptom: the black-hole verdict was declared on the probe that was being
  // SENT — it had not had a single millisecond to be answered. Two lost probe
  // answers were enough: the third probe was declared "unanswered x3", the
  // ceiling was pinned to the size of that probe, and the peer answered it one
  // millisecond later. `ceiling - acked <= PMTU_PROBE_STEP` then stopped every
  // further probe for the rest of the session: the tunnel stayed at 676 B
  // forever on a path that carried 1500 B, roughly halving throughput with a
  // single line in the log. The ceiling was never lifted either.
  const { client, dropped } = pmtudWalk({ dropAcks: 2 });
  assert.equal(dropped, 2, 'two probe answers were really lost');
  assert.equal(client.mtuLimits.mtu, 1500,
    `the walk must continue past the lost answers (stuck at ${client.mtuLimits.mtu} B)`);
});

test('PMTUD: a peer that answers nothing keeps the MTU at the proven size', () => {
  // The guard for the fix above: a genuinely silent peer must still stop the
  // walk, and the budget must fall back to the last size that was proven.
  const { client } = pmtudWalk({ silentPeer: true });
  assert.equal(client.mtuLimits.mtu, 576,
    `a silent peer must not grow the MTU (it reached ${client.mtuLimits.mtu} B)`);
});

test('STREAM: a peer window too small to carry a segment must not deadlock the sender', () => {
  // C++ stream_send.cc: "A peer window that cannot carry it deadlocks the
  // sender even when the window is not zero". A DATA segment is a 6-byte
  // header plus at least one payload byte, so a peer window of 1..6 bytes
  // left pump() with no room: it sent nothing, nothing was in flight, so no
  // RTO could fire, and the persist probe was gated on `window() === 0` —
  // nextTimerMs() answered -1 and the host never even woke up. The transfer
  // sat there until the 5-minute idle timeout.
  for (const rwnd of [1, 3, 6]) {
    const sent: Buffer[] = [];
    const s = new Stream(
      { maxSegment: 1200, initialSrttMs: 40, sendWindowBytes: 256 * 1024,
        rcvBufBytes: 256 * 1024, idleTimeoutMs: 1e9, ackV2: true },
      { send: (b) => sent.push(b), read: () => {}, closed: () => {} },
    );
    s.onSegment(encodeAckV2(0, rwnd, []), 1);
    s.write(Buffer.alloc(5000), 2);
    let now = 2;
    for (let i = 0; i < 20; ++i) { s.onTick(now); now += 10; }
    assert.ok(sent.length > 0, `rwnd=${rwnd}: not even a persist probe went out`);
    assert.ok(s.nextTimerMs(now) > 0, `rwnd=${rwnd}: no deadline, so the host never wakes`);
    assert.ok(s.pendingQueueBytes < 5000, `rwnd=${rwnd}: the queue never moved`);
  }
});

test('STREAM: a backwards wall clock must not poison the RTT estimator', () => {
  // C++ stream_send.cc: "A clock that went backwards says nothing about the
  // path: the sample would be negative and, fed into srtt, would drag every
  // timer with it" — the sample is dropped. Clamping it to 0 did the
  // opposite: the invalid sample became a *perfect* 0 ms RTT, minRttMs was
  // zeroed, and the reorder gate lost its floor (395 ms -> 185 ms on a
  // measured path) — the very gate that keeps a reordering path from being
  // mistaken for a lossy one.
  const s = new Stream(
    { maxSegment: 1200, initialSrttMs: 200, sendWindowBytes: 256 * 1024,
      rcvBufBytes: 256 * 1024, idleTimeoutMs: 1e9, ackV2: true },
    { send: () => {}, read: () => {}, closed: () => {} },
  );
  s.write(Buffer.alloc(4000), 0);
  s.onSegment(encodeAckV2(1200, 65535, []), 80);   // a clean 80 ms sample
  const gateBefore = s.retxAgeGateMs;
  assert.ok(gateBefore >= 100, `the gate starts high (${gateBefore} ms)`);
  // The wall clock steps back by 5 s between the send and the ACK.
  s.write(Buffer.alloc(1200), 120);
  s.onSegment(encodeAckV2(2400, 65535, []), 120 - 5000);
  assert.ok(s.retxAgeGateMs >= gateBefore * 0.9,
    `the reorder gate collapsed on an invalid sample: ${gateBefore} -> ${s.retxAgeGateMs}`);
});

test('STREAM: the receiver never holds more than the window it advertises', () => {
  // C++ stream_recv.cc: "counting only the buffer would let the receiver hold
  // twice the window it promised" — the reorder buffer is trimmed to
  // rcv_cap - delivery_pending. The port kept only the chunk-count ceiling,
  // so oobBytes + deliveryPending reached 1.99x the advertised window while
  // rwnd already read 0, and a session with 255 mux streams multiplies that
  // overshoot.
  const CAP = 100 * 1024;
  let now = 0;
  const s = new Stream(
    { maxSegment: 1200, initialSrttMs: 40, sendWindowBytes: 256 * 1024,
      rcvBufBytes: CAP, idleTimeoutMs: 1e9, ackV2: true },
    { send: () => {}, read: () => {}, closed: () => {} },   // the app never consumes
  );
  const seg = (off: number, n: number) => {
    const b = Buffer.alloc(6 + n); b[0] = 1; b.writeUInt32LE(off >>> 0, 1); return b;
  };
  for (let off = 0; off < CAP - 1; off += 1194) {
    s.onSegment(seg(off, Math.min(1194, CAP - 1 - off)), now++);
  }
  for (let off = CAP + 1000; off < 2 * CAP + 100000; off += 1194) {
    s.onSegment(seg(off, 1194), now++);
  }
  const held = s.reorderBytes + s.deliveryPendingBytes;
  assert.ok(held <= CAP,
    `held ${held} bytes > the advertised ${CAP} (${(held / CAP).toFixed(2)}x)`);
  assert.ok(s.reorderBytes >= 0, `the reorder counter went negative: ${s.reorderBytes}`);
});

test('STREAM: a truncated ACK v2 never reports past a run it left out', () => {
  // The ACK v2 range list is cut to what the datagram budget holds, and what
  // gets cut is the tail of the list -- never a run in the middle. That is not
  // a style choice. Fast retransmit treats every segment below sackedHigh, the
  // end of the *highest reported* run, that the ACK did not name as missing.
  // Reporting the newest run while skipping middle ones therefore declares the
  // skipped runs lost while the peer is holding them in its receive queue, and
  // the sender spends its six retransmissions a round re-sending bytes that
  // already arrived. Measured on a seeded 5% loss path at MTU 300: 1499
  // retransmissions and 49 KB of duplicate delivery against 798 and 38 KB for
  // the prefix, and 19% later completion (scripts/ack-probe.ts).
  //
  // The invariant: for every ACK, every byte the receiver holds below the last
  // reported end (sackedHigh) must be inside a reported range. Anything else is
  // a phantom hole.
  const MAXSEG = 66;                    // 60 B payload + 6 B DATA header
  const HOLES = 40;
  const SPACING = 120;
  const RUN = 60;
  const acks: Buffer[] = [];
  const have: Array<{ start: number; end: number }> = [];
  const s = new Stream(
    { maxSegment: MAXSEG, initialSrttMs: 40, sendWindowBytes: 256 * 1024,
      rcvBufBytes: 256 * 1024, idleTimeoutMs: 1e9, ackV2: true },
    { send: (b) => acks.push(b), read: () => {}, closed: () => {} },
  );
  const seg = (off: number, n: number) => {
    const b = Buffer.alloc(6 + n); b[0] = 1; b.writeUInt32LE(off >>> 0, 1); return b;
  };
  // One in-order segment moves cum to 60; the runs start at 120 and are spaced
  // 120 B apart so each stays a separate run instead of merging.
  s.onSegment(seg(0, RUN), 1);
  have.push({ start: 0, end: RUN });
  for (let k = 0; k < HOLES; ++k) {
    const off = 120 + SPACING * k;
    s.onSegment(seg(off, RUN), 2 + k);
    have.push({ start: off, end: off + RUN });
  }
  s.onTick(200);
  const parsed = acks
    .map((b) => parseSegment(b))
    .filter((p): p is NonNullable<typeof p> => !!p && p.type === STREAM_TYPE_ACK_V2);
  assert.ok(parsed.length > 0, 'no ACK v2 went out');
  const last = parsed[parsed.length - 1]!;
  // The byte-accurate budget (not the old 10 B-per-range estimate) is what lets
  // a prefix ACK carry this many ranges at all.
  const worstCase = Math.floor((MAXSEG - 10) / 10);
  assert.ok(last.ranges.length > worstCase,
    `the ACK carried ${last.ranges.length} ranges, no more than the ${worstCase} the worst-case estimate allows`);
  assert.equal(last.ranges[0]!.start, 120,
    'the range nearest cum is missing: the sender cannot see where the real gap ends');
  // The cut landed somewhere: if all 40 runs fitted there would be nothing to
  // check, and the test would pass on the broken ordering too.
  assert.ok(last.ranges.length < HOLES,
    'every run fitted the datagram, so this ACK never truncated');
  for (const a of parsed) {
    const lastEnd = a.ranges.length ? a.ranges[a.ranges.length - 1]!.end : a.cum!;
    for (const r of have) {
      const from = Math.max(r.start, a.cum!);
      const to = Math.min(r.end, lastEnd);
      for (let x = from; x < to; x += 20) {
        assert.ok(a.ranges.some((q) => x >= q.start && x < q.end),
          `ACK cum=${a.cum} leaves offset ${x} unreported below sackedHigh=${lastEnd}: ` +
          'the sender will retransmit bytes the peer already holds');
      }
    }
  }
});

test('STREAM: a host that re-enters from read() must not duplicate or lose bytes', () => {
  // C++ stream_recv.cc: "Detach before handing bytes to the host: read_ may
  // re-enter with more segments, and a chunk that is no longer at the front
  // must not be dropped." The port called read() first and spliced after, so
  // the re-entrant insert replaced the queue and the splice removed the wrong
  // chunk: the same bytes were delivered over and over (328 times in the
  // measurement) and the reorder counter went negative, which lets rwndOut()
  // advertise more than the buffer can hold.
  let s: Stream | null = null;
  const delivered: number[] = [];
  const seg = (off: number, n: number) => {
    const b = Buffer.alloc(6 + n); b[0] = 1; b.writeUInt32LE(off >>> 0, 1); return b;
  };
  s = new Stream(
    { maxSegment: 1200, initialSrttMs: 40, sendWindowBytes: 64 * 1024,
      rcvBufBytes: 64 * 1024, idleTimeoutMs: 1e9, ackV2: true },
    { send: () => {}, closed: () => {},
      read: (b) => { delivered.push(b.length); (s as Stream).onSegment(seg(5000, 100), 10); } },
  );
  s.onSegment(seg(100, 100), 1);
  s.onSegment(seg(0, 100), 2);
  assert.equal(delivered.length, 1, `the same bytes were delivered ${delivered.length} times`);
  assert.ok(s.reorderBytes >= 0, `the reorder counter went negative: ${s.reorderBytes}`);
});

test('STREAM: a v1 SACK block below the cumulative point must be ignored', () => {
  // C++ stream_send.cc: "the block must describe a non-empty range above the
  // cumulative point ... Ignore the SACK half of such an ACK but keep its
  // cumulative point and window". The port accepted a block that starts below
  // cum, and that block covers the segment right in front of the hole: the
  // segment was marked SACKed, which takes it out of both the fast-retransmit
  // and the RTO paths, so the cumulative point never advanced and the stream
  // hung until the idle timeout.
  const s = new Stream(
    { maxSegment: 1200, initialSrttMs: 40, sendWindowBytes: 64 * 1024,
      rcvBufBytes: 64 * 1024, idleTimeoutMs: 1e9 },
    { send: () => {}, read: () => {}, closed: () => {} },
  );
  s.write(Buffer.alloc(12000), 0);
  s.onTick(1); s.onTick(2);
  s.onSegment(encodeAck(6000, 65535, 1000, 7164), 10);
  const tx = (s as unknown as { tx: Array<{ end: number; sacked: boolean }> }).tx;
  const above = tx.filter((x) => x.end > 6000);
  assert.ok(above.length > 0, 'the segments are in flight');
  assert.equal(above.filter((x) => x.sacked).length, 0,
    'a block below the cumulative point marked an unacked segment as delivered');
});

test('HANDSHAKE: a short local nonce is refused at construction, not at key derivation', () => {
  // nonceValid() checked 16 bytes of a buffer that could be shorter: the
  // missing bytes read as undefined, which ORs to 0, so a 3-byte nonce
  // passed the check and the failure only appeared two modules later — as an
  // uncaught throw out of deriveSessionKeyV7, on the UDP receive path.
  const h = new Handshake({
    localD: 10, localP: 6, role: HandshakeRole.Client,
    localNonce: Buffer.from([1, 2, 3]),
    send: () => {},
  });
  assert.equal(h.failed, true, 'the short nonce must be refused');
  assert.equal(h.error, HandshakeError.BadNonce);
  // A full-length nonce is still fine.
  const ok = new Handshake({
    localD: 10, localP: 6, role: HandshakeRole.Client,
    localNonce: Buffer.alloc(16, 3),
    send: () => {},
  });
  assert.equal(ok.failed, false);
});

test('HANDSHAKE: a TLV block that claims more than it holds is malformed', () => {
  // The claimed length ran past the block: `block[off]` read as undefined
  // (which is not 0, so the reserved-type test missed) and the length
  // arithmetic became NaN < undefined, which is false — both guards passed
  // and the caller got a TLV with `type: undefined` as if it were parsed.
  assert.equal(tlvParse(Buffer.from([1, 5, 0, 0]), 10), null);
  assert.equal(tlvParse(Buffer.from([1, 5, 0, 0]), 4), null, 'the value does not fit the block');
  assert.equal(tlvParse(Buffer.from([1, 2, 0xaa, 0xbb]), 4)!.length, 1, 'a legal block still parses');
});

test('HANDSHAKE: a prewarm ticket with an impossible k is malformed', () => {
  // C++ prewarm.cc: k is a 3-bit field on the wire, so anything above the
  // parity ceiling (7) that is not the "unknown" marker (15) cannot be a
  // measurement — "a value that cannot be a measurement is a malformed
  // ticket, not a seed worth honouring".
  const v = Buffer.alloc(12); v[0] = 1; v[1] = 200;
  assert.equal(decodePrewarmTlv(v), null);
  const ok = Buffer.alloc(12); ok[0] = 1; ok[1] = 6;
  assert.ok(decodePrewarmTlv(ok), 'a legal k still decodes');
});
