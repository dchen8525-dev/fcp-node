// Bare UDP tunnel with a SOCKS5 front end: framing, sequencing, in-order
// delivery, and nothing else.
//
// There is deliberately NO retransmission and NO congestion control on the
// data path. That is the whole point: it measures what the path can carry
// when you refuse to do the work that makes a proxy usable. Consequences
// are the result, not a bug:
//   - a lost datagram is never resent, so an HTTPS stream dies at the TLS
//     handshake or corrupts mid-file (the driver reports lostBytes);
//   - blasting overflows the receive buffer, so the loss rate is worse than
//     the path's inherent loss.
// Control frames (OPEN/OPEN_ACK) ARE retried, otherwise nothing could ever
// connect at all. Data frames never are.
//
//   node bench/udp-proxy.ts server --bind=0.0.0.0:7002
//   node bench/udp-proxy.ts client --listen=127.0.0.1:1082 --peer=144.34.186.164:7002
//   node bench/udp-proxy.ts sink --peer=144.34.186.164:7002 --bytes=67108864

import { createSocket, type RemoteInfo, type Socket as UdpSocket } from 'node:dgram';
import { createServer, connect, type Socket } from 'node:net';
import { randomBytes } from 'node:crypto';
import { acceptSocks5, encodeTarget, socksReply, type Target } from './socks5.ts';

const MAGIC = 0xfc;
const TYPE_OPEN = 1;
const TYPE_DATA = 2;
const TYPE_CLOSE = 3;
const TYPE_OPEN_ACK = 4;
const TYPE_SINK_REQ = 5;
const TYPE_SINK_DATA = 6;

const HDR = 12;
const PAYLOAD = 1400; // 1400 + 12 + 28 = 1440 < 1500, never fragments
const GAP_SKIP_MS = 250; // how long an out-of-order gap may hold delivery
const MAX_BUFFERED = 8192; // reorder slots; beyond this we drop the newest
const OPEN_RETRY_MS = 200;
const OPEN_TRIES = 6;
const UDP_BUFS = 32 * 1024 * 1024; // no flow control anywhere: the buffer is the only shock absorber
const SEND_HIGH_WATER = 4 * 1024 * 1024;

const argv = process.argv.slice(2);
const mode = argv.shift();

function opt(name: string, fallback?: string): string {
  const hit = argv.find((a) => a.startsWith(`--${name}=`));
  if (hit) return hit.slice(name.length + 3);
  if (fallback !== undefined) return fallback;
  throw new Error(`--${name} is required`);
}

function parseAddr(v: string): { host: string; port: number } {
  const i = v.lastIndexOf(':');
  if (i < 0) throw new Error(`expected host:port, got ${v}`);
  return { host: v.slice(0, i), port: Number(v.slice(i + 1)) };
}

function log(line: string): void {
  process.stderr.write(`[udp-proxy] ${line}\n`);
}

function frame(type: number, sid: number, seq: number, payload: Buffer): Buffer {
  const b = Buffer.allocUnsafe(HDR + payload.length);
  b[0] = MAGIC;
  b[1] = type;
  b.writeUInt32BE(sid, 2);
  b.writeUInt32BE(seq >>> 0, 6);
  b.writeUInt16BE(payload.length, 10);
  payload.copy(b, HDR);
  return b;
}

type Parsed = { type: number; sid: number; seq: number; payload: Buffer };

function parse(buf: Buffer): Parsed | null {
  if (buf.length < HDR || buf[0] !== MAGIC) return null;
  const len = buf.readUInt16BE(10);
  if (HDR + len > buf.length) return null;
  return {
    type: buf[1],
    sid: buf.readUInt32BE(2),
    seq: buf.readUInt32BE(6),
    payload: buf.subarray(HDR, HDR + len),
  };
}

/**
 * In-order delivery on top of a network that drops and reorders. A gap is
 * waited on for GAP_SKIP_MS, then written off as lost: the bytes are gone
 * for good, which is exactly what "no retransmission" means.
 */
class Reassembler {
  private expect = 1;
  private buf = new Map<number, Buffer>();
  private gapSince = 0;
  lostBytes = 0;
  lostGaps = 0;
  dups = 0;
  private readonly onData: (b: Buffer) => void;
  private readonly now: () => number;

  constructor(onData: (b: Buffer) => void, now: () => number) {
    this.onData = onData;
    this.now = now;
  }

  push(seq: number, payload: Buffer): void {
    if (seq < this.expect) {
      this.dups++;
      return;
    }
    if (seq === this.expect) {
      this.onData(payload);
      this.expect++;
      this.drain();
      return;
    }
    if (this.buf.size >= MAX_BUFFERED) {
      this.lostBytes += payload.length;
      return;
    }
    if (!this.buf.has(seq)) this.buf.set(seq, payload);
  }

  /** Called on a timer: give up on a gap that has lasted too long. */
  tick(): void {
    if (this.buf.size === 0) {
      this.gapSince = 0;
      return;
    }
    const t = this.now();
    if (this.gapSince === 0) {
      this.gapSince = t;
      return;
    }
    if (t - this.gapSince < GAP_SKIP_MS) return;
    let lowest = Infinity;
    for (const s of this.buf.keys()) if (s < lowest) lowest = s;
    this.lostBytes += (lowest - this.expect) * PAYLOAD;
    this.lostGaps++;
    this.expect = lowest;
    this.gapSince = 0;
    this.drain();
  }

  private drain(): void {
    for (;;) {
      const next = this.buf.get(this.expect);
      if (!next) return;
      this.buf.delete(this.expect);
      this.onData(next);
      this.expect++;
    }
  }
}

/**
 * Bind first, tune second: Windows rejects SO_RCVBUF/SO_SNDBUF on an unbound
 * socket with ENOTSOCK, and the callback keeps the tuning ahead of any traffic.
 */
function bindUdp(port: number, host: string | undefined, ready: () => void): UdpSocket {
  const s = createSocket('udp4');
  s.once('listening', () => {
    s.setRecvBufferSize(UDP_BUFS);
    s.setSendBufferSize(UDP_BUFS);
    ready();
  });
  s.bind(port, host);
  return s;
}

/** Pause the TCP source while the datagram send queue is backed up. */
function writeGuarded(
  sock: UdpSocket,
  buf: Buffer,
  pending: { bytes: number },
  src: Socket,
  peer: { host: string; port: number },
): void {
  pending.bytes += buf.length;
  if (pending.bytes > SEND_HIGH_WATER) src.pause();
  // Unconnected socket: the destination has to be passed on every send.
  sock.send(buf, peer.port, peer.host, (err) => {
    if (err) return;
    pending.bytes -= buf.length;
    if (pending.bytes < SEND_HIGH_WATER / 2) src.resume();
  });
}

if (mode === 'server') {
  const bind = parseAddr(opt('bind', '0.0.0.0:7002'));
  const udp = bindUdp(bind.port, bind.host, () => log(`listening udp ${bind.host}:${bind.port}`));
  const pending = { bytes: 0 };

  type Sess = { rinfo: RemoteInfo; tcp: Socket | null; txSeq: number; rx: Reassembler; rejections: number };
  const sessions = new Map<number, Sess>();

  const timer = setInterval(() => {
    const t = Date.now();
    for (const s of sessions.values()) s.rx.tick();
    if (pending.bytes === 0 && t === 0) return;
  }, 50);
  timer.unref();

  udp.on('message', (msg, rinfo) => {
    const f = parse(msg);
    if (!f) return;
    if (f.type === TYPE_SINK_REQ) {
      // Capacity mode: ignore every reliability concern and just blast.
      const total = f.payload.readUInt32BE(0);
      let sent = 0;
      let seq = 1;
      const chunk = Buffer.allocUnsafe(PAYLOAD);
      for (let i = 0; i < PAYLOAD; i++) chunk[i] = i & 0xff;
      const pump = (): void => {
        while (sent < total) {
          const n = Math.min(PAYLOAD, total - sent);
          udp.send(frame(TYPE_SINK_DATA, f.sid, seq++, chunk.subarray(0, n)), rinfo.port, rinfo.address);
          sent += n;
          if (udp.getSendQueueSize() > SEND_HIGH_WATER) {
            setTimeout(pump, 1);
            return;
          }
        }
      };
      pump();
      return;
    }

    if (f.type === TYPE_OPEN) {
      const existing = sessions.get(f.sid);
      if (existing) {
        existing.rinfo = rinfo;
        udp.send(frame(TYPE_OPEN_ACK, f.sid, 0, Buffer.alloc(0)), rinfo.port, rinfo.address);
        return;
      }
      const atyp = f.payload[0];
      let host: string;
      let at: number;
      if (atyp === 0x03) {
        const l = f.payload[1];
        host = f.payload.subarray(2, 2 + l).toString('utf8');
        at = 2 + l;
      } else {
        host = `${f.payload[1]}.${f.payload[2]}.${f.payload[3]}.${f.payload[4]}`;
        at = 5;
      }
      const port = f.payload.readUInt16BE(at);
      const sess: Sess = {
        rinfo,
        tcp: null,
        txSeq: 1,
        // Wired lazily: the reassembler exists before the TCP connection does.
        rx: new Reassembler((b) => sess.tcp?.write(b), Date.now),
        rejections: 0,
      };
      sessions.set(f.sid, sess);

      log(`open sid=${f.sid} -> ${host}:${port} from ${rinfo.address}:${rinfo.port}`);
      const up = connect({ host, port });
      up.setNoDelay(true);
      up.on('connect', () => {
        sess.tcp = up;
        log(`open sid=${f.sid} ok, ack sent`);
        udp.send(frame(TYPE_OPEN_ACK, f.sid, 0, Buffer.alloc(0)), rinfo.port, rinfo.address);
        up.on('data', (data: Buffer) => {
          for (let off = 0; off < data.length; off += PAYLOAD) {
            const part = data.subarray(off, Math.min(off + PAYLOAD, data.length));
            udp.send(frame(TYPE_DATA, f.sid, sess.txSeq++, part), sess.rinfo.port, sess.rinfo.address);
          }
        });
        up.on('close', () => {
          udp.send(frame(TYPE_CLOSE, f.sid, sess.txSeq, Buffer.alloc(0)), sess.rinfo.port, sess.rinfo.address);
          sessions.delete(f.sid);
        });
        up.on('error', () => sessions.delete(f.sid));
      });
      up.on('error', (e: Error) => {
        log(`open sid=${f.sid} failed: ${e.message}`);
        sessions.delete(f.sid);
      });
      return;
    }

    const sess = sessions.get(f.sid);
    if (!sess || !sess.tcp) return;
    sess.rinfo = rinfo;
    if (f.type === TYPE_DATA) {
      sess.rx.push(f.seq, f.payload);
    } else if (f.type === TYPE_CLOSE) {
      sess.tcp.end();
      sessions.delete(f.sid);
    }
  });
} else if (mode === 'client') {
  const listen = parseAddr(opt('listen', '127.0.0.1:1082'));
  const peer = parseAddr(opt('peer'));
  const pending = { bytes: 0 };
  // The SOCKS listener is started only once the datagram socket is tuned, so
  // the very first frame cannot race an untuned buffer.
  const udp = bindUdp(0, undefined, () => listenSocks());

  type Sess = { tcp: Socket; sid: number; txSeq: number; rx: Reassembler };
  const bySid = new Map<number, Sess>();

  const timer = setInterval(() => {
    for (const s of bySid.values()) s.rx.tick();
  }, 50);
  timer.unref();

  udp.on('message', (msg) => {
    const f = parse(msg);
    if (!f) return;
    const s = bySid.get(f.sid);
    if (!s) return;
    if (f.type === TYPE_DATA) s.rx.push(f.seq, f.payload);
    else if (f.type === TYPE_CLOSE) s.tcp.end();
  });

  function listenSocks(): void {
  createServer((sock) => {
    void (async () => {
      const req = await acceptSocks5(sock);
      if (!req) {
        sock.destroy();
        return;
      }
      if (req.cmd !== 0x01) {
        socksReply(sock, 0x07);
        sock.destroy();
        return;
      }
      const sid = randomBytes(4).readUInt32BE(0);
      const sess: Sess = {
        tcp: sock,
        sid,
        txSeq: 1,
        rx: new Reassembler((b) => sock.write(b), Date.now),
      };
      bySid.set(sid, sess);

      const open = frame(TYPE_OPEN, sid, 0, encodeTarget(req.target));
      const acked = await new Promise<boolean>((resolve) => {
        let tries = 0;
        const retry = setInterval(() => {
          if (tries++ >= OPEN_TRIES) {
            clearInterval(retry);
            resolve(false);
            return;
          }
          udp.send(open, peer.port, peer.host);
        }, OPEN_RETRY_MS);
        const onMsg = (m: Buffer): void => {
          const f = parse(m);
          if (f && f.sid === sid && f.type === TYPE_OPEN_ACK) {
            clearInterval(retry);
            udp.off('message', onMsg);
            resolve(true);
          }
        };
        udp.on('message', onMsg);
        udp.send(open, peer.port, peer.host);
      });

      if (!acked) {
        log(`open ${req.target.host}:${req.target.port} got no ack in ${OPEN_TRIES * OPEN_RETRY_MS}ms`);
        bySid.delete(sid);
        socksReply(sock, 0x04);
        sock.destroy();
        return;
      }
      socksReply(sock, 0x00);
      // PrefixedSocket.release() pauses the socket to avoid losing bytes
      // between the handshake reader and our own handler: resume it here.
      sock.resume();
      if (req.rest.length > 0) {
        for (let off = 0; off < req.rest.length; off += PAYLOAD) {
          const part = req.rest.subarray(off, Math.min(off + PAYLOAD, req.rest.length));
          writeGuarded(udp, frame(TYPE_DATA, sid, sess.txSeq++, part), pending, sock, peer);
        }
      }
      sock.on('data', (data: Buffer) => {
        for (let off = 0; off < data.length; off += PAYLOAD) {
          const part = data.subarray(off, Math.min(off + PAYLOAD, data.length));
          writeGuarded(udp, frame(TYPE_DATA, sid, sess.txSeq++, part), pending, sock, peer);
        }
      });
      sock.on('close', () => {
        udp.send(frame(TYPE_CLOSE, sid, sess.txSeq, Buffer.alloc(0)), peer.port, peer.host);
        bySid.delete(sid);
      });
      sock.on('error', () => bySid.delete(sid));
    })().catch(() => sock.destroy());
  }).listen(listen.port, listen.host, () => log(`socks5 ${listen.host}:${listen.port} -> udp ${peer.host}:${peer.port}`));
  }
} else if (mode === 'sink') {
  // Capacity mode: ask the far side for N bytes of pure UDP, count what shows
  // up. No TCP, no TLS, so this is the ceiling the path can offer.
  const peer = parseAddr(opt('peer'));
  const total = Number(opt('bytes', '67108864'));
  const sid = randomBytes(4).readUInt32BE(0);
  const seen = new Set<number>();
  let got = 0;
  const t0 = Date.now();

  const req = Buffer.alloc(4);
  req.writeUInt32BE(total >>> 0, 0);
  const sentAt = Date.now();
  const udp2 = bindUdp(0, undefined, () => {
    udp2.on('message', (m) => {
      const f = parse(m);
      if (!f || f.sid !== sid || f.type !== TYPE_SINK_DATA) return;
      if (seen.has(f.seq)) return;
      seen.add(f.seq);
      got += f.payload.length;
      if (got >= total || Date.now() - t0 > 60_000) {
        const dt = (Date.now() - t0) / 1000;
        log(`sink: ${got} B in ${dt.toFixed(2)}s = ${(got / dt / 1048576).toFixed(2)} MB/s ` +
          `unique=${seen.size} loss≈${(100 * (1 - got / total)).toFixed(1)}%`);
        process.exit(0);
      }
    });
    kick = setInterval(() => udp2.send(frame(TYPE_SINK_REQ, sid, 0, req), peer.port, peer.host), 300);
    udp2.send(frame(TYPE_SINK_REQ, sid, 0, req), peer.port, peer.host);
  });
  let kick: NodeJS.Timeout | undefined;
  setTimeout(() => {
    if (kick) clearInterval(kick);
    const dt = (Date.now() - sentAt) / 1000;
    log(`sink: timeout, got ${got} B in ${dt.toFixed(2)}s = ${(got / dt / 1048576).toFixed(2)} MB/s`);
    process.exit(1);
  }, 30_000);
} else {
  log('usage: udp-proxy.ts <client|server|sink> ...');
  process.exit(2);
}
