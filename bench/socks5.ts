// Minimal SOCKS5 (CONNECT only) parser shared by the two reference proxies.
// Deliberately no UDP ASSOCIATE, no auth, no BIND: the point of these proxies
// is to be the dumbest possible baseline, so anything extra would be a
// deviation from what is being measured.

import type { Socket } from 'node:net';

export type Target = { host: string; port: number };

/** Buffered reader that can hand the untouched tail back to the socket. */
export class PrefixedSocket {
  private q: Buffer[] = [];
  private size = 0;
  private waiting: { need: number; resolve: (b: Buffer) => void; reject: (e: Error) => void } | null = null;
  private closed = false;
  private readonly onData: (d: Buffer) => void;
  private readonly sock: Socket;

  constructor(sock: Socket) {
    this.sock = sock;
    this.onData = (d: Buffer): void => {
      this.q.push(d);
      this.size += d.length;
      this.pump();
    };
    sock.on('data', this.onData);
    sock.on('close', () => {
      this.closed = true;
      this.waiting?.reject(new Error('socket closed during handshake'));
      this.waiting = null;
    });
  }

  private pump(): void {
    const w = this.waiting;
    if (!w || this.size < w.need) return;
    this.waiting = null;
    w.resolve(this.take(w.need));
  }

  private take(n: number): Buffer {
    const all = this.q.length === 1 ? this.q[0] : Buffer.concat(this.q, this.size);
    const head = all.subarray(0, n);
    const tail = all.subarray(n);
    this.q = tail.length > 0 ? [tail] : [];
    this.size = tail.length;
    return head;
  }

  async read(n: number): Promise<Buffer> {
    if (this.size >= n) return this.take(n);
    if (this.closed) throw new Error('socket closed');
    return new Promise<Buffer>((resolve, reject) => {
      this.waiting = { need: n, resolve, reject };
    });
  }

  /** Detach and return whatever is still buffered, so the caller can pipe. */
  release(): Buffer {
    this.sock.off('data', this.onData);
    this.sock.pause();
    const rest = this.size > 0 ? Buffer.concat(this.q, this.size) : Buffer.alloc(0);
    this.q = [];
    this.size = 0;
    return rest;
  }
}

export type SocksRequest = { cmd: number; target: Target; rest: Buffer };

export function socksReply(sock: Socket, rep: number): void {
  sock.write(Buffer.from([0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
}

/** Returns null when the peer is not speaking SOCKS5 or asks for what we refuse. */
export async function acceptSocks5(sock: Socket): Promise<SocksRequest | null> {
  sock.setNoDelay(true);
  const r = new PrefixedSocket(sock);
  try {
    const head = await r.read(2);
    if (head[0] !== 0x05) return null;
    await r.read(head[1]); // offered methods; we only ever answer "no auth"
    sock.write(Buffer.from([0x05, 0x00]));

    const req = await r.read(4);
    if (req[0] !== 0x05) return null;
    const cmd = req[1];
    const atyp = req[3];
    let host: string;
    if (atyp === 0x01) {
      const b = await r.read(4);
      host = `${b[0]}.${b[1]}.${b[2]}.${b[3]}`;
    } else if (atyp === 0x03) {
      const l = (await r.read(1))[0];
      host = (await r.read(l)).toString('utf8');
    } else if (atyp === 0x04) {
      const b = await r.read(16);
      const g: string[] = [];
      for (let i = 0; i < 16; i += 2) g.push(((b[i] << 8) | b[i + 1]).toString(16));
      host = g.join(':');
    } else {
      return null;
    }
    const pb = await r.read(2);
    const port = (pb[0] << 8) | pb[1];
    const rest = r.release();
    return { cmd, target: { host, port }, rest };
  } catch {
    return null;
  }
}

/** Wire form of a target: strlen-free, address-family tagged. */
export function encodeTarget(t: Target): Buffer {
  const host = Buffer.from(t.host, 'utf8');
  const buf = Buffer.alloc(2 + host.length + 2);
  buf[0] = 0x03;
  buf[1] = host.length;
  host.copy(buf, 2);
  buf.writeUInt16BE(t.port, 2 + host.length);
  return buf;
}

/** Reads an encodeTarget() header from a stream. */
export async function readTarget(r: PrefixedSocket): Promise<Target> {
  const atyp = (await r.read(1))[0];
  let host: string;
  if (atyp === 0x01) {
    const b = await r.read(4);
    host = `${b[0]}.${b[1]}.${b[2]}.${b[3]}`;
  } else if (atyp === 0x03) {
    const l = (await r.read(1))[0];
    host = (await r.read(l)).toString('utf8');
  } else {
    throw new Error(`unsupported atyp ${atyp}`);
  }
  const p = await r.read(2);
  return { host, port: (p[0] << 8) | p[1] };
}
