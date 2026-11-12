// Plain TCP tunnel with a SOCKS5 front end.
//
// This is the baseline every "fast" UDP-based proxy gets compared against:
// one listening socket on the far side, one upstream TCP connection per
// client connection, bytes relayed verbatim. No muxing (muxing makes
// TCP-over-TCP worse, and would flatter the UDP side), no compression,
// no crypto, no Nagle.
//
//   node bench/tcp-proxy.ts server --bind=0.0.0.0:7001
//   node bench/tcp-proxy.ts client --listen=127.0.0.1:1081 --peer=144.34.186.164:7001

import { createServer, connect, type Socket } from 'node:net';
import { acceptSocks5, encodeTarget, PrefixedSocket, readTarget, socksReply } from './socks5.ts';

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
  process.stderr.write(`[tcp-proxy] ${line}\n`);
}

/** Copy one socket into another and half-close the peer when the source ends. */
function splice(a: Socket, b: Socket): void {
  a.pipe(b);
  b.pipe(a);
  const kill = (): void => {
    a.destroy();
    b.destroy();
  };
  a.on('error', kill);
  b.on('error', kill);
}

if (mode === 'server') {
  const bind = parseAddr(opt('bind', '0.0.0.0:7001'));
  let conns = 0;
  createServer((sock) => {
    sock.setNoDelay(true);
    const r = new PrefixedSocket(sock);
    void (async () => {
      const target = await readTarget(r);
      const up = connect({ host: target.host, port: target.port });
      up.setNoDelay(true);
      const rest = r.release();
      await new Promise<void>((res, rej) => {
        up.once('connect', res);
        up.once('error', rej);
      });
      if (rest.length > 0) up.write(rest);
      splice(sock, up);
      log(`#${++conns} -> ${target.host}:${target.port}`);
    })().catch((e: Error) => {
      log(`#${++conns} failed: ${e.message}`);
      sock.destroy();
    });
  }).listen(bind.port, bind.host, () => log(`listening tcp ${bind.host}:${bind.port}`));
} else if (mode === 'client') {
  const listen = parseAddr(opt('listen', '127.0.0.1:1081'));
  const peer = parseAddr(opt('peer'));
  let conns = 0;
  createServer((sock) => {
    void (async () => {
      const req = await acceptSocks5(sock);
      if (!req) {
        sock.destroy();
        return;
      }
      if (req.cmd !== 0x01) {
        socksReply(sock, 0x07); // command not supported
        sock.destroy();
        return;
      }
      const up = connect({ host: peer.host, port: peer.port });
      up.setNoDelay(true);
      up.on('error', () => {
        socksReply(sock, 0x05);
        sock.destroy();
      });
      await new Promise<void>((res) => up.once('connect', res));
      up.write(encodeTarget(req.target));
      if (req.rest.length > 0) up.write(req.rest);
      socksReply(sock, 0x00);
      splice(sock, up);
      log(`#${++conns} ${req.target.host}:${req.target.port}`);
    })().catch(() => sock.destroy());
  }).listen(listen.port, listen.host, () => log(`socks5 ${listen.host}:${listen.port} -> tcp ${peer.host}:${peer.port}`));
} else {
  log('usage: tcp-proxy.ts <client|server> --listen=H:P --peer=H:P | --bind=H:P');
  process.exit(2);
}
