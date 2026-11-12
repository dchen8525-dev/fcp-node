// SOCKS5 CONNECT server. Two jobs in this benchmark:
//   1. act as the remote half of the kcptun pair (kcptun only forwards ports,
//      it is not a SOCKS proxy, so it needs something to forward to);
//   2. act as the local front end of the TCP proxy when run on this side.
//
//   node bench/socks-server.ts --bind=127.0.0.1:1090

import { createServer, connect } from 'node:net';
import { acceptSocks5, socksReply } from './socks5.ts';

const argv = process.argv.slice(2);

function opt(name: string, fallback?: string): string {
  const hit = argv.find((a) => a.startsWith(`--${name}=`));
  if (hit) return hit.slice(name.length + 3);
  if (fallback !== undefined) return fallback;
  throw new Error(`--${name} is required`);
}

const bindArg = opt('bind', '127.0.0.1:1090');
const i = bindArg.lastIndexOf(':');
const host = bindArg.slice(0, i);
const port = Number(bindArg.slice(i + 1));

let conns = 0;

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
    const up = connect({ host: req.target.host, port: req.target.port });
    up.setNoDelay(true);
    up.on('error', () => {
      socksReply(sock, 0x05);
      sock.destroy();
    });
    await new Promise<void>((res) => up.once('connect', res));
    socksReply(sock, 0x00);
    if (req.rest.length > 0) up.write(req.rest);
    sock.pipe(up);
    up.pipe(sock);
    sock.on('error', () => up.destroy());
    up.on('error', () => sock.destroy());
    process.stderr.write(`[socks-server] #${++conns} ${req.target.host}:${req.target.port}\n`);
  })().catch(() => sock.destroy());
}).listen(port, host, () => process.stderr.write(`[socks-server] listening ${host}:${port}\n`));
