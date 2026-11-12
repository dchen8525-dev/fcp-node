// Local proxy entry codecs. Port of src/proxy/proxy_proto.{h,cc}.
// All multi-byte proxy fields are NETWORK order (BE). FCP OPEN is the first
// bytes of the tunnel stream, not a separate frame.

import {
  ATYP_IPV4, ATYP_DOMAIN, ATYP_IPV6,
  SOCKS5_VERSION, SOCKS5_METHOD_NO_AUTH, SOCKS5_METHOD_NONE, SOCKS5_CMD_CONNECT,
  SOCKS5_GREETING_REPLY_LEN, SOCKS5_REPLY_LEN, SOCKS5_MAX_GREETING_BYTES,
  SOCKS5_MAX_REQUEST_BYTES, SOCKS5_MAX_DOMAIN_LEN,
  HTTP_HEAD_MAX_BYTES, HTTP_MAX_HOST_LEN, HTTP_FORWARD_DEFAULT_PORT,
  OPEN_MAGIC, OPEN_VERSION, OPEN_KIND_OK, OPEN_KIND_ERR,
  OPEN_OK_LEN, OPEN_ERR_LEN, OPEN_MAX_BYTES, OPEN_MAX_ADDR_LEN,
  OpenError, type OpenErrorValue,
} from '../constants.ts';
import { getBe16, putBe16, bytesEqual } from '../wire.ts';

export interface ProxyTarget { atyp: number; addr: Buffer; port: number; }
export type ParseStatus = 'need_more' | 'ok' | 'malformed' | 'bad_magic' | 'bad_version'
  | 'bad_atyp' | 'bad_address' | 'command_not_supported' | 'method_not_allowed'
  | 'bad_request' | 'head_too_large';
export interface ParseResult<T = ProxyTarget> {
  status: ParseStatus; consumed: number; value?: T; extra?: Buffer;
}

export function atypValid(a: number): boolean { return a === ATYP_IPV4 || a === ATYP_DOMAIN || a === ATYP_IPV6; }
export function atypAddrLen(a: number): number { return a === ATYP_IPV4 ? 4 : a === ATYP_IPV6 ? 16 : 0; }
export function targetText(t: ProxyTarget): string {
  if (t.atyp === ATYP_DOMAIN) return `${t.addr.toString('latin1')}:${t.port}`;
  if (t.atyp === ATYP_IPV4) return `${[...t.addr].join('.')}:${t.port}`;
  return `[${t.addr.toString('hex')}]:${t.port}`;
}
function hostCharOk(c: number): boolean {
  return (c >= 0x61 && c <= 0x7a) || (c >= 0x41 && c <= 0x5a) ||
    (c >= 0x30 && c <= 0x39) || c === 0x2e || c === 0x2d || c === 0x5f;
}
function ipv6CharOk(c: number): boolean {
  return (c >= 0x30 && c <= 0x39) || (c >= 0x61 && c <= 0x66) ||
    (c >= 0x41 && c <= 0x46) || c === 0x3a || c === 0x2e;
}
function parsePort(p: Uint8Array, n: number): number {
  if (n === 0 || n > 5) return 0;
  let v = 0;
  for (let i = 0; i < n; ++i) {
    if (p[i] < 0x30 || p[i] > 0x39) return 0;
    v = v * 10 + (p[i] - 0x30);
  }
  return v === 0 || v > 65535 ? 0 : v;
}

// ---- SOCKS5 ----------------------------------------------------------------

export function socks5ParseGreeting(buf: Buffer): ParseResult<{ noAuth: boolean }> {
  if (buf.length === 0) return { status: 'need_more', consumed: 0 };
  if (buf[0] !== SOCKS5_VERSION) return { status: 'malformed', consumed: 0 };
  if (buf.length < 2) return { status: 'need_more', consumed: 0 };
  const n = buf[1];
  if (n === 0) return { status: 'malformed', consumed: 0 };
  if (buf.length < 2 + n) return { status: 'need_more', consumed: 0 };
  let noAuth = false;
  for (let i = 0; i < n; ++i) if (buf[2 + i] === SOCKS5_METHOD_NO_AUTH) { noAuth = true; break; }
  return { status: 'ok', consumed: 2 + n, value: { noAuth } };
}
export function socks5GreetingReply(accept: boolean): Buffer {
  return Buffer.from([SOCKS5_VERSION, accept ? SOCKS5_METHOD_NO_AUTH : SOCKS5_METHOD_NONE]);
}

export const Socks5Rep = {
  Succeeded: 0, GeneralFailure: 1, NotAllowed: 2, NetworkUnreachable: 3,
  HostUnreachable: 4, ConnectionRefused: 5, TtlExpired: 6,
  CommandNotSupported: 7, AtypNotSupported: 8,
} as const;

export function socks5ParseRequest(buf: Buffer): ParseResult<ProxyTarget> {
  if (buf.length === 0) return { status: 'need_more', consumed: 0 };
  const win = Math.min(buf.length, SOCKS5_MAX_REQUEST_BYTES);
  if (buf[0] !== SOCKS5_VERSION) return { status: 'malformed', consumed: 0 };
  if (win < 4) return { status: 'need_more', consumed: 0 };
  if (buf[1] !== SOCKS5_CMD_CONNECT) return { status: 'command_not_supported', consumed: 0 };
  if (buf[2] !== 0) return { status: 'malformed', consumed: 0 };
  const atyp = buf[3];
  if (!atypValid(atyp)) return { status: 'bad_atyp', consumed: 0 };
  let addrLen = atypAddrLen(atyp);
  let header = 4;
  if (atyp === ATYP_DOMAIN) {
    if (win < 5) return { status: 'need_more', consumed: 0 };
    addrLen = buf[4]; header = 5;
    if (addrLen === 0) return { status: 'malformed', consumed: 0 };
  }
  const total = header + addrLen + 2;
  if (win < total) return { status: 'need_more', consumed: 0 };
  if (atyp === ATYP_DOMAIN) {
    for (let i = 0; i < addrLen; ++i) if (!hostCharOk(buf[header + i])) return { status: 'malformed', consumed: 0 };
  }
  const port = getBe16(buf, header + addrLen);
  if (port === 0) return { status: 'malformed', consumed: 0 };
  return {
    status: 'ok', consumed: total,
    value: { atyp, addr: Buffer.from(buf.subarray(header, header + addrLen)), port },
  };
}
export function socks5Reply(rep: number): Buffer {
  const out = Buffer.alloc(SOCKS5_REPLY_LEN);
  out[0] = SOCKS5_VERSION; out[1] = rep; out[3] = ATYP_IPV4;
  return out;
}
export function socks5RepForOpenError(e: OpenErrorValue): number {
  switch (e) {
    case OpenError.Refused: return Socks5Rep.ConnectionRefused;
    case OpenError.Dns: return Socks5Rep.HostUnreachable;
    case OpenError.TargetTimeout: return Socks5Rep.TtlExpired;
    case OpenError.NotSupported: return Socks5Rep.AtypNotSupported;
    case OpenError.TooManySessions: return Socks5Rep.NotAllowed;
    default: return Socks5Rep.GeneralFailure;
  }
}

// ---- HTTP ------------------------------------------------------------------

export const HTTP_OK = Buffer.from('HTTP/1.1 200 Connection Established\r\n\r\n', 'latin1');
export const HTTP_BAD_REQUEST = Buffer.from('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n', 'latin1');
export const HTTP_BAD_GATEWAY = Buffer.from('HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n', 'latin1');
export const HTTP_METHOD_NOT_ALLOWED = Buffer.from(
  'HTTP/1.1 405 Method Not Allowed\r\nAllow: CONNECT\r\nConnection: close\r\n\r\n', 'latin1');
export const HTTP_HEAD_TOO_LARGE = Buffer.from(
  'HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\n\r\n', 'latin1');
export const HTTP_FORWARD_METHOD_NOT_ALLOWED = Buffer.from(
  'HTTP/1.1 405 Method Not Allowed\r\nAllow: CONNECT, GET, HEAD, POST, PUT, DELETE, OPTIONS, PATCH\r\nConnection: close\r\n\r\n', 'latin1');

function findHeadEnd(b: Buffer, win: number): number {
  for (let i = 0; i + 4 <= win; ++i) {
    if (b[i] === 13 && b[i + 1] === 10 && b[i + 2] === 13 && b[i + 3] === 10) return i;
  }
  return -1;
}
function findLineEnd(b: Buffer, win: number): number {
  for (let i = 0; i + 2 <= win; ++i) if (b[i] === 13 && b[i + 1] === 10) return i;
  return -1;
}
function splitRequestLine(b: Buffer, lineLen: number): string[] {
  const line = b.subarray(0, lineLen).toString('latin1');
  return line.trim().split(/\s+/);
}
function httpVersionOk(v: string): boolean { return /^HTTP\/1\.[01]$/.test(v); }

function parseAuthority(text: string, defaultPort: number): { host: string; port: number } | null {
  if (!text) return null;
  for (let i = 0; i < text.length; ++i) {
    const c = text.charCodeAt(i);
    if (c === 0x40 || c < 0x21 || c > 0x7e) return null;
  }
  let host = '', port = defaultPort;
  if (text[0] === '[') {
    const close = text.indexOf(']');
    if (close < 2) return null;
    host = text.slice(1, close);
    if (close + 1 < text.length) {
      if (text[close + 1] !== ':') return null;
      const p = parsePort(Buffer.from(text.slice(close + 2), 'latin1'), text.length - close - 2);
      if (!p) return null;
      port = p;
    }
    for (const ch of host) if (!ipv6CharOk(ch.charCodeAt(0))) return null;
  } else {
    const colons = [...text].filter((c) => c === ':').length;
    if (colons > 1) return null;
    if (colons === 1) {
      const idx = text.indexOf(':');
      host = text.slice(0, idx);
      const p = parsePort(Buffer.from(text.slice(idx + 1), 'latin1'), text.length - idx - 1);
      if (!p) return null;
      port = p;
    } else {
      host = text;
    }
    for (const ch of host) if (!hostCharOk(ch.charCodeAt(0))) return null;
  }
  if (!host || host.length > HTTP_MAX_HOST_LEN) return null;
  return { host, port };
}

export interface HttpConnectResult {
  target: ProxyTarget; consumed: number;
}
export function httpParseConnect(buf: Buffer): ParseResult<ProxyTarget> {
  const capped = buf.length >= HTTP_HEAD_MAX_BYTES;
  const win = capped ? HTTP_HEAD_MAX_BYTES : buf.length;
  const blank = findHeadEnd(buf, win);
  if (blank < 0) return { status: capped ? 'head_too_large' : 'need_more', consumed: 0 };
  const headLen = blank + 4;
  const lineEnd = findLineEnd(buf, headLen);
  if (lineEnd < 0 || lineEnd > blank) return { status: 'bad_request', consumed: 0 };
  const tok = splitRequestLine(buf, lineEnd);
  if (tok.length !== 3 || tok[0].toUpperCase() !== 'CONNECT' || !httpVersionOk(tok[2])) {
    return { status: 'method_not_allowed', consumed: 0 };
  }
  const auth = parseAuthority(tok[1], 0);
  if (!auth || !auth.port) return { status: 'bad_request', consumed: 0 };
  const addr = Buffer.from(auth.host, 'latin1');
  if (addr.length === 0 || addr.length > SOCKS5_MAX_DOMAIN_LEN) return { status: 'bad_request', consumed: 0 };
  return {
    status: 'ok', consumed: headLen,
    value: { atyp: ATYP_DOMAIN, addr, port: auth.port },
  };
}

export interface HttpForwardValue { target: ProxyTarget; rewrittenHead: Buffer; }
const FORWARD_METHODS = new Set(['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH']);

export function httpParseForward(buf: Buffer): ParseResult<HttpForwardValue> {
  const capped = buf.length >= HTTP_HEAD_MAX_BYTES;
  const win = capped ? HTTP_HEAD_MAX_BYTES : buf.length;
  const blank = findHeadEnd(buf, win);
  if (blank < 0) return { status: capped ? 'head_too_large' : 'need_more', consumed: 0 };
  const headLen = blank + 4;
  const lineEnd = findLineEnd(buf, headLen);
  if (lineEnd < 0) return { status: 'bad_request', consumed: 0 };
  const tok = splitRequestLine(buf, lineEnd);
  if (tok.length !== 3 || !FORWARD_METHODS.has(tok[0]) || !httpVersionOk(tok[2])) {
    return { status: 'method_not_allowed', consumed: 0 };
  }
  const url = tok[1];
  if (!url.startsWith('http://')) return { status: 'bad_request', consumed: 0 };
  const rest = url.slice(7);
  const slash = rest.indexOf('/');
  const authority = slash < 0 ? rest : rest.slice(0, slash);
  const path = slash < 0 ? '/' : rest.slice(slash);
  const auth = parseAuthority(authority, HTTP_FORWARD_DEFAULT_PORT);
  if (!auth) return { status: 'bad_request', consumed: 0 };
  const addr = Buffer.from(auth.host, 'latin1');
  if (!addr.length || addr.length > HTTP_MAX_HOST_LEN) return { status: 'bad_request', consumed: 0 };

  // Rewrite to origin-form, drop hop-by-hop headers, force Connection: close.
  const head = buf.subarray(0, headLen).toString('latin1');
  const lines = head.split('\r\n');
  const out: string[] = [`${tok[0]} ${path} ${tok[2]}`];
  for (let i = 1; i < lines.length; ++i) {
    const line = lines[i];
    if (!line) continue;
    const colon = line.indexOf(':');
    const name = colon < 0 ? line : line.slice(0, colon);
    const low = name.trim().toLowerCase();
    if (low === 'connection' || low === 'proxy-connection' || low === 'keep-alive' ||
        low === 'proxy-authenticate' || low === 'proxy-authorization' ||
        low === 'te' || low === 'trailer' || low === 'transfer-encoding' || low === 'upgrade') continue;
    out.push(line);
  }
  out.push('Connection: close', '', '');
  return {
    status: 'ok', consumed: headLen,
    value: {
      target: { atyp: ATYP_DOMAIN, addr, port: auth.port },
      rewrittenHead: Buffer.from(out.join('\r\n'), 'latin1'),
    },
  };
}

export function detectEntry(buf: Buffer): 'socks5' | 'connect' | 'forward' | 'need_more' | 'unknown' {
  if (buf.length === 0) return 'need_more';
  if (buf[0] === SOCKS5_VERSION) return 'socks5';
  const s = buf.subarray(0, Math.min(buf.length, 16)).toString('latin1');
  if (s.startsWith('CONNECT ')) return 'connect';
  if (/^[A-Z]+ /.test(s)) return 'forward';
  if (buf.length < 4) return 'need_more';
  return 'unknown';
}

// ---- FCP OPEN --------------------------------------------------------------

export function openWriteRequest(t: ProxyTarget): Buffer | null {
  if (!atypValid(t.atyp) || t.port === 0) return null;
  const fixed = atypAddrLen(t.atyp);
  if (t.addr.length === 0 || t.addr.length > OPEN_MAX_ADDR_LEN) return null;
  if (fixed !== 0 && t.addr.length !== fixed) return null;
  const out = Buffer.alloc(7 + t.addr.length + 2);
  OPEN_MAGIC.copy(out, 0);
  out[4] = OPEN_VERSION; out[5] = t.atyp; out[6] = t.addr.length;
  t.addr.copy(out, 7);
  putBe16(t.port, out, 7 + t.addr.length);
  return out;
}
export function openWriteOk(): Buffer {
  const out = Buffer.alloc(OPEN_OK_LEN);
  OPEN_MAGIC.copy(out, 0);
  out[4] = OPEN_VERSION; out[5] = OPEN_KIND_OK; out[6] = 0; out[7] = 0;
  return out;
}
export function openWriteErr(err: OpenErrorValue): Buffer {
  const out = Buffer.alloc(OPEN_ERR_LEN);
  OPEN_MAGIC.copy(out, 0);
  out[4] = OPEN_VERSION; out[5] = OPEN_KIND_ERR; out[6] = err;
  return out;
}
export function openParseRequest(buf: Buffer): ParseResult<ProxyTarget> {
  if (buf.length === 0) return { status: 'need_more', consumed: 0 };
  const win = Math.min(buf.length, OPEN_MAX_BYTES);
  const magicLen = Math.min(win, 4);
  if (!bytesEqual(OPEN_MAGIC, buf, magicLen)) return { status: 'bad_magic', consumed: 0 };
  if (win < 7) return { status: 'need_more', consumed: 0 };
  if (buf[4] !== OPEN_VERSION) return { status: 'bad_version', consumed: 0 };
  const atyp = buf[5];
  if (!atypValid(atyp)) return { status: 'bad_atyp', consumed: 0 };
  const addrLen = buf[6];
  if (addrLen === 0) return { status: 'bad_address', consumed: 0 };
  const fixed = atypAddrLen(atyp);
  if (fixed !== 0 && addrLen !== fixed) return { status: 'bad_address', consumed: 0 };
  const total = 7 + addrLen + 2;
  if (win < total) return { status: 'need_more', consumed: 0 };
  if (atyp === ATYP_DOMAIN) {
    for (let i = 0; i < addrLen; ++i) if (!hostCharOk(buf[7 + i])) return { status: 'bad_address', consumed: 0 };
  }
  const port = getBe16(buf, 7 + addrLen);
  if (port === 0) return { status: 'bad_address', consumed: 0 };
  return { status: 'ok', consumed: total, value: { atyp, addr: Buffer.from(buf.subarray(7, 7 + addrLen)), port } };
}
export function openParseReply(buf: Buffer): ParseResult<{ ok: boolean; err: OpenErrorValue }> {
  if (buf.length === 0) return { status: 'need_more', consumed: 0 };
  const magicLen = Math.min(buf.length, 4);
  if (!bytesEqual(OPEN_MAGIC, buf, magicLen)) return { status: 'bad_magic', consumed: 0 };
  if (buf.length < 7) return { status: 'need_more', consumed: 0 };
  if (buf[4] !== OPEN_VERSION) return { status: 'bad_version', consumed: 0 };
  const kind = buf[5];
  if (kind === OPEN_KIND_ERR) {
    return { status: 'ok', consumed: OPEN_ERR_LEN, value: { ok: false, err: buf[6] as OpenErrorValue } };
  }
  if (kind !== OPEN_KIND_OK) return { status: 'malformed', consumed: 0 };
  if (buf.length < OPEN_OK_LEN) return { status: 'need_more', consumed: 0 };
  if (buf[6] !== 0 || buf[7] !== 0) return { status: 'malformed', consumed: 0 };
  return { status: 'ok', consumed: OPEN_OK_LEN, value: { ok: true, err: 0 as OpenErrorValue } };
}

export { OPEN_OK_LEN, OPEN_ERR_LEN, OPEN_MAX_BYTES };
