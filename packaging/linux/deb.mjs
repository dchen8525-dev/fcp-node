// Minimal .deb writer: ar(1) archive + gzip'd control/data tarballs.
//
// dpkg only requires the three ar members (debian-binary, control.tar.gz,
// data.tar.gz). Writing them here keeps the release build free of nfpm/dpkg
// downloads, which matters on hosts where GitHub's asset CDN is unreachable.
import { createHash } from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';
import { gzipSync } from 'node:zlib';

const BLOCK = 512;

function octal(value, width) {
  // width includes the trailing NUL byte.
  return value.toString(8).padStart(width - 1, '0') + '\0';
}

function tarHeader({ name, mode, size, uid = 0, gid = 0, mtime = 0, type = '0', uname = 'root', gname = 'root' }) {
  if (Buffer.byteLength(name) > 100) throw new Error(`tar name too long: ${name}`);
  const h = Buffer.alloc(BLOCK, 0);
  h.write(name, 0, 100, 'utf8');
  h.write(octal(mode, 8), 100, 8, 'ascii');
  h.write(octal(uid, 8), 108, 8, 'ascii');
  h.write(octal(gid, 8), 116, 8, 'ascii');
  h.write(octal(size, 12), 124, 12, 'ascii');
  h.write(octal(mtime, 12), 136, 12, 'ascii');
  h.fill(0x20, 148, 156);             // checksum field: spaces while summing
  h.write(type, 156, 1, 'ascii');
  h.write('ustar\0', 257, 6, 'ascii');
  h.write('00', 263, 2, 'ascii');
  h.write(uname, 265, 32, 'utf8');
  h.write(gname, 297, 32, 'utf8');
  h.write(octal(0, 8), 329, 8, 'ascii');
  h.write(octal(0, 8), 337, 8, 'ascii');

  let sum = 0;
  for (const byte of h) sum += byte;
  h.write(sum.toString(8).padStart(6, '0') + '\0 ', 148, 8, 'ascii');
  return h;
}

function padToBlock(buf) {
  const rem = buf.length % BLOCK;
  return rem === 0 ? buf : Buffer.concat([buf, Buffer.alloc(BLOCK - rem, 0)]);
}

/**
 * @param {{path: string, src?: string, data?: Buffer, mode?: number,
 *          uid?: number, gid?: number, dir?: boolean}[]} entries
 *        `path` is relative to the archive root, without a leading "./".
 * @returns {Buffer} uncompressed tar
 */
export function makeTar(entries) {
  const parts = [];
  for (const e of entries) {
    const path = './' + e.path.replaceAll('\\', '/');
    if (e.dir) {
      parts.push(tarHeader({ name: path.replace(/\/?$/, '/'), mode: e.mode ?? 0o755, size: 0, uid: e.uid, gid: e.gid, type: '5' }));
      continue;
    }
    const data = e.data ?? readFileSync(e.src);
    parts.push(tarHeader({ name: path, mode: e.mode ?? 0o644, size: data.length, uid: e.uid, gid: e.gid }));
    parts.push(padToBlock(data));
  }
  parts.push(Buffer.alloc(BLOCK * 2, 0));
  return Buffer.concat(parts);
}

function arHeader(name, size) {
  const h = Buffer.alloc(60, 0x20);
  h.write(name.padEnd(16, ' '), 0, 16, 'ascii');
  h.write('0'.padEnd(12, ' '), 16, 12, 'ascii');          // mtime
  h.write('0'.padEnd(6, ' '), 28, 6, 'ascii');            // uid
  h.write('0'.padEnd(6, ' '), 34, 6, 'ascii');            // gid
  h.write('100644'.padEnd(8, ' '), 40, 8, 'ascii');       // mode
  h.write(String(size).padEnd(10, ' '), 48, 10, 'ascii');
  h.write('`\n', 58, 2, 'ascii');
  return h;
}

function arMember(name, data) {
  const h = arHeader(name, data.length);
  const body = data.length % 2 === 0 ? data : Buffer.concat([data, Buffer.from('\n')]);
  return Buffer.concat([h, body]);
}

function md5(buf) {
  return createHash('md5').update(buf).digest('hex');
}

/**
 * Build a binary deb.
 *
 * @param {object} opts
 * @param {string} opts.package      e.g. "fcp-server"
 * @param {string} opts.version
 * @param {string} opts.arch         e.g. "amd64"
 * @param {string} opts.maintainer
 * @param {string} opts.description  full Description paragraph (continuation lines
 *                                   already prefixed with a single space)
 * @param {string} [opts.section]
 * @param {string} [opts.priority]
 * @param {string} [opts.homepage]
 * @param {string} [opts.license]
 * @param {string[]} [opts.depends]
 * @param {string[]} [opts.conffiles]
 * @param {Record<string, string>} [opts.scripts]  name -> local path
 * @param {Array} opts.files         entries for makeTar()
 */
export function buildDeb(opts) {
  const {
    package: pkg, version, arch, maintainer, description,
    section = 'net', priority = 'optional', homepage, license,
    depends = [], conffiles = [], scripts = {}, files = [],
  } = opts;

  const installedSize = Math.ceil(
    files.filter((f) => !f.dir)
      .reduce((n, f) => n + (f.data ? f.data.length : statSync(f.src).size), 0) / 1024,
  );

  const lines = [
    `Package: ${pkg}`,
    `Version: ${version}`,
    `Architecture: ${arch}`,
    `Maintainer: ${maintainer}`,
    `Installed-Size: ${installedSize}`,
    `Depends: ${depends.join(', ')}`,
    `Section: ${section}`,
    `Priority: ${priority}`,
  ];
  if (homepage) lines.push(`Homepage: ${homepage}`);
  if (license) lines.push(`License: ${license}`);
  lines.push(`Description: ${description}`);
  const control = lines.join('\n') + '\n';

  const md5sums = files.filter((f) => !f.dir)
    .map((f) => `${md5(f.data ?? readFileSync(f.src))}  ${f.path.replaceAll('\\', '/')}`)
    .join('\n') + '\n';

  const controlEntries = [
    { path: 'control', data: Buffer.from(control, 'utf8'), mode: 0o644 },
    { path: 'md5sums', data: Buffer.from(md5sums, 'utf8'), mode: 0o644 },
  ];
  if (conffiles.length) {
    controlEntries.push({
      path: 'conffiles',
      data: Buffer.from(conffiles.join('\n') + '\n', 'utf8'),
      mode: 0o644,
    });
  }
  for (const [name, src] of Object.entries(scripts)) {
    // dpkg runs these with sh; keep the executable bit.
    controlEntries.push({ path: name, src, mode: 0o755 });
  }

  // Directory entries are optional for dpkg but make the archive readable and
  // give parent directories a deterministic mode.
  const dirs = new Set();
  for (const f of files) {
    const parts = f.path.replaceAll('\\', '/').split('/');
    for (let i = 1; i < parts.length; i++) dirs.add(parts.slice(0, i).join('/'));
  }
  const dataEntries = [
    ...[...dirs].sort().map((path) => ({ path, dir: true, mode: 0o755, uid: 0, gid: 0 })),
    ...files,
  ];

  const debianBinary = Buffer.from('2.0\n', 'utf8');
  const controlTarGz = gzipSync(makeTar(controlEntries), { level: 9 });
  const dataTarGz = gzipSync(makeTar(dataEntries), { level: 9 });

  return Buffer.concat([
    Buffer.from('!<arch>\n', 'ascii'),
    arMember('debian-binary', debianBinary),
    arMember('control.tar.gz', controlTarGz),
    arMember('data.tar.gz', dataTarGz),
  ]);
}
