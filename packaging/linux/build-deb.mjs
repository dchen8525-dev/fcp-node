// Build fcp-server_<version>_amd64.deb on any host (no dpkg, no nfpm).
//
// The package embeds the official Node.js linux-x64 runtime, because Debian 13
// ships Node 20 while this project needs >= 22.6. That makes the deb
// self-contained: `apt install ./fcp-server_x.y.z_amd64.deb` then
// `systemctl enable --now fcp-node`.
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  copyFileSync, existsSync, mkdirSync, readFileSync, renameSync, rmSync,
  statSync, writeFileSync,
} from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildDeb } from './deb.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..', '..');
const version = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).version;
const NODE_VERSION = process.env.FCP_NODE_VERSION || '22.22.2';
const cache = join(root, 'packaging', '.cache');
const stage = join(cache, `deb-stage-${version}`);
const outDir = join(root, 'dist');

function run(cmd, args, opts = {}) {
  process.stdout.write(`$ ${cmd} ${args.join(' ')}\n`);
  const r = spawnSync(cmd, args, { stdio: 'inherit', ...opts });
  if (r.error) throw r.error;
  if (r.status !== 0) throw new Error(`${cmd} exited with ${r.status}`);
}

async function download(url, dest) {
  if (existsSync(dest)) return dest;
  process.stdout.write(`downloading ${url}\n`);
  const tmp = `${dest}.part`;
  // curl streams to disk and survives the slow/flaky international routes this
  // project's build hosts sit behind. --speed-time/--speed-limit abort a dead
  // connection so --retry can resume it, instead of hanging for an hour.
  const curl = spawnSync('curl', ['-fL', '--connect-timeout', '20',
    '--speed-time', '30', '--speed-limit', '2048',
    '--retry', '5', '--retry-delay', '2', '--retry-all-errors',
    '--continue-at', '-', '-sS', '-o', tmp, url], { stdio: 'inherit' });
  if (curl.status !== 0) {
    const { createWriteStream } = await import('node:fs');
    const { pipeline } = await import('node:stream/promises');
    const { Readable } = await import('node:stream');
    const res = await fetch(url, { redirect: 'follow' });
    if (!res.ok) throw new Error(`GET ${url} -> ${res.status}`);
    await pipeline(Readable.fromWeb(res.body), createWriteStream(tmp));
  }
  renameSync(tmp, dest);
  return dest;
}

function sha256(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

// ---------------------------------------------------------------- inputs

rmSync(stage, { recursive: true, force: true });
mkdirSync(join(stage, 'opt', 'fcp-node', 'node', 'bin'), { recursive: true });
mkdirSync(join(stage, 'usr', 'share', 'doc', 'fcp-server'), { recursive: true });
mkdirSync(outDir, { recursive: true });

// Node.js: official tarball, verified against the published checksum list. A
// corrupted runtime inside a root-installed package is a silent failure worth
// ruling out. npmmirror is tried first because nodejs.org throttles hard from
// some networks; the checksum still comes from nodejs.org.
const nodeTgzName = `node-v${NODE_VERSION}-linux-x64.tar.gz`;
const nodeTgz = join(cache, nodeTgzName);
if (!existsSync(nodeTgz)) {
  try {
    await download(`https://npmmirror.com/mirrors/node/v${NODE_VERSION}/${nodeTgzName}`, nodeTgz);
  } catch (e) {
    process.stdout.write(`mirror failed (${e.message}); trying nodejs.org\n`);
    await download(`https://nodejs.org/dist/v${NODE_VERSION}/${nodeTgzName}`, nodeTgz);
  }
}

const sumsPath = join(cache, `SHASUMS256-${NODE_VERSION}.txt`);
await download(`https://nodejs.org/dist/v${NODE_VERSION}/SHASUMS256.txt`, sumsPath);
const want = readFileSync(sumsPath, 'utf8').split('\n')
  .map((l) => l.trim().split(/\s+/))
  .find((p) => p[1] === nodeTgzName)?.[0];
if (!want) throw new Error(`no checksum for ${nodeTgzName}`);
const got = sha256(nodeTgz);
if (got !== want) throw new Error(`checksum mismatch for ${nodeTgzName}: ${got} != ${want}`);
process.stdout.write(`node ${NODE_VERSION}: sha256 ok (${got})\n`);

const nodeRoot = `node-v${NODE_VERSION}-linux-x64`;
const nodeExtract = join(stage, '.nodedist');
mkdirSync(nodeExtract, { recursive: true });
// --force-local: GNU tar treats "D:\..." as a remote host spec without it;
// forward slashes also stop it from escaping the Windows path separators.
const fwd = (x) => x.replaceAll('\\', '/');
run('tar', ['--force-local', '-xzf', fwd(nodeTgz), '-C', fwd(nodeExtract),
  '--strip-components=1', `${nodeRoot}/bin/node`, `${nodeRoot}/LICENSE`]);
const binNode = join(stage, 'opt', 'fcp-node', 'node', 'bin', 'node');
renameSync(join(nodeExtract, 'bin', 'node'), binNode);
renameSync(join(nodeExtract, 'LICENSE'),
  join(stage, 'usr', 'share', 'doc', 'fcp-server', 'node-LICENSE'));
rmSync(nodeExtract, { recursive: true, force: true });

// Bundle the tunnel: one ESM file, node builtins external.
const serverEntry = join(root, 'src', 'app', 'server.ts');
const serverBundle = join(stage, 'opt', 'fcp-node', 'fcp-server.mjs');
const esbuildJs = join(root, 'desktop', 'node_modules', 'esbuild', 'bin', 'esbuild');
const esbuildArgs = [serverEntry, '--bundle', '--platform=node', '--format=esm',
  '--target=node22', '--packages=external', `--outfile=${serverBundle}`];
if (existsSync(esbuildJs)) {
  run(process.execPath, [esbuildJs, ...esbuildArgs]);
} else {
  const npx = process.platform === 'win32' ? 'npx.cmd' : 'npx';
  run(npx, ['--yes', 'esbuild@0.28.2', ...esbuildArgs], { shell: true });
}

// ---------------------------------------------------------------- package

const deb = buildDeb({
  package: 'fcp-server',
  version,
  arch: 'amd64',
  maintainer: 'dchen8525-dev <dchen8525-dev@users.noreply.github.com>',
  homepage: 'https://github.com/dchen8525-dev/fcp-node',
  section: 'net',
  priority: 'optional',
  depends: ['libc6', 'libstdc++6', 'libgcc-s1'],
  conffiles: ['/etc/fcp-node/server.conf'],
  scripts: {
    preinst: join(here, 'preinst'),
    postinst: join(here, 'postinst'),
    prerm: join(here, 'prerm'),
    postrm: join(here, 'postrm'),
  },
  description: [
    'FCP v7 UDP tunnel server',
    ' FCP v7 UDP tunnel server (AES-128-GCM, Reed-Solomon FEC, ARQ, BBR-lite).',
    ` Ships a bundled Node.js ${NODE_VERSION} runtime, an fcp-server launcher, a`,
    ' systemd unit and /etc/fcp-node/server.conf. The installer generates a random',
    ' PSK on first install and prints it once; both ends must use the same key.',
  ].join('\n'),
  files: [
    { path: 'opt/fcp-node/node/bin/node', src: binNode, mode: 0o755 },
    { path: 'opt/fcp-node/fcp-server.mjs', src: serverBundle, mode: 0o644 },
    { path: 'usr/bin/fcp-server', src: join(here, 'fcp-server'), mode: 0o755 },
    { path: 'usr/lib/systemd/system/fcp-node.service', src: join(here, 'fcp-node.service'), mode: 0o644 },
    // uid/gid 0 here; postinst chowns to root:fcp-node because the service
    // account's numeric gid is only known at install time.
    { path: 'etc/fcp-node/server.conf', src: join(here, 'server.conf'), mode: 0o640 },
    { path: 'usr/share/doc/fcp-server/README.md', src: join(root, 'README.md'), mode: 0o644 },
    { path: 'usr/share/doc/fcp-server/node-LICENSE',
      src: join(stage, 'usr', 'share', 'doc', 'fcp-server', 'node-LICENSE'), mode: 0o644 },
  ],
});

const debPath = join(outDir, `fcp-server_${version}_amd64.deb`);
writeFileSync(debPath, deb);
process.stdout.write(`\nartifact: ${debPath}\n`);
process.stdout.write(`size: ${(statSync(debPath).size / 1024 / 1024).toFixed(1)} MiB\n`);
process.stdout.write(`sha256: ${sha256(debPath)}\n`);
