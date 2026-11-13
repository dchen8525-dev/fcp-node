// Build a standalone Windows fcp-client.exe with Node's Single Executable
// Application pipeline: bundle -> SEA blob -> copy node.exe -> inject blob.
//
// The result needs no Node installation and behaves like `fcp-client` from the
// C++ tree: `fcp-client.exe --key=... --peer=... -b 127.0.0.1:1080`.
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  copyFileSync, existsSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync,
} from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..', '..');
const version = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).version;
const POSTJECT_VERSION = process.env.FCP_POSTJECT_VERSION || '1.0.0-alpha.6';
const cache = join(root, 'packaging', '.cache');
const stage = join(cache, `sea-${version}`);
const outDir = join(root, 'dist');
const outExe = join(outDir, `fcp-client-${version}.exe`);

function run(cmd, args, opts = {}) {
  process.stdout.write(`$ ${cmd} ${args.join(' ')}\n`);
  const r = spawnSync(cmd, args, { stdio: 'inherit', ...opts });
  if (r.error) throw r.error;
  if (r.status !== 0) throw new Error(`${cmd} exited with ${r.status}`);
  return r;
}

function sha256(path) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

rmSync(stage, { recursive: true, force: true });
mkdirSync(stage, { recursive: true });
mkdirSync(outDir, { recursive: true });

// 1. Bundle the CLI as CommonJS (SEA's main script format).
const bundle = join(stage, 'client.cjs');
const esbuildJs = join(root, 'desktop', 'node_modules', 'esbuild', 'bin', 'esbuild');
const esbuildArgs = [join(here, 'client-entry.ts'), '--bundle', '--platform=node',
  '--format=cjs', '--target=node22', '--packages=external', `--outfile=${bundle}`];
if (existsSync(esbuildJs)) {
  run(process.execPath, [esbuildJs, ...esbuildArgs]);
} else {
  const npx = process.platform === 'win32' ? 'npx.cmd' : 'npx';
  run(npx, ['--yes', 'esbuild@0.28.2', ...esbuildArgs], { shell: true });
}

// 2. Emit the SEA preparation blob with the locally installed node.exe.
const seaConfig = join(stage, 'sea-config.json');
writeFileSync(seaConfig, JSON.stringify({
  main: bundle,
  output: join(stage, 'sea-prep.blob'),
  disableExperimentalSEAWarning: true,
  useSnapshot: false,
  useCodeCache: true,
}, null, 2));
run(process.execPath, ['--experimental-sea-config', seaConfig]);

// 3. Copy node.exe and inject the blob.
copyFileSync(process.execPath, outExe);
const postject = process.platform === 'win32' ? 'npx.cmd' : 'npx';
run(postject, ['--yes', `postject@${POSTJECT_VERSION}`, outExe, 'NODE_SEA_BLOB',
  join(stage, 'sea-prep.blob'),
  '--sentinel-fuse', 'NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2'],
{ shell: true });

// 4. Smoke test: the exe must print the CLI usage with the right version.
const smoke = spawnSync(outExe, ['-h'], { encoding: 'utf8' });
if (smoke.status !== 0) throw new Error(`fcp-client.exe -h exited ${smoke.status}: ${smoke.stderr}`);
if (!smoke.stdout.includes(`FCP ${version}`)) {
  throw new Error(`fcp-client.exe -h did not report version ${version}:\n${smoke.stdout.slice(0, 200)}`);
}
process.stdout.write(`smoke: fcp-client.exe -h -> FCP ${version}\n`);

process.stdout.write(`\nartifact: ${outExe}\n`);
process.stdout.write(`size: ${(statSync(outExe).size / 1024 / 1024).toFixed(1)} MiB\n`);
process.stdout.write(`sha256: ${sha256(outExe)}\n`);
