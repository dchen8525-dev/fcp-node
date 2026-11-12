// Bundle the zero-dependency TypeScript tunnel into one ESM file the Electron
// runtime can execute as a plain Node process (ELECTRON_RUN_AS_NODE=1).
//
// The desktop shell deliberately does not import the tunnel into the renderer
// or the main process: a tunnel is a long-lived blocking event loop, and a
// crash there must not take the window with it. It runs as a child process
// exactly like the C++ Qt shell runs fcp-client.
import { build } from 'esbuild';
import { mkdirSync, statSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, '..', '..');
const outfile = resolve(here, '..', 'resources', 'cli.mjs');

mkdirSync(dirname(outfile), { recursive: true });

const result = await build({
  entryPoints: [resolve(root, 'src', 'app', 'cli.ts')],
  outfile,
  bundle: true,
  platform: 'node',
  format: 'esm',
  target: 'node22',
  // node: builtins stay external; everything else is in the bundle.
  packages: 'external',
  logLevel: 'info',
  metafile: false,
});

const bytes = statSync(outfile).size;
process.stdout.write(`tunnel bundle: ${outfile} (${(bytes / 1024).toFixed(1)} KiB)\n`);
