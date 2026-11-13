// Entry point for the standalone fcp-client.exe (Node SEA).
//
// Same as src/app/client.ts, but written without top-level await so esbuild can
// emit a CommonJS bundle: Node SEA in Node 22/24 only loads a CommonJS main
// script. The dynamic import stays where it is, so process.argv is rewritten
// before cli.ts runs its argument parser.
process.argv = [process.argv[0], process.argv[1], 'client', ...process.argv.slice(2)];
void import('../../src/app/cli.ts');
