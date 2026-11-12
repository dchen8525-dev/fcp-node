// Thin entry point: `node src/app/bench.ts [options]` (in-process loopback).
process.argv = [process.argv[0], process.argv[1], 'speedtest', ...process.argv.slice(2)];
await import('./cli.ts');
