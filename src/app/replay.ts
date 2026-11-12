// Thin entry point: `node src/app/replay.ts --trace=PREFIX`
process.argv = [process.argv[0], process.argv[1], 'replay', ...process.argv.slice(2)];
await import('./cli.ts');
