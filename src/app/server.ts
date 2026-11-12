// Thin entry point: `node src/app/server.ts [options]`
process.argv = [process.argv[0], process.argv[1], 'server', ...process.argv.slice(2)];
await import('./cli.ts');
