// Thin entry point: `node src/app/client.ts [options]`
process.argv = [process.argv[0], process.argv[1], 'client', ...process.argv.slice(2)];
await import('./cli.ts');
