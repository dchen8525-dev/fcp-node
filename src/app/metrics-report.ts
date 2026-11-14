// Thin entry point: `node src/app/metrics-report.ts --metrics=PREFIX`
process.argv = [process.argv[0], process.argv[1], 'metrics-report', ...process.argv.slice(2)];
await import('./cli.ts');
