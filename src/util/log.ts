// Log sink for the CLI. Kept out of cli.ts so it can be tested directly: the
// data path logs thousands of lines per second, and losing the log file must
// never lose the tunnel.
import { appendFileSync, mkdirSync } from 'node:fs';
import { dirname } from 'node:path';

/** How long log lines may sit in memory before being written out. */
export const LOG_FLUSH_MS = 200;
/** Force a flush once this much text is buffered, so a crash loses little. */
export const LOG_FLUSH_BYTES = 64 * 1024;

export interface LoggerOptions {
  /** Called once if the log file becomes unwritable; never throws. */
  onLogFileError?: (message: string) => void;
}

/**
 * Batched logger. One synchronous write per line costs ~0.5 ms on Windows
 * (open+write+close per call), and at 2 000 segments/s that alone drops
 * throughput from 2.3 MB/s to 100 KB/s - a 22x loss that has nothing to do
 * with the protocol. Coalescing into LOG_FLUSH_MS / LOG_FLUSH_BYTES keeps
 * debug logging usable on the data path.
 *
 * Every write path is failure-tolerant. `appendFileSync` used to run raw
 * inside a setInterval callback, so a log file that became a directory (or hit
 * ENOSPC / EACCES after startup) threw an uncaught exception and killed the
 * tunnel - the one component whose failure must not affect the connection.
 */
export function makeLogger(level: string, logFile?: string, opts: LoggerOptions = {}): (line: string) => void {
  const rank: Record<string, number> = { debug: 10, info: 20, warn: 30, error: 40, off: 100 };
  const threshold = rank[level] ?? 20;
  if (threshold >= 100) return () => {};

  let pending: string[] = [];
  let pendingBytes = 0;
  let logFileBroken = false;

  const reportLogFileError = (e: unknown): void => {
    if (logFileBroken) return;
    logFileBroken = true;
    const msg = `WRN log file ${logFile} is unwritable (${(e as Error).message}); continuing without it`;
    opts.onLogFileError?.(msg);
    try { process.stderr.write(`${msg}\n`); } catch { /* console gone */ }
  };

  // Creating the directory can fail too (the parent is a file, a read-only
  // mount, a path under /proc). That must be an advisory like any other
  // write failure, not a startup exception that stops the tunnel from running.
  if (logFile) {
    try { mkdirSync(dirname(logFile), { recursive: true }); }
    catch (e) { reportLogFileError(e); }
  }

  const flush = (): void => {
    if (pending.length === 0) return;
    const text = pending.join('');
    pending = [];
    pendingBytes = 0;
    try { process.stderr.write(text); } catch { /* console gone: nothing to do */ }
    if (!logFile || logFileBroken) return;
    try {
      appendFileSync(logFile, text);
    } catch (e) {
      reportLogFileError(e);
    }
  };
  const timer = setInterval(flush, LOG_FLUSH_MS);
  timer.unref();
  process.on('exit', flush);

  return (line: string) => {
    // Explicit prefixes ('DBG ' / 'WRN ' / 'ERR ') win over the keyword guess
    // below, so CLI-level advisories are classified deterministically.
    const isDbg = line.startsWith('DBG ');
    const isWrn = line.startsWith('WRN ');
    const isErr = line.startsWith('ERR ');
    if (isDbg && threshold > 10) return;
    const sev = isDbg ? 10 : isErr ? 40 : isWrn ? 30 :
      /error|fail|refused|exhaust/i.test(line) ? 40 :
      /warn|reset|stale|dead/i.test(line) ? 30 : 20;
    if (sev < threshold) return;
    const tag = isDbg ? 'DEBUG' : sev >= 40 ? 'ERROR' : sev >= 30 ? 'WARN' : 'INFO';
    const body = isDbg || isWrn || isErr ? line.slice(4) : line;
    const text = `[${new Date().toISOString()}] ${tag} ${body}\n`;
    pending.push(text);
    pendingBytes += text.length;
    if (pendingBytes >= LOG_FLUSH_BYTES) flush();
  };
}
