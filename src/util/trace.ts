// JSONL controller trace: the writer used on the packet path, and the offline
// reader behind `replay`. Both halves live here so the file-naming rule and the
// matching rule cannot drift apart (they did: the reader looked for `c*` while
// the writer produced `c-client-*`).
//
// Nothing in this module may throw into the data path. A trace file is an
// observer; a full disk, a deleted directory or a closed stream must cost at
// most the trace lines, never the tunnel. That is why every entry point either
// swallows the failure or reports it once through `onProblem`.
import { createWriteStream, mkdirSync, readFileSync, readdirSync, statSync } from 'node:fs';
import type { WriteStream } from 'node:fs';
import { basename, dirname, join } from 'node:path';

export interface TraceSink {
  write: (line: string) => void;
  close: () => void;
}

/** Buffered bytes after which new lines are dropped instead of queued forever. */
export const TRACE_MAX_BUFFERED = 1 << 20;

export interface TraceWriterOptions {
  /** Called at most once for a fatal error, and once more at close if lines were dropped. */
  onProblem?: (message: string) => void;
}

const live = new Set<FileTrace>();

class FileTrace implements TraceSink {
  readonly file: string;
  private stream: WriteStream | null = null;
  private broken = false;
  private closed = false;
  private dropped = 0;
  private reported = false;
  private onProblem?: (message: string) => void;
  private resolveDone: () => void = () => {};
  readonly done: Promise<void>;

  constructor(file: string, opts: TraceWriterOptions = {}) {
    this.file = file;
    this.onProblem = opts.onProblem;
    this.done = new Promise<void>((resolve) => { this.resolveDone = resolve; });
    try {
      mkdirSync(dirname(file), { recursive: true });
      const stream = createWriteStream(file, { flags: 'a' });
      // Without this listener a failed open (ENOENT / EACCES / EISDIR) is an
      // unhandled 'error' event, which takes the whole process down on the
      // first handshake.
      stream.on('error', (e: NodeJS.ErrnoException) => this.fail(e));
      stream.on('close', () => this.settle());
      this.stream = stream;
      live.add(this);
    } catch (e) {
      this.fail(e as NodeJS.ErrnoException);
    }
  }

  private fail(e: NodeJS.ErrnoException): void {
    if (this.broken) return;
    this.broken = true;
    const why = e.code ? `${e.code}${e.path ? ` (${e.path})` : ''}` : e.message;
    if (!this.reported) {
      this.reported = true;
      this.onProblem?.(`trace ${this.file}: ${why}; tracing disabled for this session`);
    }
    this.settle();
  }

  private settle(): void {
    if (live.delete(this)) this.resolveDone();
  }

  // Arrow properties: the session stores `trace.write` as a bare callback.
  write = (line: string): void => {
    if (this.broken || this.closed || !this.stream) { ++this.dropped; return; }
    const stream = this.stream;
    if (stream.writableLength > TRACE_MAX_BUFFERED) {
      // A stalled disk must not turn into unbounded heap growth. Dropping the
      // newest lines keeps the newest state on disk (the useful half).
      ++this.dropped;
      return;
    }
    try {
      stream.write(line + '\n');
    } catch (e) {
      this.fail(e as NodeJS.ErrnoException);
    }
  };

  close = (): void => {
    if (this.closed) return; // double close used to reach stream.end() twice
    this.closed = true;
    if (this.dropped > 0 && !this.broken) {
      this.onProblem?.(`trace ${this.file}: dropped ${this.dropped} line(s), disk slower than the controller`);
    }
    if (!this.stream) { this.settle(); return; }
    try {
      this.stream.end();
    } catch {
      this.settle();
    }
  };
}

export function createTraceSink(file: string, opts: TraceWriterOptions = {}): TraceSink {
  return new FileTrace(file, opts);
}

/** Await every open trace file reaching 'close', so nothing is lost on shutdown. */
export async function flushTraces(timeoutMs = 2000): Promise<number> {
  const pending = [...live].map((t) => t.done);
  if (pending.length === 0) return 0;
  let timer: NodeJS.Timeout | undefined;
  const capped = new Promise<void>((resolve) => { timer = setTimeout(resolve, timeoutMs); });
  try {
    await Promise.race([Promise.all(pending).then(() => undefined), capped]);
  } finally {
    if (timer) clearTimeout(timer);
  }
  return live.size;
}

/** Number of trace files still open (tests use it to prove nothing leaked). */
export function openTraceCount(): number {
  return live.size;
}

function statOrNull(p: string): ReturnType<typeof statSync> | null {
  try { return statSync(p); } catch { return null; }
}

/**
 * `--metrics` takes a *prefix*, not a file name: the writer appends
 * `-client-<salt>.jsonl` / `-server-<salt>.jsonl`. A trailing `.jsonl` is
 * dropped so both spellings name the same set.
 */
export function normaliseTracePrefix(raw: string): string {
  const trimmed = raw.trim();
  if (!trimmed) throw new Error('--metrics expects a file prefix, got an empty value');
  const stripped = trimmed.replace(/\.jsonl$/i, '');
  if (statOrNull(stripped)?.isDirectory()) throw new Error(directoryHint(trimmed, stripped));
  return stripped;
}

/**
 * A directory is the near-miss users actually type, so name the prefixes that
 * are sitting inside it instead of only saying "wrong again".
 */
function directoryHint(shown: string, dir: string): string {
  const sep = dir.includes('/') ? '/' : '\\';
  const head = dir.replace(/[\\/]+$/, '');
  const found = new Set<string>();
  try {
    for (const f of readdirSync(dir)) {
      const m = /^(.+)-(?:client|server)-[0-9a-f]+\.jsonl$/.exec(f);
      if (m) found.add(`${head}${sep}${m[1]}`);
    }
  } catch { /* unreadable directory: fall back to the generic message */ }
  const examples = [...found].sort().slice(0, 3);
  const tail = examples.length
    ? `did you mean ${examples.map((p) => `--metrics=${p}`).join(' or ')}?`
    : `use --trace=${head}${sep}name`;
  return `--metrics=${shown} is a directory, not a file prefix; ${tail}`;
}

/**
 * Resolve a prefix to the trace files it names. The directory comes from the
 * prefix itself — listing the current directory instead silently found nothing
 * for any absolute path.
 */
export function resolveTraceFiles(raw: string): string[] {
  const trimmed = raw.trim();
  if (!trimmed) throw new Error('--metrics expects a file prefix, got an empty value');
  // An explicit file name wins over the prefix interpretation, and has to be
  // tested before normalisation strips its `.jsonl` suffix.
  const asGiven = statOrNull(trimmed);
  if (asGiven?.isFile()) return [trimmed];
  if (asGiven?.isDirectory()) throw new Error(directoryHint(trimmed, trimmed));
  const prefix = normaliseTracePrefix(trimmed);
  const dir = dirname(prefix);
  const base = basename(prefix);
  if (!statOrNull(dir)?.isDirectory()) {
    throw new Error(`--metrics=${raw}: directory ${dir} does not exist, so no metrics can be there`);
  }
  // Match `<base>-…`, not `<base>*`: a prefix of "c" used to pull in
  // cache.jsonl and cfg.jsonl as if they were part of this run.
  return readdirSync(dir)
    .filter((f) => f.startsWith(`${base}-`) && f.endsWith('.jsonl'))
    .sort()
    .map((f) => join(dir, f));
}

export interface TraceSummary {
  files: number;
  events: number;
  malformed: number;
  kinds: Map<string, number>;
}

export function summariseTrace(files: string[]): TraceSummary {
  const kinds = new Map<string, number>();
  let events = 0;
  let malformed = 0;
  for (const f of files) {
    let text: string;
    try {
      text = readFileSync(f, 'utf8');
    } catch {
      ++malformed; // vanished between listing and reading
      continue;
    }
    for (const line of text.split(/\r?\n/)) {
      if (!line.trim()) continue;
      let obj: { t?: unknown } | null = null;
      try { obj = JSON.parse(line) as { t?: unknown }; } catch { ++malformed; continue; }
      // A half-written last line from a killed process lands here, so the count
      // is reported instead of being silently folded away.
      const k = typeof obj?.t === 'string' ? obj.t : 'unknown';
      kinds.set(k, (kinds.get(k) ?? 0) + 1);
      ++events;
    }
  }
  return { files: files.length, events, malformed, kinds };
}
