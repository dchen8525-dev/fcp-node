import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import test from 'node:test';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const source = readFileSync(require.resolve('../desktop/electron/system-proxy.cjs'), 'utf8');
const userData = '/tmp/fcp-desktop-proxy-test';
const backupPath = require('node:path').join(userData, 'system-proxy-backup.json');

type ProxyState = { enable: number; server: string; override: string; pac: string };

function loadProxy(initial: ProxyState | null, backup?: string) {
  const files = new Map<string, string>();
  if (backup !== undefined) files.set(backupPath, backup);
  let registry = initial;
  const scripts: string[] = [];
  const fsMock = {
    existsSync: (p: string) => files.has(p),
    readFileSync: (p: string) => files.get(p),
    writeFileSync: (p: string, data: string) => { files.set(p, String(data)); },
    unlinkSync: (p: string) => { files.delete(p); },
  };
  const childMock = {
    spawnSync: (_file: string, args: string[]) => {
      const script = args.at(-1)!;
      scripts.push(script);
      if (script.includes('Get-ItemProperty')) {
        return registry
          ? { status: 0, stdout: `${JSON.stringify(registry)}\n` }
          : { status: 1, stdout: '' };
      }
      return { status: 0, stdout: 'OK\n' };
    },
  };
  const module = { exports: {} as Record<string, (...args: any[]) => any> };
  vm.runInNewContext(source, {
    module,
    exports: module.exports,
    require: (id: string) => {
      if (id === 'node:fs') return fsMock;
      if (id === 'node:child_process') return childMock;
      if (id === 'node:path') return require('node:path');
      throw new Error(`unexpected require: ${id}`);
    },
    process: { platform: 'win32' },
    console,
  });
  return {
    api: module.exports,
    files,
    scripts,
    setRegistry: (next: ProxyState | null) => { registry = next; },
  };
}

const original = { enable: 0, server: '', override: '<local>', pac: '' };
const applied = { enable: 1, server: '127.0.0.1:1080', override: '<local>', pac: '' };
const saved = JSON.stringify({ appliedAt: 1, server: applied.server, original });

test('DESKTOP PROXY: a hostile host is escaped inside the PowerShell literal', () => {
  const { api, scripts } = loadProxy(original);
  const host = "x'; Write-Output PWN; #";
  assert.equal(api.apply(userData, host, 1080).ok, true);
  assert.ok(scripts.some((s) => s.includes(
    `Set-ItemProperty -Path $k -Name ProxyServer   -Value 'x''; Write-Output PWN; #:1080' -Type String`,
  )));
});

test('DESKTOP PROXY: stale backups adopt the current user settings before applying', () => {
  const current = { enable: 1, server: 'proxy.example:8080', override: 'corp.local', pac: 'http://corp/pac' };
  const { api, files } = loadProxy(current, saved);
  assert.equal(api.apply(userData, '127.0.0.1', 1080).ok, true);
  const backup = JSON.parse(files.get(backupPath)!);
  assert.deepEqual(backup.original, current);
  assert.equal(backup.server, '127.0.0.1:1080');
});

test('DESKTOP PROXY: restore preserves user changes to bypass or PAC', () => {
  for (const changed of [
    { ...applied, override: 'corp.local' },
    { ...applied, pac: 'http://corp/pac' },
    { enable: 0, server: '', override: '<local>', pac: '' },
  ]) {
    const { api, files, scripts, setRegistry } = loadProxy(applied, saved);
    setRegistry(changed);
    const result = api.restore(userData, { onlyIfOurs: true });
    assert.equal(result.ok, true);
    assert.equal(result.skipped, true);
    assert.equal(files.has(backupPath), false);
    assert.equal(scripts.some((s) => s.includes('Set-ItemProperty')), false);
  }
});

test('DESKTOP PROXY: a failed registry read never causes a blind restore', () => {
  const { api, files, scripts } = loadProxy(null, saved);
  const result = api.restore(userData, { onlyIfOurs: true });
  assert.equal(result.ok, false);
  assert.equal(files.get(backupPath), saved);
  assert.equal(scripts.some((s) => s.includes('Set-ItemProperty')), false);
});

test('DESKTOP PROXY: malformed backups are rejected before changing the registry', () => {
  for (const backup of ['{', '{}', JSON.stringify({ server: applied.server })]) {
    const { api, scripts } = loadProxy(applied, backup);
    assert.equal(api.restore(userData).ok, false);
    assert.equal(api.apply(userData, '127.0.0.2', 1080).ok, false);
    assert.equal(scripts.some((s) => s.includes('Set-ItemProperty')), false);
  }
});
