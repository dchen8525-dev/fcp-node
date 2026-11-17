// Black-box tests for the CLI failure contract.
//
// cli.ts exports nothing and is an entrypoint: the only honest way to test its
// argument parsing is to run it. Every case here is a REJECTED argument, so the
// process fails in main() before it can bind a socket or block on a tunnel —
// no port is ever opened and no key material is ever needed beyond a dummy.
//
// The assertion is the contract users actually see: non-zero exit plus a
// specific `fcp: ...` line on stderr. "Silently fell back to the default" is
// the bug class these cases pin down; that failure mode exits 0, so it cannot
// hide behind a matching message.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const CLI = fileURLToPath(new URL('../src/app/cli.ts', import.meta.url));
const KEY = '11c10975740b454b247adc95637e1c9a'; // 32 hex chars, dummy PSK

function run(args: string[]) {
  return spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', timeout: 15000 });
}

/** Assert the CLI rejected the invocation with the expected diagnostic. */
function expectReject(args: string[], message: RegExp): void {
  const r = run(args);
  assert.notEqual(r.status, 0, `expected rejection, exited 0: ${args.join(' ')}\n${r.stdout}`);
  const err = r.stderr ?? '';
  assert.match(err, /^fcp: /, `error must be prefixed (args: ${args.join(' ')})`);
  assert.match(err, message, `wrong diagnostic for: ${args.join(' ')}\nstderr: ${err}`);
}

// --- key ------------------------------------------------------------------

test('CLI: --key missing fails loudly', () => {
  expectReject(['server'], /--key is required/);
});

test('CLI: a short key, a long key, and non-hex all fail with the length-safe message', () => {
  expectReject(['server', '--key=abcd'], /32 hex chars.*got 4 char/);
  expectReject(['server', `--key=${KEY}00`], /32 hex chars.*got 34 char/);
  expectReject(['server', '--key=' + 'z'.repeat(32)], /32 hex chars/);
});

test('CLI: a malformed key never echoes its value back to stderr', () => {
  const secret = 'deadbeefdeadbeefdeadbeefdeadbeef';
  const r = run(['server', `--key=${secret}ZZ`]);
  assert.notEqual(r.status, 0);
  assert.match(r.stderr ?? '', /32 hex chars/);
  assert.ok(!(r.stderr ?? '').includes('ZZ'), 'must not echo the malformed secret');
});

test('CLI: -k is rejected with the inline-key replacement spelled out', () => {
  expectReject(['server', '-k', 'somefile'], /-k is no longer accepted.*--key=HEX32/);
});

// --- host:port ------------------------------------------------------------

test('CLI: an out-of-range or non-numeric port fails instead of using the default', () => {
  expectReject(['server', `--key=${KEY}`, '--bind=0.0.0.0:0'], /invalid port "0".*1\.\.65535/);
  expectReject(['server', `--key=${KEY}`, '--bind=0.0.0.0:65536'], /invalid port "65536"/);
  expectReject(['server', `--key=${KEY}`, '--bind=0.0.0.0:abc'], /invalid port "abc"/);
});

test('CLI: bracketed IPv6 with a bad close or a missing colon fails loudly', () => {
  expectReject(['server', `--key=${KEY}`, '--bind=[::1'], /missing ']'/);
  expectReject(['server', `--key=${KEY}`, '--bind=[::1]4460'], /expected ":port" after ']'/);
});

test('CLI: client without --peer fails instead of starting with an empty remote', () => {
  expectReject(['client', `--key=${KEY}`], /client requires --peer/);
});

// --- numeric options ------------------------------------------------------

test('CLI: integer options reject out-of-range and non-integer values', () => {
  expectReject(['server', `--key=${KEY}`, '--mtu-min=127'], /--mtu-min expects an integer in 128\.\.9000/);
  expectReject(['server', `--key=${KEY}`, '--mtu-min=9001'], /--mtu-min expects an integer in 128\.\.9000/);
  expectReject(['server', `--key=${KEY}`, '--mtu-min=abc'], /--mtu-min expects an integer/);
  expectReject(['speedtest', `--key=${KEY}`, '--mtu-min=1.5'], /--mtu-min expects an integer/);
});

test('CLI: --fec rejects a malformed shape, an oversized D, and an out-of-range P', () => {
  expectReject(['server', `--key=${KEY}`, '--fec=10'], /--fec expects D:P/);
  expectReject(['server', `--key=${KEY}`, '--fec=257:6'], /--fec out of range/);
  expectReject(['server', `--key=${KEY}`, '--fec=10:8'], /--fec out of range/);
  expectReject(['server', `--key=${KEY}`, '--fec=250:7'], /--fec out of range/);
});

test('CLI: a space-separated value that looks like an option fails loudly', () => {
  // `--mtu-min -5` used to parse as a switch: the server started on the
  // default MTU with exit 0 and a "WRN unknown switch" line, so the peer
  // budget silently disagreed with what was asked for. A value option must
  // fail the same way it fails for `--mtu-min=99999`.
  expectReject(['server', '--mtu-min', '-5'], /--mtu-min expects an integer in 128\.\.9000/);
  expectReject(['speedtest', `--key=${KEY}`, '--seconds', '-5'], /--seconds expects an integer in 3\.\.30/);
  // The string-valued ones have no range check to run, so the parser itself
  // has to say that the value is missing.
  expectReject(['server', '--key', '-abc'], /--key expects a value/);
  expectReject(['server', `--key=${KEY}`, '-b', '-1'], /-b expects a value/);
  expectReject(['server', `--key=${KEY}`, '--bind'], /--bind expects a value/);
});

test('CLI: an invalid --log-level fails instead of silently using info', () => {
  expectReject(['server', `--key=${KEY}`, '--log-level=verbose'], /--log-level expects debug\|info\|warn\|error\|off/);
});

// --- removed knobs --------------------------------------------------------

test('CLI: every renamed knob fails loudly with its replacement, never ignored', () => {
  const cases: Array<[string, RegExp]> = [
    ['--mtu=1400', /--mtu is no longer accepted.*--mtu-min=N/],
    ['--mtu-max=1500', /--mtu-max is no longer accepted.*--mtu-min=N/],
    ['--log=debug', /--log is no longer accepted.*--log-level=LEVEL/],
    ['--parity=5', /--parity is no longer accepted.*--fec=D:P/],
    ['--fec-budget=0.8', /--fec-budget is no longer accepted/],
    ['--key-env=FCP_KEY', /--key-env is no longer accepted.*--key=HEX32/],
    ['--host=1.2.3.4', /--host is no longer accepted.*--peer=IP\[:P\]/],
    ['--version', /--version is no longer accepted.*-h/],
    ['--trace=/tmp/x', /--trace is no longer accepted.*--metrics=PREFIX/],
  ];
  for (const [arg, msg] of cases) expectReject(['server', `--key=${KEY}`, arg], msg);
});

test('CLI: short removed flags are shown with a single dash', () => {
  expectReject(['server', `--key=${KEY}`, '-m', '1400'], /^-?fcp: -m is no longer accepted/m);
  expectReject(['server', `--key=${KEY}`, '-H', '1.2.3.4'], /fcp: -H is no longer accepted/);
  expectReject(['server', `--key=${KEY}`, '-p', '4460'], /fcp: -p is no longer accepted/);
});

test('CLI: replay mode is rejected with its metrics-report replacement', () => {
  expectReject(['replay', `--key=${KEY}`], /replay was renamed: use metrics-report/);
});

test('CLI: an unknown mode fails with the allowed list', () => {
  expectReject(['frobnicate', `--key=${KEY}`], /unknown mode "frobnicate"; use server \| client \| speedtest \| metrics-report/);
});

// --- help/version shortcuts ----------------------------------------------

test('CLI: help exits 0, prints version on line 1, and needs no key', () => {
  const r = run(['--help']);
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stdout, /^FCP \d+\.\d+\.\d+ \(Node\.js port\)/);
  assert.match(r.stdout, /Usage:/);
});

test('CLI: --version is rejected even though it looks like a help request', () => {
  // A mode-less `--version` used to print usage (argv[0] starts with '-' →
  // mode "help"). The removed-opt check must run BEFORE that shortcut.
  expectReject(['--version'], /--version is no longer accepted/);
});

// --- speedtest --seconds --------------------------------------------------

test('CLI: speedtest --seconds is range-checked like every other numeric option', () => {
  // REGRESSION: --seconds used Number(raw)||8 clamped to 3..30, so "abc", 2,
  // 100 and -5 all ran with exit 0 — the only numeric option that silently
  // swallowed bad input instead of failing loudly.
  for (const bad of ['abc', '2', '100', '-5', '3.5']) {
    expectReject(['speedtest', `--key=${KEY}`, `--seconds=${bad}`], /--seconds expects an integer in 3\.\.30/);
  }
  // The deprecated spelling is held to the same contract.
  expectReject(['speedtest', `--key=${KEY}`, '--speedtest-seconds=99'], /--seconds expects an integer in 3\.\.30/);
});
