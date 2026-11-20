// The probe's idle gate asks "how much did the application move in the last
// 20 s", not "when did a byte last move". These cases pin the difference: a
// browser's background polling must not look like a busy path, and a transfer
// must. Both used to be the same answer under the old timestamp gate, which is
// why a page left open starved the probe for hours.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ByteWindow } from '../src/util/bytewindow.ts';
import { PROBE_IDLE_MS, PROBE_QUIET_BYTES } from '../src/constants.ts';

const T0 = 1_700_000_000_000;

test('BYTEWINDOW: a beacon every few seconds stays far below the gate', () => {
  const w = new ByteWindow();
  // 400 B every 5 s for two minutes: an open page's analytics poll.
  for (let ms = 0; ms <= 120_000; ms += 5_000) w.add(400, T0 + ms);
  const moved = w.total(T0 + 120_000, PROBE_IDLE_MS);
  assert.ok(moved > 0, 'the beacon must be counted at all');
  assert.ok(moved < PROBE_QUIET_BYTES,
    `a trickle must not trip the busy gate (${moved} < ${PROBE_QUIET_BYTES})`);
});

test('BYTEWINDOW: a transfer inside the window trips the gate', () => {
  const w = new ByteWindow();
  w.add(1 << 20, T0);
  assert.ok(w.total(T0, PROBE_IDLE_MS) >= PROBE_QUIET_BYTES);
  assert.ok(w.total(T0 + 1_000, PROBE_IDLE_MS) >= PROBE_QUIET_BYTES,
    'still inside the window one second later');
});

test('BYTEWINDOW: traffic ages out of the window', () => {
  const w = new ByteWindow();
  w.add(4 << 20, T0);
  assert.ok(w.total(T0 + PROBE_IDLE_MS - 500, PROBE_IDLE_MS) > 0);
  assert.equal(w.total(T0 + PROBE_IDLE_MS + 1_500, PROBE_IDLE_MS), 0,
    'nothing moved in the last 20 s');
});

test('BYTEWINDOW: a ring lap does not resurrect stale bytes', () => {
  const w = new ByteWindow();
  w.add(8 << 20, T0);
  // 70 s of one-byte seconds: every ring slot has been overwritten once.
  for (let s = 1; s <= 70; ++s) w.add(1, T0 + s * 1_000);
  const moved = w.total(T0 + 70_000, PROBE_IDLE_MS);
  assert.ok(moved <= 21, `only the last 20 buckets may count, got ${moved}`);
});

test('BYTEWINDOW: an hour of silence reads zero, not an old lap', () => {
  const w = new ByteWindow();
  w.add(1 << 20, T0);
  assert.equal(w.total(T0 + 3_600_000, PROBE_IDLE_MS), 0);
});

test('BYTEWINDOW: same-second writes accumulate', () => {
  const w = new ByteWindow();
  w.add(100, T0);
  w.add(250, T0 + 400);
  assert.equal(w.total(T0 + 400, PROBE_IDLE_MS), 350);
});
