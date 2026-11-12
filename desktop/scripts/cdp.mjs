// Minimal CDP driver for self-testing the shell: evaluate JS, reload, screenshot.
// Node 22 has a global WebSocket, so no dependency is needed.
//   node cdp.mjs eval "<expression>"
//   node cdp.mjs shot <out.png> [width] [height]
//   node cdp.mjs reload
import { writeFileSync } from 'node:fs';

const port = Number(process.env.FCP_CDP_PORT || 9222);
const [cmd, ...rest] = process.argv.slice(2);

const targets = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
const page = targets.find((t) => t.type === 'page');
if (!page) { console.error('no page target'); process.exit(1); }

const ws = new WebSocket(page.webSocketDebuggerUrl);
let id = 0;
const pending = new Map();
const call = (method, params = {}) => new Promise((resolve, reject) => {
  const msgId = ++id;
  pending.set(msgId, { resolve, reject });
  ws.send(JSON.stringify({ id: msgId, method, params }));
});
ws.addEventListener('message', (ev) => {
  const msg = JSON.parse(ev.data);
  if (msg.id && pending.has(msg.id)) {
    const { resolve, reject } = pending.get(msg.id);
    pending.delete(msg.id);
    if (msg.error) reject(new Error(JSON.stringify(msg.error)));
    else resolve(msg.result);
  }
});
await new Promise((r) => ws.addEventListener('open', r));
await call('Runtime.enable');

if (cmd === 'eval') {
  const r = await call('Runtime.evaluate', {
    expression: rest.join(' '), awaitPromise: true, returnByValue: true,
  });
  if (r.exceptionDetails) {
    console.error('EXCEPTION', JSON.stringify(r.exceptionDetails.exception || r.exceptionDetails));
    process.exit(1);
  }
  console.log(JSON.stringify(r.result.value));
} else if (cmd === 'reload') {
  await call('Page.enable');
  await call('Page.reload', { ignoreCache: true });
  console.log('reloaded');
} else if (cmd === 'shot') {
  const out = rest[0] || 'shot.png';
  const width = Number(rest[1] || 0);
  const height = Number(rest[2] || 0);
  if (width && height) {
    await call('Emulation.setDeviceMetricsOverride', {
      width, height, deviceScaleFactor: 2, mobile: false,
    });
  }
  const shot = await call('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true });
  writeFileSync(out, Buffer.from(shot.data, 'base64'));
  console.log(`wrote ${out}`);
} else {
  console.error('usage: cdp.mjs eval|shot|reload');
  process.exit(64);
}
ws.close();
