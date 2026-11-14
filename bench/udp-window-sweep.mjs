// Raw UDP goodput vs in-flight window against a bench/udp-echo.mjs endpoint.
// Answers "is the path or the protocol the limiter": sweep the window, watch
// goodput AND loss — a tunnel that matches the path's best raw window is done.
// Usage: node bench/udp-window-sweep.mjs HOST [PORT=4463] [DGRAM=1400] [SECS=8]
import { createSocket } from 'node:dgram';
const [host = '127.0.0.1', portStr = '4463', dgramStr = '1400', secsStr = '8'] = process.argv.slice(2);
const PORT = Number(portStr), DGRAM = Number(dgramStr), DURATION_MS = Number(secsStr) * 1000;

function run(windowDatagrams) {
  return new Promise((resolve) => {
    const sock = createSocket('udp4');
    const outstanding = new Set();
    let seq = 0, echoedBytes = 0, echoedCount = 0, sentCount = 0;
    let running = true;
    const start = process.hrtime.bigint();
    const fill = () => {
      while (running && outstanding.size < windowDatagrams) {
        const id = seq++;
        outstanding.add(id);
        const buf = Buffer.allocUnsafe(DGRAM);
        buf.writeBigUInt64BE(BigInt(id), 0);
        sock.send(buf, PORT, host);
        ++sentCount;
      }
    };
    sock.on('message', (msg) => {
      const id = Number(msg.readBigUInt64BE(0));
      if (outstanding.delete(id)) { echoedBytes += DGRAM; ++echoedCount; }
      if (running) fill();
    });
    sock.on('error', () => {});
    sock.bind(0, () => {
      fill();
      setTimeout(() => {
        running = false;
        const elapsed = Math.max(0.001, Number(process.hrtime.bigint() - start) / 1e9);
        sock.close();
        resolve({ windowDatagrams, sentCount, echoedCount,
          lossPct: 100 - (echoedCount / Math.max(1, sentCount)) * 100,
          mbps: echoedBytes * 8 / elapsed / 1e6 });
      }, DURATION_MS);
    });
  });
}
console.log(`udp window sweep vs ${host}:${PORT} (${DGRAM}B dgrams, ${Number(secsStr)}s per window)`);
console.log('window      goodput     loss');
for (const w of [64, 186, 366, 730, 1460, 2925]) {
  const r = await run(w);
  console.log(`${String(r.windowDatagrams).padStart(6)} (${String(r.windowDatagrams * DGRAM >> 10).padStart(4)} KiB) ${r.mbps.toFixed(2).padStart(7)} Mbit/s  ${r.lossPct.toFixed(1)}%`);
}
process.exit(0);
