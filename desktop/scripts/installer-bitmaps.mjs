// Installer wizard bitmaps (NSIS side/header images), generated from code so
// the design stays in sync with the GUI theme (dark bg + brand gradient +
// amber dot). The pixel drawing needs a real text rasterizer, so the shapes
// and text are painted in a browser <canvas> (chrome-devtools evaluate_script
// against about:blank is enough) and POSTed here as raw RGBA; this process
// converts to the BMPs electron-builder consumes and, for eyeballing, to PNG.
//
//   node scripts/installer-bitmaps.mjs serve     # listen on 127.0.0.1:9777
//   node scripts/installer-bitmaps.mjs png A B C # RGBA files -> preview PNG
//
// Browser side (paste into evaluate_script):
//   fetch('http://127.0.0.1:9777', { method: 'POST', body: JSON.stringify({
//     side: b64Of(getImageData(164x314)), head: b64Of(getImageData(150x57)) }) })
//
// Sizes are the NSIS conventions: sidebar 164x314 (welcome/finish pages),
// header 150x57 (directory page). 24bpp BMP, bottom-up rows.
import { writeFileSync, mkdirSync, readFileSync } from 'node:fs';
import { deflateSync } from 'node:zlib';
import { createServer } from 'node:http';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', 'build');
const PORT = 9777;

// ---------------------------------------------------------------- BMP writer

function bmpFromRGBA(rgba, w, h) {
  const rowBytes = Math.ceil((w * 3) / 4) * 4;
  const dataSize = rowBytes * h;
  const buf = Buffer.alloc(54 + dataSize);
  buf.write('BM', 0);
  buf.writeUInt32LE(54 + dataSize, 2);
  buf.writeUInt32LE(54, 10);
  buf.writeUInt32LE(40, 14);              // BITMAPINFOHEADER
  buf.writeInt32LE(w, 18);
  buf.writeInt32LE(h, 22);                // positive = bottom-up rows
  buf.writeUInt16LE(1, 26);               // planes
  buf.writeUInt16LE(24, 28);              // bpp
  buf.writeUInt32LE(dataSize, 34);
  for (let y = 0; y < h; ++y) {
    const srcY = h - 1 - y;
    for (let x = 0; x < w; ++x) {
      const si = (srcY * w + x) * 4;
      const di = 54 + y * rowBytes + x * 3;
      buf[di] = rgba[si + 2];             // BGR, alpha dropped (opaque wizard)
      buf[di + 1] = rgba[si + 1];
      buf[di + 2] = rgba[si];
    }
  }
  return buf;
}

// ---------------------------------------------------------------- PNG writer (previews only)

const CRC_TABLE = new Int32Array(256).map((_, n) => {
  let c = n;
  for (let k = 0; k < 8; ++k) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c;
});
function crc32(buf) {
  let c = 0xffffffff;
  for (const b of buf) c = CRC_TABLE[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}
function pngChunk(type, data) {
  const head = Buffer.alloc(8);
  head.writeUInt32BE(data.length, 0);     // PNG chunk fields are big-endian
  head.write(type, 4, 'ascii');
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(Buffer.concat([Buffer.from(type, 'ascii'), data])), 0);
  return Buffer.concat([head, data, crc]);
}
function pngFromRGBA(rgba, w, h) {
  const raw = Buffer.alloc((w * 4 + 1) * h);
  for (let y = 0; y < h; ++y) {
    raw[y * (w * 4 + 1)] = 0;           // filter: none
    rgba.copy(raw, y * (w * 4 + 1) + 1, y * w * 4, (y + 1) * w * 4);
  }
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(w, 0);
  ihdr.writeUInt32BE(h, 4);
  ihdr[8] = 8; ihdr[9] = 6;             // 8bpp RGBA
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    pngChunk('IHDR', ihdr),
    pngChunk('IDAT', deflateSync(raw)),
    pngChunk('IEND', Buffer.alloc(0)),
  ]);
}

// ---------------------------------------------------------------- modes

function decodeB64(b64) {
  return Buffer.from(b64, 'base64');
}
function writeAll({ side, head }) {
  mkdirSync(ROOT, { recursive: true });
  const jobs = [
    ['side', 'installerSidebar.bmp', 164, 314],
    ['side', 'uninstallerSidebar.bmp', 164, 314],
    ['head', 'installerHeader.bmp', 150, 57],
  ];
  for (const [key, name, w, h] of jobs) {
    const rgba = decodeB64({ side, head }[key]);
    if (rgba.length !== w * h * 4) {
      throw new Error(`${key}: expected ${w * h * 4} RGBA bytes, got ${rgba.length}`);
    }
    writeFileSync(join(ROOT, name), bmpFromRGBA(rgba, w, h));
    writeFileSync(join(ROOT, `${name}.preview.png`), pngFromRGBA(rgba, w, h));
    console.log(`wrote build/${name} (${w}x${h})`);
  }
}

function serve() {
  createServer((req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    if (req.method === 'POST') {
      let body = '';
      req.on('data', (c) => { body += c; });
      req.on('end', () => {
        try {
          writeAll(JSON.parse(body));
          res.end('ok');
        } catch (e) {
          res.statusCode = 400;
          res.end(String(e.message));
        }
      });
      return;
    }
    const name = new URL(req.url, 'http://x').searchParams.get('name');
    if (name && /^[\w.-]+\.bmp$/.test(name)) {
      res.setHeader('Content-Type', 'image/bmp');
      res.end(readFileSync(join(ROOT, name)));
      return;
    }
    res.statusCode = 404;
    res.end('POST {side,head} base64 RGBA, or GET ?name=installerSidebar.bmp');
  }).listen(PORT, '127.0.0.1', () => {
    console.log(`installer-bitmaps listening on http://127.0.0.1:${PORT}`);
  });
}

if (process.argv[2] === 'png') {
  // png <rgbaFile> <w> <h> <out> — for debugging single buffers
  const [, , f, w, h, out] = process.argv;
  writeFileSync(out, pngFromRGBA(readFileSync(f), Number(w), Number(h)));
} else {
  serve();
}
