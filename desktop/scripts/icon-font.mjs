// Draws an ARTISTIC "P" (variable-width calligraphic strokes, not a plain
// system font) on a gradient tile via headless Edge canvas. No npm deps.
//
//   node scripts/icon-font.mjs                 # write icon-options/ gallery
//   node scripts/icon-font.mjs --final <n>     # write build/icon.png+ico, resources/icon.png
//
// Edge runs under an isolated --user-data-dir and is killed by its own PID
// (never by window title — that once killed the user's live app windows).
import { spawn } from 'node:child_process';
import { writeFileSync, mkdirSync, rmSync, existsSync } from 'node:fs';
import { deflateSync } from 'node:zlib';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const OUT = join(ROOT, 'icon-options');
const PROFILE = join(ROOT, '.icon-edge-profile');
const EDGE = process.env.EDGE_BIN
  || 'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe';
const PORT = 9337;

// ---------------------------------------------------------------- option set
const WHITE = '#ffffff';
const GREEN = ['#1fd6a0', '#079a70'];
const INDIGO = ['#6a7cff', '#3b2fb0'];
const INK = ['#2b3138', '#0d1013'];

// A stroke is an array of [x, y, width] centreline samples in a 512 canvas.
// The renderer offsets left/right by width/2 along the local normal and fills
// a smoothed outline — that's what gives the tapered calligraphic look.
const BRUSH_STEM = [[166, 112, 56], [162, 182, 51], [157, 262, 44], [153, 336, 34], [152, 392, 19]];
const BRUSH_BOWL = [[182, 114, 50], [236, 104, 50], [292, 121, 45], [324, 159, 40],
  [330, 203, 36], [312, 241, 31], [258, 259, 27], [205, 255, 25], [184, 250, 24]];
const CURSIVE_BOWL = [[182, 114, 50], [238, 104, 49], [296, 122, 44], [328, 160, 39],
  [332, 205, 34], [312, 244, 29], [256, 262, 25], [198, 258, 22], [176, 250, 20],
  [214, 286, 12], [262, 306, 6]];

const OPTIONS = [
  { name: '1 · 书法笔触', draw: 'brush', strokes: [BRUSH_STEM, BRUSH_BOWL],
    colors: GREEN, dir: 'diag', glyph: WHITE, dot: WHITE, dotR: 28, sheen: true,
    note: '变宽笔画：竖笔由粗到细、碗收笔渐细。像钢笔手写，最艺术。' },
  { name: '2 · 草书连笔', draw: 'brush', strokes: [BRUSH_STEM, CURSIVE_BOWL],
    colors: GREEN, dir: 'diag', glyph: WHITE, dot: WHITE, dotR: 26, sheen: true,
    note: '碗的收尾拖出一条飘逸细尾，草书味最浓，动感强。' },
  { name: '3 · 丝带渐变', draw: 'brush', strokes: [BRUSH_STEM, BRUSH_BOWL],
    colors: INDIGO, dir: 'diag', glyph: null, glyphGrad: ['#ffffff', '#c9d2ff'],
    dot: '#ffc46b', dotR: 27, sheen: true,
    note: '书法笔画 + 白到淡蓝渐变填充，丝带质感；靛蓝底琥珀点。' },
  { name: '4 · 几何圆弧', draw: 'geo',
    colors: INK, dir: 'vert', glyph: WHITE, dot: WHITE, dotR: 26, sheen: false,
    note: '竖笔是矩形，碗是正圆弧挖空。极致简洁的几何构成。' },
  { name: '5 · 衬线斜体', draw: 'serif', font: 'Georgia', weight: 'italic 700',
    colors: GREEN, dir: 'diag', glyph: WHITE, dot: WHITE, dotR: 28, sheen: true,
    note: 'Georgia 斜体粗衬线，优雅古典，和其他方案气质完全不同。' },
  { name: '6 · 粗笔留白', draw: 'negative',
    colors: ['#1fd6a0', '#079a70'], dir: 'diag', glyph: WHITE, dot: WHITE, dotR: 30, sheen: true,
    note: '笔画加粗、碗孔收成圆角方孔，负空间强烈，视觉冲击最大。' },
];

// ---------------------------------------------------------------- browser draw
// Runs INSIDE the page. Returns base64 of raw RGBA (size*size*4).
function drawExpression(opt, size = 512) {
  const cfg = JSON.stringify(opt);
  return `(() => {
    const o = ${cfg};
    const S = ${size};
    const c = document.createElement('canvas');
    c.width = c.height = S;
    const x = c.getContext('2d', { willReadFrequently: true });
    const k = S / 512;
    x.scale(k, k);                       // all coordinates below are in 512 space

    // ---- tile ----
    const lo = 31, hi = 481, rad = 112;
    x.beginPath();
    x.moveTo(lo+rad, lo);
    x.arcTo(hi, lo, hi, hi, rad);
    x.arcTo(hi, hi, lo, hi, rad);
    x.arcTo(lo, hi, lo, lo, rad);
    x.arcTo(lo, lo, hi, lo, rad);
    x.closePath();
    const diag = o.dir === 'diag';
    const g = x.createLinearGradient(lo, lo, diag ? hi : lo, diag ? hi : hi);
    g.addColorStop(0, o.colors[0]); g.addColorStop(1, o.colors[1]);
    x.fillStyle = g; x.fill();
    if (o.sheen) {
      x.save(); x.clip();
      const sh = x.createLinearGradient(0, lo, 0, hi*0.6);
      sh.addColorStop(0, 'rgba(255,255,255,.17)');
      sh.addColorStop(1, 'rgba(255,255,255,0)');
      x.fillStyle = sh; x.fillRect(0, 0, 512, 512);
      x.restore();
    }

    // ---- fill style for the glyph ----
    let glyphFill = o.glyph;
    if (o.glyphGrad) {
      const gg = x.createLinearGradient(150, 100, 350, 400);
      gg.addColorStop(0, o.glyphGrad[0]); gg.addColorStop(1, o.glyphGrad[1]);
      glyphFill = gg;
    }

    // ---- variable-width stroke -> smoothed filled outline ----
    const stroke = (pts) => {
      const L = [], R = [];
      for (let i = 0; i < pts.length; i++) {
        const p = pts[i], a = pts[Math.max(0, i-1)], b = pts[Math.min(pts.length-1, i+1)];
        let dx = b[0]-a[0], dy = b[1]-a[1];
        const len = Math.hypot(dx, dy) || 1; dx /= len; dy /= len;
        const nx = -dy, ny = dx, hw = p[2]/2;
        L.push([p[0]+nx*hw, p[1]+ny*hw]);
        R.push([p[0]-nx*hw, p[1]-ny*hw]);
      }
      const ring = [...L, ...R.slice().reverse()];
      const mid = (a, b) => [(a[0]+b[0])/2, (a[1]+b[1])/2];
      const start = mid(ring[ring.length-1], ring[0]);
      x.beginPath();
      x.moveTo(start[0], start[1]);
      for (let i = 0; i < ring.length; i++) {
        const cur = ring[i], nxt = ring[(i+1) % ring.length], m = mid(cur, nxt);
        x.quadraticCurveTo(cur[0], cur[1], m[0], m[1]);
      }
      x.closePath();
      x.fillStyle = glyphFill; x.fill();
    };

    if (o.draw === 'brush') {
      for (const s of o.strokes) stroke(s);
    } else if (o.draw === 'geo') {
      // full-height stem + bowl only on the UPPER half (that's what makes a P)
      x.fillStyle = glyphFill;
      x.beginPath();
      x.moveTo(150, 108); x.lineTo(206, 108);
      x.arc(206, 190, 82, -Math.PI/2, Math.PI/2, false);  // outer bowl, to (206,272)
      x.lineTo(206, 392); x.lineTo(150, 392); x.closePath();
      x.moveTo(206, 152);
      x.arc(206, 190, 40, -Math.PI/2, Math.PI/2, false);  // inner half-round hole
      x.lineTo(206, 152); x.closePath();
      x.fill('evenodd');
    } else if (o.draw === 'serif') {
      x.textAlign = 'left'; x.textBaseline = 'alphabetic';
      x.font = o.weight + ' 400px "' + o.font + '"';
      let size = 400;
      x.font = o.weight + ' ' + size + 'px "' + o.font + '"';
      let m = x.measureText('P');
      const targetH = 286;
      let h = m.actualBoundingBoxAscent + m.actualBoundingBoxDescent;
      if (h > 0) { size = size*targetH/h; x.font = o.weight + ' ' + size + 'px "' + o.font + '"'; m = x.measureText('P'); }
      const px = 246 + (m.actualBoundingBoxLeft - m.actualBoundingBoxRight)/2;
      const py = 236 + (m.actualBoundingBoxAscent - m.actualBoundingBoxDescent)/2;
      x.fillStyle = glyphFill; x.fillText('P', px, py);
    } else if (o.draw === 'negative') {
      // thick solid stem, one union-like path: stem + upper-half bowl ring
      x.fillStyle = glyphFill;
      x.beginPath();
      x.moveTo(150, 104); x.lineTo(214, 104);
      x.arc(214, 196, 124, -Math.PI/2, Math.PI/2, false);  // outer bowl to (214,320)
      x.lineTo(214, 400); x.lineTo(150, 400); x.closePath();
      x.moveTo(214, 156);
      x.arc(214, 196, 74, -Math.PI/2, Math.PI/2, false);   // inner hole
      x.lineTo(214, 156); x.closePath();
      x.fill('evenodd');
    }

    // ---- dot, lower-right ----
    x.beginPath();
    x.arc(374, 366, o.dotR || 28, 0, Math.PI*2);
    x.fillStyle = o.dot; x.fill();

    const d = x.getImageData(0, 0, S, S).data;
    let s = '';
    for (let i = 0; i < d.length; i += 8192) s += String.fromCharCode.apply(null, d.subarray(i, i+8192));
    return btoa(s);
  })()`;
}

// ---------------------------------------------------------------- encoders
const CRC = new Int32Array(256).map((_, n) => {
  let c = n;
  for (let k = 0; k < 8; ++k) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c;
});
function crc32(buf) {
  let c = 0xffffffff;
  for (const b of buf) c = CRC[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}
function chunk(type, data) {
  const h = Buffer.alloc(8);
  h.writeUInt32BE(data.length, 0); h.write(type, 4, 'ascii');
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(Buffer.concat([Buffer.from(type, 'ascii'), data])), 0);
  return Buffer.concat([h, data, crc]);
}
function toPNG(rgba, w, h) {
  const raw = Buffer.alloc((w * 4 + 1) * h);
  for (let y = 0; y < h; ++y) rgba.copy(raw, y * (w * 4 + 1) + 1, y * w * 4, (y + 1) * w * 4);
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(w, 0); ihdr.writeUInt32BE(h, 4); ihdr[8] = 8; ihdr[9] = 6;
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr), chunk('IDAT', deflateSync(raw, { level: 9 })), chunk('IEND', Buffer.alloc(0)),
  ]);
}
function toICO(imgs) {
  const head = Buffer.alloc(6 + 16 * imgs.length);
  head.writeUInt16LE(0, 0); head.writeUInt16LE(1, 2); head.writeUInt16LE(imgs.length, 4);
  let off = head.length;
  imgs.forEach((im, i) => {
    const o = 6 + 16 * i;
    head[o] = im.size === 256 ? 0 : im.size;
    head[o + 1] = im.size === 256 ? 0 : im.size;
    head.writeUInt16LE(1, o + 4); head.writeUInt16LE(32, o + 6);
    head.writeUInt32LE(im.data.length, o + 8);
    head.writeUInt32LE(off, o + 12);
    off += im.data.length;
  });
  return Buffer.concat([head, ...imgs.map((im) => im.data)]);
}
function dibFromRGBA(rgba, w) {
  const h = w, row = w * 4, maskRow = Math.ceil(w / 32) * 4;
  const buf = Buffer.alloc(40 + row * h + maskRow * h);
  buf.writeUInt32LE(40, 0); buf.writeInt32LE(w, 4); buf.writeInt32LE(h * 2, 8);
  buf.writeUInt16LE(1, 12); buf.writeUInt16LE(32, 14);
  buf.writeUInt32LE(row * h + maskRow * h, 20);
  for (let y = 0; y < h; ++y) for (let x = 0; x < w; ++x) {
    const s = ((h - 1 - y) * w + x) * 4, d = 40 + y * row + x * 4;
    const a = rgba[s + 3] / 255;
    buf[d] = Math.round(rgba[s + 2] * a); buf[d + 1] = Math.round(rgba[s + 1] * a);
    buf[d + 2] = Math.round(rgba[s] * a); buf[d + 3] = rgba[s + 3];
  }
  const mask = 40 + row * h;
  for (let y = 0; y < h; ++y) for (let x = 0; x < w; ++x)
    if (rgba[((h - 1 - y) * w + x) * 4 + 3] < 128) buf[mask + y * maskRow + (x >> 3)] |= 0x80 >> (x & 7);
  return buf;
}

// ---------------------------------------------------------------- CDP plumbing
async function main() {
  if (existsSync(PROFILE)) rmSync(PROFILE, { recursive: true, force: true });
  mkdirSync(PROFILE, { recursive: true });
  const edge = spawn(EDGE, [
    `--remote-debugging-port=${PORT}`, `--user-data-dir=${PROFILE}`,
    '--headless=new', '--disable-gpu', '--no-first-run',
    '--no-default-browser-check', '--disable-background-networking',
    '--disable-features=Translate,MediaRouter', 'about:blank',
  ], { stdio: 'ignore' });

  let page = null;
  for (let i = 0; i < 80; ++i) {
    try {
      const targets = await (await fetch(`http://127.0.0.1:${PORT}/json/list`)).json();
      page = targets.find((t) => t.type === 'page');
      if (page) break;
    } catch {}
    await new Promise((r) => setTimeout(r, 150));
  }
  if (!page) { edge.kill(); throw new Error('headless Edge did not expose a page target'); }

  const ws = new WebSocket(page.webSocketDebuggerUrl);
  let seq = 0;
  const pending = new Map();
  const call = (method, params = {}) => new Promise((resolve, reject) => {
    const id = ++seq;
    pending.set(id, { resolve, reject });
    ws.send(JSON.stringify({ id, method, params }));
  });
  ws.addEventListener('message', (ev) => {
    const msg = JSON.parse(ev.data);
    if (msg.id && pending.has(msg.id)) {
      const p = pending.get(msg.id); pending.delete(msg.id);
      msg.error ? p.reject(new Error(JSON.stringify(msg.error))) : p.resolve(msg.result);
    }
  });
  await new Promise((r) => ws.addEventListener('open', r));
  await call('Runtime.enable');

  const raster = async (opt, size) => {
    const r = await call('Runtime.evaluate', {
      expression: drawExpression(opt, size), awaitPromise: true, returnByValue: true,
    });
    if (r.exceptionDetails) throw new Error(JSON.stringify(r.exceptionDetails));
    return Buffer.from(r.result.value, 'base64');
  };

  const finalArg = process.argv.indexOf('--final');
  if (finalArg >= 0) {
    const n = Number(process.argv[finalArg + 1]);
    const opt = OPTIONS[n - 1];
    if (!opt) throw new Error(`no option ${n}`);
    const rgba = await raster(opt, 512);
    writeFileSync(join(ROOT, 'build', 'icon.png'), toPNG(rgba, 512, 512));
    writeFileSync(join(ROOT, 'resources', 'icon.png'), toPNG(rgba, 512, 512));
    const imgs = [];
    for (const s of [16, 32, 48, 64, 128, 256]) {
      const px = await raster(opt, s);
      imgs.push({ size: s, data: s === 256 ? toPNG(px, s, s) : dibFromRGBA(px, s) });
    }
    writeFileSync(join(ROOT, 'build', 'icon.ico'), toICO(imgs));
    console.log(`final: option ${n} (${opt.name}) -> build/icon.png, build/icon.ico, resources/icon.png`);
  } else {
    mkdirSync(OUT, { recursive: true });
    const cards = [];
    for (let i = 0; i < OPTIONS.length; ++i) {
      const o = OPTIONS[i];
      const rgba = await raster(o, 512);
      writeFileSync(join(OUT, `option${i + 1}.png`), toPNG(rgba, 512, 512));
      cards.push(`<div class="card"><div class="swatch"><img src="option${i + 1}.png"></div>
        <div class="meta"><div class="title">${o.name}</div><div class="desc">${o.note}</div></div></div>`);
    }
    const html = `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<title>FCP Node 图标 · 艺术 P</title><style>
:root{color-scheme:light}*{box-sizing:border-box}
body{margin:0;padding:36px 40px 48px;background:#faf8f4;color:#26221d;font-family:"Segoe UI","PingFang SC","Microsoft YaHei",sans-serif}
h1{margin:0 0 6px;font-size:24px}.lead{margin:0 0 28px;color:#777064;font-size:13px}
.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:22px;max-width:1180px}
.card{background:#fff;border:1px solid #e6e1d7;border-radius:14px;overflow:hidden;box-shadow:0 2px 10px rgba(60,50,35,.04)}
.swatch{height:250px;display:flex;align-items:center;justify-content:center;background:
linear-gradient(45deg,#f1ede5 25%,transparent 25%),linear-gradient(-45deg,#f1ede5 25%,transparent 25%),
linear-gradient(45deg,transparent 75%,#f1ede5 75%),linear-gradient(-45deg,transparent 75%,#f1ede5 75%);
background-size:20px 20px;background-position:0 0,0 10px,10px -10px,-10px 0}
.swatch img{width:210px;height:210px}
.meta{padding:16px 18px 20px;border-top:1px solid #efebe3}
.title{font-weight:600;font-size:15px;margin-bottom:6px}.desc{color:#777064;font-size:12.5px;line-height:1.65}
@media(max-width:900px){.grid{grid-template-columns:repeat(2,1fr)}}</style></head><body>
<h1>FCP Node 图标 · 艺术 P</h1>
<p class="lead">P 由变宽贝塞尔笔画手绘，不再是标准方块字。书法 / 草书 / 丝带 / 几何 / 衬线 / 粗笔六种造型。挑一个编号定稿。</p>
<div class="grid">${cards.join('')}</div></body></html>`;
    writeFileSync(join(OUT, 'index.html'), html);
    console.log('wrote 6 artistic-P options + index.html');
  }

  ws.close();
  edge.kill();
  await new Promise((r) => setTimeout(r, 500));
  try { rmSync(PROFILE, { recursive: true, force: true }); } catch {}
}
main().catch((e) => { console.error(e); process.exit(1); });
