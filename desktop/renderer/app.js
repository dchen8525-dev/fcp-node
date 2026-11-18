'use strict';

// ---------------------------------------------------------------- elements

const $ = (id) => document.getElementById(id);
const el = {
  nav: $('nav'),
  appVersion: $('appVersion'),
  pages: document.querySelectorAll('.page'),
  host: $('host'), port: $('port'), listenHost: $('listenHost'), listenPort: $('listenPort'),
  key: $('key'), keyToggle: $('keyToggle'), remember: $('remember'),
  mtu: $('mtu'), fecData: $('fecData'), fecParityMax: $('fecParityMax'),
  logLevel: $('logLevel'), logFile: $('logFile'), pmtud: $('pmtud'),
  probeInterval: $('probeInterval'), probeOn: $('probeOn'),
  advToggle: $('advToggle'), advBody: $('advBody'),
  toggleBtn: $('toggleBtn'), actionNote: $('actionNote'),
  stateDot: $('stateDot'), stateText: $('stateText'), stateAddr: $('stateAddr'), stateUptime: $('stateUptime'),
  rxRate: $('rxRate'), rxTotal: $('rxTotal'), txRate: $('txRate'), txTotal: $('txTotal'),
  chart: $('chart'), chartPeak: $('chartPeak'),
  kSessions: $('kSessions'), kUp: $('kUp'), kUptime: $('kUptime'), kListen: $('kListen'),
  speedUrl: $('speedUrl'), speedSeconds: $('speedSeconds'), speedPort: $('speedPort'),
  speedBtn: $('speedBtn'), speedNote: $('speedNote'),
  speedMbps: $('speedMbps'), speedBytes: $('speedBytes'), speedElapsed: $('speedElapsed'),
  speedMiB: $('speedMiB'), speedMeter: $('speedMeter'),
  probeWhen: $('probeWhen'), probeDown: $('probeDown'), probeDownSub: $('probeDownSub'),
  probeUp: $('probeUp'), probeUpSub: $('probeUpSub'), probeAt: $('probeAt'),
  probeRtt: $('probeRtt'), probeJitter: $('probeJitter'), probeQueue: $('probeQueue'),
  probeRun: $('probeRun'), probeBytes: $('probeBytes'), probeElapsed: $('probeElapsed'),
  probeMtu: $('probeMtu'), probeFec: $('probeFec'),
  probeHistory: $('probeHistory'), probeHistoryNote: $('probeHistoryNote'),
  logView: $('logView'), logFilter: $('logFilter'), logClear: $('logClear'), logDir: $('logDir'),
  themeBtn: $('themeBtn'), themeMenu: $('themeMenu'),
};

// ---------------------------------------------------------------- helpers

const CHART_POINTS = 120;           // 500 ms per sample -> 60 s
const state = {
  running: false,
  samples: [],                      // { rx, tx } in bytes/s
  peak: 0,
  logs: [],                         // { level, line, ts }
  filter: 'all',
  startedAt: 0,
  speedTesting: false,
  // Newest first. In memory only: a measurement is a property of the tunnel
  // that produced it, and replaying last week's numbers against today's server
  // would be worse than an empty list.
  probes: [],
  probeRunning: false,
  probeNextSec: -1,
  probeCount: 0,
};

function fmtBytes(n) {
  if (!Number.isFinite(n) || n <= 0) return '0 B';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i += 1; }
  return `${v >= 100 || i === 0 ? v.toFixed(0) : v.toFixed(v >= 10 ? 1 : 2)} ${units[i]}`;
}

function fmtRate(n) {
  const s = fmtBytes(n);
  const parts = s.split(' ');
  return `${parts[0]} <small>${parts[1]}/s</small>`;
}

function fmtUptime(ms) {
  if (!ms || ms < 1000) return '—';
  const total = Math.floor(ms / 1000);
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  if (h > 0) return `${h} 小时 ${m} 分`;
  if (m > 0) return `${m} 分 ${s} 秒`;
  return `${s} 秒`;
}

function clock(ts) {
  const d = new Date(ts);
  const p = (n, w = 2) => String(n).padStart(w, '0');
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

// ---------------------------------------------------------------- nav

el.nav.addEventListener('click', (e) => {
  const btn = e.target.closest('.nav-item');
  if (!btn) return;
  const page = btn.dataset.page;
  el.nav.querySelectorAll('.nav-item').forEach((b) => b.classList.toggle('is-active', b === btn));
  el.pages.forEach((p) => p.classList.toggle('is-active', p.dataset.page === page));
  if (page === 'status') drawChart();
});

el.advToggle.addEventListener('click', () => {
  const open = el.advToggle.getAttribute('aria-expanded') === 'true';
  el.advToggle.setAttribute('aria-expanded', String(!open));
  el.advBody.hidden = open;
});

el.keyToggle.addEventListener('click', () => {
  const hidden = el.key.type === 'password';
  el.key.type = hidden ? 'text' : 'password';
  el.keyToggle.textContent = hidden ? '隐藏' : '显示';
});

// ---------------------------------------------------------------- key state

const HEX32 = /^[0-9a-fA-F]{32}$/;

// ---------------------------------------------------------------- theme

// Palettes live in styles.css; this table is only the picker's identity + the
// preview chip. The chip colours cannot come from CSS variables because each
// swatch has to show a theme it is not currently rendered in, so they are the
// accent/background pair of each palette written out once.
const THEMES = [
  { id: 'ink',    name: '墨绿', dark: true,  swatch: ['#34d399', '#0b1210'] },
  { id: 'indigo', name: '靛蓝', dark: true,  swatch: ['#7aa2ff', '#0b0e18'] },
  { id: 'ember',  name: '炭火', dark: true,  swatch: ['#f59e0b', '#141110'] },
  { id: 'paper',  name: '暖白', dark: false, swatch: ['#1c8a63', '#f5f2ec'] },
  { id: 'mist',   name: '雾灰', dark: false, swatch: ['#3b6df6', '#eef1f6'] },
];
const THEME_BY_ID = new Map(THEMES.map((t) => [t.id, t]));
const DEFAULT_THEME = 'ink';

let themeId = document.documentElement.dataset.theme || DEFAULT_THEME;
// Resolved once per theme instead of per frame: drawChart() runs every 500 ms
// and getComputedStyle in that loop is avoidable work on the UI thread.
let chartColors = null;

const swatchCss = (t) =>
  `linear-gradient(135deg, ${t.swatch[0]} 0 54%, ${t.swatch[1]} 54% 100%)`;

function buildThemeMenu() {
  const frag = document.createDocumentFragment();
  for (const t of THEMES) {
    const item = document.createElement('button');
    item.type = 'button';
    item.className = 'theme-item';
    item.dataset.theme = t.id;
    item.setAttribute('role', 'menuitemradio');
    item.setAttribute('aria-checked', 'false');
    const sw = document.createElement('span');
    sw.className = 'sw';
    sw.style.background = swatchCss(t);
    const label = document.createElement('span');
    label.textContent = t.name;
    const mode = document.createElement('span');
    mode.className = 'mode';
    mode.textContent = t.dark ? '深色' : '浅色';
    item.append(sw, label, mode);
    frag.appendChild(item);
  }
  el.themeMenu.textContent = '';
  el.themeMenu.appendChild(frag);
}

/**
 * Puts a palette on screen. `persist` is separate from `notifyMain` because the
 * two have different callers: a click has to survive a restart and has to
 * repaint the native frame, a boot restore has already done both.
 */
function applyTheme(id, opts = {}) {
  const t = THEME_BY_ID.get(id) || THEME_BY_ID.get(DEFAULT_THEME);
  themeId = t.id;
  document.documentElement.dataset.theme = t.id;
  // The pill is styled by CSS (accent ring + half fill), so it follows the
  // palette without help. The button carries no visible label, so the name goes
  // where assistive tech and the tooltip will find it.
  el.themeBtn.title = `主题：${t.name}`;
  el.themeBtn.setAttribute('aria-label', `主题：${t.name}`);
  for (const item of el.themeMenu.querySelectorAll('.theme-item')) {
    item.setAttribute('aria-checked', String(item.dataset.theme === t.id));
  }
  chartColors = null;
  drawChart();
  if (opts.notifyMain !== false && window.fcp.setTheme) {
    window.fcp.setTheme({ id: t.id, dark: t.dark });
  }
  if (opts.persist) window.fcp.saveSettings({ theme: t.id });
}

function setThemeMenuOpen(open) {
  el.themeMenu.hidden = !open;
  el.themeBtn.setAttribute('aria-expanded', String(open));
  if (open) {
    const active = el.themeMenu.querySelector('.theme-item[aria-checked="true"]');
    if (active) active.focus();
  }
}

buildThemeMenu();

el.themeBtn.addEventListener('click', () => setThemeMenuOpen(el.themeMenu.hidden));

el.themeMenu.addEventListener('click', (e) => {
  const item = e.target.closest('.theme-item');
  if (!item) return;
  applyTheme(item.dataset.theme, { persist: true });
  setThemeMenuOpen(false);
  el.themeBtn.focus();
});

document.addEventListener('click', (e) => {
  if (el.themeMenu.hidden) return;
  if (!e.target.closest('.theme-dock')) setThemeMenuOpen(false);
});

document.addEventListener('keydown', (e) => {
  if (e.key !== 'Escape' || el.themeMenu.hidden) return;
  setThemeMenuOpen(false);
  el.themeBtn.focus();
});

// ---------------------------------------------------------------- settings

let saveTimer = null;

function collectSettings() {
  const key = el.key.value.replace(/\s+/g, '').replace(/^0x/i, '');
  return {
    key: el.remember.checked ? key : '',
    host: el.host.value.trim(),
    port: Number(el.port.value) || 4460,
    listenHost: el.listenHost.value.trim() || '127.0.0.1',
    listenPort: Number(el.listenPort.value) || 1080,
    mtu: Number(el.mtu.value) || 1040,
    // 两半是独立的整数,与 --fec-data / --fec-parity-max 一一对应。
    // 空框才落回默认值:0 是合法的 P,不能用 `|| 默认` 吞掉。
    fecData: el.fecData.value === '' ? 10 : Number(el.fecData.value),
    fecParityMax: el.fecParityMax.value === '' ? 4 : Number(el.fecParityMax.value),
    logLevel: el.logLevel.value,
    logFile: el.logFile.value.trim(),
    pmtud: el.pmtud.checked,
    // 秒,与 --probe-interval 同一单位
    probeInterval: Math.max(1, Number(el.probeInterval.value) || 5) * 60,
    probe: el.probeOn.checked,
    remember: el.remember.checked,
    speedUrl: el.speedUrl.value.trim(),
    speedSeconds: Number(el.speedSeconds.value) || 10,
    speedPort: Number(el.speedPort.value) || 1080,
  };
}

function scheduleSave() {
  if (!el.remember.checked) {
    // Wipe every stored field, including the key, so unchecking really forgets.
    window.fcp.saveSettings({
      remember: false, key: '', host: '', port: 4460, listenHost: '',
      listenPort: 1080, mtu: 1040, fecData: 10, fecParityMax: 4, logLevel: '', logFile: '',
      pmtud: true, speedUrl: '', speedSeconds: 10, speedPort: 1080,
      probeInterval: 300, probe: true,
    });
    return;
  }
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    // Keep remember:true in the stored object. Dropping it saved the key but
    // left the flag false, so after a restart the checkbox was unchecked while
    // the key was restored — and the next field edit wiped the key.
    window.fcp.saveSettings(collectSettings());
  }, 350);
}

function applySettings(s) {
  if (!s || typeof s !== 'object') return;
  const set = (node, v) => { if (v !== undefined && v !== null) node.value = v; };
  if (typeof s.key === 'string' && s.key) {
    el.key.value = s.key;
  }
  set(el.host, s.host);
  set(el.port, s.port);
  set(el.listenHost, s.listenHost);
  set(el.listenPort, s.listenPort);
  set(el.mtu, s.mtu);
  // 旧版存的是字符串 "10:4";这里不迁移,直接忽略(与 CLI 一样不做兼容),
  // 读不到就留在 HTML 的默认值上。
  if (typeof s.fecData === 'number') el.fecData.value = String(s.fecData);
  if (typeof s.fecParityMax === 'number') el.fecParityMax.value = String(s.fecParityMax);
  if (s.logLevel) el.logLevel.value = s.logLevel;
  set(el.logFile, s.logFile);
  if (typeof s.pmtud === 'boolean') el.pmtud.checked = s.pmtud;
  if (typeof s.probeInterval === 'number') el.probeInterval.value = String(Math.max(1, Math.round(s.probeInterval / 60)));
  if (typeof s.probe === 'boolean') el.probeOn.checked = s.probe;
  if (typeof s.remember === 'boolean') el.remember.checked = s.remember;
  set(el.speedUrl, s.speedUrl);
  set(el.speedSeconds, s.speedSeconds);
  set(el.speedPort, s.speedPort);
}

document.querySelectorAll('input, select').forEach((node) => {
  node.addEventListener('change', scheduleSave);
});

// ---------------------------------------------------------------- start/stop

function setRunning(on) {
  state.running = on;
  el.toggleBtn.textContent = on ? '停止代理' : '启动代理';
  el.toggleBtn.classList.toggle('is-stop', on);
  el.stateDot.classList.toggle('on', on);
  el.stateText.textContent = on ? '运行中' : '未启动';
  if (!on) {
    el.stateAddr.textContent = '—';
    el.stateUptime.textContent = '—';
    el.kListen.textContent = '—';
    state.samples = [];
    state.peak = 0;
    drawChart();
  }
  renderProbeWhen();
}

function flashNote(text, kind) {
  el.actionNote.textContent = text || '';
  el.actionNote.style.color = kind === 'error' ? 'var(--danger)' : '';
  if (text) setTimeout(() => { if (el.actionNote.textContent === text) el.actionNote.textContent = ''; }, 5000);
}

async function start() {
  const cfg = collectSettings();
  if (!cfg.host) return flashNote('请填写服务器地址', 'error');
  if (!(cfg.port >= 1 && cfg.port <= 65535)) return flashNote('UDP 端口需在 1..65535', 'error');
  if (!(cfg.listenPort >= 1 && cfg.listenPort <= 65535)) return flashNote('本地代理端口需在 1..65535', 'error');
  if (!(cfg.mtu >= 128 && cfg.mtu <= 9000)) return flashNote('MTU 需在 128..9000', 'error');
  const key = el.key.value.replace(/\s+/g, '').replace(/^0x/i, '');
  if (!HEX32.test(key)) return flashNote('密钥需为 32 位十六进制', 'error');
  // 两个整数各自的区间,再加唯一需要两者一起判的约束(索引一字节)
  if (!Number.isInteger(cfg.fecData) || cfg.fecData < 1 || cfg.fecData > 256) {
    return flashNote('FEC 数据 symbol 需为 1..256 的整数', 'error');
  }
  if (!Number.isInteger(cfg.fecParityMax) || cfg.fecParityMax < 0 || cfg.fecParityMax > 7) {
    return flashNote('FEC 冗余上限需为 0..7 的整数', 'error');
  }
  if (cfg.fecData + cfg.fecParityMax > 256) {
    return flashNote('FEC 数据 + 冗余上限不能超过 256', 'error');
  }

  el.toggleBtn.disabled = true;
  try {
    const r = await window.fcp.start({ ...cfg, key });
    if (!r || r.ok === false) return flashNote(r && r.error ? r.error : '启动失败', 'error');
    setRunning(true);
    el.speedPort.value = cfg.listenPort;
    flashNote('已启动');
  } finally {
    el.toggleBtn.disabled = false;
  }
}

async function stop() {
  el.toggleBtn.disabled = true;
  try {
    await window.fcp.stop();
    setRunning(false);
    flashNote('已停止');
  } finally {
    el.toggleBtn.disabled = false;
  }
}

// One button drives both directions: its label and colour follow the tunnel
// state, so there is no second control that can disagree with it.
el.toggleBtn.addEventListener('click', () => {
  if (state.running) void stop(); else void start();
});

// ---------------------------------------------------------------- stats + chart

// 应用层(浏览器真实)速率:0.0.5 及更早的隧道不携带 app_* → 回退 wire 值。
// 卡片显示用 2 样本滑动平均压掉 0.5s 采样的抖动(单样本曾显示 629 B/s)。
// 4 样本(2s 窗口)在速度爬坡时滞后 1.5s+,与浏览器速度偏差肉眼可见;
// 2 样本只滞后一个采样周期(0.5s),抖动压平效果仍然够用。
const rateWindow = { rx: [], tx: [] };
function avgRate(win, v) {
  win.push(v);
  while (win.length > 2) win.shift();
  return Math.round(win.reduce((a, b) => a + b, 0) / win.length);
}

function pushSample(rx, tx) {
  state.samples.push({ rx: Math.max(0, rx), tx: Math.max(0, tx) });
  while (state.samples.length > CHART_POINTS) state.samples.shift();
  state.peak = Math.max(state.peak, rx, tx);
}

window.fcp.onStats((s) => {
  const wireRx = Math.max(0, s.rxRate ?? 0);
  const wireTx = Math.max(0, s.txRate ?? 0);
  const appRxRate = s.appRxRate !== undefined ? Math.max(0, s.appRxRate) : wireRx;
  const appTxRate = s.appTxRate !== undefined ? Math.max(0, s.appTxRate) : wireTx;
  const rxSmooth = avgRate(rateWindow.rx, appRxRate);
  const txSmooth = avgRate(rateWindow.tx, appTxRate);
  const appRx = s.appRx !== undefined ? s.appRx : s.rx;
  const appTx = s.appTx !== undefined ? s.appTx : s.tx;
  pushSample(appRxRate, appTxRate);
  el.rxRate.innerHTML = fmtRate(rxSmooth);
  el.txRate.innerHTML = fmtRate(txSmooth);
  el.rxTotal.textContent = `累计 ${fmtBytes(appRx)}`;
  el.txTotal.textContent = `累计 ${fmtBytes(appTx)}`;
  el.kSessions.textContent = String(s.live);
  el.kUp.textContent = String(s.up);
  el.kUptime.textContent = fmtUptime(s.uptimeSec * 1000);
  el.stateUptime.textContent = fmtUptime(s.uptimeSec * 1000);
  el.chartPeak.textContent = `峰值 ${fmtBytes(state.peak)}/s`;
  if (s.probeRun !== undefined) state.probeRunning = s.probeRun;
  if (s.probeNextSec !== undefined) state.probeNextSec = s.probeNextSec;
  if (s.probeCount !== undefined) state.probeCount = s.probeCount;
  renderProbeWhen();
  drawChart();
});

// The canvas cannot inherit CSS: colours are read from the active palette
// once per theme change and cached (see applyTheme).
function readChartColors() {
  const cs = getComputedStyle(document.documentElement);
  const v = (name, fallback) => (cs.getPropertyValue(name) || '').trim() || fallback;
  return {
    grid: v('--chart-grid', 'rgba(127, 127, 127, 0.12)'),
    accent: v('--accent', '#34d399'),
    sand: v('--sand', '#fbbf24'),
    label: v('--muted-2', '#5b6f66'),
  };
}

function withAlpha(hex, a) {
  const m = /^#([0-9a-f]{6})$/i.exec(String(hex).trim());
  if (!m) return hex;
  const n = parseInt(m[1], 16);
  return `rgba(${(n >> 16) & 255}, ${(n >> 8) & 255}, ${n & 255}, ${a})`;
}

function drawChart() {
  const c = el.chart;
  if (!c) return;
  if (!chartColors) chartColors = readChartColors();
  const cc = chartColors;
  const dpr = window.devicePixelRatio || 1;
  const w = c.clientWidth;
  const h = c.clientHeight || 150;
  if (c.width !== Math.round(w * dpr) || c.height !== Math.round(h * dpr)) {
    c.width = Math.round(w * dpr);
    c.height = Math.round(h * dpr);
  }
  const ctx = c.getContext('2d');
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, w, h);

  const padL = 8, padR = 8, padT = 10, padB = 18;
  const plotW = w - padL - padR;
  const plotH = h - padT - padB;

  // horizontal grid
  ctx.strokeStyle = cc.grid;
  ctx.lineWidth = 1;
  for (let i = 0; i <= 3; i += 1) {
    const y = padT + (plotH * i) / 3;
    ctx.beginPath();
    ctx.moveTo(padL, y + 0.5);
    ctx.lineTo(padL + plotW, y + 0.5);
    ctx.stroke();
  }

  const data = state.samples;
  let max = 1;
  for (const p of data) max = Math.max(max, p.rx, p.tx);
  max *= 1.15;

  const xAt = (i) => padL + (plotW * i) / Math.max(1, CHART_POINTS - 1);
  const yAt = (v) => padT + plotH - (plotH * Math.min(v, max)) / max;

  const drawSeries = (key, stroke, fillTop) => {
    if (data.length < 2) return;
    const startIdx = CHART_POINTS - data.length;
    ctx.beginPath();
    for (let i = 0; i < data.length; i += 1) {
      const x = xAt(startIdx + i);
      const y = yAt(data[i][key]);
      if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
    }
    ctx.strokeStyle = stroke;
    ctx.lineWidth = 1.8;
    ctx.lineJoin = 'round';
    ctx.lineCap = 'round';
    ctx.stroke();

    // soft fill under the line
    ctx.lineTo(xAt(startIdx + data.length - 1), padT + plotH);
    ctx.lineTo(xAt(startIdx), padT + plotH);
    ctx.closePath();
    const g = ctx.createLinearGradient(0, padT, 0, padT + plotH);
    g.addColorStop(0, fillTop);
    g.addColorStop(1, 'transparent');
    ctx.fillStyle = g;
    ctx.fill();
  };

  drawSeries('tx', cc.sand, withAlpha(cc.sand, 0.20));
  drawSeries('rx', cc.accent, withAlpha(cc.accent, 0.22));

  // baseline labels
  ctx.fillStyle = cc.label;
  ctx.font = '10px "Cascadia Mono", Consolas, monospace';
  ctx.textBaseline = 'top';
  const peak = data.length ? data.reduce((m, p) => Math.max(m, p.rx, p.tx), 0) : 0;
  ctx.fillText(`${fmtBytes(peak)}/s`, padL, padT + plotH + 4);
  ctx.textAlign = 'right';
  ctx.fillText('现在', padL + plotW, padT + plotH + 4);
  ctx.textAlign = 'left';
}

// ---------------------------------------------------------------- state events

window.fcp.onState((s) => {
  setRunning(!!s.running);
  if (s.running) {
    el.stateAddr.textContent = s.listen;
    el.kListen.textContent = s.listen;
    state.startedAt = s.startedAt;
  }
});

// ---------------------------------------------------------------- log

const MAX_LOG = 2000;

// The tunnel prefixes every line with its own ISO timestamp. The shell draws a
// local HH:MM:SS gutter instead, so the ISO copy is stripped: two clocks in one
// row is noise, and the gutter is what the eye scans.
const ISO_PREFIX = /^\[\d{4}-\d{2}-\d{2}T[\d:.]+Z\]\s*/;

function addLog(entry) {
  entry.line = entry.line.replace(ISO_PREFIX, '');
  state.logs.push(entry);
  if (state.logs.length > MAX_LOG) state.logs.splice(0, state.logs.length - MAX_LOG);
  if (state.filter === 'all' || entry.level === state.filter ||
      (state.filter === 'warn' && entry.level === 'error')) {
    appendLogNode(entry);
  }
}

function appendLogNode(entry) {
  const stick = el.logView.scrollTop + el.logView.clientHeight >= el.logView.scrollHeight - 24;
  const div = document.createElement('div');
  div.className = `log-line ${entry.level}`;
  const ts = document.createElement('span');
  ts.className = 'ts';
  ts.textContent = clock(entry.ts);
  div.appendChild(ts);
  const body = document.createElement('span');
  body.className = 'body';
  body.textContent = entry.line;
  div.appendChild(body);
  el.logView.appendChild(div);
  while (el.logView.childElementCount > MAX_LOG) el.logView.removeChild(el.logView.firstElementChild);
  if (stick) el.logView.scrollTop = el.logView.scrollHeight;
}

function renderLogs() {
  el.logView.textContent = '';
  for (const entry of state.logs) {
    if (state.filter === 'all' || entry.level === state.filter ||
        (state.filter === 'warn' && entry.level === 'error')) {
      appendLogNode(entry);
    }
  }
  el.logView.scrollTop = el.logView.scrollHeight;
}

window.fcp.onLog((p) => addLog({ level: p.level || 'info', line: p.line, ts: Date.now() }));

el.logFilter.addEventListener('click', (e) => {
  const btn = e.target.closest('button');
  if (!btn) return;
  state.filter = btn.dataset.level;
  el.logFilter.querySelectorAll('button').forEach((b) => b.classList.toggle('is-active', b === btn));
  renderLogs();
});

el.logClear.addEventListener('click', () => { state.logs = []; el.logView.textContent = ''; });
el.logDir.addEventListener('click', async () => {
  const dir = await window.fcp.openLogDir();
  if (dir) addLog({ level: 'info', line: `log dir: ${dir}`, ts: Date.now() });
});

// ---------------------------------------------------------------- speed

let speedTimer = null;

// 与主开关同一套"一按钮双向"模式:标签与颜色跟随测速状态
function setSpeedTesting(on) {
  state.speedTesting = on;
  el.speedBtn.textContent = on ? '停止' : '开始测速';
  el.speedBtn.classList.toggle('is-stop', on);
}

el.speedBtn.addEventListener('click', async () => {
  if (state.speedTesting) {
    await window.fcp.speedStop();
    clearInterval(speedTimer);
    setSpeedTesting(false);
    el.speedNote.textContent = '已停止';
    return;
  }
  const url = el.speedUrl.value.trim();
  if (!/^https?:\/\//i.test(url)) { el.speedNote.textContent = 'URL 需以 http:// 或 https:// 开头'; return; }
  if (!state.running) { el.speedNote.textContent = '请先启动代理'; return; }
  setSpeedTesting(true);
  el.speedMbps.parentElement.classList.remove('is-empty');
  el.speedMbps.textContent = '0.00';
  el.speedBytes.textContent = '—';
  el.speedElapsed.textContent = '—';
  el.speedMiB.textContent = '—';
  el.speedMeter.style.width = '0%';
  el.speedNote.textContent = '测速中…';
  state.speedStart = Date.now();
  clearInterval(speedTimer);
  speedTimer = setInterval(() => {
    const s = (Date.now() - state.speedStart) / 1000;
    el.speedElapsed.textContent = `${s.toFixed(1)} s`;
    const total = Number(el.speedSeconds.value) || 10;
    el.speedMeter.style.width = `${Math.min(100, (s / total) * 100).toFixed(1)}%`;
  }, 200);
  // The proxy may be bound to a specific address; hardcoding 127.0.0.1 made
  // every speed test fail with ECONNREFUSED unless the bind was loopback.
  // Wildcard binds are reachable on loopback.
  const bind = el.listenHost.value.trim() || '127.0.0.1';
  const socksHost = (bind === '0.0.0.0' || bind === '::' || bind === '[::]') ? '127.0.0.1' : bind;
  await window.fcp.speedStart({
    url, seconds: Number(el.speedSeconds.value) || 10,
    socksHost, socksPort: Number(el.speedPort.value) || 1080,
  });
});

window.fcp.onSpeed((p) => {
  if (!p.done) return;
  clearInterval(speedTimer);
  setSpeedTesting(false);
  el.speedMeter.style.width = '100%';
  if (p.error) {
    el.speedNote.textContent = p.error;
    el.speedMbps.parentElement.classList.add('is-empty');
    el.speedMbps.textContent = '—';
    addLog({ level: 'error', line: `speedtest: ${p.error}`, ts: Date.now() });
    return;
  }
  el.speedMbps.textContent = p.mbps.toFixed(2);
  el.speedBytes.textContent = fmtBytes(p.bytes);
  el.speedElapsed.textContent = `${p.seconds.toFixed(1)} s`;
  el.speedMiB.textContent = `${p.mbPerSec.toFixed(2)} MiB/s`;
  el.speedNote.textContent = '完成';
  addLog({ level: 'info',
    line: `speedtest: ${p.mbPerSec.toFixed(2)} MiB/s (${fmtBytes(p.bytes)} / ${p.seconds.toFixed(1)}s) ${p.url}`,
    ts: Date.now() });
});

// ---------------------------------------------------------------- link probe
//
// The tunnel probes itself while idle and prints one `probe {...}` line per run.
// Nothing here triggers a measurement: the whole point is that it happens when
// the user is not looking, and the tab is a window onto what it found.

const PROBE_HISTORY = 24;

const fmtMbs = (bps) => (bps > 0 ? (bps / 1048576).toFixed(2) : '—');
const fmtLoss = (v) => (v < 0 || v === undefined ? '—' : `${(v * 100).toFixed(1)}%`);
const fmtMs = (v) => (v < 0 || v === undefined ? '—' : `${Math.round(v)} ms`);

function mmss(sec) {
  const s = Math.max(0, Math.round(sec));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
}

function renderProbeWhen() {
  const node = el.probeWhen;
  node.classList.remove('is-live', 'is-off');
  if (!state.running) { node.textContent = '代理未启动'; node.classList.add('is-off'); return; }
  if (state.probeNextSec < 0) { node.textContent = '已关闭（--no-probe）'; node.classList.add('is-off'); return; }
  if (state.probeRunning) { node.textContent = '测量中…'; node.classList.add('is-live'); return; }
  node.textContent = state.probeCount > 0
    ? `下次 ${mmss(state.probeNextSec)} ｜ 已测 ${state.probeCount} 次`
    : `首次测量 ${mmss(state.probeNextSec)} 后（需空闲）`;
}

/** One direction's two cards. `ramp` is the pacing rate the ramp proved clean;
 *  `rate` is what actually arrived, so a path that loses 20% shows both. */
function renderProbeDir(valueNode, subNode, d, label) {
  if (!d) {
    valueNode.innerHTML = '— <small>MB/s</small>';
    subNode.textContent = `${label}未测`;
    return;
  }
  const cap = d.capped ? '≥ ' : '';
  valueNode.innerHTML = `${cap}${fmtMbs(d.ramp)} <small>MB/s</small>`;
  const loss = d.lossRx >= 0 ? d.lossRx : d.lossTx;
  // 丢包优先用接收端自己的计数(lossRx);拿不到才退回发送端"回显缺失"。
  subNode.textContent = `丢包 ${fmtLoss(loss)} · 有效 ${fmtMbs(d.rate)} MB/s ${d.reason === 'timeout' ? '· 超时' : ''}`;
}

function renderProbe() {
  const p = state.probes[0];
  renderProbeWhen();
  if (!p) {
    renderProbeDir(el.probeDown, el.probeDownSub, null, '下行');
    renderProbeDir(el.probeUp, el.probeUpSub, null, '上行');
    el.probeAt.textContent = '—';
    for (const k of ['probeRtt', 'probeJitter', 'probeQueue', 'probeRun',
      'probeBytes', 'probeElapsed', 'probeMtu', 'probeFec']) el[k].textContent = '—';
    el.probeHistory.textContent = '';
    el.probeHistoryNote.textContent = '还没有记录';
    return;
  }
  const up = p.up;
  const down = p.down;
  renderProbeDir(el.probeDown, el.probeDownSub, down, '下行');
  renderProbeDir(el.probeUp, el.probeUpSub, up, '上行');
  el.probeAt.textContent = `${clock(p.recvAt || Date.now())} · ${(p.ms / 1000).toFixed(1)} 秒`;
  // RTT can only come from the uplink half: its echoes carry the sent timestamp.
  el.probeRtt.textContent = up && up.rttMin >= 0 ? `${up.rttMin} / ${up.rttAvg}` : '—';
  el.probeJitter.textContent = fmtMs((up && up.jitter >= 0 ? up.jitter : (down ? down.jitter : -1)));
  el.probeQueue.textContent = fmtMs(up ? up.queue : (down ? down.queue : -1));
  const maxRun = Math.max(up ? up.maxRun : -1, down ? down.maxRun : -1);
  el.probeRun.textContent = maxRun < 0 ? '—' : `${maxRun} 包`;
  el.probeBytes.textContent = `${fmtBytes(p.used)} / ${fmtBytes(p.budget)}`;
  el.probeElapsed.textContent = `${(p.ms / 1000).toFixed(1)} 秒`;
  el.probeMtu.textContent = p.mtu ? `${p.mtu} B` : '—';
  el.probeFec.textContent = p.k ? `${p.k} / ${p.d}` : '—';

  const rows = state.probes.slice(0, PROBE_HISTORY);
  const peak = rows.reduce((m, r) => Math.max(m, r.down ? r.down.ramp : 0, r.up ? r.up.ramp : 0), 0) || 1;
  const every = Math.max(1, Math.round((Number(el.probeInterval.value) || 5)));
  el.probeHistoryNote.textContent = `${rows.length} 条 · 空闲时每 ${every} 分钟一次`;
  const frag = document.createDocumentFragment();
  const head = document.createElement('div');
  head.className = 'probe-row head';
  head.innerHTML = '<span class="t">时间</span><span>下行</span><span>上行</span>'
    + '<span class="n">RTT</span><span class="l">丢包 下/上</span>';
  frag.appendChild(head);
  for (const r of rows) {
    const row = document.createElement('div');
    row.className = 'probe-row';
    const bar = (d, cls) => `<div class="bar"><div class="track"><div class="fill ${cls}" style="width:${
      Math.min(100, ((d && d.ramp ? d.ramp : 0) / peak) * 100).toFixed(0)}%"></div></div>`
      + `<span class="n">${d && d.capped ? '≥' : ''}${fmtMbs(d ? d.ramp : 0)}</span></div>`;
    row.innerHTML = `<span class="t">${clock(r.recvAt || Date.now())}</span>`
      + bar(r.down, 'down') + bar(r.up, 'up')
      + `<span class="n">${r.up && r.up.rttAvg >= 0 ? `${r.up.rttAvg}ms` : '—'}</span>`
      + `<span class="l">${fmtLoss(r.down ? r.down.lossRx : -1)} / ${fmtLoss(r.up ? r.up.lossRx : -1)}</span>`;
    frag.appendChild(row);
  }
  el.probeHistory.textContent = '';
  el.probeHistory.appendChild(frag);
}

window.fcp.onProbe((p) => {
  state.probes.unshift(p);
  while (state.probes.length > PROBE_HISTORY) state.probes.pop();
  state.probeRunning = false;
  renderProbe();
});

// ---------------------------------------------------------------- boot

(async () => {
  // 版本号取自主进程 package.json(与安装包同源),启动即固定,失败时保持占位符
  try {
    const v = await window.fcp.version();
    if (v) el.appVersion.textContent = `v${v}`;
  } catch { /* 老版本主进程没有该 IPC,保持 v— */ }
  const s = await window.fcp.loadSettings();
  applySettings(s);
  // theme-boot.js has already painted the stored palette; applying it again is
  // what labels the picker and marks the active row. No IPC: the main process
  // is the one that told us which theme to boot with.
  applyTheme((s && s.theme) || themeId, { notifyMain: false });
  const st = await window.fcp.state();
  setRunning(!!st.running);
  if (st.running) {
    el.stateAddr.textContent = st.listen;
    el.kListen.textContent = st.listen;
  }
  drawChart();
  renderProbe();
  if (!el.host.value) el.host.focus();
})();

window.addEventListener('resize', () => drawChart());
