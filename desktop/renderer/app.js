'use strict';

// ---------------------------------------------------------------- elements

const $ = (id) => document.getElementById(id);
const el = {
  nav: $('nav'),
  appVersion: $('appVersion'),
  pages: document.querySelectorAll('.page'),
  server: $('server'), proxy: $('proxy'),
  key: $('key'), keyToggle: $('keyToggle'), remember: $('remember'),
  mtu: $('mtu'), fecData: $('fecData'), fecParityMax: $('fecParityMax'),
  logLevel: $('logLevel'), probeInterval: $('probeInterval'),
  advToggle: $('advToggle'), advBody: $('advBody'),
  toggleBtn: $('toggleBtn'), actionNote: $('actionNote'),
  stateDot: $('stateDot'), stateText: $('stateText'), stateAddr: $('stateAddr'), stateUptime: $('stateUptime'),
  rxRate: $('rxRate'), rxTotal: $('rxTotal'), txRate: $('txRate'), txTotal: $('txTotal'),
  chart: $('chart'), chartPeak: $('chartPeak'),
  kSessions: $('kSessions'), kUp: $('kUp'), kUptime: $('kUptime'), kListen: $('kListen'),
  sysProxy: $('sysProxy'), kSysProxy: $('kSysProxy'),
  sysProxyApplyBtn: $('sysProxyApplyBtn'), sysProxyRestoreBtn: $('sysProxyRestoreBtn'),
  sysProxyNote: $('sysProxyNote'),
  probeNowBtn: $('probeNowBtn'),
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
  // Newest first. In memory only: a measurement is a property of the tunnel
  // that produced it, and replaying last week's numbers against today's server
  // would be worse than an empty list.
  probes: [],
  probeRunning: false,
  probeNextSec: -1,
  probeCount: 0,
  probeWait: false,
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

// "地址:端口" -> [host, port]。用最后一个冒号分割,因此 IPv4/域名没问题;
// IPv6 请用方括号 [::1]:1080。返回 NaN 端口交给 start() 的校验去报错。
function splitEndpoint(text, defaultPort) {
  const s = String(text || '').trim();
  const i = s.lastIndexOf(':');
  if (i < 0) return [s, defaultPort];
  const host = s.slice(0, i).trim();
  const raw = s.slice(i + 1).trim();
  const port = raw === '' ? defaultPort : Number(raw);
  return [host, port];
}

function collectSettings() {
  const key = el.key.value.replace(/\s+/g, '').replace(/^0x/i, '');
  const [host, port] = splitEndpoint(el.server.value, 4460);
  const [listenHost, listenPort] = splitEndpoint(el.proxy.value, 1080);
  const probeMin = el.probeInterval.value === '' ? 0 : Number(el.probeInterval.value);
  return {
    key: el.remember.checked ? key : '',
    host, port,
    listenHost: listenHost || '127.0.0.1',
    listenPort,
    mtu: Number(el.mtu.value) || 1040,
    // 两半是独立的整数,与 --fec-data / --fec-parity-max 一一对应。
    // 空框才落回默认值:0 是合法的 P,不能用 `|| 默认` 吞掉。
    fecData: el.fecData.value === '' ? 10 : Number(el.fecData.value),
    fecParityMax: el.fecParityMax.value === '' ? 4 : Number(el.fecParityMax.value),
    logLevel: el.logLevel.value,
    // PMTUD 已恒定默认开启，界面不再有开关；存档里不再写 pmtud 字段。
    // 分钟 -> 秒,与 --probe-interval 同一单位。≤0 一律记 0:CLI 侧 0 就是关闭,
    // 不再有 --no-probe 这个第二开关。正数钳到 CLI 接受的 30..86400 秒,
    // 这样"填 >0 就体检"不会被边界值拒绝。
    probeInterval: probeMin > 0
      ? Math.min(86400, Math.max(30, Math.round(probeMin * 60))) : 0,
    remember: el.remember.checked,
    systemProxy: el.sysProxy.checked,
  };
}

function scheduleSave() {
  if (!el.remember.checked) {
    // Wipe every stored field, including the key, so unchecking really forgets.
    window.fcp.saveSettings({
      remember: false, key: '', host: '', port: 4460, listenHost: '127.0.0.1',
      listenPort: 1080, mtu: 1040, fecData: 10, fecParityMax: 4, logLevel: '',
      probeInterval: 300,
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
  // 存档仍按拆开的四字段写,这里拼回两个合并框。旧存档也是这四字段,
  // 所以升级后密钥/地址不丢。
  if (s.host) el.server.value = `${s.host}:${s.port || 4460}`;
  if (s.listenHost || s.listenPort) {
    el.proxy.value = `${s.listenHost || '127.0.0.1'}:${s.listenPort || 1080}`;
  }
  set(el.mtu, s.mtu);
  // 旧版存的是字符串 "10:4";这里不迁移,直接忽略(与 CLI 一样不做兼容),
  // 读不到就留在 HTML 的默认值上。
  if (typeof s.fecData === 'number') el.fecData.value = String(s.fecData);
  if (typeof s.fecParityMax === 'number') el.fecParityMax.value = String(s.fecParityMax);
  if (s.logLevel) el.logLevel.value = s.logLevel;
  // 旧存档里的 pmtud 字段刻意忽略：PMTUD 现在恒定开启，不再由界面控制。
  // 分钟 -> 秒。旧存档的 probe:false 是已废弃的第二开关,只读不写,折算成 0。
  if (typeof s.probeInterval === 'number') {
    el.probeInterval.value = String(Math.round(s.probeInterval / 60));
  }
  if (s.probe === false) el.probeInterval.value = '0';
  if (typeof s.remember === 'boolean') el.remember.checked = s.remember;
  if (typeof s.systemProxy === 'boolean') el.sysProxy.checked = s.systemProxy;
}

document.querySelectorAll('input, select').forEach((node) => {
  node.addEventListener('change', scheduleSave);
});


// ---------------------------------------------------------------- 系统代理

/** 渲染 Windows 系统代理的接管状态。 */
function renderSysProxy(st) {
  if (!st) return;
  if (!st.supported) {
    el.kSysProxy.textContent = '仅 Windows';
    el.sysProxyApplyBtn.disabled = true;
    el.sysProxyRestoreBtn.disabled = true;
    el.sysProxyNote.textContent = '当前平台不支持';
    return;
  }
  el.kSysProxy.textContent = st.applied ? '已接管' : (st.enabled ? '其他代理' : '未设置');
  el.kSysProxy.title = st.server ? `当前系统代理：${st.server}` : '当前未启用系统代理';
  el.sysProxyApplyBtn.disabled = st.applied || !state.running;
  el.sysProxyRestoreBtn.disabled = !st.applied;
  el.sysProxyNote.textContent = st.applied
    ? `全部应用经 ${st.target} 出网`
    : (state.running ? '可手动接管，或勾选"连接时设为系统代理"' : '连接后可接管');
}

async function refreshSysProxy() {
  try {
    renderSysProxy(await window.fcp.sysProxyStatus());
  } catch { /* 主进程退出中 */ }
}

el.sysProxyApplyBtn.addEventListener('click', async () => {
  const r = await window.fcp.sysProxyApply();
  if (!r.ok) el.sysProxyNote.textContent = r.reason || '设置失败';
  refreshSysProxy();
});
el.sysProxyRestoreBtn.addEventListener('click', async () => {
  const r = await window.fcp.sysProxyRestore();
  if (!r.ok) el.sysProxyNote.textContent = r.reason || '恢复失败';
  refreshSysProxy();
});
window.fcp.onSysProxy((st) => renderSysProxy(st));
el.sysProxy.addEventListener('change', scheduleSave);

// ---------------------------------------------------------------- start/stop

function setRunning(on) {
  state.running = on;
  refreshSysProxy();
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
  if (!cfg.host) return flashNote('请填写服务器地址，格式：地址:UDP 端口', 'error');
  if (!Number.isInteger(cfg.port) || !(cfg.port >= 1 && cfg.port <= 65535)) {
    return flashNote('服务器 UDP 端口需在 1..65535', 'error');
  }
  if (!Number.isInteger(cfg.listenPort) || !(cfg.listenPort >= 1 && cfg.listenPort <= 65535)) {
    return flashNote('本地代理端口需在 1..65535', 'error');
  }
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
  // 老隧道不带 probe_wait:保持 false,倒计时按原样显示。
  if (s.probeWait !== undefined) state.probeWait = s.probeWait;
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

// ---------------------------------------------------------------- link probe
//
// The tunnel probes itself while idle and prints one `probe {...}` line per run.
// The button asks for one immediately (bypassing the idle gate); every result
// is also appended to probe.jsonl next to client.log by the main process.

const PROBE_HISTORY = 24;

/** 「最近几次」卡片里最多同时显示多少行数据;超出部分由滚动条承载。
 *  行高和这个数字都写成 CSS 变量,样式与逻辑只在这里定义一次,避免两边各写死一个数字。 */
const PROBE_HISTORY_VISIBLE = 10;
document.documentElement.style.setProperty('--probe-visible-rows', String(PROBE_HISTORY_VISIBLE));

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
  if (state.probeNextSec < 0) { node.textContent = '自动体检已关闭（仍可手动测）'; node.classList.add('is-off'); return; }
  if (state.probeRunning) { node.textContent = '测量中…'; node.classList.add('is-live'); return; }
  // 到点了但链路有流量:隧道每 30 s 重试一次,倒计时会在 0:30 -> 0:00 之间
  // 反复打转,看着像坏了。直接说清楚在等什么。
  if (state.probeWait) { node.textContent = '有流量，等空闲后测量'; node.classList.add('is-off'); return; }
  node.textContent = state.probeCount > 0
    ? `下次 ${mmss(state.probeNextSec)} ｜ 已测 ${state.probeCount} 次`
    : `首次测量 ${mmss(state.probeNextSec)} 后（需空闲）`;
}

/** 「最近几次」右上角那句说明:条数 + 当前配置的体检间隔。
 *  间隔直接读输入框,所以用户在高级设置里把 5 改成 10,这里立刻跟着变,
 *  不用等下一次体检结果回来。 */
function renderProbeHistoryNote(count) {
  const n = count === undefined ? Math.min(state.probes.length, PROBE_HISTORY) : count;
  const probeMin = Number(el.probeInterval.value);
  const tail = !(probeMin > 0) ? '体检已关闭' : `空闲时每 ${probeMin} 分钟一次`;
  el.probeHistoryNote.textContent = n > 0 ? `${n} 条 · ${tail}` : `还没有记录 · ${tail}`;
}

// 输入框一改就刷新这句（不等体检结果），5 改成 10 立即可见。
el.probeInterval.addEventListener('input', () => renderProbeHistoryNote());

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
    renderProbeHistoryNote(0);
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
  renderProbeHistoryNote(rows.length);
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

// 立即体检:绕过空闲与排期,由隧道在下一次 tick 触发。按钮只在运行且有
// 代理时可点;请求发出后先把状态显示成"测量中",结果回来由 onProbe 收尾。
let probeNowTimer = null;
el.probeNowBtn.addEventListener('click', async () => {
  if (!state.running) { renderProbeWhen(); return; }
  el.probeNowBtn.disabled = true;
  try {
    const r = await window.fcp.probeNow();
    if (!r || r.ok === false) {
      el.probeWhen.textContent = r && r.error ? r.error : '发起失败';
      el.probeWhen.classList.add('is-off');
      return;
    }
    state.probeRunning = true;
    renderProbeWhen();
    // 隧道可能拒绝(正在测/会话未就绪);8 s 还没出结果就恢复按钮,
    // 避免按钮永久转圈。结果到达时 onProbe 会清掉这个计时器。
    clearTimeout(probeNowTimer);
    probeNowTimer = setTimeout(() => {
      state.probeRunning = false;
      renderProbeWhen();
    }, 8000);
  } finally {
    el.probeNowBtn.disabled = false;
  }
});

window.fcp.onProbe((p) => {
  clearTimeout(probeNowTimer);
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
  if (!el.server.value) el.server.focus();
})();

window.addEventListener('resize', () => drawChart());
