'use strict';

// ---------------------------------------------------------------- elements

const $ = (id) => document.getElementById(id);
const el = {
  nav: $('nav'),
  pages: document.querySelectorAll('.page'),
  host: $('host'), port: $('port'), listenHost: $('listenHost'), listenPort: $('listenPort'),
  key: $('key'), keyToggle: $('keyToggle'), keyState: $('keyState'), remember: $('remember'),
  mtu: $('mtu'), fec: $('fec'), logLevel: $('logLevel'), logFile: $('logFile'), pmtud: $('pmtud'),
  advToggle: $('advToggle'), advBody: $('advBody'),
  toggleBtn: $('toggleBtn'), actionNote: $('actionNote'),
  stateDot: $('stateDot'), stateText: $('stateText'), stateAddr: $('stateAddr'), stateUptime: $('stateUptime'),
  rxRate: $('rxRate'), rxTotal: $('rxTotal'), txRate: $('txRate'), txTotal: $('txTotal'),
  chart: $('chart'), chartPeak: $('chartPeak'),
  kSessions: $('kSessions'), kUp: $('kUp'), kUptime: $('kUptime'), kListen: $('kListen'),
  speedUrl: $('speedUrl'), speedSeconds: $('speedSeconds'), speedPort: $('speedPort'),
  speedBtn: $('speedBtn'), speedStopBtn: $('speedStopBtn'), speedNote: $('speedNote'),
  speedMbps: $('speedMbps'), speedBytes: $('speedBytes'), speedElapsed: $('speedElapsed'),
  speedMiB: $('speedMiB'), speedMeter: $('speedMeter'),
  logView: $('logView'), logFilter: $('logFilter'), logClear: $('logClear'), logDir: $('logDir'),
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

function refreshKeyState() {
  const raw = el.key.value.replace(/\s+/g, '');
  const clean = raw.replace(/^0x/i, '');
  if (!raw) {
    el.keyState.textContent = '等待输入';
    el.keyState.className = 'key-state';
    return false;
  }
  if (HEX32.test(clean)) {
    el.keyState.textContent = '16 字节 ✓';
    el.keyState.className = 'key-state ok';
    return true;
  }
  el.keyState.textContent = `${clean.length} 位`;
  el.keyState.className = 'key-state bad';
  return false;
}

el.key.addEventListener('input', refreshKeyState);

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
    fec: el.fec.value.trim() || '10:4',
    logLevel: el.logLevel.value,
    logFile: el.logFile.value.trim(),
    pmtud: el.pmtud.checked,
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
      listenPort: 1080, mtu: 1040, fec: '', logLevel: '', logFile: '',
      pmtud: true, speedUrl: '', speedSeconds: 10, speedPort: 1080,
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
    refreshKeyState();
  }
  set(el.host, s.host);
  set(el.port, s.port);
  set(el.listenHost, s.listenHost);
  set(el.listenPort, s.listenPort);
  set(el.mtu, s.mtu);
  set(el.fec, s.fec);
  if (s.logLevel) el.logLevel.value = s.logLevel;
  set(el.logFile, s.logFile);
  if (typeof s.pmtud === 'boolean') el.pmtud.checked = s.pmtud;
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
  const fecMatch = /^(\d+):(\d+)$/.exec(cfg.fec);
  if (!fecMatch) return flashNote('FEC 需形如 10:4', 'error');
  const fecD = Number(fecMatch[1]), fecP = Number(fecMatch[2]);
  if (fecD < 1 || fecD > 256 || fecP < 0 || fecP > 7 || fecD + fecP > 256) {
    return flashNote('FEC 超出范围（D 1..256，P 0..7，D+P≤256）', 'error');
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
// 卡片显示用 4 样本滑动平均压掉 0.5s 采样的抖动(单样本曾显示 629 B/s)。
const rateWindow = { rx: [], tx: [] };
function avgRate(win, v) {
  win.push(v);
  while (win.length > 4) win.shift();
  return Math.round(win.reduce((a, b) => a + b, 0) / win.length);
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
  pushSample({ rxRate: appRxRate, txRate: appTxRate });
  el.rxRate.innerHTML = fmtRate(rxSmooth);
  el.txRate.innerHTML = fmtRate(txSmooth);
  el.rxTotal.textContent = `累计 ${fmtBytes(appRx)}`;
  el.txTotal.textContent = `累计 ${fmtBytes(appTx)}`;
  el.kSessions.textContent = String(s.live);
  el.kUp.textContent = String(s.up);
  el.kUptime.textContent = fmtUptime(s.uptimeSec * 1000);
  el.stateUptime.textContent = fmtUptime(s.uptimeSec * 1000);
  el.chartPeak.textContent = `峰值 ${fmtBytes(state.peak)}/s`;
  drawChart();
});

function drawChart() {
  const c = el.chart;
  if (!c) return;
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
  ctx.strokeStyle = 'rgba(255, 255, 255, 0.055)';
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
    g.addColorStop(1, 'rgba(8, 13, 11, 0)');
    ctx.fillStyle = g;
    ctx.fill();
  };

  drawSeries('tx', '#fbbf24', 'rgba(251, 191, 36, 0.20)');
  drawSeries('rx', '#34d399', 'rgba(52, 211, 153, 0.22)');

  // baseline labels
  ctx.fillStyle = '#5b6f66';
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

el.speedBtn.addEventListener('click', async () => {
  const url = el.speedUrl.value.trim();
  if (!/^https?:\/\//i.test(url)) { el.speedNote.textContent = 'URL 需以 http:// 或 https:// 开头'; return; }
  if (!state.running) { el.speedNote.textContent = '请先启动代理'; return; }
  el.speedBtn.disabled = true;
  el.speedStopBtn.disabled = false;
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

el.speedStopBtn.addEventListener('click', async () => {
  await window.fcp.speedStop();
  clearInterval(speedTimer);
  el.speedBtn.disabled = false;
  el.speedStopBtn.disabled = true;
  el.speedNote.textContent = '已停止';
});

window.fcp.onSpeed((p) => {
  if (!p.done) return;
  clearInterval(speedTimer);
  el.speedBtn.disabled = false;
  el.speedStopBtn.disabled = true;
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

// ---------------------------------------------------------------- boot

(async () => {
  const s = await window.fcp.loadSettings();
  applySettings(s);
  refreshKeyState();
  const st = await window.fcp.state();
  setRunning(!!st.running);
  if (st.running) {
    el.stateAddr.textContent = st.listen;
    el.kListen.textContent = st.listen;
  }
  drawChart();
  if (!el.host.value) el.host.focus();
})();

window.addEventListener('resize', () => drawChart());
