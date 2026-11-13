// Electron main process: window + tunnel child process + a real SOCKS download
// speed test. The tunnel never runs in this process -- it is spawned exactly the
// way the Qt shell spawns fcp-client, so a tunnel crash cannot take the UI down.
'use strict';

const { app, BrowserWindow, ipcMain, dialog, shell, Tray, Menu, nativeImage } = require('electron');
const { spawn } = require('node:child_process');
const path = require('node:path');
const fs = require('node:fs');
const net = require('node:net');
const tls = require('node:tls');

const CLI_PATH = path.join(__dirname, '..', 'resources', 'cli.mjs');
const ICON_PATH = path.join(__dirname, '..', 'resources', 'icon.png');
const IS_PACKAGED = app.isPackaged;
const SETTINGS_PATH = () => path.join(app.getPath('userData'), 'settings.json');

let win = null;
let tray = null;
let isQuitting = false;
let trayHintShown = false;
let child = null;
let childState = { running: false, pid: 0, startedAt: 0, peer: '', listen: '' };
let speedJob = null;

// ---------------------------------------------------------------- settings

function readSettings() {
  try {
    return JSON.parse(fs.readFileSync(SETTINGS_PATH(), 'utf8'));
  } catch {
    return {};
  }
}

function writeSettings(patch) {
  const next = { ...readSettings(), ...patch };
  try {
    fs.mkdirSync(path.dirname(SETTINGS_PATH()), { recursive: true });
    fs.writeFileSync(SETTINGS_PATH(), JSON.stringify(next, null, 2), 'utf8');
  } catch (e) {
    // A settings write must never break the tunnel; report it in the log page.
    send('fcp:log', { level: 'warn', line: `settings: ${e.message}` });
  }
  return next;
}

function send(channel, payload) {
  if (win && !win.isDestroyed()) win.webContents.send(channel, payload);
}

// ---------------------------------------------------------------- tray

function showWindow() {
  if (!win || win.isDestroyed()) { createWindow(); return; }
  if (win.isMinimized()) win.restore();
  win.show();
  win.focus();
}

function quitApp() {
  isQuitting = true;
  stopTunnel();
  app.quit();
}

function openLogDir() {
  const dir = path.join(app.getPath('userData'), 'log');
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

async function revealLogDir() {
  const dir = openLogDir();
  await shell.openPath(dir);
  return dir;
}

/**
 * Tray icon + menu. The window close button hides instead of quitting while
 * the tray exists, so the tunnel is no longer tied to the window's lifetime;
 * "退出" is the only path that really terminates the process.
 */
function createTray() {
  if (tray) return;
  try {
    const source = nativeImage.createFromPath(ICON_PATH);
    if (source.isEmpty()) throw new Error(`tray icon not found: ${ICON_PATH}`);
    // Windows renders the notification area at 16 px (scale factor applies on
    // top); resizing here keeps the tray crisp instead of downscaling a large
    // window icon on every paint.
    const image = source.resize({ width: 16, height: 16, quality: 'best' });
    tray = new Tray(image);
    tray.setToolTip('FCP Node · 未启动');
    tray.on('click', showWindow);
    tray.on('double-click', showWindow);
    rebuildTrayMenu();
  } catch (e) {
    tray = null;
    send('fcp:log', { level: 'warn', line: `tray unavailable: ${e.message}` });
  }
}

function rebuildTrayMenu() {
  if (!tray) return;
  const running = childState.running;
  const status = running ? `运行中 · ${childState.peer || '已连接'}` : '未启动';
  const listen = childState.listen || '—';
  const template = [
    { label: '显示主窗口', click: showWindow },
    { type: 'separator' },
    { label: `状态：${status}`, enabled: false },
    { label: `本地代理：${listen}`, enabled: false },
    { type: 'separator' },
  ];
  if (running) {
    template.push({ label: '停止隧道', click: () => { stopTunnel(); } });
  } else {
    template.push({
      label: '启动隧道…',
      click: () => {
        showWindow();
        send('fcp:log', { level: 'info', line: '请在主窗口填写密钥后点击“启动”' });
      },
    });
  }
  template.push(
    { label: '打开日志目录', click: () => { void revealLogDir(); } },
    { type: 'separator' },
    { label: '退出 FCP Node', click: quitApp },
  );
  tray.setContextMenu(Menu.buildFromTemplate(template));
  tray.setToolTip(running ? `FCP Node · 运行中 · ${childState.peer || ''}`.trim() : 'FCP Node · 未启动');
}

/** One-time hint when the window is first hidden; Windows-only and silent
 *  where the platform has no balloon support. */
function notifyMinimizedToTray() {
  if (trayHintShown || !tray) return;
  trayHintShown = true;
  if (process.platform === 'win32' && typeof tray.displayBalloon === 'function') {
    try {
      tray.displayBalloon({
        title: 'FCP Node 仍在运行',
        content: '窗口已隐藏到托盘；右键托盘图标可停止隧道或退出。',
      });
    } catch { /* balloon is decorative */ }
  }
}

// ---------------------------------------------------------------- tunnel

function statsArgs(cfg) {
  const args = ['client', `--key=${cfg.key}`, `--peer=${cfg.host}:${cfg.port}`,
    `--bind=${cfg.listenHost}:${cfg.listenPort}`];
  if (cfg.mtu) args.push(`--mtu-min=${cfg.mtu}`);
  if (cfg.pmtud === false) args.push('--no-pmtud');
  args.push(`--fec=${cfg.fec || '10:6'}`);
  args.push(`--log-level=${cfg.logLevel || 'info'}`);
  if (cfg.logFile) args.push(`--log-file=${cfg.logFile}`);
  return args;
}

function classify(line) {
  if (line.startsWith('DBG ')) return 'debug';
  if (line.startsWith('WRN ')) return 'warn';
  if (line.startsWith('ERR ')) return 'error';
  if (/\b(error|fail|refused|exhaust)\b/i.test(line)) return 'error';
  if (/\b(warn|retrans|loss)\b/i.test(line)) return 'warn';
  return 'info';
}

const STATS_RE = /^stats\s+([\d.]+)s\s+live=(\d+)\s+up=(\d+)\s+tunnels=(\d+)\s+tx=(\d+)B\s+rx=(\d+)B\s+tx_rate=(-?\d+)B\/s\s+rx_rate=(-?\d+)B\/s/;

function startTunnel(cfg) {
  if (child) stopTunnel();
  if (!fs.existsSync(CLI_PATH)) {
    send('fcp:log', { level: 'error', line: `missing tunnel bundle: ${CLI_PATH}` });
    return { ok: false, error: 'missing tunnel bundle' };
  }
  const args = [CLI_PATH, ...statsArgs(cfg)];
  child = spawn(process.execPath, args, {
    // Electron's own binary doubles as the Node runtime: one exe, no sidecar
    // node.exe to ship. --experimental-strip-types is not needed because the
    // bundle is plain ESM.
    env: { ...process.env, ELECTRON_RUN_AS_NODE: '1' },
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  childState = { running: true, pid: child.pid || 0, startedAt: Date.now(),
    peer: `${cfg.host}:${cfg.port}`, listen: `${cfg.listenHost}:${cfg.listenPort}` };
  send('fcp:state', childState);
  rebuildTrayMenu();

  let buf = '';
  child.stdout.setEncoding('utf8');
  child.stdout.on('data', (chunk) => {
    buf += chunk;
    let idx;
    while ((idx = buf.indexOf('\n')) >= 0) {
      const line = buf.slice(0, idx).trim();
      buf = buf.slice(idx + 1);
      if (!line) continue;
      const m = STATS_RE.exec(line);
      if (m) {
        send('fcp:stats', {
          uptimeSec: Number(m[1]), live: Number(m[2]), up: Number(m[3]),
          tunnels: Number(m[4]), tx: Number(m[5]), rx: Number(m[6]),
          txRate: Number(m[7]), rxRate: Number(m[8]),
        });
      } else {
        send('fcp:log', { level: 'info', line });
      }
    }
  });
  child.stderr.setEncoding('utf8');
  child.stderr.on('data', (chunk) => {
    for (const raw of chunk.split('\n')) {
      const line = raw.trimEnd();
      if (!line) continue;
      send('fcp:log', { level: classify(line), line });
    }
  });
  child.on('exit', (code, signal) => {
    const wasRunning = childState.running;
    child = null;
    childState = { running: false, pid: 0, startedAt: 0, peer: '', listen: '' };
    send('fcp:state', childState);
    rebuildTrayMenu();
    if (wasRunning) {
      send('fcp:log', { level: code === 0 ? 'info' : 'error',
        line: `tunnel exited: code=${code} signal=${signal || 'none'}` });
    }
  });
  child.on('error', (e) => {
    send('fcp:log', { level: 'error', line: `tunnel spawn failed: ${e.message}` });
    child = null;
    childState = { running: false, pid: 0, startedAt: 0, peer: '', listen: '' };
    send('fcp:state', childState);
    rebuildTrayMenu();
  });
  return { ok: true, pid: child.pid };
}

function stopTunnel() {
  if (!child) return { ok: true };
  const c = child;
  child = null;
  try {
    // SIGTERM lets the tunnel close its sockets; the forced kill is the escape
    // hatch for a wedged process (Windows has no SIGTERM delivery for GUI
    // children, so taskkill is what actually lands there).
    c.kill('SIGTERM');
    setTimeout(() => { try { c.kill('SIGKILL'); } catch { /* already gone */ } }, 1500);
  } catch {
    /* already gone */
  }
  childState = { running: false, pid: 0, startedAt: 0, peer: '', listen: '' };
  send('fcp:state', childState);
  rebuildTrayMenu();
  return { ok: true };
}

// ---------------------------------------------------------------- speed test
//
// The Node port's `speedtest` subcommand measures an in-process loopback, which
// says nothing about the path the user cares about. This one dials the local
// SOCKS listener the tunnel exposes and pulls a real URL through it.

function socksConnect(socksHost, socksPort, host, port, timeoutMs = 8000) {
  return new Promise((resolve, reject) => {
    const sock = net.connect(socksPort, socksHost);
    let stage = 0;
    const fail = (e) => { sock.destroy(); reject(e); };
    const timer = setTimeout(() => fail(new Error('SOCKS handshake timeout')), timeoutMs);
    sock.setNoDelay(true);
    sock.on('error', fail);
    sock.on('close', () => { if (stage < 2) fail(new Error('SOCKS closed early')); });
    sock.on('connect', () => sock.write(Buffer.from([0x05, 0x01, 0x00])));
    sock.on('data', function onData(buf) {
      if (stage === 0) {
        if (buf[0] !== 0x05 || buf[1] !== 0x00) return fail(new Error('SOCKS greeting rejected'));
        stage = 1;
        const name = Buffer.from(host, 'utf8');
        const req = Buffer.alloc(7 + name.length);
        req[0] = 0x05; req[1] = 0x01; req[2] = 0x00; req[3] = 0x03;
        req[4] = name.length; name.copy(req, 5);
        req.writeUInt16BE(port, 5 + name.length);
        sock.write(req);
        sock.removeListener('data', onData);
        sock.once('data', (reply) => {
          if (reply[0] !== 0x05 || reply[1] !== 0x00) {
            return fail(new Error(`SOCKS connect failed (rep=${reply[1]})`));
          }
          clearTimeout(timer);
          stage = 2;
          sock.removeAllListeners('close');
          resolve(sock);
        });
        return;
      }
    });
  });
}

async function runSpeedTest(cfg, onDone) {
  const started = Date.now();
  const target = new URL(cfg.url);
  const host = target.hostname;
  const port = Number(target.port || (target.protocol === 'https:' ? 443 : 80));
  const tlsTarget = target.protocol === 'https:';
  let total = 0, headerBytes = 0, ended = false;

  const finish = (message) => {
    if (ended) return;
    ended = true;
    const elapsed = Math.max(0.2, (Date.now() - started) / 1000);
    const body = Math.max(0, total - headerBytes);
    const result = {
      ok: !message, bytes: body, seconds: elapsed,
      mbps: body * 8 / elapsed / 1e6, mbPerSec: body / elapsed / 1048576,
      error: message || '', url: cfg.url,
    };
    send('fcp:speed', { done: true, ...result });
    if (speedJob) { try { speedJob.destroy(); } catch { /* closed */ } speedJob = null; }
    if (onDone) onDone(result);
  };

  let sock;
  try {
    sock = await socksConnect(cfg.socksHost || '127.0.0.1', cfg.socksPort || 1080, host, port);
  } catch (e) {
    finish(`SOCKS: ${e.message}`);
    return;
  }
  speedJob = sock;
  if (tlsTarget) {
    sock = tls.connect({ socket: sock, servername: host },
      () => sock.write(buildRequest(target, host)));
    sock.on('error', (e) => finish(`TLS: ${e.message}`));
  } else {
    sock.write(buildRequest(target, host));
    sock.on('error', (e) => finish(`HTTP: ${e.message}`));
  }
  sock.on('data', (b) => {
    total += b.length;
    if (headerBytes === 0) {
      const text = b.subarray(0, Math.min(b.length, 2048)).toString('latin1');
      const idx = text.indexOf('\r\n\r\n');
      if (idx >= 0) headerBytes = Math.min(b.length, idx + 4);
    }
    if (Date.now() - started > (cfg.seconds || 10) * 1000) finish('');
  });
  sock.on('close', () => { if (!ended) finish(''); });
  sock.on('end', () => { if (!ended) finish(''); });
  setTimeout(() => finish(''), (cfg.seconds || 10) * 1000 + 250);
  send('fcp:speed', { done: false, url: cfg.url, seconds: (cfg.seconds || 10) });
}

function buildRequest(target, host) {
  const pathAndQuery = `${target.pathname || '/'}${target.search || ''}`;
  return `GET ${pathAndQuery} HTTP/1.1\r\n` +
    `Host: ${host}\r\n` +
    'User-Agent: fcp-desktop/0.0.1\r\n' +
    'Accept: */*\r\n' +
    'Accept-Encoding: identity\r\n' +
    'Connection: close\r\n\r\n';
}

// ---------------------------------------------------------------- window

function createWindow() {
  win = new BrowserWindow({
    width: 980, height: 700, minWidth: 820, minHeight: 600,
    backgroundColor: '#f4f7f5',
    title: 'FCP Node',
    icon: ICON_PATH,
    show: false,
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload.cjs'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
    },
  });
  win.loadFile(path.join(__dirname, '..', 'renderer', 'index.html'));
  win.once('ready-to-show', () => win.show());
  win.on('close', (e) => {
    // With a tray the close button only hides the window; quitting is the
    // tray's "退出" entry (or the menu's Quit), which sets isQuitting first.
    // Without a tray there would be no way back, so a close really exits.
    if (isQuitting || !tray) return;
    e.preventDefault();
    win.hide();
    send('fcp:log', { level: 'info', line: '窗口已隐藏到托盘；隧道继续运行' });
    notifyMinimizedToTray();
  });
  win.on('closed', () => { win = null; });
}

// ---------------------------------------------------------------- ipc

ipcMain.handle('fcp:settings:load', () => readSettings());
ipcMain.handle('fcp:settings:save', (_e, patch) => writeSettings(patch || {}));
ipcMain.handle('fcp:start', (_e, cfg) => startTunnel(cfg || {}));
ipcMain.handle('fcp:stop', () => stopTunnel());
ipcMain.handle('fcp:state', () => childState);
ipcMain.handle('fcp:speed:start', (_e, cfg) => {
  if (speedJob) { try { speedJob.destroy(); } catch { /* closed */ } speedJob = null; }
  runSpeedTest(cfg || {});
  return { ok: true };
});
ipcMain.handle('fcp:speed:stop', () => {
  if (speedJob) { try { speedJob.destroy(); } catch { /* closed */ } speedJob = null; }
  return { ok: true };
});
ipcMain.handle('fcp:open-log-dir', async () => revealLogDir());
ipcMain.handle('fcp:pick-url', async () => {
  const r = await dialog.showMessageBox(win, {
    type: 'question',
    buttons: ['取消', '使用默认测速地址'],
    message: '测速地址',
    detail: '测速会经本地 SOCKS 代理真实下载该 URL。',
  });
  return r.response === 1 ? 'https://downloads.claude.ai/claude-code-releases/2.1.319/win32-x64/claude.exe' : '';
});

app.on('second-instance', () => { showWindow(); });

const gotLock = app.requestSingleInstanceLock();
if (!gotLock) {
  app.quit();
} else {
  app.whenReady().then(() => {
    createWindow();
    createTray();
  });
  // With a tray, closing the last window is only "hide"; without one there is
  // no way to bring the app back, so let it quit (before-quit stops the tunnel).
  app.on('window-all-closed', () => {
    if (!tray) app.quit();
  });
  app.on('before-quit', () => {
    isQuitting = true;
    stopTunnel();
  });
  app.on('will-quit', () => {
    if (tray) { tray.destroy(); tray = null; }
  });
}
