// Electron main process: window + tunnel child process. The tunnel never runs
// in this process -- it is spawned exactly the way the Qt shell spawns
// fcp-client, so a tunnel crash cannot take the UI down.
'use strict';

const { app, BrowserWindow, ipcMain, shell, Tray, Menu, nativeImage, nativeTheme } = require('electron');
const { spawn } = require('node:child_process');
const path = require('node:path');
const fs = require('node:fs');
const sysproxy = require('./system-proxy.cjs');

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

// ---------------------------------------------------------------- theme

// Mirrors renderer/app.js THEMES. The main process only needs two facts per
// theme: the native frame's light/dark mode and the window background, which
// is what shows through during resize and before the first paint. Keeping the
// list here avoids an IPC round trip at window-creation time.
const THEMES = {
  ink:    { dark: true,  bg: '#080d0b' },
  indigo: { dark: true,  bg: '#080a11' },
  ember:  { dark: true,  bg: '#100e0d' },
  paper:  { dark: false, bg: '#f5f2ec' },
  mist:   { dark: false, bg: '#eef1f6' },
};
let themeId = 'ink';

const themeMeta = (id) => THEMES[id] || THEMES.ink;
const normaliseTheme = (id) => (Object.prototype.hasOwnProperty.call(THEMES, id) ? id : 'ink');

/** Applies a theme to everything the renderer cannot reach: the native title
 *  bar (nativeTheme) and the window's own background. */
function applyNativeTheme(id) {
  themeId = normaliseTheme(id);
  const meta = themeMeta(themeId);
  nativeTheme.themeSource = meta.dark ? 'dark' : 'light';
  if (win && !win.isDestroyed()) win.setBackgroundColor(meta.bg);
}

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

// 体检记录与日志同目录,一行一个 JSON(JSONL),按到达时间排序。保留全部字段,
// 这样能用 jq / 文本工具按小时筛出丢包时段;写失败不能影响实时 UI。
const PROBE_LOG = () => path.join(openLogDir(), 'probe.jsonl');
function appendProbeLog(report) {
  try {
    fs.appendFileSync(PROBE_LOG(), JSON.stringify(report) + '\n', 'utf8');
  } catch (e) {
    send('fcp:log', { level: 'warn', line: `probe log: ${e.message}` });
  }
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
    tray.setToolTip('FCP Client · 未启动');
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
    { label: '退出 FCP Client', click: quitApp },
  );
  tray.setContextMenu(Menu.buildFromTemplate(template));
  tray.setToolTip(running ? `FCP Client · 运行中 · ${childState.peer || ''}`.trim() : 'FCP Client · 未启动');
}

/** One-time hint when the window is first hidden; Windows-only and silent
 *  where the platform has no balloon support. */
function notifyMinimizedToTray() {
  if (trayHintShown || !tray) return;
  trayHintShown = true;
  if (process.platform === 'win32' && typeof tray.displayBalloon === 'function') {
    try {
      tray.displayBalloon({
        title: 'FCP Client 仍在运行',
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
  // PMTUD 恒定默认开启：界面已无开关，主进程也不再发 --no-pmtud。
  // 旧存档里可能残留 pmtud:false，这里刻意不读，避免把探测关掉。
  // 两半各自透传。旧版的 `fec: "10:4"` 不再被识别,--fec= 在 CLI 侧已被拒绝。
  // 兜底值取渲染层的默认(10/4),不是 CLI 的 10/6:GUI 一直发的是 4,这里不偷偷改。
  args.push(`--fec-data=${Number.isInteger(cfg.fecData) ? cfg.fecData : 10}`);
  args.push(`--fec-parity-max=${Number.isInteger(cfg.fecParityMax) ? cfg.fecParityMax : 4}`);
  // 体检只有一个旋钮:间隔 <= 0 就是关闭,CLI 侧也没有 --no-probe。
  // 缺字段(很老的存档)当默认值 300,不让一次升级顺手把体检关掉。
  const probeSec = Number.isFinite(Number(cfg.probeInterval)) && cfg.probeInterval !== ''
    ? Math.round(Number(cfg.probeInterval)) : 300;
  args.push(`--probe-interval=${probeSec > 0 ? probeSec : 0}`);
  args.push(`--log-level=${cfg.logLevel || 'info'}`);
  // 日志默认开启、固定落在用户数据目录,界面不再提供路径框。
  // openLogDir() 会 mkdirSync,所以这里直接用它的返回值。
  args.push(`--log-file=${path.join(openLogDir(), 'client.log')}`);
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

// 末尾的 app_* 字段为应用层(浏览器真实)字节:0.0.5 及更早的隧道不带,捕获可选。
// probe_* 同理:0.0.18 及更早的隧道不发,渲染层按"未启用"处理。
const STATS_RE = /^stats\s+([\d.]+)s\s+live=(\d+)\s+up=(\d+)\s+tunnels=(\d+)\s+tx=(\d+)B\s+rx=(\d+)B\s+tx_rate=(-?\d+)B\/s\s+rx_rate=(-?\d+)B\/s(?:\s+app_rx=(\d+)B\s+app_tx=(\d+)B\s+app_rx_rate=(-?\d+)B\/s\s+app_tx_rate=(-?\d+)B\/s)?(?:\s+probe_run=(\d)\s+probe_next=(-?\d+)s\s+probe_n=(\d+)(?:\s+probe_wait=(\d))?)?/;

function startTunnel(cfg) {
  if (child) stopTunnel();
  if (!fs.existsSync(CLI_PATH)) {
    send('fcp:log', { level: 'error', line: `missing tunnel bundle: ${CLI_PATH}` });
    return { ok: false, error: 'missing tunnel bundle' };
  }
  const args = [CLI_PATH, ...statsArgs(cfg)];
  // Keep a local handle: a restarted tunnel's predecessor exits asynchronously,
  // and its handlers must not clear the new process or overwrite its state.
  // (The exit of the old child used to null out `child` after the new one was
  // already spawned, so Stop did nothing while the UI showed "stopped".)
  const proc = spawn(process.execPath, args, {
    // Electron's own binary doubles as the Node runtime: one exe, no sidecar
    // node.exe to ship. --experimental-strip-types is not needed because the
    // bundle is plain ESM.
    env: { ...process.env, ELECTRON_RUN_AS_NODE: '1' },
    windowsHide: true,
    // stdin is a local command channel (probe-now); never a remote input.
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  child = proc;
  childState = { running: true, pid: proc.pid || 0, startedAt: Date.now(),
    peer: `${cfg.host}:${cfg.port}`, listen: `${cfg.listenHost}:${cfg.listenPort}` };
  send('fcp:state', childState);
  rebuildTrayMenu();

  // 系统代理跟随连接：开关开着就接管，失败只记日志（不影响隧道本身）。
  if (readSettings().systemProxy) {
    const r = sysProxyApply();
    if (!r.ok) send('fcp:log', { level: 'warn', line: `系统代理设置失败：${r.reason || '未知原因'}` });
  }

  let buf = '';
  proc.stdout.setEncoding('utf8');
  proc.stdout.on('data', (chunk) => {
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
          // 应用层(浏览器真实)字节:0.0.5 及更早的隧道不携带 → undefined,
          // 渲染层自行降级到 wire 值显示。
          appRx: m[9] !== undefined ? Number(m[9]) : undefined,
          appTx: m[10] !== undefined ? Number(m[10]) : undefined,
          appRxRate: m[11] !== undefined ? Number(m[11]) : undefined,
          appTxRate: m[12] !== undefined ? Number(m[12]) : undefined,
          // 空闲链路体检:probe_next 为 -1 表示未启用,-2 之类不会出现。
          probeRun: m[13] !== undefined ? m[13] === '1' : undefined,
          probeNextSec: m[14] !== undefined ? Number(m[14]) : undefined,
          probeCount: m[15] !== undefined ? Number(m[15]) : undefined,
          // 到点但链路有流量,隧道在等空闲:界面不该再显示一个会被推迟的倒计时。
          probeWait: m[16] !== undefined ? m[16] === '1' : undefined,
        });
        return;
      }
      // One line per finished idle measurement. Not a log line: the log page is
      // for what went wrong, and a probe that worked is not an event.
      if (line.startsWith('probe ')) {
        try {
          // `at` is the tunnel's monotonic clock (process uptime), useless as a
          // timestamp; the shelf stamps the arrival time instead. Both the ms
          // epoch and an ISO string go out: the UI needs the number, the JSONL
          // log is meant to be read by humans/tools by hour of day.
          const recvAt = Date.now();
          const report = { ...JSON.parse(line.slice(6)), recvAt, atIso: new Date(recvAt).toISOString() };
          appendProbeLog(report);
          send('fcp:probe', report);
        } catch {
          send('fcp:log', { level: 'warn', line: `probe: unparsable result ${line.slice(6, 120)}` });
        }
        return;
      }
      send('fcp:log', { level: 'info', line });
    }
  });
  proc.stderr.setEncoding('utf8');
  proc.stderr.on('data', (chunk) => {
    for (const raw of chunk.split('\n')) {
      const line = raw.trimEnd();
      if (!line) continue;
      send('fcp:log', { level: classify(line), line });
    }
  });
  proc.on('exit', (code, signal) => {
    if (child !== proc) return; // a superseded process: leave the live state alone
    const wasRunning = childState.running;
    child = null;
    childState = { running: false, pid: 0, startedAt: 0, peer: '', listen: '' };
    send('fcp:state', childState);
    rebuildTrayMenu();
    if (wasRunning) {
      send('fcp:log', { level: code === 0 ? 'info' : 'error',
        line: `tunnel exited: code=${code} signal=${signal || 'none'}` });
      // 异常退出也要交还可能由我们接管的系统代理，否则浏览器会继续访问
      // 已经关闭的本地端口，表现为整机无法上网。
      const r = sysProxyRestore();
      if (!r.ok) send('fcp:log', { level: 'warn', line: `系统代理恢复失败：${r.reason || '未知原因'}` });
    }
  });
  proc.on('error', (e) => {
    if (child !== proc) return;
    send('fcp:log', { level: 'error', line: `tunnel spawn failed: ${e.message}` });
    child = null;
    childState = { running: false, pid: 0, startedAt: 0, peer: '', listen: '' };
    send('fcp:state', childState);
    rebuildTrayMenu();
    const r = sysProxyRestore();
    if (!r.ok) send('fcp:log', { level: 'warn', line: `系统代理恢复失败：${r.reason || '未知原因'}` });
  });
  return { ok: true, pid: proc.pid };
}

function stopTunnel() {
  const c = child;
  if (c) {
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
  }
  childState = { running: false, pid: 0, startedAt: 0, peer: '', listen: '' };
  send('fcp:state', childState);
  rebuildTrayMenu();
  // 断开就交还系统代理：留着它会让整机断网（代理端口已经不在了）。
  const r = sysProxyRestore();
  if (!r.ok) send('fcp:log', { level: 'warn', line: `系统代理恢复失败：${r.reason || '未知原因'}` });
  return { ok: true };
}

// ---------------------------------------------------------------- system proxy

/** 当前本地代理地址（未连接时用设置里的值，保证"先设系统代理"也能用）。 */
function currentListen() {
  if (childState.listen && childState.listen !== ':') {
    const i = childState.listen.lastIndexOf(':');
    return { host: childState.listen.slice(0, i) || '127.0.0.1', port: Number(childState.listen.slice(i + 1)) || 1080 };
  }
  const s = readSettings();
  return { host: s.listenHost || '127.0.0.1', port: s.listenPort || 1080 };
}

function sysProxyStatus() {
  const { host, port } = currentListen();
  const st = sysproxy.readState();
  return {
    supported: sysproxy.IS_WIN,
    applied: sysproxy.isAppliedTo(app.getPath('userData'), host, port),
    server: st ? st.server : '',
    enabled: st ? st.enable === 1 : false,
    target: `${host}:${port}`,
  };
}

function sysProxyApply() {
  const { host, port } = currentListen();
  const r = sysproxy.apply(app.getPath('userData'), host, port);
  send('fcp:sysproxy', sysProxyStatus());
  return r;
}

function sysProxyRestore() {
  const r = sysproxy.restore(app.getPath('userData'), { onlyIfOurs: true });
  send('fcp:sysproxy', sysProxyStatus());
  return r;
}

// ---------------------------------------------------------------- window

function createWindow() {
  win = new BrowserWindow({
    width: 980, height: 700, minWidth: 820, minHeight: 600,
    backgroundColor: themeMeta(themeId).bg,
    title: 'FCP Client',
    icon: ICON_PATH,
    show: false,
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload.cjs'),
      contextIsolation: true,
      nodeIntegration: false,
      // The preload only uses contextBridge/ipcRenderer, both available in a
      // sandboxed renderer. Leaving the sandbox off removed the last defence
      // for a window that only ever shows local content.
      sandbox: true,
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
// Synchronous on purpose: the preload reads it while the document is still
// empty, so the stored palette is on <html> before the first paint.
ipcMain.on('fcp:theme:boot', (e) => { e.returnValue = themeId; });
ipcMain.handle('fcp:theme:set', (_e, t) => {
  applyNativeTheme(t && t.id);
  return themeId;
});
ipcMain.handle('fcp:start', (_e, cfg) => startTunnel(cfg || {}));
ipcMain.handle('fcp:stop', () => stopTunnel());
ipcMain.handle('fcp:state', () => childState);
ipcMain.handle('fcp:version', () => app.getVersion());
// Manual "measure now": a line on the child's stdin. The tunnel queues it on
// its next tick and bypasses the idle/schedule gates; the result comes back on
// the normal probe channel (and is appended to probe.jsonl).
ipcMain.handle('fcp:probe:now', () => {
  if (!child || !child.stdin || childState.running === false) return { ok: false, error: '代理未运行' };
  child.stdin.write('probe\n');
  return { ok: true };
});
ipcMain.handle('fcp:open-log-dir', async () => revealLogDir());

// ---- 系统代理（WinINET）----
// 只暴露只读状态：接管/恢复由连接与断开自动完成，界面不提供手动开关。
ipcMain.handle('fcp:sysproxy:status', () => sysProxyStatus());
app.on('second-instance', () => { showWindow(); });

const gotLock = app.requestSingleInstanceLock();
if (!gotLock) {
  app.quit();
} else {
  app.whenReady().then(() => {
    // 上次进程如果没干净退出（崩溃 / 强杀），系统代理可能还指着我们的端口，
    // 而端口已经没了 —— 那会让整机断网。启动时只有在当前代理确实是我们设的
    // 值时才恢复，用户后来自己改过的不碰。
    const leftover = sysproxy.restore(app.getPath('userData'), { onlyIfOurs: true });
    if (leftover.ok && !leftover.skipped) {
      send('fcp:log', { level: 'info', line: '已清理上次残留的系统代理设置' });
    }
    // The stored theme decides the native title bar and the window background.
    // Doing it before createWindow() is what keeps a light theme from opening
    // with a dark frame for the first frame.
    applyNativeTheme(readSettings().theme);
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
    stopTunnel();   // 内部会恢复系统代理
  });
  app.on('will-quit', () => {
    if (tray) { tray.destroy(); tray = null; }
  });
}
