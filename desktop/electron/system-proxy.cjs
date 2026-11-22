// Windows 系统代理（WinINET）的接管与恢复。
//
// 为什么需要它：桌面客户端只在 127.0.0.1:1080 起一个混合代理端口，应用不会
// 自动走它。把 WinINET 的 ProxyEnable/ProxyServer 指过来，浏览器、Electron
// 应用和所有遵守系统代理的程序就立刻可用——这是 Windows 上唯一不需要内核
// 驱动就能生效的方式（按进程分流需要 WFP/WinDivert 驱动，本包不做）。
//
// 关键约束：改注册表后必须调用 InternetSetOption(SETTINGS_CHANGED/REFRESH)，
// 否则 WinINET 一直用进程启动时缓存的值，用户会以为"没生效"。这两条消息只在
// 用户态广播，不需要管理员权限。
//
// 恢复策略：接管前把原始 ProxyEnable/ProxyServer/ProxyOverride/AutoConfigURL
// 存到 userData 备份文件，断开或退出时写回。备份文件同时是"上次没有干净退出"
// 的判据——下次启动时若它还在一律先恢复，避免把用户永久留在我们的代理上。
'use strict';

const { spawnSync } = require('node:child_process');
const path = require('node:path');
const fs = require('node:fs');

const IS_WIN = process.platform === 'win32';
const REG_PATH = 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings';

function backupPath(userDataDir) {
  return path.join(userDataDir, 'system-proxy-backup.json');
}

/** 用 PowerShell 执行一段脚本；返回 stdout 或 null。不经过 shell，免转义。 */
function ps(script) {
  if (!IS_WIN) return null;
  const r = spawnSync('powershell.exe',
    ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', script],
    { encoding: 'utf8', timeout: 15000, windowsHide: true });
  if (r.status !== 0 || !r.stdout) return null;
  return r.stdout.trim();
}

/** 广播设置变更，让已经在跑的 WinINET 应用重新读取代理。 */
const REFRESH_SNIPPET = `
$sig = '[DllImport("wininet.dll", SetLastError=true)] public static extern bool InternetSetOption(IntPtr h, int opt, IntPtr buf, int len);'
$t = Add-Type -MemberDefinition $sig -Name FcpWinInet -Namespace Fcp -PassThru
[void]$t::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0)
[void]$t::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0)
`;

/** 读当前系统代理状态：{enable, server, override, pac}；读取失败返回 null。 */
function readState() {
  if (!IS_WIN) return null;
  const out = ps(`
$k = '${REG_PATH}'
$p = Get-ItemProperty -Path $k -ErrorAction Stop
$o = [ordered]@{
  enable   = [int]($p.ProxyEnable)
  server   = [string]($p.ProxyServer)
  override = [string]($p.ProxyOverride)
  pac      = [string]($p.AutoConfigURL)
}
$o | ConvertTo-Json -Compress
`);
  if (!out) return null;
  try {
    const j = JSON.parse(out);
    return {
      enable: Number(j.enable) || 0,
      server: j.server || '',
      override: j.override || '',
      pac: j.pac || '',
    };
  } catch {
    return null;
  }
}

/**
 * 把系统代理指向 host:port，并备份原值。
 * @returns {{ok: boolean, reason?: string}}
 */
function apply(userDataDir, host, port) {
  if (!IS_WIN) return { ok: false, reason: '仅 Windows 支持系统代理接管' };
  const server = `${host}:${port}`;

  // 已经指向我们：只刷新一次，不覆盖备份（否则会把我们自己的值当成"原值"）
  const cur = readState();
  if (cur && cur.enable === 1 && cur.server === server) {
    ps(REFRESH_SNIPPET);
    return { ok: true, alreadyApplied: true };
  }

  const backup = backupPath(userDataDir);
  if (!fs.existsSync(backup)) {
    if (!cur) return { ok: false, reason: '无法读取当前系统代理设置' };
    try {
      fs.writeFileSync(backup, JSON.stringify({
        appliedAt: Date.now(),
        server,
        original: cur,
      }, null, 2));
    } catch (e) {
      return { ok: false, reason: `写备份失败：${e.message}` };
    }
  }

  const out = ps(`
$k = '${REG_PATH}'
Set-ItemProperty -Path $k -Name ProxyEnable   -Value 1 -Type DWord
Set-ItemProperty -Path $k -Name ProxyServer   -Value '${server}' -Type String
Set-ItemProperty -Path $k -Name ProxyOverride -Value '<local>' -Type String
# PAC 优先级高于 ProxyServer，留着它我们就不会生效；原值已在备份里
Remove-ItemProperty -Path $k -Name AutoConfigURL -ErrorAction SilentlyContinue
${REFRESH_SNIPPET}
Write-Output OK
`);
  return out === 'OK' ? { ok: true } : { ok: false, reason: '写入注册表失败' };
}

/**
 * 恢复接管前的设置并删除备份。
 * @param {{onlyIfOurs?: boolean}} opts onlyIfOurs=true 时，仅当当前代理确实是
 *        我们设置的值才恢复——用于"启动时发现上次残留"的自动清理。
 * @returns {{ok: boolean, reason?: string, skipped?: boolean}}
 */
function restore(userDataDir, opts = {}) {
  if (!IS_WIN) return { ok: false, reason: '仅 Windows 支持系统代理接管' };
  const backup = backupPath(userDataDir);
  if (!fs.existsSync(backup)) return { ok: true, skipped: true };

  let saved;
  try {
    saved = JSON.parse(fs.readFileSync(backup, 'utf8'));
  } catch {
    // 备份坏了：宁可不动注册表，让用户手动检查，也不要盲写
    return { ok: false, reason: '备份文件损坏，未改动系统代理' };
  }

  const cur = readState();
  if (opts.onlyIfOurs && cur && !(cur.enable === 1 && cur.server === saved.server)) {
    // 用户后来自己改过代理：删掉陈旧备份，别再碰
    try { fs.unlinkSync(backup); } catch { /* ignore */ }
    return { ok: true, skipped: true };
  }

  const o = saved.original || {};
  const setEnable = Number(o.enable) === 1 ? 1 : 0;
  const setServer = (o.server || '').replace(/'/g, "''");
  const setOverride = (o.override || '').replace(/'/g, "''");
  const pac = (o.pac || '').replace(/'/g, "''");
  const pacLine = pac
    ? `Set-ItemProperty -Path $k -Name AutoConfigURL -Value '${pac}' -Type String`
    : `Remove-ItemProperty -Path $k -Name AutoConfigURL -ErrorAction SilentlyContinue`;

  const out = ps(`
$k = '${REG_PATH}'
Set-ItemProperty -Path $k -Name ProxyEnable   -Value ${setEnable} -Type DWord
Set-ItemProperty -Path $k -Name ProxyServer   -Value '${setServer}' -Type String
Set-ItemProperty -Path $k -Name ProxyOverride -Value '${setOverride}' -Type String
${pacLine}
${REFRESH_SNIPPET}
Write-Output OK
`);
  if (out !== 'OK') return { ok: false, reason: '恢复注册表失败' };
  try { fs.unlinkSync(backup); } catch { /* ignore */ }
  return { ok: true };
}

/** 当前是否仍指在被我们接管的状态（UI 显示用）。 */
function isAppliedTo(userDataDir, host, port) {
  const backup = backupPath(userDataDir);
  if (!fs.existsSync(backup)) return false;
  const cur = readState();
  return !!cur && cur.enable === 1 && cur.server === `${host}:${port}`;
}

module.exports = { IS_WIN, readState, apply, restore, isAppliedTo };
