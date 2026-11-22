'use strict';
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('fcp', {
  // Read synchronously, before any page script runs: theme-boot.js needs the
  // answer to set data-theme ahead of the first paint (see renderer/theme-boot.js).
  bootTheme: (() => {
    try { return ipcRenderer.sendSync('fcp:theme:boot'); } catch { return 'ink'; }
  })(),
  setTheme: (t) => ipcRenderer.invoke('fcp:theme:set', t),
  start: (cfg) => ipcRenderer.invoke('fcp:start', cfg),
  stop: () => ipcRenderer.invoke('fcp:stop'),
  state: () => ipcRenderer.invoke('fcp:state'),
  version: () => ipcRenderer.invoke('fcp:version'),
  loadSettings: () => ipcRenderer.invoke('fcp:settings:load'),
  saveSettings: (patch) => ipcRenderer.invoke('fcp:settings:save', patch),
  probeNow: () => ipcRenderer.invoke('fcp:probe:now'),
  sysProxyStatus: () => ipcRenderer.invoke('fcp:sysproxy:status'),
  sysProxyApply: () => ipcRenderer.invoke('fcp:sysproxy:apply'),
  sysProxyRestore: () => ipcRenderer.invoke('fcp:sysproxy:restore'),
  onSysProxy: (fn) => ipcRenderer.on('fcp:sysproxy', (_e, p) => fn(p)),
  openLogDir: () => ipcRenderer.invoke('fcp:open-log-dir'),
  onStats: (fn) => ipcRenderer.on('fcp:stats', (_e, p) => fn(p)),
  onProbe: (fn) => ipcRenderer.on('fcp:probe', (_e, p) => fn(p)),
  onLog: (fn) => ipcRenderer.on('fcp:log', (_e, p) => fn(p)),
  onState: (fn) => ipcRenderer.on('fcp:state', (_e, p) => fn(p)),
});
