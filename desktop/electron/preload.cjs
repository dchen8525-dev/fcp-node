'use strict';
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('fcp', {
  start: (cfg) => ipcRenderer.invoke('fcp:start', cfg),
  stop: () => ipcRenderer.invoke('fcp:stop'),
  state: () => ipcRenderer.invoke('fcp:state'),
  version: () => ipcRenderer.invoke('fcp:version'),
  loadSettings: () => ipcRenderer.invoke('fcp:settings:load'),
  saveSettings: (patch) => ipcRenderer.invoke('fcp:settings:save', patch),
  speedStart: (cfg) => ipcRenderer.invoke('fcp:speed:start', cfg),
  speedStop: () => ipcRenderer.invoke('fcp:speed:stop'),
  openLogDir: () => ipcRenderer.invoke('fcp:open-log-dir'),
  onStats: (fn) => ipcRenderer.on('fcp:stats', (_e, p) => fn(p)),
  onLog: (fn) => ipcRenderer.on('fcp:log', (_e, p) => fn(p)),
  onState: (fn) => ipcRenderer.on('fcp:state', (_e, p) => fn(p)),
  onSpeed: (fn) => ipcRenderer.on('fcp:speed', (_e, p) => fn(p)),
});
