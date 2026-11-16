'use strict';

// Applies the stored theme before the first paint.
//
// The preload has already asked the main process which theme is on disk, so the
// attribute is set here — inside <head>, ahead of the stylesheet — instead of
// waiting for app.js. Without this a light theme paints the dark default for a
// frame or two, which reads as a flash on every launch.
(() => {
  const KNOWN = ['ink', 'indigo', 'ember', 'paper', 'mist'];
  let id = 'ink';
  try {
    id = (window.fcp && window.fcp.bootTheme) || 'ink';
  } catch {
    // A preload without the theme bridge (older build): keep the default.
  }
  document.documentElement.dataset.theme = KNOWN.includes(id) ? id : 'ink';
})();
