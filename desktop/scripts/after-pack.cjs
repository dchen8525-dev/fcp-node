// afterPack: strip Electron runtime components this app never uses.
//
// The shell UI is plain DOM + 2D canvas (renderer/app.js getContext('2d'));
// no WebGPU, no WebGL, no <video>/<audio>. That makes these safe to drop:
//   dxcompiler.dll          - Dawn's HLSL shader compiler, loaded only when
//                             WebGPU is actually used (~25 MB, the single
//                             biggest file after the main exe)
//   vk_swiftshader.dll      - software-Vulkan fallback for WebGL/WebGPU on
//                             machines without GPU drivers; 2D canvas goes
//                             through ANGLE/D3D11 (d3dcompiler_47.dll, kept)
//                             and never reaches it
//   vk_swiftshader_icd.json - its loader manifest
//   vulkan-1.dll            - the Vulkan loader; with every Vulkan consumer
//                             above gone nothing ever loads it (~0.9 MB,
//                             renderer verified to spawn without it)
//   electron_wer.dll        - Windows Error Reporting integration; only
//                             crash-dump quality is affected (~0.4 MB,
//                             renderer verified to spawn without it)
// NOT removable (measured 2026-11-15, both hang startup before the renderer
// spawns — GPU + network children only, no --type=renderer process):
//   chrome_200_percent.pak  - ResourceBundle registers the 200% DPI pack at
//                             startup, it is not a lazy asset (~0.9 MB)
//   ffmpeg.dll              - the media stack initializes the library at
//                             startup, not on first media use (~3.1 MB)
// LICENSES.chromium.html is REPLACED with a short notice carrying the
// Chromium BSD-3 attribution plus a pointer to the full upstream bundle
// (5.7 MB of generated text for a GUI that ships none of it to users).
// d3dcompiler_47.dll and libEGL/libGLESv2 stay: ANGLE's D3D11 path needs
// them, and without GPU rendering the window would go blank. If this app
// ever grows a <video> tag, a WebGL chart, or WebGPU, restore those files
// by deleting this hook.
const { unlinkSync, writeFileSync, statSync, existsSync } = require('node:fs');
const { join } = require('node:path');

const DROP = [
  'dxcompiler.dll',
  'vk_swiftshader.dll',
  'vk_swiftshader_icd.json',
  'vulkan-1.dll',
  'electron_wer.dll',
];

const LICENSES_SHORT = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Third-party notices</title></head>
<body><pre>
Chromium
Copyright (c) The Chromium Authors. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

  1. Redistributions of source code must retain the above copyright notice,
     this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in the
     documentation and/or other materials provided with the distribution.
  3. Neither the name of Google Inc. nor the names of its contributors may
     be used to endorse or promote products derived from this software
     without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

Electron is MIT licensed; see LICENSE.electron.txt next to this file.

The generated license text for every third-party component compiled into
this Chromium build is shipped upstream and readable at:
https://github.com/electron/electron/blob/main/LICENSES.chromium.html
</pre></body></html>
`;

exports.default = async function afterPack(context) {
  let bytes = 0;
  for (const name of DROP) {
    const p = join(context.appOutDir, name);
    if (existsSync(p)) {
      bytes += statSync(p).size;
      unlinkSync(p);
    }
  }
  // Replace, don't delete: the attribution stays in the package, only the
  // megabytes of generated boilerplate go.
  const lic = join(context.appOutDir, 'LICENSES.chromium.html');
  if (existsSync(lic)) {
    bytes += statSync(lic).size - Buffer.byteLength(LICENSES_SHORT);
    writeFileSync(lic, LICENSES_SHORT);
  }
  if (bytes > 0) {
    console.log(`after-pack: stripped ${(bytes / 1048576).toFixed(1)} MB of unused WebGPU/SwiftShader/media/DPI components`);
  }
};
