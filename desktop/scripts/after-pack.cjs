// afterPack: strip Electron runtime components this app never uses.
//
// The shell UI is plain DOM + 2D canvas (renderer/app.js getContext('2d'));
// no WebGPU and no WebGL. That makes these safe to drop:
//   dxcompiler.dll          - Dawn's HLSL shader compiler, loaded only when
//                             WebGPU is actually used (~25 MB, the single
//                             biggest file after the main exe)
//   vk_swiftshader.dll      - software-Vulkan fallback for WebGL/WebGPU on
//                             machines without GPU drivers; 2D canvas goes
//                             through ANGLE/D3D11 (d3dcompiler_47.dll, kept)
//                             and never reaches it
//   vk_swiftshader_icd.json - its loader manifest
// d3dcompiler_47.dll, libEGL/libGLESv2 and ffmpeg.dll stay: ANGLE and the
// media pipeline need them. If this app ever grows a <video> tag or a WebGL
// chart, restore these files by deleting this hook.
const { unlinkSync, existsSync } = require('node:fs');
const { join } = require('node:path');

const DROP = [
  'dxcompiler.dll',
  'vk_swiftshader.dll',
  'vk_swiftshader_icd.json',
];

exports.default = async function afterPack(context) {
  let bytes = 0;
  for (const name of DROP) {
    const p = join(context.appOutDir, name);
    if (existsSync(p)) {
      bytes += require('node:fs').statSync(p).size;
      unlinkSync(p);
    }
  }
  if (bytes > 0) {
    console.log(`after-pack: stripped ${(bytes / 1048576).toFixed(1)} MB of unused WebGPU/SwiftShader components`);
  }
};
