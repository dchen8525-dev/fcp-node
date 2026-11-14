# FCP Node 桌面端（Electron）

一个薄壳：**隧道不在这里**。真正的代理是同一仓库 `src/app/cli.ts` 编译出的
`resources/cli.mjs`，由主进程以子进程方式启动，接口与 C++ 版的 `fcp-client`
完全一致（同一套 12 参数白名单、同一行 `stats` 格式）。

页面结构沿用 `../fcp/apps/desktop`（Qt Widgets 版），视觉改为深色控制台：

| 项 | Qt 版 | 这里 |
|---|---|---|
| 配色 | 浅色 `#f4f7f5` / `#e6ede9` / `#0f9d76` / `#f0b46a` | 近黑绿底、翡翠绿强调、琥珀色上行；`nativeTheme` 同步深色标题栏 |
| 页面 | 连接 / 状态 / 测速 / 日志 | 同四页 |
| 图表 | `QPainter` sparkline | Canvas 双线 + 渐变填充 |
| 测速 | `fcp-client --speedtest` 对远端打流 | 经本地 SOCKS 真实下载（见下） |

## 为什么测速要自己实现

Node 版的 `speedtest` 子命令是**进程内自环**（自己起 echo server 再自己连），
测的是本机回环，与用户关心的链路无关。C++ 版没有这个问题，因为它的测速是
对远端 server 打流。

所以测速页不复用子命令，而是由主进程写一个最小 SOCKS5 客户端，经当前本地
代理真实下载用户给的 URL，统计 5 秒/10 秒窗口内的字节数。TLS 走
`tls.connect({ socket })`，明文 HTTP 直接写请求行。

## 目录

```
electron/main.cjs     窗口、托盘、子进程管理、stats 解析、SOCKS 测速
electron/preload.cjs  contextBridge 暴露的 IPC 面
renderer/index.html   四页结构
renderer/styles.css   视觉（深色控制台主题、卡片分层、等宽数字）
renderer/app.js       导航、表单校验、图表、日志、测速交互
scripts/build-tunnel.mjs  esbuild 把 src/app/cli.ts 打成一个 ESM
scripts/cdp.mjs           自测用：CDP eval / reload / 截图
```

## 构建

```bash
cd desktop
npm install
npm run build:tunnel     # -> resources/cli.mjs（约 170 KiB）
npm start                # 开发模式起窗口
npm run pack             # -> dist/fcp-node-<version>-portable.exe + dist/fcp-node-setup-<version>.exe
npm run pack:nsis        # 只打 NSIS 安装包
```

NSIS 安装包为 per-user 安装（无需管理员），向导里可以改安装目录，创建桌面
与开始菜单快捷方式；卸载默认保留 `%APPDATA%\fcp-desktop` 下的设置与日志。

Electron 二进制与 electron-builder 的 NSIS 工具都在境外，国内首次安装需要
镜像：

```bash
ELECTRON_MIRROR=https://npmmirror.com/mirrors/electron/ node node_modules/electron/install.js
ELECTRON_BUILDER_BINARIES_MIRROR=https://npmmirror.com/mirrors/electron-builder-binaries/ npm run pack
```

## 关键实现取舍

**单 exe，不额外带 node.exe。** 子进程用 `process.execPath`（Electron 自己）
加 `ELECTRON_RUN_AS_NODE=1` 启动，等价于一个 Node 运行时。因此
`build.asar` 必须为 `false`：`ELECTRON_RUN_AS_NODE` 模式下 asar 虚拟文件系统
不可靠，bundle 会读不到。

**stats 走 stdout，日志走 stderr。** 隧道每 500 ms 打一行

```
stats 12.4s live=1 up=1 tunnels=1 tx=1620549B rx=177108615B tx_rate=321448B/s rx_rate=40114944B/s
```

这一行不受 `--log-level` 影响 —— `error` 级别下也照发，否则界面在大流量时
反而没有曲线。`src/app/tunnel.ts` 的 `onStats` 回调就是为此加的。

**密钥不进设置文件。** `settings.json` 只存地址、端口、MTU、FEC、日志级别；
`--key` 每次启动从输入框读，和 C++ 版、Node CLI 一样内联进进程命令行。
界面里明确写了这一点。

**托盘常驻。** 主进程创建系统托盘（`resources/icon.png` 缩放到 16 px）。关闭
窗口只 `hide()`，隧道继续运行；托盘菜单提供「显示主窗口 / 停止隧道 / 打开日志
目录 / 退出」，左键单击或双击托盘图标会恢复窗口。只有托盘的「退出」（或系统
退出）会置 `isQuitting` 并终止子进程；托盘创建失败时关窗仍会真正退出，避免
出现无窗口也无法找回的僵尸进程。

## 自测

```bash
# 起一个对端
node ../src/app/server.ts --key=<HEX32> -b 127.0.0.1:4473 --log-level=debug

# 起带调试端口的壳
ELECTRON_RUN_AS_NODE= ./node_modules/electron/dist/electron.exe . --remote-debugging-port=9222

# 驱动与截图
node scripts/cdp.mjs reload
node scripts/cdp.mjs eval "document.getElementById('host').value='127.0.0.1'; 'ok'"
node scripts/cdp.mjs shot shot.png 980 700
```

`ELECTRON_RUN_AS_NODE` 一旦在 shell 里被导出，后续 `electron .` 会退化成
纯 Node 模式并报 `app.isPackaged` undefined。启动前用 `env -u` 清掉。
