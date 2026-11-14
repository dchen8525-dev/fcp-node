# 发布打包

三个脚本，产物统一落在仓库根目录的 `dist/`（已 gitignore）。
所有下载缓存放在 `packaging/.cache/`，同样不进版本库。

## Linux 服务端 deb

```bash
npm run pack:deb
# -> dist/fcp-server_<version>_amd64.deb
```

- 内嵌官方 Node.js `22.22.2` linux-x64（Debian 13 源里的 Node 太旧），并校验
  `SHASUMS256.txt`；包本身不依赖系统 nodejs。tarball 先走 npmmirror，失败再走
  nodejs.org，校验和始终取 nodejs.org。
- 依赖只有 `libc6` / `libstdc++6` / `libgcc-s1`。
- `.deb` 由 `packaging/linux/deb.mjs` 直接生成（ar + control/data.tar.gz），不依赖
  dpkg-deb、nfpm 或任何外部打包工具；唯一外部命令是解 Node tarball 用的 `tar`。
- 文件布局：
  - `/opt/fcp-node/node/bin/node`、`/opt/fcp-node/fcp-server.mjs`（esbuild 单文件 bundle）
  - `/usr/bin/fcp-server`（读取环境变量的启动器）
  - `/usr/lib/systemd/system/fcp-node.service`
  - `/etc/fcp-node/server.conf`（conffile，`0640 root:fcp-node`）
  - `/var/log/fcp-node/server.log`（systemd `LogsDirectory=`）
- `preinst` 建 `fcp-node` 系统用户；`postinst` 在仍是占位符时生成随机 PSK 并打印一次；
  `prerm` 停止并禁用服务；`postrm` 仅在 `purge` 时删用户、配置目录与日志。
- 服务默认**不自动启动**：先改 `/etc/fcp-node/server.conf`，再
  `systemctl enable --now fcp-node`。

环境变量（全部有默认值，通常只改 `FCP_KEY`）：

| 变量 | 默认 |
|---|---|
| `FCP_KEY` | 首次安装随机生成 |
| `FCP_BIND` | `0.0.0.0:4461` |
| `FCP_MTU_MIN` / `FCP_MTU_MAX` | `1040` / `1500` |
| `FCP_FEC` | `10:4` |
| `FCP_LOG_LEVEL` / `FCP_LOG_FILE` | `info` / `/var/log/fcp-node/server.log` |

可覆盖的构建变量：`FCP_NODE_VERSION`（默认 `22.22.2`）。

## Windows 命令行客户端 exe

```bash
npm run pack:client-exe
# -> dist/fcp-client-<version>.exe
```

Node SEA：esbuild 打成 CJS（`packaging/win/client-entry.ts` 强制 client 模式）→
`node --experimental-sea-config` 生成 blob → 复制当前 `node.exe` → `postject` 注入。
产物是单文件，不需要目标机装 Node；脚本结尾会跑一次 `-h` 冒烟并校验版本号。
需要 `desktop/node_modules/esbuild`（`npm --prefix desktop install`），否则退回 `npx esbuild`。

## Windows 桌面端

```bash
npm --prefix desktop install
npm --prefix desktop run pack
# -> desktop/dist/fcp-node-<version>-portable.exe
# -> desktop/dist/fcp-node-setup-<version>.exe
```

国内下载 Electron / NSIS 工具链需要镜像：

```bash
ELECTRON_MIRROR=https://npmmirror.com/mirrors/electron/ \
ELECTRON_BUILDER_BINARIES_MIRROR=https://npmmirror.com/mirrors/electron-builder-binaries/ \
  npm --prefix desktop run pack
```

版本号唯一来源是根 `package.json`；`src/constants.ts` 的 `PRODUCT_VERSION`、
`desktop/package.json` 与安装包文件名都应与它一致。

## GitHub Actions 自动发布

`.github/workflows/release.yml`：推 tag（`0.0.3` 或 `v0.0.3`）时，ubuntu 构建
deb、windows 构建 client exe 与桌面安装包，自动创建同名 Release（已存在则复用）
并上传 4 个资产 + `sha256sums.txt`（`--clobber`，重跑可覆盖）。`workflow_dispatch`
手动触发只构建不发布，产物在 Actions 页面下载检查。`verify` 作业会先校验 tag
与根 `package.json` 版本一致。首次手工发 0.0.3 后旧资产不会自动删除，如需替换
请在 Release 页面处理。
