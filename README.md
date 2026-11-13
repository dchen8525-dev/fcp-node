# fcp-node

FCP v7 UDP 隧道的 Node.js / TypeScript 改写，位于 `D:\work\fcp-node`，原 C++ 工程 `D:\work\fcp` 保持不动。

**验收范围（2026-11-11 用户裁定）**：C++ 服务端自身存在 bug，**不要求**与任何 C++ 二进制互通。
C++ 源码只作为线格式参考；唯一验收线是 **Node 服务端与 Node 客户端能握手并实际代理流量**。
线格式契约见 [`docs/协议格式.md`](docs/协议格式.md)，实现差异见 [`docs/移植对照与差异.md`](docs/移植对照与差异.md)。

## 环境要求

- Node.js **>= 22.6**（实测 v22.22.2），依赖其原生 TypeScript strip-types，直接 `node xxx.ts`
- **零运行时依赖、零构建步骤**：只用 `node:crypto` / `node:dgram` / `node:net` / `node:test` / `node:fs`
- 不需要 `npm install`，不需要 `tsc`

## 快速开始

用**两个终端**分别启动（PSK 两端必须一致，16 字节 = 32 个十六进制字符）：

```bash
# 终端 1：服务端（VPS 上跑这个）
node src/app/server.ts --key=00112233445566778899aabbccddeeff -b 0.0.0.0:4460

# 终端 2：客户端（本地跑这个）
node src/app/client.ts --key=00112233445566778899aabbccddeeff --peer=127.0.0.1:4460 -b 127.0.0.1:1080
```

同一个本地端口 `1080` 同时说三种代理协议：

```bash
curl --socks5-hostname 127.0.0.1:1080 https://example.com
curl -x http://127.0.0.1:1080 https://example.com          # HTTP CONNECT
curl -x http://127.0.0.1:1080 http://example.com/index.html # absolute-form / 正向代理
```

PSK 在本项目的部署方式里是**直接内联**的（两端同一个值，32 位十六进制）：

```bash
--key=00112233445566778899aabbccddeeff
```

密钥只有一个来源：`--key=HEX32`，必须显式给出，两端相同。
`--key-env` / 隐式 `FCP_PSK` / `--key-file` / `--psk-file` / `-k` 全部删除 —— 环境变量与文件都只是把同一串 32 位十六进制绕一圈再交给 `--key`。

**握手是按需触发的**：客户端在收到第一条本地代理连接时才为该连接创建会话（一个本地 TCP 连接 = 一个 salt = 一条 FCP 会话），所以刚启动进程时还没有握手；发起第一次 `curl` 后，两端日志会出现 `FCP established: ...`。

## 主要参数

| 参数 | 默认值 | 说明 |
|---|---|---|
| `--key=HEX32` | 必填 | 16 字节预共享密钥，32 位十六进制；两端必须相同。`--key-env` / `FCP_PSK` / `--key-file` / `--psk-file` / `-k` 已全部删除，写了会直接报错；格式错只报字符数，不回显密钥 |
| `-b, --bind=IP[:P]` | 服务端 `0.0.0.0:4460`；客户端 `127.0.0.1:1080` | **本机监听地址**，两端同一个参数同一个含义：服务端是 UDP 监听，客户端是本地代理入口（一个端口同时说 SOCKS5 / HTTP CONNECT / absolute-form） |
| `--peer=IP[:P]`（客户端） | 必填 | 服务端 UDP 地址（往哪连）。`-H` / `--host` 已删除 |
| `-p, --port=N` | ~~已删除~~ | **写端口要用地址里的 `:P`**（`-b 0.0.0.0:4461` / `--peer=IP:4461`）。原来是第二个说法，写错时会静默覆盖地址里的端口 |
| `--mtu-min=N` | `1040` | PMTUD 的**起点（下限）**，也是 `--no-pmtud` 时的固定预算。含 20 B IP + 8 B UDP 头，允许 128..9000。它是下限不是上限：探测会从这里向上走。旧名 `--packet-size` / `--mtu` / `-m` 已移除，写了会直接报错 |
| `--mtu-max=N` | `1500` | 探测上限，允许 128..9000，必须 ≥ `--mtu-min`；步长 100 B（1040→1500 共 5 步） |
| `--fec=D:P` | `10:3` | 每集合 D 个数据 symbol，P 既是冗余**槽位上限**，也是控制器能把 k 涨到的上限（取协商后的 `min(本端P, 对端P)`）。发送端从 `min(3,P)` 起步，之后按丢包反馈自行增减 k；`--parity` / `--k` / `--fec-budget` 已移除（写了会直接报错） |
| `--fec-budget=R` | ~~已删除~~ | 冗余上限就是 `--fec=D:P` 里的 P：控制器最高只能把 k 涨到协商后的 P，超过的冗余包对端会当 `IndexPastS` 丢弃 |
| `--no-pmtud` | 探测默认**开** | 唯一的关闭方式：把整包预算固定在 `--mtu-min`。反向开关 `--pmtud` 已移除（探测本来就是默认，写了会直接报错） |
| `--key-update` | ~~已删除~~ | `#84` epoch 换密钥（TLV type=4）**已经常开**：两端都发布该 TLV 时自动启用，只有一端支持时自动保持关闭、连接照常跑 |
| `--ack-v2` | ~~已删除~~ | 宽 ACK（一次最多 64 个 SACK 块）**已经常开**，不再有开关；对端不支持时会自己退回旧 ACK |
| `--tlv` | ~~已删除~~ | 它本身不发布任何 TLV 类型，写不写都改不了线上内容 |
| `--trace=PREFIX` | 无 | 每会话控制器 JSONL 轨迹，一个会话一个文件：`<PREFIX>-client-<salt>.jsonl` / `-server-<salt>.jsonl`。目录不存在会自动创建；写不进只打一条 `WRN` 并关闭该文件，不影响隧道。回读用 `node src/app/replay.ts --trace=PREFIX`（给目录会提示正确前缀） |
| `--log-level=LEVEL` | `info` | `debug|info|warn|error|off`；旧名 `--log` 已移除，写了会直接报错 |
| `--log-file=PATH` | 无 | 日志同时追加落盘 |
| `-h, --help` | — | 完整 Usage，第一行就是版本号（`--version` 已删除，写了会直接报错） |

吞吐自测是子命令不是开关（旧 `--speedtest` 开关在任何模式下都到达不了，已删除）：

```bash
node src/app/cli.ts speedtest --seconds=8 --key=00112233445566778899aabbccddeeff
```

参数解析约定：

- 布尔开关（`--no-pmtud --help`）**永不吞下一个 token**；
  带值选项写 `--name=value` 或 `--name value`。
- 数值选项越界或非数字**立即报错退出**（`--mtu-min=abc`、`--mtu-max<--mtu-min`、`--fec=10:9` 都不会静默回退默认值）。
- 未知选项/开关打 `WARN unknown option --x ignored`，不再静默丢弃。
- 已删除的参数不是“忽略”，而是**直接报错退出**（`--port` / `-p` / `--tlv` / `--ack-v2` / `--key-update` / `--version` 等），报错里给替代写法。

完整 Usage：`node src/app/cli.ts --help`（与 C++ `apps/cli/cli.cc` 的默认端口、参数名对齐）。

## 门禁与自检

```bash
npm test              # node:test 全量：字节层 / 协议层 / golden / 同进程 e2e / 双进程 self-interop
npm run self-check    # 人类可读的双进程握手 + 代理报告（推荐先跑这个）
npm run check         # 门禁汇总表
```

`npm run self-check` 会启动**两个独立 CLI 进程**，用真实 UDP socket 握手，然后验证：

| 检查 | 判据 |
|---|---|
| 握手 | 两个进程都打出 `FCP established` |
| SOCKS5 / HTTP CONNECT / absolute-form HTTP | 经隧道访问本地 HTTP origin 返回 200，正文一致 |
| 320 KiB 载荷 | 跨 FEC + ARQ 后 327680 字节逐字节无损（>256 KiB 发送窗口，覆盖短写余量与 FIN 顺序） |
| 错 PSK | 本地入口可达，但不建立会话、不返回 SOCKS5 成功 |
| 加密路径 | 日志无 `auth_fail` / 结构失败 |
| PMTUD 抬升 | 日志出现 `PMTU ack mtu=`，即探测包被对端接受并 ACK、`payloadMax` 变大（8/8 项） |

`--json` 参数输出机器可读结果：`node scripts/self-interop.mjs --json`。

## 目录

```
src/
  constants.ts wire.ts              线格式常量与小端读写、序列比较
  crypto/     aes.ts keys.ts        原生 AES-128-GCM、会话/方向密钥派生
              envelope.ts           28 字节双信封、1024 槽反重放
              handshake.ts          HELLO/HELLO_ACK、caps、TLV、协商状态机
  fec/        gf256.ts cauchy.ts rs.ts hdr.ts   字段运算与 6 字节 FEC 头
              frame.ts             FrameTx/FrameRx、集合结算、MTU 预算、oob
              fecstat.ts           128 字节 FECSTAT 编解码与校验
  control/    controller.ts        AdaptiveFec / BbrLite / FecstatReporter
  stream/     segment.ts stream.ts FCP-STREAM 段头、ARQ、窗口、FIN
  session/    session.ts           密钥 epoch、握手、FEC、流、oob 的编排
  proxy/      codec.ts             SOCKS5 / HTTP CONNECT / 正向 / FCP OPEN
  app/        tunnel.ts            UDP 反应堆 + 本地 TCP 代理
              cli.ts server.ts client.ts bench.ts replay.ts
tests/        bytes / protocol / golden / e2e / self-interop
scripts/      check.mjs self-interop.mjs
docs/         协议格式.md 移植对照与差异.md
deploy/       psk.txt（该 PSK 的文本备份；脚本已改为内联 --key，不再读取它）
scripts/      start-client.cmd（本机客户端一键启动）
```

## 调试日志

`--log-level=debug` 打开逐包日志，`--log-file=PATH` 同步落盘（自动创建父目录，追加写）。
`--log-level=info`（默认）时调试埋点是 no-op，不产生额外开销。

埋点覆盖：

- 每个 UDP 数据报的收/发：salt 前 8 位、字节数、来源/目的；
- `HELLO` / `HELLO_ACK`、bootstrap-key 与 session-key 的切换、`ESTABLISHED` 协商参数；
- FEC symbol 的 `set / idx / type / k / len`、keepalive、FECSTAT / PMTUD；
- FCP-STREAM 段发送、`OPEN` 请求与应答、目标 TCP 连接/错误；
- 本地入口识别（SOCKS5 / CONNECT / forward）、进出隧道的字节数、会话关闭原因。

自检脚本可以把三个进程的日志分别落盘：

```bash
node scripts/self-interop.mjs --log-dir=logs/smoke
# logs/smoke/{server,client,bad}.log
```

## 发布产物（Release）

每次发布带四个资产，全部由本仓库的 `packaging/` 脚本生成：

| 资产 | 平台 | 说明 |
|---|---|---|
| `fcp-server_<ver>_amd64.deb` | Debian/Ubuntu amd64 | 服务端。内嵌 Node 22 运行时，带 systemd unit 和 `/etc/fcp-node/server.conf`；首次安装自动生成 PSK 并只打印一次 |
| `FCP-Node-Setup-<ver>.exe` | Windows x64 | 桌面 GUI 客户端 NSIS 安装包（per-user，无需管理员） |
| `FCP-Node-<ver>-portable.exe` | Windows x64 | 桌面 GUI 客户端免安装单文件版 |
| `fcp-client-<ver>.exe` | Windows x64 | 纯命令行客户端（Node SEA 单文件，不需要装 Node） |

构建：

```bash
npm run pack:deb            # 首次会下载并校验 Node 22 到 packaging/.cache；deb 由 Node 直接生成
npm run pack:client-exe     # 复用 desktop/node_modules 里的 esbuild
npm --prefix desktop install
npm --prefix desktop run pack   # -> desktop/dist/FCP-Node-*.exe
```

服务端安装：

```bash
sudo apt install ./fcp-server_0.0.2_amd64.deb
# 安装脚本会打印随机生成的 PSK；把同一个 key 填到客户端
sudo systemctl enable --now fcp-node
systemctl status fcp-node
tail -f /var/log/fcp-node/server.log
```

配置在 `/etc/fcp-node/server.conf`（`0640 root:fcp-node`），升级时作为 conffile 保留。
卸载用 `apt remove fcp-server`；`apt purge` 会连同服务账号、配置和日志一起删除。

客户端 exe 与桌面端参数一致：

```bat
fcp-client-0.0.2.exe --key=<HEX32> --peer=<SERVER_IP>:4461 -b 127.0.0.1:1080
```

## 当前 VPS 部署（2026-11-11）

| 项 | 值 |
|---|---|
| VPS | `144.34.186.164`，Debian GNU/Linux 13 (trixie) x86_64（2026-11-11 系统重建后重新部署） |
| Node 运行时 | `/opt/node-v22.22.2-linux-x64/bin/node`（软链 `/usr/local/bin/node`），无需额外 flag 直接跑 `.ts` |
| 部署目录 | `/opt/fcp-node`（23 个 `.ts` + `package.json`，由本机 `src/` 同步） |
| 服务端 | systemd `fcp-node.service`，UDP `0.0.0.0:4461`，开机自启，`Restart=always` |
| 服务日志 | `/var/log/fcp-node/server.log`（`--log-level=debug`），另见 `journalctl -u fcp-node -f` |
| PSK | 两端**内联同一个** `--key=00112233445566778899aabbccddeeff`（示例占位密钥，部署时替换为你的真实 PSK）；VPS unit 现为 `chmod 600`（明文含密钥），旧 `/etc/fcp-node.env` 已删除 |
| 本机客户端 | `127.0.0.1:1080`，日志 `logs/client.log`，一键启动 `scripts/start-client.cmd` |
| 两端参数 | `--key=11c1…c9a --mtu-min=1040 --mtu-max=1500 --fec=10:3 --log-level=debug` |
| 防火墙 | 无 ufw/iptables 规则，UDP 4461 直通 |

服务端 `ExecStart`（唯一权威版本，改参数只改这里与本机 `start-client.cmd`）：

```
/usr/local/bin/node /opt/fcp-node/src/app/server.ts \
  --key=00112233445566778899aabbccddeeff \
  -b 0.0.0.0:4461 --mtu-min=1040 --mtu-max=1500 --fec=10:3 \
  --log-level=debug --log-file=/var/log/fcp-node/server.log
```

`--mtu-min` 是**探测起点**：会话建立后两端各自以 100 B 为步长向上探，收到 ACK 就把发送预算抬上去，
5 步左右（≈5–10 s）到达 `--mtu-max`，日志会出现
`FCP PMTUD: path carries 1500B (ceiling reached, started at 1040B)`，`payloadMax` 从 976 涨到 1436。

探测被黑洞挡住时（连续 3 个 probe 无 ACK）会回退到已验证尺寸并按 1 s→2 s→4 s…（上限 60 s）退避重试。

**接收判据不再跟本端发送预算挂钩**（2026-11-11 修正）：早期版本把 `maxSymbolLen` 设成本端预算，
于是对端探测包本身就在接收端被当结构错误丢掉，探测永远收不到 ACK；真实数据在「一端 1040、一端 1400」时也会被整包丢弃。
现在接收上限固定为 `--mtu-max` 对应的尺寸，内核收得下就能解出来。

注意探测是**每会话**重新开始的：短连接（几个请求就关）基本停在 1040–1340，
想直接从小包起跑就用 `--mtu-min` 把起点抬高（例如 1400），或在长连接上才指望它走满。

运维：

```bash
# VPS
systemctl status fcp-node.service
systemctl restart fcp-node.service
tail -f /var/log/fcp-node/server.log
journalctl -u fcp-node -f

# 本机：重启客户端（若 1080 断开）
D:\work\fcp-node\scripts\start-client.cmd
# 停止：taskkill /PID <node进程PID> /F
```

改参数时必须**两端同时改**（`/etc/systemd/system/fcp-node.service` 的 `ExecStart` 与
`scripts/start-client.cmd`），然后重启服务端和客户端，否则 FEC 几何或 MTU 不匹配。

### 公网实测（2026-11-11 历史基线，修复前）

> 下表是三项修复（发送窗口估计源、重传率、FEC 控制器信号）**之前**的早期基线，
> 仅作对照留存。当前状态见下一节「当前基线」。

| 检查 | 结果（修复尾部截断后复测） |
|---|---|
| `http://example.com` | 200，577 B，1.9 s |
| `http://www.baidu.com` / `https://` | 200，2381 B / 2443 B，1.5 s / 3.8 s |
| `http://neverssl.com` | 200，3961 B，2.6 s |
| `https://github.com` | 200，**525 747 B**，15.8 s（修复前 TUNNEL_FAIL） |
| `https://www.cloudflare.com` | 200，**887 593 B**，30.0 s（修复前 TUNNEL_FAIL） |
| `https://www.bing.com` | 200，78 436 B，9.9 s |
| `https://www.debian.org` | 200，15 863 B，8.5 s |
| 静态文件完整性 | 64 KiB / 200 KiB / **512 KiB** sha256 与 VPS 侧逐字节一致（修复前 512 KiB 缺 6 B） |
| 吞吐 | 约 33 KB/s（自适应 k=3，约 30% 冗余开销）；探测到 1500 后 `payloadMax` 976→1436 |
| 已知限制 | 大页面仍慢（800 KB 级接近 30 s）；尚未做 pacing/窗口调优 |

以上两行的「慢」与「未调优」都是**修复前状态，现已失效**。

### 当前基线（2026-11-12，三项修复 + #92 之后）

| 检查 | 结果 |
|---|---|
| 线上服务 | `fcp-node.service` active（2026-11-12 06:41 UTC 重启）、UDP 4461 监听；`cli.ts` / `tunnel.ts` / `session.ts` / `controller.ts` / `stream.ts` / `constants.ts` 六个核心文件本地与 VPS sha256 **全一致** |
| 公网下载冒烟（`claude.exe`，SOCKS5 → VPS） | **1.99 MB/s**、**1.90 MB/s**（两杆，各 37–39 MiB） |
| 客户端观测 | loss `0.0%`、k `3→2→1`、重传率约 `2.2%`（修复前 58%） |
| 跨实现同窗口 A/B（本机环回，Node client → C++ server） | 修复组 **4.44–5.25 MB/s**（均值 4.65 MB/s）；把 `session.cc` 反编译回「单方面滚键」的对照组 **10.47 KiB/s**（四杆标准差 0.8 B/s）——**455×**，详见 `docs/移植对照与差异.md` §3.7.2 |
| 门禁 | Node 19 模块 / 72 tests ALL GATES PASSED；C++ Debug / Release ctest 各 46/46 |

线上跑的是 Node 实现，C++ 侧 #91/#92 的修复**无需部署到 VPS**。VPS 上
`scripts/start-client.cmd` 仍残留旧 `--fec=10:3`；那是 Windows 本地客户端脚本，Linux 侧
不执行，实际生效的 systemd `ExecStart` 已是 `--fec=10:6`。下次同步部署包时应一并覆盖，
避免有人照旧脚本启动本地客户端时用了错的参数。

历史候选（**均未实测，不默认改动**）：把 `--mtu-min` 提到 `1400` 省掉爬升窗口，
或 `--fec=20:2` 降低固定冗余上限。当前两端已统一为
`--mtu-min=1040 --mtu-max=1500 --fec=10:6`，改任何一项都必须两端同时改并重新实测。
