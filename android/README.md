# FCP v7 安卓客户端

本目录是 `fcp-node` 的安卓端：**VpnService 全局代理**（TUN）+ **本机混合代理端口**
（SOCKS5 / HTTP CONNECT / absolute-form，首字节分流）。纯 Java 8、零第三方协议内核，
`core/` 不依赖 `android.*`，因此协议栈可以在桌面 JVM 上直接对拍本仓库的服务端。

## 构建与测试

```bash
export JAVA_HOME=/path/to/jdk          # JDK 17+；路径不要写进 gradle.properties
cd android
echo "sdk.dir=/path/to/Android/Sdk" > local.properties   # 本机专用，勿提交

./gradlew test                        # 桌面 JVM 单测 + 与真实服务端的互操作测试
./gradlew assembleDebug               # app/build/outputs/apk/debug/app-debug.apk
./gradlew installDebug                # 装到已连接的设备/模拟器
```

`local.properties` 与 `build/` 已在 `.gitignore` 中。

### 互操作测试怎么找到服务端

`core/interop/FcpServerProcess` 从工作目录向上探测 `src/app/server.ts`（即本仓库根），
也接受 `-DfcpNodeRoot=...` 或环境变量 `FCP_NODE_ROOT` 覆盖。测试会在随机端口拉起
`node src/app/server.ts`，跑完销毁；`node` 不可用时用 `Assume` 跳过而不是失败。

## 协议同步纪律

**这是 monorepo 的全部意义**：协议只有一个实现（仓库根的 `src/`），安卓端是它的
第二实现，两边必须逐字节一致。

改动协议时，同一个提交里必须同步：

| 协议面 | TS 侧 | Java 侧 |
|---|---|---|
| 常量（magic/长度/上限） | `src/constants.ts` | 对应类内的 `static final`（javadoc 标注 constants.ts 行号） |
| 信封 / 密钥 | `src/crypto/` | `core/crypto/` |
| FEC 头与组帧 | `src/fec/` | `core/fec/` |
| 流与 ARQ | `src/stream/` | `core/stream/` |
| 握手 / oob 分派 | `src/session/session.ts` | `core/session/FcpSession.java`、`FcpHandshake.java` |
| 代理编解码 / FCP OPEN | `src/proxy/codec.ts` | `core/proxy/ProxyCodec.java` |
| 线格式文档 | `docs/协议格式.md` | 同左（单一来源） |

测试期望值必须**抄自** TS 侧的 `tests/golden.test.ts` / `tests/protocol.test.ts`，
不得自行编造；跨语言一致性通过互操作测试与本仓库服务端实跑验证。

## 为什么安卓端有 DNS 能力（而桌面端没有）

- 桌面客户端与安卓「仅代理」模式工作在**应用层**：域名作为 `OPEN` 的 atyp=3 交给
  服务端解析，客户端一行 DNS 代码都不需要。
- 安卓 **VpnService 全局模式**工作在 **IP 层**：TUN 里只有目的 IP 包，域名只存在于
  应用自己的 DNS 查询中，客户端必须先完成解析。

因此协议里加了 oob `FCP_DNS1`（`docs/协议格式.md` §8.x）：客户端把 DNS 报文塞进
隧道，由服务端用自己的 resolver 解析。不占端口、不占流、不需要额外服务。
客户端另有一层 TTL 缓存（`core/proxy/DnsWire` + `PacketRouter`），命中率约 50%。

## 目录

```
app/src/main/java/com/dchen/fcpvpn/
  core/            纯 Java 协议栈（无 android.*，可桌面单测）
    wire/          LE/BE 读写、LEB128、u32 半窗比较
    crypto/        AES-GCM 信封、密钥派生、握手编解码
    fec/           GF(256)、Cauchy、RS、7 字节 FEC v2 头、FrameTx/Rx、FECSTAT
    stream/        FCP-STREAM v1 段编解码与 ARQ
    control/       自适应 FEC、BBR-lite、FECSTAT 上报、组大小选择
    session/       FcpSession（会话编排）、FcpHandshake（状态机）、FcpTunnelEngine（会话池）
    proxy/         ProxyCodec（三入口 + FCP OPEN）、MixedProxyListener、DnsWire
  vpn/             FcpVpnService、TunnelManager、PacketRouter（TUN ↔ 隧道）
  ui/ log/ util/   Material 3 界面、滚动日志、配置存储
app/src/test/java/ 107 个单测 + 3 个互操作测试（对拍真实服务端）
```

## 已知取舍

- **引擎 tick 2 ms**（500 Hz）对手机偏耗电；`FcpSession.nextTimerMs()` 已就绪，
  后续可换成动态调度。
- **DNS 缓存**不区分 EDNS Client Subnet（单机 APP 无影响）。
- 运行时修改配置需先断开再连（`FcpVpnService` 中的既有 TODO）。
