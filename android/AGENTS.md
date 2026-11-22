# AGENTS.md — fcp-node/android（FCP v7 安卓客户端）

本目录是 **fcp-node 仓库内的安卓客户端**（monorepo 子项目）：VpnService 全局代理（TUN）
+ 本机混合代理端口（SOCKS5 / HTTP CONNECT / absolute-form）。协议实现只有一份参考源——
**本仓库根的 `src/`**；安卓端是它的第二实现，两边必须逐字节一致。

工程范式继承自 `D:\work\kcp-proxy-andriod`（同作者的 KCP 安卓客户端，只读参考）。

## 铁律

1. **协议参数与本仓库根 `src/` 逐字节一致**——`../docs/协议格式.md` 是线格式规范；
   文档与代码冲突时以代码为准，并在提交说明里登记差异。
2. **`core/` 内禁止 import 任何 `android.*`**——协议栈必须能在桌面 JVM 上跑单测，
   并直接对拍本仓库的服务端（`../src/app/server.ts`）。
3. **纯 Java 8、零第三方协议依赖**（除 AndroidX/Material UI 与 junit）：不引入
   netty/okhttp/kcp 等内核；AES-GCM 用 `javax.crypto`。
4. u32 用 Java `int` 按位保真，u64 用 `long` 按位保真；字节序：**除代理层（FCP OPEN
   端口、HTTP 字段）为大端外，其余全部小端**。
5. 不得修改 `D:\work\kcp-proxy-andriod`（只读模板）。仓库根 `src/` 可以改——但改了
   协议就必须同步本目录，具体见 `README.md` 的同步表。
6. 每个 agent 只写自己负责的包，跨包改动在文件头注释说明。

## 构建 / 测试

```bash
export JAVA_HOME=/path/to/jdk17+      # 不要把本机路径写进 gradle.properties
cd android                            # 仓库根 → android 子项目
echo "sdk.dir=/path/to/Android/Sdk" > local.properties   # 本机专用，勿提交

./gradlew test            # 桌面 JVM 单测 + 对拍真实服务端的互操作测试
./gradlew assembleDebug   # APK: app/build/outputs/apk/debug/app-debug.apk
```

- minSdk 30（Android 11+），compileSdk 34，AGP 8.13.2，Gradle 8.14.5。
- 测试向量来源：`../tests/golden.test.ts`（AES/GCM/FEC 头/RS）、
  `../tests/protocol.test.ts`（握手/流用例）。**期望值必须从这两个文件抄录，不得编造。**
- 互操作测试通过 `FcpServerProcess` 自动定位仓库根并拉起 `src/app/server.ts`；
  `node` 不可用时跳过而非失败。
- 多 agent 并行时 gradle 有项目锁：构建等待超过 ~60s 就跳过编译验证，由集成阶段统一跑。

## 包结构（com.dchen.fcpvpn）

```
core/       纯 Java 协议栈（无 android.*）
  wire/     Wire(LE/BE)、Uvarint(LEB128)、Seq(u32 半窗)
  crypto/   Envelope/FcpKeys/Handshake/AesGcm        ← 对应 src/crypto/*
  fec/      Gf256/Cauchy/Rs/FecHeader/FrameTx/Rx     ← 对应 src/fec/*
  stream/   SegmentCodec/Stream                      ← 对应 src/stream/*
  control/  AdaptiveFec/BbrLite/FecstatReporter      ← 对应 src/control/controller.ts
  session/  FcpSession/FcpHandshake/FcpTunnelEngine  ← 对应 src/session/session.ts + src/app/tunnel.ts
  proxy/    ProxyCodec/MixedProxyListener/DnsWire    ← 对应 src/proxy/codec.ts + oob DNS
vpn/        FcpVpnService/TunnelManager/PacketRouter
ui/ log/ util/   界面 / 滚动日志 / 配置
```

## 关键移植锚点（速查）

| 项 | 值 |
|---|---|
| 信封 | `salt(8) \| nonce(8 LE) \| AES-128-GCM 密文 \| tag(12)`，开销 28B |
| IV | `LE64(counter) \| direction(C2S=01/S2C=02) \| 000000` |
| 引导密钥 | `X0 = AES128-ECB(PSK, salt ‖ 0^8)`；仅 HELLO/ACK/RESET |
| 会话密钥 | `X2 = AES(PSK, AES(PSK, X0⊕client_nonce) ⊕ server_nonce)` |
| 方向密钥 | SP800-108，label `fcp-c2`/`fcp-s2`，**L=128 是 bits 且大端** |
| 重放窗口 | 1024 槽，**先查窗口再解密**，tag 通过才提交 |
| FEC 头 v2 | 7B：`set_id u32 LE \| index u8 \| d u8 \| (k<<5)\|(j<<2)\|type` |
| MTU 预算 | `payloadMax = MTU − 20 − 8 − 37`；`symbolMax = base − 35` |
| HELLO | caps{ver,D,P,flags}；flags 必需 FRAMING\|FECSTAT，提供 TLV 时**自动并入 CAP_TLV** |
| 重试表 | 9 次：0/250/750/1750/3750/7750/15750/23750/31750 ms（`FcpHandshakeRetryTest` 锁死） |
| 流段 | DATA `type1\|seq u32\|flags(FIN)\|payload`；ACKv2 `type4\|cum\|rwnd\|n\|(gap,len) LEB128` |
| MUX | TLV5 协商后每符号 1 字节 sid；mux 下 segment 上限 −1；池 ≤4 |
| OPEN | `"FCPO" ver=1 atyp len addr port(BE)` 作流首字节 |
| oob DNS | `"FCP_DNS1" \| type1 \| token4 LE \| DNS 报文`，头 13B，payload ≤900B |
| 维护 | keepalive 45s；静默 135s 判死；FECSTAT 128B ×2/1s；复位 36B `FCPRST1\0` |

## 已知坑（都踩过）

1. GCM tag **12 字节**；KDF 的 `L` 是 **bits 且大端**；FEC 头是 **v2 7 字节**（勿参照 C++ v1）。
2. HELLO 每次重试必须换新 counter（服务端 180s 去重）。
3. mux 下控制段的流类型在 `seg[1]` 不是 `seg[0]`。
4. **FcpSession 单写者**：UDP 接收、tick、写入必须串行在同一线程；`queryDns` 的发送
   投递到引擎线程、等待留在调用线程。
5. 正向代理改写后的请求头必须写入**隧道**，不是本地客户端。
6. 池里 4 条会话各自会触发回调，上层只应看到一次 connected/down。
