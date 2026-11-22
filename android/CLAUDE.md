# CLAUDE.md

本目录是 **fcp-node 仓库内的安卓客户端**（Android 11+ / API 30）：VpnService 全局代理 + 本机
混合代理端口。协议参考实现就是**仓库根的 `src/`**（同一仓库，可改但要同步两端）；
工程模板 `D:\work\kcp-proxy-andriod`（只读）。完整约定见 `AGENTS.md`。

**核心约束**：`core/` 禁止 `android.*`；协议与 `../src/` 逐字节一致；纯 Java 8、零第三方协议内核；
测试期望值必须抄自 `../tests/golden.test.ts` / `../tests/protocol.test.ts`。

## 构建

```bash
export JAVA_HOME=/path/to/jdk17+
cd android
./gradlew test            # 桌面 JVM 单测 + 对拍真实服务端的互操作测试
./gradlew assembleDebug   # app/build/outputs/apk/debug/app-debug.apk
```

## 包结构

- `core/wire/` — Wire(LE/BE)、Uvarint(LEB128)、Seq(u32 半窗)、Bytes
- `core/crypto|fec|stream|control/` — 对应仓库根 `src/crypto|fec|stream|control`
- `core/session/` — `FcpSession`（编排）、`FcpHandshake`（状态机）、`FcpTunnelEngine`（4 会话池）
- `core/proxy/` — `ProxyCodec`（三入口 + FCP OPEN）、`MixedProxyListener`、`DnsWire`（DNS 缓存）
- `vpn/` — `FcpVpnService` / `TunnelManager` / `PacketRouter`（TUN ↔ 隧道）
- `ui/` `log/` `util/` — Material 3 界面、滚动日志、配置

## 数据流

```
出站: 浏览器/系统 → [混合代理端口 或 VpnService TUN→PacketRouter] → TunnelEngine.open()
      → FCP OPEN(流首字节) → FCP-STREAM(ARQ) → FEC(RS) → AES-128-GCM → UDP → 服务端
入站: UDP → 解密 → FEC 还原 → 流重组 → sid 分路 → StreamHandle → 本地 socket / TUN 回写
DNS:  TUN 应用查 UDP:53 → PacketRouter 缓存 → 未命中则 oob FCP_DNS1 经隧道 → 服务端 resolver
```

## 两条必须记住的规则

1. **FcpSession 是单写者**：UDP 接收、tick、写入全部串行在引擎线程。`queryDns` 的发送
   投递到引擎线程，等待留在调用线程——不要在引擎线程上等自己的应答（死锁）。
2. **协议改动要两端一起改**：Java 常量、TS 常量、`../docs/协议格式.md`、以及互操作测试，
   同一个提交内完成。
