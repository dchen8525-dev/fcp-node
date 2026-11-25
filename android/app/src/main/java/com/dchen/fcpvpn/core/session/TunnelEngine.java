package com.dchen.fcpvpn.core.session;

import java.net.DatagramSocket;

/**
 * FCP v7 客户端引擎的门面接口（对应 fcp-node TunnelClient 的对外行为）。
 *
 * 契约（波次 2 的 session agent 实现，vpn/proxy 层依赖）：
 * - start：创建并 protect 自己的 UDP socket，向 peer 发起握手（新 salt），
 *   建立后回调 onEstablished；失败/断链后由实现内部按指数退避重连。
 * - open：把一个目标连接挂到会话池（≤4 会话轮转）的空闲 sid 上，
 *   以 FCP OPEN 作为流首字节发出；对端 OPEN_OK 后回调 onOpened，
 *   OPEN_ERR 后回调 onFailed（code 见 FcpOpen 错误码 1..5）。
 * - stats：周期性统计快照（速率/会话数/uptime），供 UI 与日志使用。
 */
public interface TunnelEngine {

    interface EngineListener {
        void onEstablished(String salt);

        void onDown(String reason);

        /** 兼容 fcp-node 每 500ms 的 stats 行（stdout 通道的等价物）。 */
        void onStatsLine(String line);
    }

    void start(EngineConfig config, SocketProtector protector, EngineListener listener) throws Exception;

    void stop();

    /** 异步建立到 target 的隧道流；callback 恰好被回调一次。 */
    void open(OpenTarget target, OpenCallback callback);

    /** 供 VPN 场景直接复用已连接的 UDP socket（FcpVpnService.protect）。 */
    DatagramSocket socket();

    /**
     * 请求服务端解析一个 DNS 报文（oob FCP_DNS1，走隧道本身，不开新端口）。
     * 同步阻塞至应答或超时；返回原始 DNS 应答报文，失败返回 null。
     * 供 VPN 的 TUN 路径使用——TUN 里只有 IP 包，应用必须自己完成解析。
     */
    default byte[] queryDns(byte[] dnsQuery, int timeoutMs) {
        return null;
    }

    /**
     * 底层网络路径变化（Wi-Fi↔蜂窝、断网重连）。宿主在 ConnectivityManager 回调里
     * 调用；实现应尽快让会话探测新路径，而不是等 45 秒的空闲保活或 135 秒的静默判死。
     *
     * @param reset true = 网络上下线，路径确实换了（需要重测 PMTU）；
     *              false = 只是网络能力变化（带宽/信号提示），做一次轻量探测即可。
     */
    default void onPathChanged(boolean reset) { }

    boolean isEstablished();
}
