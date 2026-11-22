package com.dchen.fcpvpn.vpn;

/**
 * VPN 状态广播 —— VPN 服务 / TunnelManager 向 UI 同步状态（与 kcp 同构，增加会话数与引擎 stats 行）。
 */
public final class VpnStateBroadcast {
    private VpnStateBroadcast() {
    }

    public static final String ACTION_STATE_CHANGED = "com.dchen.fcpvpn.VPN_STATE_CHANGED";
    public static final String EXTRA_STATE = "state";
    public static final String EXTRA_UPLOAD_BYTES = "upload_bytes";
    public static final String EXTRA_DOWNLOAD_BYTES = "download_bytes";
    /** 已连接时长（秒）；-1 表示本条广播未携带（由 UI 本地计时兜底）。 */
    public static final String EXTRA_DURATION = "duration";
    /** 当前隧道内活跃连接数；-1 表示未知。 */
    public static final String EXTRA_SESSIONS = "sessions";
    /** 引擎周期性 stats 原始行（TunnelEngine.EngineListener.onStatsLine），Stub 阶段为空。 */
    public static final String EXTRA_STATS_LINE = "stats_line";
}
