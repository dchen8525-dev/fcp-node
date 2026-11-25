package com.dchen.fcpvpn.vpn;

/**
 * VPN 接口与前台服务的常量配置（参考 kcp 同名类，按 FCP 语义调整）。
 */
public final class VpnConfig {
    private VpnConfig() {
    }

    // VPN 接口配置
    public static final String VPN_SESSION_NAME = "FCP VPN";
    /** TUN 的本地 IPv4 地址（/32）。 */
    public static final String VPN_ADDRESS = "10.0.0.2";
    public static final int VPN_ADDRESS_PREFIX = 32;
    /**
     * TUN 的本地 IPv6 地址（/128）。
     *
     * <p>通告 IPv6 地址 + ::/0 路由是为了把应用的 IPv6 流量收进 TUN 再拒掉
     * （PacketRouter.rejectIpv6）。不这么做的后果：Android 的 per-UID VPN 规则
     * 只收本接口通告过的地址族，IPv6 会绕过隧道从物理网卡直出——"按应用代理"
     * 看起来就完全没生效。</p>
     */
    public static final String VPN_ADDRESS_V6 = "fd00::2";
    public static final int VPN_ADDRESS_V6_PREFIX = 128;
    /**
     * 通告 IPv6 时 TUN MTU 的下限。
     *
     * <p>IPv6 要求链路 MTU ≥ 1280（RFC 8200）。Linux 不会在 MTU 小于该值的接口上
     * 启用 IPv6——那样 fd00::2 与 ::/0 路由都装不上，IPv6 又回到"绕过隧道直出"。
     * 所以 TUN 的 MTU 在这些情况下会被抬到 1280；引擎自己的路径 MTU（mtuMin）
     * 不受影响，FCP 流内部本来就会再分包。</p>
     */
    public static final int VPN_MTU_V6_MIN = 1280;
    /**
     * TUN MTU 默认值 = EngineConfig.mtuMin 的默认值（1040）。
     * FCP 的 MTU 预算：base = MTU − 28(IP+UDP)，payloadMax = base − 37，
     * 引擎在 StreamHandle.write 内部自行分包，TUN 侧整包写流即可，
     * 因此 TUN MTU 与 mtuMin 同值（与 kcp 的 VPN_MTU = KCP_MTU 同构）。
     */
    public static final int VPN_MTU = 1040;

    // 引擎默认参数（对齐 fcp-node CLI 默认值）
    public static final int DEFAULT_PEER_PORT = 4460;
    public static final int DEFAULT_FEC_DATA = 10;
    public static final int DEFAULT_FEC_PARITY_MAX = 6;
    public static final int DEFAULT_MTU_MIN = 1040;
    public static final int DEFAULT_PROBE_INTERVAL_SEC = 600;
    public static final int DEFAULT_PROXY_PORT = 1080;

    // 前台服务通知
    public static final int NOTIFICATION_ID = 1001;
    public static final String NOTIFICATION_CHANNEL_ID = "fcpvpn_service";
    public static final String NOTIFICATION_CHANNEL_NAME = "VPN 服务";
}
