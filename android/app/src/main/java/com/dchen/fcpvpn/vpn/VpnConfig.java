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
