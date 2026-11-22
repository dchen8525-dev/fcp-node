package com.dchen.fcpvpn.vpn;

/**
 * VPN 连接状态枚举（与 kcp 同构）。
 */
public enum VpnConnectionState {
    DISCONNECTED,    // 未连接
    CONNECTING,      // 正在连接
    CONNECTED,       // 已连接
    RECONNECTING,    // 正在重连（引擎断链后指数退避中）
    DISCONNECTING;   // 正在断开

    /**
     * 获取状态显示文本
     */
    public String getDisplayText() {
        switch (this) {
            case DISCONNECTED:
                return "已断开";
            case CONNECTING:
                return "连接中…";
            case CONNECTED:
                return "已连接";
            case RECONNECTING:
                return "重连中…";
            case DISCONNECTING:
                return "断开中…";
            default:
                return "未知";
        }
    }
}
