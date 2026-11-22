package com.dchen.fcpvpn.core.session;

/** 引擎配置（对齐 fcp-node CLI 参数）。 */
public final class EngineConfig {

    public final String peerHost;
    public final int peerPort;        // UDP 端口，默认 4460
    public final String pskHex32;     // 32 个十六进制字符 = 16 字节 PSK
    public final int fecData;         // --fec-data，默认 10
    public final int fecParityMax;    // --fec-parity-max，默认 6
    public final int mtuMin;          // --mtu-min，默认 1040
    public final int probeIntervalSec;// --probe-interval，默认 600；<=0 关闭
    public final String logLevel;     // debug/info/warn/error/off
    /** 本机混合代理端口（SOCKS5/HTTP CONNECT/正向代理三合一）；<=0 不启动监听。 */
    public int proxyPort = 1080;

    public EngineConfig(String peerHost, int peerPort, String pskHex32,
                        int fecData, int fecParityMax, int mtuMin,
                        int probeIntervalSec, String logLevel) {
        this.peerHost = peerHost;
        this.peerPort = peerPort;
        this.pskHex32 = pskHex32;
        this.fecData = fecData;
        this.fecParityMax = fecParityMax;
        this.mtuMin = mtuMin;
        this.probeIntervalSec = probeIntervalSec;
        this.logLevel = logLevel;
    }
}
