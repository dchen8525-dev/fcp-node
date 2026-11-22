package com.dchen.fcpvpn.core.stream;

/**
 * Stream 配置（stream.ts StreamConfig；Required&lt;StreamConfig&gt; 的默认值在字段初始化处）。
 */
public class StreamConfig {

    /** 整个流段大小（含 6 字节 DATA 头）；对应 Session::payload_max()。 */
    public int maxSegment;
    public int sendWindowBytes = StreamConstants.DEFAULT_SEND_WINDOW_BYTES;
    public int rcvBufBytes = StreamConstants.DEFAULT_RCV_BUF_BYTES;
    public int ackEvery = StreamConstants.ACK_EVERY_SEGMENTS;
    public boolean ackV2 = false;
    public int initialSrttMs = StreamConstants.DEFAULT_SRTT_MS;
    public int rtoMinMs = 100;
    public int rtoMaxMs = 5000;
    public int idleTimeoutMs = StreamConstants.DEFAULT_IDLE_TIMEOUT_MS;

    public StreamConfig(int maxSegment) {
        this.maxSegment = maxSegment;
    }
}
