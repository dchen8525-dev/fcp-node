package com.dchen.fcpvpn.core.stream;

/**
 * FCP-STREAM 线协议常量。移植自 fcp-node src/constants.ts（368-479 行），
 * 逐项对照，勿改值。
 */
public final class StreamConstants {

    private StreamConstants() {}

    // 段类型
    public static final int STREAM_TYPE_DATA = 1;
    public static final int STREAM_TYPE_ACK = 2;
    public static final int STREAM_TYPE_RST = 3;
    public static final int STREAM_TYPE_ACK_V2 = 4;

    public static final int STREAM_DATA_HDR_LEN = 6;   // DATA 头：type1+seq4+flags1
    public static final int STREAM_ACK_LEN = 17;       // v1 ACK 固定长
    public static final int STREAM_ACK_V2_MIN_LEN = 10;
    public static final int STREAM_ACK_V2_MAX_RANGES = 64;
    public static final int STREAM_RST_LEN = 2;
    public static final int STREAM_FLAG_FIN = 1 << 0;
    /** ACK v2 range-count 字节的 bit7 = 冗余拷贝标志（计数本身 ≤64，bit7 空闲）。 */
    public static final int ACK_V2_FLAG_COPY = 0x80;
    public static final int STREAM_RST_ABORT = 1;

    /** 触发快速重传所需的重复 ACK 数（DUP_ACK_THRESH）。 */
    public static final int DUP_ACK_THRESH = 1;
    /** 接收端记住的近期 ACK 签名个数（抑制冗余拷贝被当成新鲜丢包证据）。 */
    public static final int ACK_SIG_RING = 4;

    public static final int ACK_DELAY_MS = 4;
    public static final int ACK_EVERY_SEGMENTS = 3;
    /** 有洞时重复 ACK 的上限间隔；实际为 clamp(srtt/DIVISOR, MIN, MAX)。 */
    public static final int HOLE_DUP_ACK_MS = 50;
    public static final int HOLE_DUP_ACK_MIN_MS = 10;
    public static final int HOLE_DUP_ACK_DIVISOR = 8;

    public static final int FAST_RETX_SEGMENTS = 6;
    public static final int FAST_RETX_MIN_AGE_MS = 30;
    public static final double FAST_RETX_TIGHTEN_STEP = 0.85;
    public static final double FAST_RETX_TIGHTEN_FLOOR = 0.25;
    public static final int RTT_PEAK_DECAY_MS = 10000;
    public static final int RTT_PEAK_MAX_MS = 1000;
    public static final int RTTVAR_NOISE_FLOOR_MS = 5;
    public static final int MIN_RETX_INTERVAL_MS = 120;
    public static final double RETX_RTT_FACTOR = 1.0;
    public static final int TLP_MIN_PTO_MS = 60;
    public static final int TLP_MAX_PROBES = 2;
    public static final int RETX_LAT_SAMPLES = 256;

    public static final int MIN_OOB_CHUNKS = 1024;
    public static final int MAX_OOB_CHUNKS = 8192;

    // 默认值（defaults 段）
    public static final int DEFAULT_SEND_WINDOW_BYTES = 512 * 1024;
    public static final int DEFAULT_RCV_BUF_BYTES = 256 * 1024;
    public static final int DEFAULT_SRTT_MS = 200;
    public static final int DEFAULT_IDLE_TIMEOUT_MS = 300000;
    public static final int PUMP_BURST_BYTES = 6 * 1024;
    public static final int ZERO_WINDOW_PROBE_MS = 50;
}
