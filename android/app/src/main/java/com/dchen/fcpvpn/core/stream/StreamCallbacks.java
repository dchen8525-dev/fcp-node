package com.dchen.fcpvpn.core.stream;

/**
 * Stream 的宿主回调（stream.ts StreamCallbacks）。send/read/closed 必须提供；
 * 其余按需覆写（Java 8 default 空实现）。
 */
public interface StreamCallbacks {

    /** 发出一个段（DATA/ACK/RST 编码后的字节）→ 上层装入 FEC data 符号。 */
    void send(byte[] seg);

    /** 收到对端有序数据（交付给本地 socket / TUN）。 */
    void read(byte[] bytes);

    /** 流关闭（reason: reset / idle / peer_close / local_eof）。 */
    void closed(String reason);

    /** 对端 FIN 已交付（半关闭）。 */
    default void eof() {}

    /** srtt 更新（毫秒）。 */
    default void rtt(double srttMs) {}

    /**
     * 新被累计确认的字节数（= 已确认送达对端）——这是发送方向速率的诚实度量。
     * read() 报告的是接收方向（下载时只是 ACK 涓流）。
     */
    default void acked(long bytes, long nowMs) {}
}
