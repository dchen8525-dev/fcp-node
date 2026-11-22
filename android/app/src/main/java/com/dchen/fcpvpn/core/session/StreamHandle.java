package com.dchen.fcpvpn.core.session;

/**
 * 一条隧道内双向字节流（FCP-STREAM stream，sid 1..255）的句柄。
 * 语义与 fcp-node TunnelClient 的本地连接管道一致：write 缓冲/背压由实现负责，
 * FIN 半关闭（closeWrite）后仍可继续收对端数据，abort 发 RST 立即终止。
 */
public interface StreamHandle {

    interface Listener {
        /** 收到对端有序数据（实现方处理完后必须调用 handle.consumed(n) 才推进流控窗口）。 */
        void onData(byte[] data, int offset, int len);

        /** 对端半关闭（收到 FIN）。之后不再有 onData。 */
        void onFin();

        /** 对端或本端异常中止（RST / 会话死亡 / 超时）。 */
        void onReset(int code);
    }

    void setListener(Listener listener);

    /** 写数据到隧道（实现方内部排队，受流控背压约束）。 */
    void write(byte[] data, int offset, int len);

    /** 本端 FIN 半关闭：发完已排队数据后发送 FIN。 */
    void closeWrite();

    /** 发送 RST 并立即终止本流。 */
    void abort();

    /** 本端已消费 n 字节，推进对端发送窗口（背压）。 */
    void consumed(int n);
}
