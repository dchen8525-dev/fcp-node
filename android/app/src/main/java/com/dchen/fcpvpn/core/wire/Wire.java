package com.dchen.fcpvpn.core.wire;

/**
 * 字节级线格式读写助手。移植自 fcp-node src/wire.ts（LE 协议字段；代理编解码用 BE）。
 * u32 一律用 Java int 按位保真存储（运算时需注意无符号语义），u64 用 long 按位保真。
 * 所有偏移量由调用方保证有效。
 */
public final class Wire {

    private Wire() {}

    // ---- little-endian ----

    public static int getLe16(byte[] b, int off) {
        return (b[off] & 0xff) | ((b[off + 1] & 0xff) << 8);
    }

    public static void putLe16(int v, byte[] out, int off) {
        out[off] = (byte) (v & 0xff);
        out[off + 1] = (byte) ((v >>> 8) & 0xff);
    }

    public static int getLe24(byte[] b, int off) {
        return (b[off] & 0xff) | ((b[off + 1] & 0xff) << 8) | ((b[off + 2] & 0xff) << 16);
    }

    public static void putLe24(int v, byte[] out, int off) {
        out[off] = (byte) (v & 0xff);
        out[off + 1] = (byte) ((v >>> 8) & 0xff);
        out[off + 2] = (byte) ((v >>> 16) & 0xff);
    }

    public static int getLe32(byte[] b, int off) {
        return (b[off] & 0xff)
                | ((b[off + 1] & 0xff) << 8)
                | ((b[off + 2] & 0xff) << 16)
                | ((b[off + 3] & 0xff) << 24);
    }

    public static void putLe32(int v, byte[] out, int off) {
        out[off] = (byte) v;
        out[off + 1] = (byte) (v >>> 8);
        out[off + 2] = (byte) (v >>> 16);
        out[off + 3] = (byte) (v >>> 24);
    }

    /** u64 按位保真读入 long（无符号语义由调用方处理）。 */
    public static long getLe64(byte[] b, int off) {
        long v = 0;
        for (int i = 7; i >= 0; --i) v = (v << 8) | (b[off + i] & 0xffL);
        return v;
    }

    public static void putLe64(long v, byte[] out, int off) {
        long x = v;
        for (int i = 0; i < 8; ++i) {
            out[off + i] = (byte) x;
            x >>>= 8;
        }
    }

    // ---- big-endian（仅代理层：OPEN 端口、HTTP 相关长度） ----

    public static int getBe16(byte[] b, int off) {
        return ((b[off] & 0xff) << 8) | (b[off + 1] & 0xff);
    }

    public static void putBe16(int v, byte[] out, int off) {
        out[off] = (byte) (v >>> 8);
        out[off + 1] = (byte) v;
    }

    public static int getBe32(byte[] b, int off) {
        return ((b[off] & 0xff) << 24)
                | ((b[off + 1] & 0xff) << 16)
                | ((b[off + 2] & 0xff) << 8)
                | (b[off + 3] & 0xff);
    }

    public static void putBe32(int v, byte[] out, int off) {
        out[off] = (byte) (v >>> 24);
        out[off + 1] = (byte) (v >>> 16);
        out[off + 2] = (byte) (v >>> 8);
        out[off + 3] = (byte) v;
    }
}
