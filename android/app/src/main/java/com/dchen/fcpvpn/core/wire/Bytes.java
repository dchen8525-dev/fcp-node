package com.dchen.fcpvpn.core.wire;

/** 字节数组小工具（移植自 src/wire.ts 尾部）。 */
public final class Bytes {

    private Bytes() {}

    public static boolean bytesEqual(byte[] a, byte[] b, int len) {
        if (b.length < len || a.length < len) return false;
        for (int i = 0; i < len; ++i) if (a[i] != b[i]) return false;
        return true;
    }

    public static boolean bytesEqual(byte[] a, byte[] b) {
        return bytesEqual(a, b, a.length);
    }

    public static void secureZero(byte[] b) {
        if (b != null) java.util.Arrays.fill(b, (byte) 0);
    }

    public static byte[] concat(byte[]... parts) {
        int total = 0;
        for (byte[] p : parts) total += p.length;
        byte[] out = new byte[total];
        int off = 0;
        for (byte[] p : parts) {
            System.arraycopy(p, 0, out, off, p.length);
            off += p.length;
        }
        return out;
    }
}
