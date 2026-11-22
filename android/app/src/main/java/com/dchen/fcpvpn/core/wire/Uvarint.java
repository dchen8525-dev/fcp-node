package com.dchen.fcpvpn.core.wire;

/**
 * LEB128 无符号变长整数（fcp-node #78：FCP-STREAM ACK v2 的 (gap,len) 编码）。
 * u32 最多 5 字节。移植自 src/wire.ts，含第 5 字节只允许 4 个有效位的规范检查。
 */
public final class Uvarint {

    private Uvarint() {}

    /** 写入 v，返回消耗字节数。 */
    public static int putUvarint(int v, byte[] out, int off) {
        int x = v;
        int n = 0;
        while (x >= 0x80) {
            out[off + n++] = (byte) ((x & 0x7f) | 0x80);
            x >>>= 7;
        }
        out[off + n++] = (byte) x;
        return n;
    }

    /**
     * 从 b[off[0] .. cap) 读取一个 uvarint，成功时更新 off[0] 并返回值；
     * 越界或编码非法（含第 5 字节 > 0x0f 的非规范编码）返回 -1。
     */
    public static int getUvarint(byte[] b, int cap, int[] off) {
        int v = 0;
        int shift = 0;
        for (int i = 0; i < 5; ++i) {
            int pos = off[0];
            if (pos >= cap) return -1;
            int byteVal = b[pos++] & 0xff;
            off[0] = pos;
            // u32 LEB128 的第 5 字节只允许 4 个有效位：否则 0x7f<<28 会溢出 32 位
            // 累加器回绕，非规范编码会被解码成一个小值而不是失败——这个值随后
            // 会与编码端的规范形式不一致（wire.ts 同款修复）。
            if (i == 4 && (byteVal & 0x7f) > 0x0f) return -1;
            v |= (byteVal & 0x7f) << shift;
            if ((byteVal & 0x80) == 0) return v;
            shift += 7;
        }
        return -1;
    }

    /** putUvarint 对该值会消耗的字节数（用于编码前预算 ACK 大小）。 */
    public static int uvarintSize(int v) {
        int x = v;
        int n = 1;
        while (x >= 0x80) {
            x >>>= 7;
            ++n;
        }
        return n;
    }
}
