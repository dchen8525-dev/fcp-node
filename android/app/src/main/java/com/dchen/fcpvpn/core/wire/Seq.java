package com.dchen.fcpvpn.core.wire;

/**
 * 回绕安全的 u32 模半窗比较（fcp-node src/wire.ts seqAfter 系列，对应 C++ src/fcp/seq.h）。
 * a、b 以 Java int 按位保真存储 u32；int 减法即低 32 位运算，与 TS 的
 * ((a - b) >>> 0) | 0 语义一致。
 */
public final class Seq {

    private Seq() {}

    /** a 是否在 b 之后（模 2^32 半窗内）。 */
    public static boolean seqAfter(int a, int b) {
        return a - b > 0;
    }

    /** a >= b（模半窗）。 */
    public static boolean seqAtOrAfter(int a, int b) {
        return !seqAfter(b, a);
    }

    /** b 到 a 的前向距离（u32 回绕语义，结果按有符号 int 解释）。 */
    public static int seqDist(int a, int b) {
        return a - b;
    }
}
