package com.dchen.fcpvpn.core.fec;

/**
 * GF(2^8) 算术。移植自 fcp-node src/fec/gf256.ts:1-39（其移植自 C++ src/fcp/gf256.cc）。
 *
 * 约减多项式 0x11D，生成元 2；乘法结果经 parity 字节直接上线上可见，表内容必须与
 * 参考实现逐位一致。exp 表 512 项（免逐次回绕取模），log 表 256 项，另有 256x256
 * 乘法表——TS 的 gfMulRow 返回乘法表的行切片视图，Java 无 TypedArray 视图语义，
 * 改为 gfMulRow(coeff, v) 按行内下标取值，结果逐位一致。
 */
public final class Gf256 {

    /** 约减多项式（fcp-node src/constants.ts:122 GF256_POLY）。 */
    public static final int POLY = 0x11d;

    private static final int[] EXP = new int[512];
    private static final int[] LOG = new int[256];
    private static final int[] MUL = new int[256 * 256];

    static {
        // gf256.ts:9-23 的建表块，逐行一致。
        int x = 1;
        for (int i = 0; i < 255; ++i) {
            EXP[i] = x;
            LOG[x] = i;
            x <<= 1;
            if ((x & 0x100) != 0) x ^= POLY;
        }
        for (int i = 255; i < 512; ++i) EXP[i] = EXP[i - 255];
        for (int a = 0; a < 256; ++a) {
            for (int b = 0; b < 256; ++b) {
                MUL[(a << 8) | b] = (a == 0 || b == 0) ? 0 : EXP[LOG[a] + LOG[b]];
            }
        }
    }

    private Gf256() {}

    /** 乘法（gf256.ts:25 gfMul）。入参按 8 位掩码保护，合法域 0..255。 */
    public static int gfMul(int a, int b) {
        return MUL[((a & 0xff) << 8) | (b & 0xff)];
    }

    /** 逆元（gf256.ts:26 gfInv）：0 的逆定义为 0，与源码一致。 */
    public static int gfInv(int a) {
        a &= 0xff;
        return a == 0 ? 0 : EXP[255 - LOG[a]];
    }

    /** 除法（gf256.ts:27 gfDiv）。 */
    public static int gfDiv(int a, int b) {
        return a == 0 ? 0 : MUL[((a & 0xff) << 8) | gfInv(b)];
    }

    /** 幂（gf256.ts:28-32 gfPow）。 */
    public static int gfPow(int a, int e) {
        if (e == 0) return 1;
        if (a == 0) return 0;
        return EXP[(LOG[a & 0xff] * (e % 255)) % 255];
    }

    /** exp 表取值（gf256.ts:33 gfExp；i 需非负）。 */
    public static int gfExp(int i) {
        return EXP[i % 255];
    }

    /** log 表取值（gf256.ts:34 gfLog）。 */
    public static int gfLog(int a) {
        return LOG[a & 0xff];
    }

    /**
     * 乘法表行内取值，等价于 gf256.ts:35 的 gfMulRow(coeff)[v]。
     * rs.ts 的 xorScaled 即以 row[src[i]] 查此表；这里按 (coeff<<8)|v 直接索引全表。
     */
    public static int gfMulRow(int coeff, int v) {
        return MUL[((coeff & 0xff) << 8) | (v & 0xff)];
    }
}
