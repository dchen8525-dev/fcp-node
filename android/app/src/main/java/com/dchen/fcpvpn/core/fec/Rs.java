package com.dchen.fcpvpn.core.fec;

/**
 * 系统 Cauchy Reed-Solomon 编解码。移植自 fcp-node src/fec/rs.ts:1-68
 * （其移植自 C++ src/fcp/rs.cc）。
 *
 * data 段索引 [0, n)，parity 段索引 [n, n + k)。所有符号由调用方补零到
 * symbolMax 字节后再编码/解码（FrameTx.closeLane / FrameRx.tryDecode 负责）。
 */
public final class Rs {

    /** 单次编解码允许的最大分片总数 n + k（constants.ts:123 RS_MAX_SHARDS）。 */
    public static final int RS_MAX_SHARDS = 256;
    /** parity 上限（constants.ts:124 RS_MAX_PARITY；FEC 头 k 字段只有 3 位）。 */
    public static final int RS_MAX_PARITY = 7;

    private Rs() {}

    /** dst[0..len) ^= coeff · src[0..len)（rs.ts:9-13 xorScaled，经乘法表行查表）。 */
    private static void xorScaled(byte[] dst, byte[] src, int len, int coeff) {
        if (coeff == 0) return;
        for (int i = 0; i < len; ++i) {
            dst[i] ^= (byte) Gf256.gfMulRow(coeff, src[i] & 0xff);
        }
    }

    /**
     * 系统 RS 编码：n 个 data 段 → k 个 parity 段，各 symbolMax 字节
     * （rs.ts:15-25 rsEncode）。k==0 / n==0 / n+k 超过 RS_MAX_SHARDS 返回 null。
     */
    public static byte[][] rsEncode(byte[][] data, int n, int k, int symbolMax) {
        if (k == 0 || n == 0 || n + k > RS_MAX_SHARDS) return null;
        byte[][] parity = new byte[k][];
        for (int r = 0; r < k; ++r) parity[r] = new byte[symbolMax];
        for (int c = 0; c < n; ++c) {
            for (int r = 0; r < k; ++r) {
                xorScaled(parity[r], data[c], symbolMax, Cauchy.cauchyCoeff(r, c, k));
            }
        }
        return parity;
    }

    /**
     * 从任意 ≥ n − k 个幸存符号重构（rs.ts:32-68 rsDecode）。
     *
     * symbols 有 n + k 项，null 项表示擦除。返回长度 n 的数组：被重构的 data 段
     * 位置非 null；原本就在场的 data 段保持 null（系统码不重复给出）。
     * 缺失数超过可用 parity 数、矩阵奇异或几何非法时整体返回 null。
     */
    public static byte[][] rsDecode(byte[][] symbols, int n, int k, int symbolMax) {
        if (n == 0 || k == 0 || n + k > RS_MAX_SHARDS) return null;
        byte[][] recovered = new byte[n][];
        int[] missing = new int[n];
        int missingCount = 0;
        for (int i = 0; i < n; ++i) if (symbols[i] == null) missing[missingCount++] = i;
        if (missingCount == 0) return recovered;
        if (missingCount > k) return null;

        int[] rows = new int[missingCount];
        int rowCount = 0;
        for (int r = 0; r < k && rowCount < missingCount; ++r) {
            if (symbols[n + r] != null) rows[rowCount++] = r;
        }
        if (rowCount < missingCount) return null;

        int t = missingCount;
        byte[] matrix = new byte[t * t];
        for (int i = 0; i < t; ++i) {
            for (int j = 0; j < t; ++j) matrix[i * t + j] = (byte) Cauchy.cauchyCoeff(rows[i], missing[j], k);
        }
        if (!Cauchy.cauchyInvertMatrix(matrix, t)) return null;

        // rhs[i] = parity_row[i] - Σ(在场 data 段 · coeff)，TS 用 Buffer.from 复制整行；
        // 这里按 symbolMax 复制（调用方保证幸存符号恰为 symbolMax 字节）。
        byte[][] rhs = new byte[t][];
        for (int i = 0; i < t; ++i) {
            byte[] src = symbols[n + rows[i]];
            byte[] row = new byte[symbolMax];
            System.arraycopy(src, 0, row, 0, Math.min(symbolMax, src.length));
            for (int c = 0; c < n; ++c) {
                if (symbols[c] == null) continue;
                xorScaled(row, symbols[c], symbolMax, Cauchy.cauchyCoeff(rows[i], c, k));
            }
            rhs[i] = row;
        }
        for (int j = 0; j < t; ++j) {
            byte[] out = new byte[symbolMax];
            for (int i = 0; i < t; ++i) xorScaled(out, rhs[i], symbolMax, matrix[j * t + i] & 0xff);
            recovered[missing[j]] = out;
        }
        return recovered;
    }
}
