package com.dchen.fcpvpn.core.fec;

import com.dchen.fcpvpn.core.wire.Seq;
import com.dchen.fcpvpn.core.wire.Wire;

/**
 * FCP 7 字节 FEC 头（v2）。移植自 fcp-node src/fec/hdr.ts:1-77
 * （C++ src/fcp/hdr.{h,cc} 是 6 字节 v1，故意不互通，勿参照）。
 * <pre>
 *   offset 0  set_id u32 LE
 *   offset 4  index  u8
 *   offset 5  d      u8   本集合实际使用的 data 片数（v2 新增，使集合自描述）
 *   offset 6  type_k = (k << 5) | (j << 2) | type
 * </pre>
 * type 0=data 1=parity 2=oob（3 未定义）；k 为集合计划 parity 数（3 位），
 * j 为 parity 组内序号。set_id 比较用 u32 半窗。
 */
public final class FecHeader {

    /** 头长（constants.ts:18 FEC_HDR_LEN）。 */
    public static final int FEC_HDR_LEN = 7;
    /** 单集合最大符号数 S = d + p 的上界（constants.ts:19 MAX_S）。 */
    public static final int MAX_S = 256;
    /** parity 上限（constants.ts:20 MAX_PARITY）。 */
    public static final int MAX_PARITY = 7;

    /** 符号类型（constants.ts:22-26 SymbolType）。 */
    public static final int TYPE_DATA = 0;
    public static final int TYPE_PARITY = 1;
    public static final int TYPE_OOB = 2;

    /** validateHdr 状态码（hdr.ts:18-21 HdrStatus）。 */
    public static final int OK = 0;
    public static final int INDEX_PAST_S = 1;
    public static final int DATA_INDEX_PAST_D = 2;
    public static final int J_NOT_BELOW_K = 3;
    public static final int BAD_N = 4;
    public static final int DATA_PAST_KNOWN_N = 5;
    public static final int INVALID_TYPE = 6;
    public static final int BAD_D = 7;

    /** 解析/打包用头结构（hdr.ts:16 FecHdr）。setId 为 u32 按 int 位保真。 */
    public static final class FecHdr {
        public final int setId;
        public final int index;
        public final int d;
        public final int typeK;

        public FecHdr(int setId, int index, int d, int typeK) {
            this.setId = setId;
            this.index = index;
            this.d = d;
            this.typeK = typeK;
        }
    }

    private FecHeader() {}

    /** type_k 打包（hdr.ts:24-26 packTypeK）。 */
    public static int packTypeK(int k, int j, int type) {
        return (((k & 0x07) << 5) | ((j & 0x07) << 2) | (type & 0x03)) & 0xff;
    }

    public static int hdrType(int typeK) { return typeK & 0x03; }

    public static int hdrK(int typeK) { return (typeK >>> 5) & 0x07; }

    public static int hdrJ(int typeK) { return (typeK >>> 2) & 0x07; }

    public static boolean isParity(int typeK) { return (typeK & 0x03) == TYPE_PARITY; }

    public static boolean validSymbolType(int t) {
        return t == TYPE_DATA || t == TYPE_PARITY || t == TYPE_OOB;
    }

    /** 打包 7 字节头（hdr.ts:35-42 packHdr）。 */
    public static byte[] packHdr(FecHdr hdr) {
        byte[] out = new byte[FEC_HDR_LEN];
        putHdr(out, 0, hdr);
        return out;
    }

    /** 就地写头（FrameTx 拼数据报用，避免多一次数组拷贝）。 */
    public static void putHdr(byte[] out, int off, FecHdr hdr) {
        Wire.putLe32(hdr.setId, out, off);
        out[off + 4] = (byte) hdr.index;
        out[off + 5] = (byte) hdr.d;
        out[off + 6] = (byte) hdr.typeK;
    }

    public static FecHdr parseHdr(byte[] input) {
        return parseHdr(input, input.length);
    }

    /** 解析头（hdr.ts:43-46 parseHdr）；不足 7 字节返回 null。 */
    public static FecHdr parseHdr(byte[] input, int len) {
        if (len < FEC_HDR_LEN) return null;
        return new FecHdr(Wire.getLe32(input, 0), input[4] & 0xff, input[5] & 0xff, input[6] & 0xff);
    }

    /**
     * 按符号头自带的几何做结构校验（hdr.ts:56-74 validateHdr）。
     *
     * p 是协商的 parity 上限（不是本头里的 k）：j 必须低于头里的 k，而 index
     * 上界由头自己的 d 决定——比会话协商更小的组仍然合法，这正是携带 d 的意义。
     * 校验顺序：oob 直接放行 → type 合法性 → d 合法（d ≥ 1 且 d + p ≤ 256）
     * → index < d + p → data 的 index < d / index < n（若已知）
     * → parity 的 j < k 与 1 ≤ index − j ≤ d。
     */
    public static int validateHdr(FecHdr hdr, int p, boolean nKnown, int n) {
        int type = hdrType(hdr.typeK);
        if (type == TYPE_OOB) return OK;
        if (!validSymbolType(type)) return INVALID_TYPE;
        if (hdr.d < 1 || hdr.d + p > MAX_S) return BAD_D;
        int s = hdr.d + p;
        if (hdr.index >= s) return INDEX_PAST_S;
        if (type == TYPE_DATA) {
            if (hdr.index >= hdr.d) return DATA_INDEX_PAST_D;
            if (nKnown && hdr.index >= n) return DATA_PAST_KNOWN_N;
            return OK;
        }
        int k = hdrK(hdr.typeK);
        int j = hdrJ(hdr.typeK);
        if (j >= k) return J_NOT_BELOW_K;
        int parityN = hdr.index - j;
        if (parityN < 1 || parityN > hdr.d) return BAD_N;
        return OK;
    }

    /** b 是否严格在 a 之后（u32 半窗；hdr.ts:77 setIdAfter = seqAfter(b, a)）。 */
    public static boolean setIdAfter(int a, int b) {
        return Seq.seqAfter(b, a);
    }
}
