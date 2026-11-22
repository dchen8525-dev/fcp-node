package com.dchen.fcpvpn.core.fec;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * FEC 头打包/解析/校验测试。期望值逐字抄自：
 * <ul>
 *   <li>fcp-node tests/golden.test.ts:59-78（hdr_test.cc:9-27 金标向量）</li>
 *   <li>fcp-node tests/bytes.test.ts:85-107（pack/parse/validate）</li>
 * </ul>
 */
public class FecHeaderTest {

    @Test
    public void goldenPackTypeK() {
        // golden.test.ts:60-66
        assertEquals(0x20, FecHeader.packTypeK(1, 0, 0));
        assertEquals(0x21, FecHeader.packTypeK(1, 0, 1));
        assertEquals(0x25, FecHeader.packTypeK(1, 1, 1));
        assertEquals(0x89, FecHeader.packTypeK(4, 2, 1));
        assertEquals(0xfd, FecHeader.packTypeK(7, 7, 1));
        assertEquals(0x02, FecHeader.packTypeK(0, 0, 2));
        assertEquals(0x03, FecHeader.packTypeK(0, 0, 3));
    }

    @Test
    public void goldenPackHdrAndParse() {
        // golden.test.ts:67-77
        byte[] bytes = FecHeader.packHdr(
                new FecHeader.FecHdr(0x04030201, 5, 10, FecHeader.packTypeK(1, 0, 0)));
        assertEquals("01020304050a20", TestHex.hex(bytes));
        FecHeader.FecHdr parsed = FecHeader.parseHdr(bytes);
        assertNotNull(parsed);
        assertEquals(0x04030201, parsed.setId);
        assertEquals(5, parsed.index);
        assertEquals(10, parsed.d);
        assertEquals(0x20, parsed.typeK);
        assertEquals(0, FecHeader.hdrType(parsed.typeK));
        assertEquals(1, FecHeader.hdrK(parsed.typeK));
        assertEquals(0, FecHeader.hdrJ(parsed.typeK));
        assertNull("不足 7 字节必须解析失败", FecHeader.parseHdr(bytes, 6));
    }

    @Test
    public void packParseRoundTrip() {
        // bytes.test.ts:85-90
        byte[] h = FecHeader.packHdr(
                new FecHeader.FecHdr(0x12345678, 3, 10, (3 << 5) | (1 << 2) | 1));
        assertEquals("78563412030a65", TestHex.hex(h));
        FecHeader.FecHdr p = FecHeader.parseHdr(h);
        assertNotNull(p);
        assertEquals(0x12345678, p.setId);
        assertEquals(3, p.index);
        assertEquals(10, p.d);
        assertEquals(0x65, p.typeK);
        assertEquals(1, FecHeader.hdrType(p.typeK));
        assertEquals(3, FecHeader.hdrK(p.typeK));
        assertEquals(1, FecHeader.hdrJ(p.typeK));
    }

    @Test
    public void validateHdrStatuses() {
        // bytes.test.ts:91-107
        FecHeader.FecHdr p = FecHeader.parseHdr(FecHeader.packHdr(
                new FecHeader.FecHdr(0x12345678, 3, 10, (3 << 5) | (1 << 2) | 1)));
        assertEquals(FecHeader.OK, FecHeader.validateHdr(p, 3, true, 3));
        // data index 3 已知 n=3 → 越过已知 n
        assertEquals(FecHeader.DATA_PAST_KNOWN_N, FecHeader.validateHdr(hdr(1, 3, 10, 3, 0, 0), 3, true, 3));
        // type 3 未定义
        assertEquals(FecHeader.INVALID_TYPE, FecHeader.validateHdr(hdr(1, 0, 10, 0, 0, 3), 3, false, 0));
        // 自描述几何：d=4 而 index 5 越过 d（即便会话上限是 10）
        assertEquals(FecHeader.DATA_INDEX_PAST_D, FecHeader.validateHdr(hdr(1, 5, 4, 3, 0, 0), 3, false, 0));
        assertEquals(FecHeader.INDEX_PAST_S, FecHeader.validateHdr(hdr(1, 7, 4, 3, 0, 0), 3, false, 0));
        assertEquals(FecHeader.BAD_D, FecHeader.validateHdr(hdr(1, 0, 0, 3, 0, 0), 3, false, 0));
    }

    @Test
    public void validateHdrParityStatuses() {
        // parity：j 必须 < k，n = index - j 必须落在 [1, d]（hdr.ts:68-73）
        assertEquals(FecHeader.OK, FecHeader.validateHdr(hdr(1, 5, 10, 3, 1, 1), 3, false, 0));
        assertEquals(FecHeader.J_NOT_BELOW_K, FecHeader.validateHdr(hdr(1, 5, 10, 3, 3, 1), 3, false, 0));
        assertEquals(FecHeader.BAD_N, FecHeader.validateHdr(hdr(1, 0, 10, 3, 0, 1), 3, false, 0));
        // parityN = index - j = 11 > d = 10（index 12 仍 < s = 13）
        assertEquals(FecHeader.BAD_N, FecHeader.validateHdr(hdr(1, 12, 10, 3, 1, 1), 3, false, 0));
        // oob 直接放行（hdr.ts:58）
        assertEquals(FecHeader.OK, FecHeader.validateHdr(hdr(1, 0, 0, 0, 0, 2), 3, false, 0));
    }

    private static FecHeader.FecHdr hdr(int setId, int index, int d, int k, int j, int type) {
        return FecHeader.parseHdr(FecHeader.packHdr(
                new FecHeader.FecHdr(setId, index, d, FecHeader.packTypeK(k, j, type))));
    }

    @Test
    public void setIdAfterHalfWindow() {
        // hdr.ts:77 setIdAfter(a, b) = seqAfter(b, a)：b 严格在 a 之后为真
        assertTrue(FecHeader.setIdAfter(5, 7));
        assertFalse(FecHeader.setIdAfter(7, 5));
        assertFalse(FecHeader.setIdAfter(5, 5));
        // u32 回绕：0xffffffff 之后再 +1
        assertTrue(FecHeader.setIdAfter(-1, 0)); // 0xffffffff → 0
        assertFalse(FecHeader.setIdAfter(0, -1));
    }
}
