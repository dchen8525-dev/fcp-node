package com.dchen.fcpvpn.core.fec;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;

import org.junit.Test;

import com.dchen.fcpvpn.core.wire.Wire;

/**
 * FECSTAT 128 字节块测试。期望值抄自 fcp-node tests/bytes.test.ts:126-148
 * （'FECSTAT: 128-byte layout round-trip and validator'）；逐偏移断言的
 * 偏移表来自 src/fec/fecstat.ts encodeFecstat（fecstat.h static_assert）。
 */
public class FecstatBlockTest {

    private static final byte[] SALT = TestHex.bin("0102030405060708");

    @Test
    public void layoutRoundTripAndValidator() {
        // bytes.test.ts:127-148
        FecstatBlock.FecstatPacket p = FecstatBlock.makeFecstatPacket(SALT);
        p.accountedThroughSetId = (int) 0xfffffff0L;
        p.dataExpected = 1234;
        p.dataRxOrig = 1000;
        p.parityRx = 7;
        p.ledgerGroups = 64;
        p.ledgerMeta = (0x1234 << 16) | 3;
        byte[] wire = FecstatBlock.encodeFecstat(p);
        assertEquals(128, wire.length);
        byte[] magic = Arrays.copyOfRange(wire, 0, 16);
        assertEquals("FCP_FECSTAT_V1\u0000\u0000", new String(magic,
                java.nio.charset.StandardCharsets.ISO_8859_1));
        assertEquals(1, wire[24] & 0xff);
        assertEquals(0xfffffff0, Wire.getLe32(wire, 28));

        FecstatBlock.Decoded r = FecstatBlock.decodeFecstat(wire, SALT);
        assertEquals(FecstatBlock.OK, r.status);
        assertEquals(1234, r.packet.dataExpected);
        assertEquals(p.ledgerMeta, r.packet.ledgerMeta);

        assertEquals(FecstatBlock.BAD_LENGTH,
                FecstatBlock.decodeFecstat(Arrays.copyOfRange(wire, 0, 127), SALT).status);
        assertEquals(FecstatBlock.BAD_SALT,
                FecstatBlock.decodeFecstat(wire, new byte[8]).status);

        FecstatBlock.FecstatValidator v = new FecstatBlock.FecstatValidator();
        assertEquals(FecstatBlock.OK, v.validate(wire, SALT).status);
        assertEquals(FecstatBlock.DUPLICATE, v.validate(wire, SALT).status);
        FecstatBlock.FecstatPacket older = FecstatBlock.makeFecstatPacket(SALT);
        older.accountedThroughSetId = (int) 0xffffffe0L;
        assertEquals(FecstatBlock.STALE,
                v.validate(FecstatBlock.encodeFecstat(older), SALT).status);
        // 前跳 2^21 > 2^20 → stale（wire 值为 0xfffffff0 + 2^21 的 u32 截断）
        FecstatBlock.FecstatPacket future = FecstatBlock.makeFecstatPacket(SALT);
        future.accountedThroughSetId = (int) (0xfffffff0L + (1L << 21));
        assertEquals(FecstatBlock.STALE,
                v.validate(FecstatBlock.encodeFecstat(future), SALT).status);
        assertEquals(1, v.futureRejects);
    }

    @Test
    public void fieldOffsets() {
        // 每个字段写到独立值，按 fecstat.ts encodeFecstat 的偏移表逐项核对
        FecstatBlock.FecstatPacket p = FecstatBlock.makeFecstatPacket(SALT);
        p.ver = 1;
        p.flg = FecstatBlock.FLG_LEDGER | FecstatBlock.FLG_DIRECTION;
        p.intervalMs = 1000;
        p.accountedThroughSetId = 0x01020304;
        p.setsExpected = 11;
        p.dataExpected = 12;
        p.dataRxOrig = 13;
        p.dataRecoveredDl = 14;
        p.dataRecoveredLate = 15;
        p.dataDelivered = 16;
        p.parityRx = 17;
        p.parityExpected = 18;
        p.setsKUnknown = 19;
        p.setsFull = 20;
        p.authFail = 21;
        p.lateDup = 22;
        p.structFail = 23;
        p.repairLatP50Ms = 24;
        p.repairLatP95Ms = 25;
        p.dataBytesRx = 26;
        p.parityBytesRx = 27;
        p.setsTailDropped = 28;
        p.dataLateRx = 29;
        p.setsPartial = 30;
        p.ledgerGroups = 31;
        p.ledgerFailPpm = 32;
        p.ledgerMeta = (7 << 16) | 5;
        byte[] w = FecstatBlock.encodeFecstat(p);
        assertEquals(FecstatBlock.FLG_LEDGER | FecstatBlock.FLG_DIRECTION, w[25] & 0xff);
        assertEquals(1000, Wire.getLe16(w, 26));
        assertEquals(0x01020304, Wire.getLe32(w, 28));
        assertEquals(11, Wire.getLe32(w, 32));
        assertEquals(12, Wire.getLe32(w, 36));
        assertEquals(13, Wire.getLe32(w, 40));
        assertEquals(14, Wire.getLe32(w, 44));
        assertEquals(15, Wire.getLe32(w, 48));
        assertEquals(16, Wire.getLe32(w, 52));
        assertEquals(17, Wire.getLe32(w, 56));
        assertEquals(18, Wire.getLe32(w, 60));
        assertEquals(19, Wire.getLe32(w, 64));
        assertEquals(20, Wire.getLe32(w, 68));
        assertEquals(21, Wire.getLe32(w, 72));
        assertEquals(22, Wire.getLe32(w, 76));
        assertEquals(23, Wire.getLe32(w, 80));
        assertEquals(24, Wire.getLe16(w, 84));
        assertEquals(25, Wire.getLe16(w, 86));
        assertEquals(26, Wire.getLe32(w, 88));
        assertEquals(27, Wire.getLe32(w, 92));
        assertEquals(28, Wire.getLe32(w, 96));
        assertEquals(29, Wire.getLe32(w, 100));
        assertEquals(30, Wire.getLe32(w, 104));
        assertEquals(31, Wire.getLe32(w, 108));
        assertEquals(32, Wire.getLe32(w, 112));
        assertEquals((7 << 16) | 5, Wire.getLe32(w, 116));
        // reserved[2]（120..127）保持 0
        for (int i = 120; i < 128; ++i) assertEquals(0, w[i]);
        // 解码侧逐字段回读
        FecstatBlock.Decoded r = FecstatBlock.decodeFecstat(w, SALT);
        assertEquals(FecstatBlock.OK, r.status);
        FecstatBlock.FecstatPacket q = r.packet;
        assertEquals(1, q.ver);
        assertEquals(FecstatBlock.FLG_LEDGER | FecstatBlock.FLG_DIRECTION, q.flg);
        assertEquals(1000, q.intervalMs);
        assertEquals(0x01020304, q.accountedThroughSetId);
        assertEquals(11, q.setsExpected);
        assertEquals(12, q.dataExpected);
        assertEquals(13, q.dataRxOrig);
        assertEquals(14, q.dataRecoveredDl);
        assertEquals(15, q.dataRecoveredLate);
        assertEquals(16, q.dataDelivered);
        assertEquals(17, q.parityRx);
        assertEquals(18, q.parityExpected);
        assertEquals(19, q.setsKUnknown);
        assertEquals(20, q.setsFull);
        assertEquals(21, q.authFail);
        assertEquals(22, q.lateDup);
        assertEquals(23, q.structFail);
        assertEquals(24, q.repairLatP50Ms);
        assertEquals(25, q.repairLatP95Ms);
        assertEquals(26, q.dataBytesRx);
        assertEquals(27, q.parityBytesRx);
        assertEquals(28, q.setsTailDropped);
        assertEquals(29, q.dataLateRx);
        assertEquals(30, q.setsPartial);
        assertEquals(31, q.ledgerGroups);
        assertEquals(32, q.ledgerFailPpm);
        assertEquals((7 << 16) | 5, q.ledgerMeta);
        assertTrue(Arrays.equals(SALT, q.salt));
    }

    @Test
    public void ledgerMetaAccessors() {
        // bytes.test.ts:135-136 的 ledgerMeta 值 (0x1234 << 16) | 3
        FecstatBlock.FecstatPacket p = FecstatBlock.makeFecstatPacket(SALT);
        p.ledgerMeta = (0x1234 << 16) | 3;
        assertEquals(3, FecstatBlock.ledgerK(p));
        assertEquals(0x1234, FecstatBlock.ledgerBurstKl(p));
    }

    @Test
    public void decodeValidationOrder() {
        // fecstat.ts:82-86：最小长度 → magic → 版本（先于精确长度）→ len == 128
        FecstatBlock.FecstatPacket p = FecstatBlock.makeFecstatPacket(SALT);
        byte[] w = FecstatBlock.encodeFecstat(p);
        assertEquals(FecstatBlock.BAD_LENGTH, FecstatBlock.decodeFecstat(new byte[24], SALT).status);
        byte[] badMagic = Arrays.copyOf(w, 128);
        badMagic[0] = 'X';
        assertEquals(FecstatBlock.BAD_MAGIC, FecstatBlock.decodeFecstat(badMagic, SALT).status);
        byte[] badVer = Arrays.copyOf(w, 128);
        badVer[24] = 2;
        assertEquals(FecstatBlock.BAD_VER, FecstatBlock.decodeFecstat(badVer, SALT).status);
        // 长度 25..127 且 magic/ver 合法 → BadLength（精确长度检查在版本之后）
        byte[] shortOk = Arrays.copyOf(w, 30);
        assertEquals(FecstatBlock.BAD_LENGTH, FecstatBlock.decodeFecstat(shortOk, SALT).status);
        // salt 在精确长度之后校验
        byte[] wrongSalt = TestHex.bin("ffffffffffffffff");
        assertEquals(FecstatBlock.BAD_SALT, FecstatBlock.decodeFecstat(w, wrongSalt).status);
    }
}
