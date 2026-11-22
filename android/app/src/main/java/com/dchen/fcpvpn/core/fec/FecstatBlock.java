package com.dchen.fcpvpn.core.fec;

import java.util.Arrays;

import com.dchen.fcpvpn.core.wire.Seq;
import com.dchen.fcpvpn.core.wire.Wire;

/**
 * FECSTAT v1：定长 128 字节小端统计块。移植自 fcp-node src/fec/fecstat.ts:1-144
 * （C++ fecstat.{h,cc}；所有整数域小端，偏移由 fecstat.h static_assert 固定，
 * 改动任何一项即破坏线兼容）。布局见 docs/协议格式.md §8.1。
 *
 * 编码（发送/上报）与解码（接收/校验）都在本类；自适应逻辑在 control 层
 * （后期移植 controller.ts），本层不做。
 */
public final class FecstatBlock {

    /** 块长（constants.ts:111 FECSTAT_LEN）。 */
    public static final int FECSTAT_LEN = 128;
    /** 版本（constants.ts:112 FECSTAT_VERSION）。 */
    public static final int FECSTAT_VERSION = 1;
    /** accounted_through_set_id 允许的前跳上限（constants.ts:113）。 */
    public static final int FECSTAT_MAX_FORWARD_SETS = 1 << 20;
    /** magic 16 字节（constants.ts:115 FECSTAT_MAGIC）。 */
    public static final byte[] FECSTAT_MAGIC = "FCP_FECSTAT_V1\u0000\u0000".getBytes(
            java.nio.charset.StandardCharsets.ISO_8859_1);
    /** flags 位（constants.ts:116-119）。 */
    public static final int FLG_DIRECTION = 0x01;
    public static final int FLG_TAIL_DROPPED = 0x02;
    public static final int FLG_LATE_RECOVERY = 0x04;
    public static final int FLG_LEDGER = 0x08;

    /** decode/validate 状态码（fecstat.ts:42-44 FecstatStatus）。 */
    public static final int OK = 0;
    public static final int BAD_LENGTH = 1;
    public static final int BAD_MAGIC = 2;
    public static final int BAD_VER = 3;
    public static final int BAD_SALT = 4;
    public static final int DUPLICATE = 5;
    public static final int STALE = 6;

    /** 一份 FECSTAT 报文的全部字段（fecstat.ts:11-40 FecstatPacket）。u32 用 int 位保真。 */
    public static final class FecstatPacket {
        public byte[] salt;
        public int ver;
        public int flg;
        public int intervalMs;
        public int accountedThroughSetId;
        public int setsExpected;
        public int dataExpected;
        public int dataRxOrig;
        public int dataRecoveredDl;
        public int dataRecoveredLate;
        public int dataDelivered;
        public int parityRx;
        public int parityExpected;
        public int setsKUnknown;
        public int setsFull;
        public int authFail;
        public int lateDup;
        public int structFail;
        public int repairLatP50Ms;
        public int repairLatP95Ms;
        public int dataBytesRx;
        public int parityBytesRx;
        public int setsTailDropped;
        public int dataLateRx;
        public int setsPartial;
        public int ledgerGroups;
        public int ledgerFailPpm;
        public int ledgerMeta;
    }

    /** decode/validate 的返回（fecstat.ts 返回 {status, packet}）。 */
    public static final class Decoded {
        public final int status;
        public final FecstatPacket packet;

        Decoded(int status, FecstatPacket packet) {
            this.status = status;
            this.packet = packet;
        }
    }

    private FecstatBlock() {}

    /** 全零报文模板，salt 复制自入参（fecstat.ts:47-57 makeFecstatPacket）。 */
    public static FecstatPacket makeFecstatPacket(byte[] salt) {
        FecstatPacket p = new FecstatPacket();
        p.salt = Arrays.copyOf(salt, salt.length);
        p.ver = FECSTAT_VERSION;
        return p;
    }

    /** 编码 128 字节块（fecstat.ts:59-79 encodeFecstat）。offset 与 fecstat.h 一致。 */
    public static byte[] encodeFecstat(FecstatPacket p) {
        byte[] out = new byte[FECSTAT_LEN];
        System.arraycopy(FECSTAT_MAGIC, 0, out, 0, FECSTAT_MAGIC.length);
        System.arraycopy(p.salt, 0, out, 16, 8);
        out[24] = (byte) p.ver;
        out[25] = (byte) p.flg;
        Wire.putLe16(p.intervalMs, out, 26);
        Wire.putLe32(p.accountedThroughSetId, out, 28);
        Wire.putLe32(p.setsExpected, out, 32);
        Wire.putLe32(p.dataExpected, out, 36);
        Wire.putLe32(p.dataRxOrig, out, 40);
        Wire.putLe32(p.dataRecoveredDl, out, 44);
        Wire.putLe32(p.dataRecoveredLate, out, 48);
        Wire.putLe32(p.dataDelivered, out, 52);
        Wire.putLe32(p.parityRx, out, 56);
        Wire.putLe32(p.parityExpected, out, 60);
        Wire.putLe32(p.setsKUnknown, out, 64);
        Wire.putLe32(p.setsFull, out, 68);
        Wire.putLe32(p.authFail, out, 72);
        Wire.putLe32(p.lateDup, out, 76);
        Wire.putLe32(p.structFail, out, 80);
        Wire.putLe16(p.repairLatP50Ms, out, 84);
        Wire.putLe16(p.repairLatP95Ms, out, 86);
        Wire.putLe32(p.dataBytesRx, out, 88);
        Wire.putLe32(p.parityBytesRx, out, 92);
        Wire.putLe32(p.setsTailDropped, out, 96);
        Wire.putLe32(p.dataLateRx, out, 100);
        Wire.putLe32(p.setsPartial, out, 104);
        Wire.putLe32(p.ledgerGroups, out, 108);
        Wire.putLe32(p.ledgerFailPpm, out, 112);
        Wire.putLe32(p.ledgerMeta, out, 116);
        return out; // reserved[2]（120..127）保持 0
    }

    /**
     * 解码并校验（fecstat.ts:81-116 decodeFecstat）。校验顺序：最小长度 → magic
     * → 版本（先于精确长度）→ len == 128 → salt 匹配。
     */
    public static Decoded decodeFecstat(byte[] input, byte[] salt) {
        if (input.length < 25) return new Decoded(BAD_LENGTH, null);
        boolean magicOk = FECSTAT_MAGIC.length >= 16 && input.length >= 16;
        for (int i = 0; magicOk && i < 16; ++i) {
            if (FECSTAT_MAGIC[i] != input[i]) magicOk = false;
        }
        if (!magicOk) return new Decoded(BAD_MAGIC, null);
        if ((input[24] & 0xff) != FECSTAT_VERSION) return new Decoded(BAD_VER, null);
        if (input.length != FECSTAT_LEN) return new Decoded(BAD_LENGTH, null);
        if (salt.length < 8) return new Decoded(BAD_SALT, null);
        for (int i = 0; i < 8; ++i) {
            if (salt[i] != input[16 + i]) return new Decoded(BAD_SALT, null);
        }
        FecstatPacket p = makeFecstatPacket(Arrays.copyOfRange(input, 16, 24));
        p.ver = input[24] & 0xff;
        p.flg = input[25] & 0xff;
        p.intervalMs = Wire.getLe16(input, 26);
        p.accountedThroughSetId = Wire.getLe32(input, 28);
        p.setsExpected = Wire.getLe32(input, 32);
        p.dataExpected = Wire.getLe32(input, 36);
        p.dataRxOrig = Wire.getLe32(input, 40);
        p.dataRecoveredDl = Wire.getLe32(input, 44);
        p.dataRecoveredLate = Wire.getLe32(input, 48);
        p.dataDelivered = Wire.getLe32(input, 52);
        p.parityRx = Wire.getLe32(input, 56);
        p.parityExpected = Wire.getLe32(input, 60);
        p.setsKUnknown = Wire.getLe32(input, 64);
        p.setsFull = Wire.getLe32(input, 68);
        p.authFail = Wire.getLe32(input, 72);
        p.lateDup = Wire.getLe32(input, 76);
        p.structFail = Wire.getLe32(input, 80);
        p.repairLatP50Ms = Wire.getLe16(input, 84);
        p.repairLatP95Ms = Wire.getLe16(input, 86);
        p.dataBytesRx = Wire.getLe32(input, 88);
        p.parityBytesRx = Wire.getLe32(input, 92);
        p.setsTailDropped = Wire.getLe32(input, 96);
        p.dataLateRx = Wire.getLe32(input, 100);
        p.setsPartial = Wire.getLe32(input, 104);
        p.ledgerGroups = Wire.getLe32(input, 108);
        p.ledgerFailPpm = Wire.getLe32(input, 112);
        p.ledgerMeta = Wire.getLe32(input, 116);
        return new Decoded(OK, p);
    }

    /**
     * 半窗单调校验器（fecstat.ts:119-141 FecstatValidator::validate）。
     * accounted_through_set_id：相等 = DUPLICATE（双发的第二份）；落后 = STALE；
     * 前跳超过 2^20 也判 STALE（防伪造前跳把控制器永久冻住）并计 futureRejects。
     */
    public static final class FecstatValidator {
        private boolean haveLast;
        private int lastSetId;
        public int futureRejects;

        public Decoded validate(byte[] input, byte[] salt) {
            Decoded r = decodeFecstat(input, salt);
            if (r.status != OK || r.packet == null) return r;
            int id = r.packet.accountedThroughSetId;
            if (haveLast) {
                if (id == lastSetId) return new Decoded(DUPLICATE, r.packet);
                if (!Seq.seqAfter(id, lastSetId)) return new Decoded(STALE, r.packet);
                int forward = id - lastSetId; // seqAfter 已保证正差值，无符号语义一致
                if (forward > FECSTAT_MAX_FORWARD_SETS) {
                    ++futureRejects;
                    return new Decoded(STALE, r.packet);
                }
            }
            haveLast = true;
            lastSetId = id;
            return r;
        }
    }

    /** ledger_meta byte0 = 主导 k（fecstat.ts:143）。 */
    public static int ledgerK(FecstatPacket p) {
        return p.ledgerMeta & 0xff;
    }

    /** ledger_meta byte2-3 = burst KL（0.01 nat）（fecstat.ts:144）。 */
    public static int ledgerBurstKl(FecstatPacket p) {
        return p.ledgerMeta >>> 16;
    }
}
