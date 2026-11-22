package com.dchen.fcpvpn.core.fec;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Random;
import java.util.Set;

import org.junit.Test;

/**
 * FrameRx 测试。期望值抄自 fcp-node tests/protocol.test.ts:196-260、658-800
 * 与 tests/golden.test.ts；帧级 round-trip（随机丢至剩 k 个幸存者）为任务书
 * 要求的自洽用例，覆盖 d + p = 256 边界。
 */
public class FrameRxTest {

    /** protocol.test.ts:247-249 的 dataFrame：单 data 符号 [3, 0, 0xab]，typeK=0x60（k=3 data）。 */
    private static byte[] dataFrame(int setId, int index, int d) {
        return FrameTx.packTxFrame(setId, index, d, 0x60, new byte[]{3, 0, (byte) 0xab});
    }

    private static final FrameTx.MtuLimits LIMITS = FrameTx.computeMtuLimits(1400, 20);

    // ------------------------------------------------------------------
    // FrameTx/FrameRx 联合：D=10 k=3 修复两个丢失（protocol.test.ts:196-226）
    // ------------------------------------------------------------------

    @Test
    public void d10k3RepairsTwoLostSymbols() {
        FrameTx.MtuLimits limits = FrameTx.computeMtuLimits(1400, 20);
        FrameTxTest.ListSink sink = new FrameTxTest.ListSink();
        FrameTx tx = new FrameTx(10, limits, sink);
        tx.setK(3);
        byte[][] payloads = new byte[10][];
        for (int i = 0; i < 10; ++i) {
            payloads[i] = new byte[100];
            Arrays.fill(payloads[i], (byte) (i + 1));
        }
        for (byte[] p : payloads) tx.onSegment(p, 0);
        assertEquals(13, sink.got.size()); // 10 data + 3 parity
        assertEquals(1, tx.closedFull);
        assertEquals(1, tx.currentSetId());

        List<FrameTxTest.Delivered> delivered = new ArrayList<>();
        FrameRx rx = FrameTxTest.makeRx(10, 3, limits.symbolMax, delivered);
        // 丢 data index 2 和 7；其余按序（data 先、parity 后）
        for (byte[] f : sink.got) {
            FecHeader.FecHdr h = FecHeader.parseHdr(f);
            if (h.index == 2 || h.index == 7) continue;
            rx.onDatagram(f, 0);
        }
        assertEquals(10, delivered.size());
        assertEquals(2, rx.counters.recovered);
        Set<String> got = new HashSet<>();
        int recoveredMarks = 0;
        for (FrameTxTest.Delivered d : delivered) {
            got.add(TestHex.hex(d.payload));
            if (d.recovered) ++recoveredMarks;
        }
        for (byte[] p : payloads) assertTrue(got.contains(TestHex.hex(p)));
        assertEquals(2, recoveredMarks);
    }

    // ------------------------------------------------------------------
    // oob 分路与坏头拒收（protocol.test.ts:228-240）
    // ------------------------------------------------------------------

    @Test
    public void oobDispatchedMalformedRejected() {
        List<byte[]> oobs = new ArrayList<>();
        List<byte[]> delivered = new ArrayList<>();
        FrameRx rx = new FrameRx(10, 3,
                (b, rec, late) -> delivered.add(b),
                (b, now) -> oobs.add(b));
        // 手工拼 oob 帧：头 [0,0,0,0,0,0,2] + 消息（与 protocol.test.ts 相同的字节）
        byte[] oobFrame = new byte[15];
        oobFrame[6] = 2;
        System.arraycopy(new byte[]{'F', 'C', 'P', 'K', 'A', 'L', '1', 0}, 0, oobFrame, 7, 8);
        rx.onDatagram(oobFrame, 0);
        assertEquals(1, oobs.size());
        assertTrue("oob 内容原样分路",
                Arrays.equals(new byte[]{'F', 'C', 'P', 'K', 'A', 'L', '1', 0}, oobs.get(0)));
        assertEquals(0, delivered.size());
        rx.onDatagram(new byte[]{0, 0, 0}, 0);
        assertEquals(1, rx.counters.structFail);
    }

    // ------------------------------------------------------------------
    // len 自校验失败路径（任务书要求）
    // ------------------------------------------------------------------

    @Test
    public void lenSelfCheckFailure() {
        List<FrameTxTest.Delivered> delivered = new ArrayList<>();
        FrameRx rx = FrameTxTest.makeRx(10, 3, 65535, delivered);
        // data 符号声明 len=5，实际符号只有 3 字节 → structFail，且不创建集合
        rx.onDatagram(FrameTx.packTxFrame(3, 0, 10, 0x60, new byte[]{5, 0, (byte) 0xab}), 0);
        assertEquals(1, rx.counters.structFail);
        assertEquals(0, delivered.size());
        assertNull(rx.view(3));
        // 符号本身不足 2 字节 → structFail
        rx.onDatagram(FrameTx.packTxFrame(4, 0, 10, 0x60, new byte[]{1}), 0);
        assertEquals(2, rx.counters.structFail);
        // 符号超过 maxSymbolLen → structFail
        rx.setMaxSymbolLen(4);
        rx.onDatagram(FrameTx.packTxFrame(5, 0, 10, 0x60,
                new byte[]{6, 0, 1, 2, 3, 4}), 0);
        assertEquals(3, rx.counters.structFail);
    }

    // ------------------------------------------------------------------
    // FECSTAT 单调键（protocol.test.ts:242-260）
    // ------------------------------------------------------------------

    @Test
    public void accountedThroughStaysMonotonicAfterRetirement() {
        FrameRx rx = FrameTxTest.makeRx(10, 3, 65535, new ArrayList<>());
        rx.onDatagram(dataFrame(5, 0, 10), 0);
        rx.onTick(1001);
        assertEquals(5, rx.accountedThroughSetId());
        rx.onTick(2001); // 集合 5 已退役并从表中删除
        assertEquals("退役不得重置单调键", 5, rx.accountedThroughSetId());
        rx.onTick(4000);
        assertEquals(5, rx.accountedThroughSetId());
        rx.onDatagram(dataFrame(6, 0, 10), 4000);
        rx.onTick(5001);
        assertEquals(6, rx.accountedThroughSetId());
    }

    // ------------------------------------------------------------------
    // 容量驱逐退役已记账集合（protocol.test.ts:658-687）
    // ------------------------------------------------------------------

    @Test
    public void evictingAccountedSetRetiresItsId() {
        FrameRx rx = FrameTxTest.makeRx(10, 3, 65535, new ArrayList<>());
        for (int id = 0; id < 256; ++id) rx.onDatagram(dataFrame(id, 0, 10), 0);
        rx.onTick(1000); // 全部记账（1s 门），尚未退役（2s）
        int before = rx.counters.setsExpected;
        assertEquals(256, before);

        rx.onDatagram(dataFrame(256, 0, 10), 1000); // 逼出对 set 0 的驱逐
        assertNull("set 0 被驱逐", rx.view(0));

        rx.onDatagram(dataFrame(0, 0, 10), 1001); // 迟到符号不得重建已记账集合
        assertNull(rx.view(0));
        assertEquals(1, rx.counters.retiredDropped);
        rx.onTick(2200);
        assertEquals("被驱逐的 set 0 不得二次记账", before + 1, rx.counters.setsExpected);
    }

    // ------------------------------------------------------------------
    // 重构符号字节预算（protocol.test.ts:689-714）
    // ------------------------------------------------------------------

    @Test
    public void recoveredSymbolObeysByteBudget() {
        FrameRx rx = FrameTxTest.makeRx(10, 3, 65535, new ArrayList<>());
        int ceiling = FrameRx.MAX_RX_SYMBOL_BYTES;
        rx.symbolBytes = ceiling - 10;
        FrameRx.RxSet fakeSet = new FrameRx.RxSet();
        byte[] big = new byte[100];
        Arrays.fill(big, (byte) 0x7b);

        rx.storeRecovered(fakeSet, 0, big); // 将超预算 90 字节
        assertEquals("拒收不得增长 symbolBytes", ceiling - 10, rx.symbolBytes);
        assertEquals("拒收不得缓存行", 0, fakeSet.data.size());
        assertEquals(1, rx.counters.symbolBudgetDrops);

        byte[] small = new byte[8];
        Arrays.fill(small, (byte) 0x5a);
        rx.storeRecovered(fakeSet, 1, small);
        assertEquals(ceiling - 2, rx.symbolBytes);
        assertEquals(8, fakeSet.data.get(1).length);
    }

    // ------------------------------------------------------------------
    // 空隙占位集合（protocol.test.ts:753-767）
    // ------------------------------------------------------------------

    @Test
    public void gapPlaceholdersCountAsKUnknown() {
        FrameRx rx = FrameTxTest.makeRx(10, 3, 65535, new ArrayList<>());
        rx.onDatagram(dataFrame(0, 0, 10), 0);
        rx.onDatagram(dataFrame(5, 0, 10), 0); // 跳变 0→5 创建占位 1..4
        rx.onTick(1000);
        assertEquals(4, rx.counters.setsKUnknown);
        assertEquals(0, rx.counters.setsTailDropped);
    }

    // ------------------------------------------------------------------
    // 迟到原件（protocol.test.ts:769-783）
    // ------------------------------------------------------------------

    @Test
    public void lateOriginalCountsAsDataLateRxNotLateDup() {
        FrameRx rx = FrameTxTest.makeRx(5, 3, 65535, new ArrayList<>());
        rx.onDatagram(dataFrame(7, 0, 5), 0);
        rx.onDatagram(dataFrame(7, 2, 5), 0); // maxDataIndex=2 → nUsed/边界=3，洞在 1
        rx.onTick(1000);                      // 集合 7 记账
        rx.onDatagram(dataFrame(7, 1, 5), 1001); // 边界内的迟到原件
        assertEquals(1, rx.counters.dataLateRx);
        assertEquals(0, rx.counters.lateDup);
    }

    // ------------------------------------------------------------------
    // k 冲突（protocol.test.ts:785-800）
    // ------------------------------------------------------------------

    @Test
    public void conflictingKRejectedAsStructFail() {
        FrameRx rx = FrameTxTest.makeRx(5, 3, 65535, new ArrayList<>());
        rx.onDatagram(FrameTx.packTxFrame(9, 0, 5, (1 << 5) | 0, new byte[]{3, 0, (byte) 0xab}), 0);
        assertEquals(0, rx.counters.structFail);
        assertNotNull(rx.view(9));
        int before = rx.view(9).orig.size();
        rx.onDatagram(FrameTx.packTxFrame(9, 1, 5, (2 << 5) | 0, new byte[]{3, 0, (byte) 0xab}), 0);
        assertEquals("冲突 k 计 structFail", 1, rx.counters.structFail);
        assertEquals("冲突符号不进集合", before, rx.view(9).orig.size());
    }

    // ------------------------------------------------------------------
    // 帧级 round-trip：随机丢至剩 k 个幸存者，逐字节重构（任务书要求）
    // ------------------------------------------------------------------

    @Test
    public void frameLevelRoundTripDropsToKSurvivors() {
        int[][] cases = {{10, 6}, {4, 2}, {1, 1}};
        Random rnd = new Random(20261122);
        for (int[] cs : cases) {
            int d = cs[0];
            int k = cs[1];
            FrameTxTest.ListSink sink = new FrameTxTest.ListSink();
            FrameTx tx = new FrameTx(d, LIMITS, sink);
            tx.setK(k);
            byte[][] payloads = new byte[d][];
            for (int i = 0; i < d; ++i) {
                payloads[i] = new byte[50];
                rnd.nextBytes(payloads[i]);
            }
            for (byte[] p : payloads) tx.onSegment(p, 0);
            assertEquals(d + k, sink.got.size());

            // 丢 k 个 data（index 0..k-1），保留全部 parity：解码恰好消耗 k 个 parity
            List<FrameTxTest.Delivered> delivered = new ArrayList<>();
            FrameRx rx = FrameTxTest.makeRx(d, k, LIMITS.symbolMax, delivered);
            for (byte[] f : sink.got) {
                FecHeader.FecHdr h = FecHeader.parseHdr(f);
                if (FecHeader.hdrType(h.typeK) == FecHeader.TYPE_DATA && h.index < k) continue;
                rx.onDatagram(f, 0);
            }
            assertEquals("delivered d=" + d + " k=" + k, d, delivered.size());
            assertEquals(k, rx.counters.recovered);
            Set<String> got = new HashSet<>();
            for (FrameTxTest.Delivered dd : delivered) got.add(TestHex.hex(dd.payload));
            for (byte[] p : payloads) assertTrue(got.contains(TestHex.hex(p)));
        }
    }

    @Test
    public void frameLevelRoundTripAtMaxSBoundary() {
        // d + p = 256 = MAX_S 边界：d=249, k=7
        int d = 249;
        int k = 7;
        FrameTxTest.ListSink sink = new FrameTxTest.ListSink();
        FrameTx tx = new FrameTx(d, LIMITS, sink);
        tx.setK(k);
        byte[][] payloads = new byte[d][];
        for (int i = 0; i < d; ++i) {
            payloads[i] = new byte[50];
            payloads[i][0] = (byte) i;
            payloads[i][1] = (byte) (i * 7);
        }
        for (byte[] p : payloads) tx.onSegment(p, 0);
        assertEquals(d + k, sink.got.size()); // 249 data + 7 parity

        // 丢 7 个 data（= k，7 次擦除恰好耗尽冗余度），全部 parity 保留 → 全部重构
        List<FrameTxTest.Delivered> delivered = new ArrayList<>();
        FrameRx rx = FrameTxTest.makeRx(d, k, LIMITS.symbolMax, delivered);
        for (byte[] f : sink.got) {
            FecHeader.FecHdr h = FecHeader.parseHdr(f);
            if (FecHeader.hdrType(h.typeK) == FecHeader.TYPE_DATA && h.index < 7) continue;
            rx.onDatagram(f, 0);
        }
        assertEquals(d, delivered.size());
        assertEquals(7, rx.counters.recovered);
        assertEquals(0, rx.counters.badRecon);
        Set<String> got = new HashSet<>();
        for (FrameTxTest.Delivered dd : delivered) got.add(TestHex.hex(dd.payload));
        for (byte[] p : payloads) assertTrue(got.contains(TestHex.hex(p)));
    }

    @Test
    public void unsolvableLossIsSilentlySkipped() {
        // 丢 k+1 个：不可解，不交付重构，也不崩
        FrameTxTest.ListSink sink = new FrameTxTest.ListSink();
        FrameTx tx = new FrameTx(10, LIMITS, sink);
        tx.setK(3);
        for (int i = 0; i < 10; ++i) tx.onSegment(TestHex.fill(30, i), 0);
        List<FrameTxTest.Delivered> delivered = new ArrayList<>();
        FrameRx rx = FrameTxTest.makeRx(10, 3, LIMITS.symbolMax, delivered);
        for (byte[] f : sink.got) {
            FecHeader.FecHdr h = FecHeader.parseHdr(f);
            if (FecHeader.hdrType(h.typeK) == FecHeader.TYPE_DATA && h.index < 4) continue;
            rx.onDatagram(f, 0);
        }
        assertEquals(6, delivered.size());
        assertEquals(0, rx.counters.recovered);
        assertEquals(0, rx.counters.badRecon);
    }
}
