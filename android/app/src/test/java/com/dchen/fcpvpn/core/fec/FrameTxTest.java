package com.dchen.fcpvpn.core.fec;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import org.junit.Test;

/**
 * FrameTx 封集/定时/MTU 预算测试。期望值抄自 fcp-node tests/bytes.test.ts:150-162
 * （MTU 预算）、tests/geom.test.ts:43-143（交织/控制 lane/短组 k_eff）。
 * flush 定时与 MTU 拒收为任务书要求的用例。
 */
public class FrameTxTest {

    private static final FrameTx.MtuLimits LIMITS = FrameTx.computeMtuLimits(1400, 20);

    /** 收集"待发送 UDP 载荷"的 sink。 */
    static final class ListSink implements FrameTx.UdpSink {
        final List<byte[]> got = new ArrayList<>();

        @Override
        public void send(byte[] datagram) {
            got.add(datagram);
        }
    }

    static final class Delivered {
        final byte[] payload;
        final boolean recovered;

        Delivered(byte[] payload, boolean recovered) {
            this.payload = payload;
            this.recovered = recovered;
        }
    }

    static FrameRx makeRx(int d, int p, int maxSymbolLen, List<Delivered> out) {
        return new FrameRx(d, p,
                (b, rec, late) -> out.add(new Delivered(b, rec)),
                (b, now) -> {}, null, maxSymbolLen);
    }

    private static Set<Integer> firstBytes(List<Delivered> delivered) {
        Set<Integer> got = new TreeSet<>();
        for (Delivered d : delivered) got.add(d.payload[0] & 0xff);
        return got;
    }

    // ------------------------------------------------------------------
    // MTU 预算（bytes.test.ts:150-158 'MTU limits match frame_tx.h static_assert'）
    // ------------------------------------------------------------------

    @Test
    public void mtuLimits() {
        FrameTx.MtuLimits a = FrameTx.computeMtuLimits(1400, 20);
        assertTrue(a.valid);
        assertEquals(1335, a.payloadMax); // 1372 - 37（envelope 28 + hdr 7 + len 2）
        assertEquals(1337, a.symbolMax);  // 1372 - 35（envelope 28 + hdr 7）
        assertEquals(1311, a.mss);        // payloadMax - 24 legacy KCP 预留
        FrameTx.MtuLimits b = FrameTx.computeMtuLimits(1400, 40);
        assertEquals(1315, b.payloadMax);
        assertEquals(1291, b.mss);
        assertFalse(FrameTx.computeMtuLimits(80, 20).valid);
        // pmtuProbeLen：源码公式 (mtu − ip − 8) − 28 − 7（协议格式.md §8.2 的 −28−6 是 v1 旧数）
        assertEquals(1337, FrameTx.pmtuProbeLen(1400, 20));
    }

    @Test
    public void packOobFrameLayout() {
        // bytes.test.ts:159-161
        byte[] oob = FrameTx.packOobFrame(new byte[]{'F', 'C', 'P', 'K', 'A', 'L', '1', 0});
        assertEquals(7 + 8, oob.length);
        assertEquals(0, oob[0]);
        assertEquals(0, oob[4]);
        assertEquals(0, oob[5]);
        assertEquals(2, oob[6]);
    }

    // ------------------------------------------------------------------
    // 封集：D 满触发 / flush 定时触发 / MTU 拒收
    // ------------------------------------------------------------------

    @Test
    public void dFillTriggersClose() {
        ListSink sink = new ListSink();
        FrameTx tx = new FrameTx(4, LIMITS, sink);
        tx.setK(2);
        for (int i = 0; i < 4; ++i) tx.onSegment(TestHex.fill(20, i), 0);
        assertEquals(6, sink.got.size()); // 4 data + 2 parity
        assertEquals(1, tx.closedFull);
        assertEquals(0, tx.closedIdle);
        assertEquals(1, tx.currentSetId());
        // parity index = n + j = 4, 5；头上的 d 是本组 data 片数，k 是计划值而非 k_eff
        FecHeader.FecHdr p0 = FecHeader.parseHdr(sink.got.get(4));
        assertEquals(FecHeader.TYPE_PARITY, FecHeader.hdrType(p0.typeK));
        assertEquals(4, p0.index);
        assertEquals(4, p0.d);
        assertEquals(2, FecHeader.hdrK(p0.typeK));
        assertEquals(0, FecHeader.hdrJ(p0.typeK));
        // parity 符号恰为 symbolMax 字节 → 数据报 7 + symbolMax
        assertEquals(29, sink.got.get(0).length); // 7 头 + 2 len + 20 payload
        assertEquals(7 + 22, sink.got.get(4).length); // symbolMax = max(symLen) = 22
    }

    @Test
    public void flushTimerClosesIdleLane() {
        ListSink sink = new ListSink();
        FrameTx tx = new FrameTx(10, LIMITS, sink);
        tx.setK(2);
        tx.onSegment(TestHex.fill(20, 1), 0);
        assertEquals(1, tx.openN());
        // 默认 srtt 200ms：未到期不闭合
        tx.onTick(24);
        assertEquals(1, tx.openN());
        tx.onTick(199);
        assertEquals(1, tx.openN());
        // now - tLast >= flushMs → 闭合
        tx.onTick(200);
        assertEquals(0, tx.openN());
        assertEquals(1, tx.closedIdle);
        // k_eff = max(1, min(2, ceil(2*1/10))) = 1 → 恰好 1 个 parity
        int parity = 0;
        for (byte[] f : sink.got) {
            FecHeader.FecHdr h = FecHeader.parseHdr(f);
            if (FecHeader.hdrType(h.typeK) == FecHeader.TYPE_PARITY) ++parity;
        }
        assertEquals(1, parity);
    }

    @Test
    public void nextTimerMsTracksEarliestOpenLane() {
        ListSink sink = new ListSink();
        FrameTx tx = new FrameTx(10, LIMITS, sink);
        assertEquals(-1, tx.nextTimerMs(0));
        tx.onSegment(TestHex.fill(10, 0), 0);
        assertEquals(200, tx.nextTimerMs(0));
        assertEquals(1, tx.nextTimerMs(199));
        // setSrttMs 收紧 flush
        tx.setSrttMs(50);
        assertEquals(50, tx.nextTimerMs(0));
        // setGroupDrainMs：byRate = max(25, ceil(10*1.5)) = 25 < 50 → 收紧到 25
        tx.setGroupDrainMs(10);
        assertEquals(25, tx.nextTimerMs(0)); // byRate = max(MIN_FLUSH_MS=25, ceil(10*1.5)=15) = 25
        // byRate 大于 srtt 项时不延长
        tx.setGroupDrainMs(300);
        assertEquals(50, tx.nextTimerMs(0));
        // srtt 项受 [25, 200] 钳位
        tx.setSrttMs(10);
        assertEquals(25, tx.nextTimerMs(0));
        tx.setSrttMs(500);
        assertEquals(200, tx.nextTimerMs(0));
    }

    @Test
    public void oversizeSegmentDropped() {
        ListSink sink = new ListSink();
        FrameTx tx = new FrameTx(10, LIMITS, sink); // payloadMax 1335
        tx.onSegment(new byte[1336], 0);
        assertEquals(1, tx.mtuDrops);
        assertEquals(0, sink.got.size());
        tx.onSegment(new byte[1335], 0);
        assertEquals(1, tx.mtuDrops);
        assertEquals(1, sink.got.size());
    }

    @Test
    public void abortDropsOpenLanesWithoutParity() {
        ListSink sink = new ListSink();
        FrameTx tx = new FrameTx(10, LIMITS, sink);
        tx.setK(3);
        tx.onSegment(TestHex.fill(20, 1), 0);
        tx.onSegment(TestHex.fill(20, 2), 0);
        assertEquals(2, tx.openN());
        tx.abort();
        assertEquals(0, tx.openN());
        assertEquals(1, tx.abortedSets);
        assertEquals(2, sink.got.size()); // 只有 2 个 data，无 parity
    }

    // ------------------------------------------------------------------
    // 交织（geom.test.ts:43-94）
    // ------------------------------------------------------------------

    /** geom.test.ts:21-41 runLaneless：驱动一个发送端，丢指定线位置的符号，数接收端交付。 */
    private static final class Run {
        final List<byte[]> emitted;
        final List<Delivered> delivered = new ArrayList<>();
        final Set<Integer> got;
        final FrameTx tx;

        Run(List<byte[]> emitted, FrameTx tx) {
            this.emitted = emitted;
            this.tx = tx;
            this.got = firstBytes(delivered);
        }
    }

    private static Run runLaneless(int d, int k, int lanes, int nSegs, Set<Integer> dropAt) {
        ListSink sink = new ListSink();
        FrameTx tx = new FrameTx(d, LIMITS, sink);
        tx.setInterleave(lanes);
        tx.setK(k);
        byte[][] payloads = new byte[nSegs][];
        for (int i = 0; i < nSegs; ++i) {
            payloads[i] = new byte[40];
            Arrays.fill(payloads[i], 0, 4, (byte) (i & 0xff));
        }
        for (byte[] p : payloads) tx.onSegment(p, 0);
        List<Delivered> delivered = new ArrayList<>();
        FrameRx rx = makeRx(d, k, LIMITS.symbolMax, delivered);
        for (int i = 0; i < sink.got.size(); ++i) {
            if (!dropAt.contains(i)) rx.onDatagram(sink.got.get(i), 0);
        }
        Run r = new Run(sink.got, tx);
        r.delivered.addAll(delivered);
        // got 需含重构件：重新计算
        r.got.clear();
        r.got.addAll(firstBytes(r.delivered));
        return r;
    }

    @Test
    public void interleaveSameKSurvivesLongerBurst() {
        // geom.test.ts:43-62：d=10, k=3，连续丢 4 个数据符号
        Set<Integer> drop = new HashSet<>(Arrays.asList(4, 5, 6, 7));
        Run flat = runLaneless(10, 3, 1, 40, drop);
        assertEquals(4, flat.tx.closedFull);
        assertEquals(36, flat.got.size()); // 整组被抹掉
        Run spread = runLaneless(10, 3, 4, 40, drop);
        assertEquals(4, spread.tx.closedFull);
        assertEquals(40, spread.got.size()); // 全部交付
        // 交织不买冗余：parity 条数与总包数完全相同
        assertEquals(flat.tx.paritySymbols, spread.tx.paritySymbols);
        assertEquals(flat.emitted.size(), spread.emitted.size());
    }

    @Test
    public void interleaveRoundRobinAcrossLanes() {
        // geom.test.ts:64-76：set id 按 lane 开启顺序分配
        Run r = runLaneless(10, 3, 3, 30, new HashSet<Integer>());
        assertEquals(3, r.tx.closedFull);
        assertEquals(3, r.tx.getInterleave());
        List<int[]> firstData = new ArrayList<>();
        for (byte[] f : r.emitted) {
            FecHeader.FecHdr h = FecHeader.parseHdr(f);
            if (FecHeader.hdrType(h.typeK) == FecHeader.TYPE_DATA) {
                firstData.add(new int[]{h.setId, h.index});
                if (firstData.size() == 6) break;
            }
        }
        int[] ids = {0, 1, 2, 0, 1, 2};
        int[] idx = {0, 0, 0, 1, 1, 1};
        assertEquals(6, firstData.size());
        for (int i = 0; i < 6; ++i) {
            assertEquals(ids[i], firstData.get(i)[0]);
            assertEquals(idx[i], firstData.get(i)[1]);
        }
        assertEquals(0, r.tx.openN());
    }

    @Test
    public void idleLaneStillGetsParityFromFlushTimer() {
        // geom.test.ts:78-94：23 段 / 4 条 lane，两条 lane 差一个没满，flush 定时器兜底
        ListSink sink = new ListSink();
        FrameTx tx = new FrameTx(10, LIMITS, sink);
        tx.setInterleave(4);
        tx.setK(2);
        for (int i = 0; i < 23; ++i) tx.onSegment(TestHex.fill(30, i), 0);
        assertEquals(23, tx.openN());
        tx.onTick(1000);
        assertEquals(0, tx.openN());
        List<byte[]> parity = new ArrayList<>();
        for (byte[] f : sink.got) {
            FecHeader.FecHdr h = FecHeader.parseHdr(f);
            if (FecHeader.hdrType(h.typeK) == FecHeader.TYPE_PARITY) parity.add(f);
        }
        assertTrue(parity.size() > 0);
        // 短 lane 缩放 parity：ceil(k*n/d)，头上的 k（计划值）不超过 2
        for (byte[] f : parity) {
            FecHeader.FecHdr h = FecHeader.parseHdr(f);
            assertTrue(FecHeader.hdrK(h.typeK) <= 2);
        }
    }

    // ------------------------------------------------------------------
    // 控制段专用 lane（geom.test.ts:128-143）
    // ------------------------------------------------------------------

    @Test
    public void controlSegmentsNeverJoinDataGroup() {
        ListSink sink = new ListSink();
        FrameTx tx = new FrameTx(10, LIMITS, sink);
        tx.setInterleave(4);
        tx.setK(3);
        assertEquals(10, tx.getGroupD());
        tx.onSegment(TestHex.fill(20, 1), 0);
        tx.onSegment(TestHex.fill(20, 2), 0);
        assertEquals(2, tx.openN());

        tx.onSegment(TestHex.fill(20, 3), 0, true); // 一个 ACK
        assertEquals("控制 lane 立即闭合", 2, tx.openN());
        // 找 type=data 且 payload 首字节（数据报偏移 9）为 3 的符号
        List<byte[]> acks = new ArrayList<>();
        for (byte[] f : sink.got) {
            FecHeader.FecHdr h = FecHeader.parseHdr(f);
            if (FecHeader.hdrType(h.typeK) == FecHeader.TYPE_DATA && f[9] == 3) acks.add(f);
        }
        assertEquals(1, acks.size());
        int ackSet = FecHeader.parseHdr(acks.get(0)).setId;
        int inSet = 0;
        for (byte[] f : sink.got) {
            if (FecHeader.parseHdr(f).setId == ackSet) ++inSet;
        }
        assertEquals(2, inSet); // 1 个 ACK + 1 个 repair
    }

    // ------------------------------------------------------------------
    // 短组 k_eff（geom.test.ts:96-126）
    // ------------------------------------------------------------------

    @Test
    public void shortGroupRepairsBecauseDecoderDerivesKEff() {
        byte[] p0 = TestHex.fill(40, 0x11);
        byte[] p1 = TestHex.fill(40, 0x22);
        ListSink sink = new ListSink();
        FrameTx tx = new FrameTx(10, LIMITS, sink);
        tx.setK(6);
        tx.onSegment(p0, 0);
        tx.onSegment(p1, 0);
        tx.onTick(5000);
        assertEquals(4, sink.got.size()); // 2 data + kEff=2 parity

        List<Delivered> delivered = new ArrayList<>();
        FrameRx rx = makeRx(10, 6, LIMITS.symbolMax, delivered);
        // 除第一个 data 符号外全部送达（现在时刻 1ms）
        for (int i = 1; i < sink.got.size(); ++i) rx.onDatagram(sink.got.get(i), 1);
        assertEquals(0, rx.counters.badRecon);
        int repaired = 0;
        byte[] repairedPayload = null;
        for (Delivered d : delivered) {
            if (d.recovered) {
                ++repaired;
                repairedPayload = d.payload;
            }
        }
        assertEquals(1, repaired);
        assertTrue(Arrays.equals(p0, repairedPayload));
    }
}
