package com.dchen.fcpvpn.core.stream;

import com.dchen.fcpvpn.core.wire.Wire;

import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Stream 行为测试。逐条转写自 fcp-node tests/protocol.test.ts 的 STREAM 用例
 * （行号 262 / 875 / 900 / 924 / 953 / 1022 / 1047），断言条件保持一致。
 */
public class StreamTest {

    private static byte[] seg(int off, int n) {
        byte[] b = new byte[6 + n];
        b[0] = 1;
        Wire.putLe32(off, b, 1);
        return b;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private interface SenderHook {
        void onSend(byte[] seg);
    }

    private static StreamCallbacks callbacks(final List<byte[]> sink, SenderHook extra) {
        return new StreamCallbacks() {
            @Override
            public void send(byte[] seg) {
                sink.add(seg);
                if (extra != null) extra.onSend(seg);
            }

            @Override
            public void read(byte[] bytes) {
                sink.add(bytes); // 语义按各用例区分：read 单独集合的用例用自己的回调
            }

            @Override
            public void closed(String reason) {
            }
        };
    }

    /** protocol.test.ts:262 —— 乱序/重复/FIN 的按序重组。 */
    @Test
    public void orderedDeliveryAcrossLossReorderDuplicatesAndFin() {
        final List<byte[]> aToB = new ArrayList<>();
        final List<byte[]> bToA = new ArrayList<>();
        final byte[][] aRead = {new byte[0]};
        final byte[][] bRead = {new byte[0]};
        final int[] bEof = {0};
        StreamConfig cfg = new StreamConfig(8);
        cfg.ackEvery = 1;
        cfg.initialSrttMs = 50;
        cfg.idleTimeoutMs = 100000;
        Stream a = new Stream(cfg, new StreamCallbacks() {
            @Override
            public void send(byte[] s) { aToB.add(s); }

            @Override
            public void read(byte[] b) { aRead[0] = concat(aRead[0], b); }

            @Override
            public void closed(String reason) { }
        });
        Stream b = new Stream(new StreamConfig(8) {{
            ackEvery = 1;
            initialSrttMs = 50;
            idleTimeoutMs = 100000;
        }}, new StreamCallbacks() {
            @Override
            public void send(byte[] s) { bToA.add(s); }

            @Override
            public void read(byte[] b2) { bRead[0] = concat(bRead[0], b2); }

            @Override
            public void closed(String reason) { }

            @Override
            public void eof() { ++bEof[0]; }
        });
        byte[] msg = "the quick brown fox jumps over the lazy dog".getBytes(StandardCharsets.US_ASCII);
        a.write(msg, 0);
        a.closeWrite(0);
        assertTrue("payload is chunked into maxSegment-sized DATA segments", aToB.size() >= 6);

        // 乱序投递 + 一段重复；RTO 之后（t>20）把所有 DATA 段重新投递一次。
        int n = aToB.size();
        List<Integer> scrambled = new ArrayList<>();
        scrambled.add(0);
        scrambled.add(2);
        scrambled.add(1);
        scrambled.add(1); // 重复
        scrambled.add(4);
        scrambled.add(3);
        for (int i = 5; i < n; ++i) scrambled.add(i);
        for (int t = 1; t <= 40; ++t) {
            for (int i : scrambled) {
                Segment parsed = SegmentCodec.parseSegment(aToB.get(i));
                if (t == 1 || (t > 20 && parsed != null && parsed.type == StreamConstants.STREAM_TYPE_DATA)) {
                    b.onSegment(aToB.get(i), t);
                }
            }
            while (!bToA.isEmpty()) a.onSegment(bToA.remove(0), t);
            a.onTick(t);
            b.onTick(t);
        }
        assertEquals("reassembly is byte-exact", new String(msg, StandardCharsets.US_ASCII),
                new String(bRead[0], StandardCharsets.US_ASCII));
        assertEquals("FIN delivered once", 1, bEof[0]);
        assertTrue(b.isEofReceived());
    }

    /** protocol.test.ts:875 —— 对端窗口小到装不下一个段时不得死锁发送端。 */
    @Test
    public void tinyPeerWindowMustNotDeadlockSender() {
        int[] rwnds = {1, 3, 6};
        for (int rwnd : rwnds) {
            final List<byte[]> sent = new ArrayList<>();
            StreamConfig cfg = new StreamConfig(1200);
            cfg.initialSrttMs = 40;
            cfg.sendWindowBytes = 256 * 1024;
            cfg.rcvBufBytes = 256 * 1024;
            cfg.idleTimeoutMs = 1000000000;
            cfg.ackV2 = true;
            Stream s = new Stream(cfg, callbacks(sent, null));
            s.onSegment(SegmentCodec.encodeAckV2(0, rwnd, new ArrayList<Segment.AckRange>()), 1);
            byte[] data = new byte[5000];
            s.write(data, 2);
            long now = 2;
            for (int i = 0; i < 20; ++i) {
                s.onTick(now);
                now += 10;
            }
            assertTrue("rwnd=" + rwnd + ": not even a persist probe went out", sent.size() > 0);
            assertTrue("rwnd=" + rwnd + ": no deadline, so the host never wakes",
                    s.nextTimerMs(now) > 0);
            assertTrue("rwnd=" + rwnd + ": the queue never moved",
                    s.getPendingQueueBytes() < 5000);
        }
    }

    /** protocol.test.ts:900 —— 倒走的墙钟不得毒化 RTT 估计器。 */
    @Test
    public void backwardsWallClockMustNotPoisonRttEstimator() {
        Stream s = new Stream(new StreamConfig(1200) {{
            initialSrttMs = 200;
            sendWindowBytes = 256 * 1024;
            rcvBufBytes = 256 * 1024;
            idleTimeoutMs = 1000000000;
            ackV2 = true;
        }}, new StreamCallbacks() {
            @Override
            public void send(byte[] seg) { }

            @Override
            public void read(byte[] bytes) { }

            @Override
            public void closed(String reason) { }
        });
        s.write(new byte[4000], 0);
        s.onSegment(SegmentCodec.encodeAckV2(1200, 65535, new ArrayList<Segment.AckRange>()), 80); // 干净的 80ms 样本
        int gateBefore = s.retxAgeGateMs();
        assertTrue("the gate starts high (" + gateBefore + " ms)", gateBefore >= 100);
        // 墙钟在发送与 ACK 之间倒退 5 秒。
        s.write(new byte[1200], 120);
        s.onSegment(SegmentCodec.encodeAckV2(2400, 65535, new ArrayList<Segment.AckRange>()), 120 - 5000);
        assertTrue("the reorder gate collapsed on an invalid sample: " + gateBefore
                        + " -> " + s.retxAgeGateMs(),
                s.retxAgeGateMs() >= gateBefore * 0.9);
    }

    /** protocol.test.ts:924 —— 接收端持有量不得超过其公告的窗口。 */
    @Test
    public void receiverNeverHoldsMoreThanAdvertisedWindow() {
        final int CAP = 100 * 1024;
        long[] now = {0};
        Stream s = new Stream(new StreamConfig(1200) {{
            initialSrttMs = 40;
            sendWindowBytes = 256 * 1024;
            rcvBufBytes = CAP;
            idleTimeoutMs = 1000000000;
            ackV2 = true;
        }}, new StreamCallbacks() {
            @Override
            public void send(byte[] seg) { }

            @Override
            public void read(byte[] bytes) { } // 应用层永不消费

            @Override
            public void closed(String reason) { }
        });
        for (int off = 0; off < CAP - 1; off += 1194) {
            s.onSegment(seg(off, Math.min(1194, CAP - 1 - off)), now[0]++);
        }
        for (int off = CAP + 1000; off < 2 * CAP + 100000; off += 1194) {
            s.onSegment(seg(off, 1194), now[0]++);
        }
        long held = s.getReorderBytes() + s.getDeliveryPendingBytes();
        assertTrue("held " + held + " bytes > the advertised " + CAP
                        + " (" + String.format("%.2f", held / (double) CAP) + "x)",
                held <= CAP);
        assertTrue("the reorder counter went negative: " + s.getReorderBytes(),
                s.getReorderBytes() >= 0);
    }

    /** protocol.test.ts:953 —— 截断的 ACK v2 绝不报告它跳过的区间之后的内容（前缀规则）。 */
    @Test
    public void truncatedAckV2NeverReportsPastARunItLeftOut() {
        final int MAXSEG = 66; // 60B 负载 + 6B DATA 头
        final int HOLES = 40;
        final int SPACING = 120;
        final int RUN = 60;
        final List<byte[]> acks = new ArrayList<>();
        final List<Segment.AckRange> have = new ArrayList<>();
        Stream s = new Stream(new StreamConfig(MAXSEG) {{
            initialSrttMs = 40;
            sendWindowBytes = 256 * 1024;
            rcvBufBytes = 256 * 1024;
            idleTimeoutMs = 1000000000;
            ackV2 = true;
        }}, new StreamCallbacks() {
            @Override
            public void send(byte[] b) { acks.add(b); }

            @Override
            public void read(byte[] bytes) { }

            @Override
            public void closed(String reason) { }
        });
        // 一段按序到达把 cum 推到 60；区间从 120 起、间隔 120B，保持互不合并。
        s.onSegment(seg(0, RUN), 1);
        have.add(new Segment.AckRange(0, RUN));
        for (int k = 0; k < HOLES; ++k) {
            int off = 120 + SPACING * k;
            s.onSegment(seg(off, RUN), 2 + k);
            have.add(new Segment.AckRange(off, off + RUN));
        }
        s.onTick(200);
        List<Segment> parsed = new ArrayList<>();
        for (byte[] b : acks) {
            Segment p = SegmentCodec.parseSegment(b);
            if (p != null && p.type == StreamConstants.STREAM_TYPE_ACK_V2) parsed.add(p);
        }
        assertTrue("no ACK v2 went out", parsed.size() > 0);
        Segment last = parsed.get(parsed.size() - 1);
        // 字节精确预算（而非旧的每区间 10B 估计）才让前缀 ACK 装下这么多区间。
        int worstCase = (MAXSEG - 10) / 10;
        assertTrue("the ACK carried " + last.ranges.size() + " ranges, no more than the "
                        + worstCase + " the worst-case estimate allows",
                last.ranges.size() > worstCase);
        assertEquals("the range nearest cum is missing", 120, last.ranges.get(0).start);
        // 截断确实发生了：40 个区间全装得下的话本用例就失去意义。
        assertTrue("every run fitted the datagram, so this ACK never truncated",
                last.ranges.size() < HOLES);
        for (Segment a : parsed) {
            int lastEnd = a.ranges.isEmpty() ? a.cum : a.ranges.get(a.ranges.size() - 1).end;
            for (Segment.AckRange r : have) {
                int from = Math.max(r.start, a.cum);
                int to = Math.min(r.end, lastEnd);
                for (int x = from; x < to; x += 20) {
                    boolean covered = false;
                    for (Segment.AckRange q : a.ranges) {
                        if (x >= q.start && x < q.end) {
                            covered = true;
                            break;
                        }
                    }
                    assertTrue("ACK cum=" + a.cum + " leaves offset " + x
                            + " unreported below sackedHigh=" + lastEnd, covered);
                }
            }
        }
    }

    /** protocol.test.ts:1022 —— read() 重入不得重复或丢失字节。 */
    @Test
    public void reentrantReadMustNotDuplicateOrLoseBytes() {
        final Stream[] holder = new Stream[1];
        final List<Integer> delivered = new ArrayList<>();
        Stream s = new Stream(new StreamConfig(1200) {{
            initialSrttMs = 40;
            sendWindowBytes = 64 * 1024;
            rcvBufBytes = 64 * 1024;
            idleTimeoutMs = 1000000000;
            ackV2 = true;
        }}, new StreamCallbacks() {
            @Override
            public void send(byte[] seg) { }

            @Override
            public void closed(String reason) { }

            @Override
            public void read(byte[] b) {
                delivered.add(b.length);
                holder[0].onSegment(seg(5000, 100), 10); // 从 read() 里重入
            }
        });
        holder[0] = s;
        s.onSegment(seg(100, 100), 1);
        s.onSegment(seg(0, 100), 2);
        assertEquals("the same bytes were delivered " + delivered.size() + " times",
                1, delivered.size());
        assertTrue("the reorder counter went negative: " + s.getReorderBytes(),
                s.getReorderBytes() >= 0);
    }

    /** protocol.test.ts:1047 —— 低于累计点的 v1 SACK 块必须被忽略。 */
    @Test
    public void v1SackBlockBelowCumulativePointMustBeIgnored() {
        Stream s = new Stream(new StreamConfig(1200) {{
            initialSrttMs = 40;
            sendWindowBytes = 64 * 1024;
            rcvBufBytes = 64 * 1024;
            idleTimeoutMs = 1000000000;
        }}, new StreamCallbacks() {
            @Override
            public void send(byte[] seg) { }

            @Override
            public void read(byte[] bytes) { }

            @Override
            public void closed(String reason) { }
        });
        s.write(new byte[12000], 0);
        s.onTick(1);
        s.onTick(2);
        s.onSegment(SegmentCodec.encodeAck(6000, 65535, 1000, 7164), 10);
        assertTrue("the segments are in flight", s.txCountAbove(6000) > 0);
        assertEquals("a block below the cumulative point marked an unacked segment as delivered",
                0, s.txSackedAbove(6000));
    }

    /** 补充：两条 Stream 对接传输随机分片数据，校验有序完整性与 FIN 语义。 */
    @Test
    public void twoWiredStreamsRoundTripLargePayloadWithFin() {
        final List<byte[]> aToB = new ArrayList<>();
        final List<byte[]> bToA = new ArrayList<>();
        final byte[][] bRead = {new byte[0]};
        final int[] bEof = {0};
        StreamConfig cfg = new StreamConfig(1200);
        cfg.ackV2 = true;
        cfg.initialSrttMs = 40;
        Stream a = new Stream(cfg, new StreamCallbacks() {
            @Override
            public void send(byte[] seg) { aToB.add(seg); }

            @Override
            public void read(byte[] bytes) { }

            @Override
            public void closed(String reason) { }
        });
        Stream b = new Stream(new StreamConfig(1200) {{
            ackV2 = true;
            initialSrttMs = 40;
        }}, new StreamCallbacks() {
            @Override
            public void send(byte[] seg) { bToA.add(seg); }

            @Override
            public void read(byte[] bytes) { bRead[0] = concat(bRead[0], bytes); }

            @Override
            public void closed(String reason) { }

            @Override
            public void eof() { ++bEof[0]; }
        });
        byte[] payload = new byte[60000];
        for (int i = 0; i < payload.length; ++i) payload[i] = (byte) (i * 31 + 7);
        a.write(payload, 0);
        a.closeWrite(0);
        for (long t = 1; t <= 600 && !(b.isEofReceived()); ++t) {
            for (byte[] seg : new ArrayList<>(aToB)) {
                b.onSegment(seg, t);
            }
            aToB.clear();
            for (byte[] seg : new ArrayList<>(bToA)) {
                a.onSegment(seg, t);
            }
            bToA.clear();
            a.onTick(t);
            b.onTick(t);
        }
        assertArrayEquals("payload integrity across the wired pair", payload, bRead[0]);
        assertEquals(1, bEof[0]);
    }
}
