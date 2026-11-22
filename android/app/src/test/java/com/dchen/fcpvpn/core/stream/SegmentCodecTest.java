package com.dchen.fcpvpn.core.stream;

import com.dchen.fcpvpn.core.wire.Wire;

import org.junit.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/** 段编解码测试：线格式字节级对照 + 非法输入拒绝（语义对照 protocol.test.ts）。 */
public class SegmentCodecTest {

    @Test
    public void dataSegmentRoundTrip() {
        byte[] payload = "hello world".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        byte[] wire = SegmentCodec.encodeData(0x11223344, StreamConstants.STREAM_FLAG_FIN, payload);
        assertEquals(StreamConstants.STREAM_DATA_HDR_LEN + payload.length, wire.length);
        assertEquals(1, wire[0]);
        assertEquals(0x44, wire[1] & 0xff);   // seq LE 首字节
        assertEquals(0x33, wire[2] & 0xff);
        assertEquals(0x22, wire[3] & 0xff);
        assertEquals(0x11, wire[4] & 0xff);
        assertEquals(StreamConstants.STREAM_FLAG_FIN, wire[5] & 0xff);

        Segment s = SegmentCodec.parseSegment(wire);
        assertEquals(StreamConstants.STREAM_TYPE_DATA, s.type);
        assertEquals(0x11223344, s.seq);
        assertEquals(StreamConstants.STREAM_FLAG_FIN, s.flags);
        assertArrayEquals(payload, s.payload);
    }

    @Test
    public void dataSegmentTruncatedHeaderRejected() {
        assertNull(SegmentCodec.parseSegment(new byte[]{1, 2, 3}));
    }

    @Test
    public void ackSegmentIsFixed17Bytes() {
        byte[] wire = SegmentCodec.encodeAck(0x0a0b0c0d, 65535, 1000, 7164);
        assertEquals(StreamConstants.STREAM_ACK_LEN, wire.length);
        assertEquals(2, wire[0]);
        Segment s = SegmentCodec.parseSegment(wire);
        assertEquals(StreamConstants.STREAM_TYPE_ACK, s.type);
        assertEquals(0x0a0b0c0d, s.cum);
        assertEquals(65535, s.rwnd);
        assertEquals(1000, s.sackStart);
        assertEquals(7164, s.sackEnd);
        // 长度不等于 17 视为非法
        assertNull(SegmentCodec.parseSegment(Arrays.copyOf(wire, wire.length - 1)));
    }

    @Test
    public void ackV2RangesAreUvarintGapLenPairs() {
        // cum=100，区间 [120,180) 与 [300,340)：gap 分别 20 与 120，len 分别 60 与 40
        List<Segment.AckRange> blocks = new ArrayList<>();
        blocks.add(new Segment.AckRange(120, 180));
        blocks.add(new Segment.AckRange(300, 340));
        byte[] wire = SegmentCodec.encodeAckV2(100, 4096, blocks);
        Segment s = SegmentCodec.parseSegment(wire);
        assertEquals(StreamConstants.STREAM_TYPE_ACK_V2, s.type);
        assertEquals(100, s.cum);
        assertEquals(4096, s.rwnd);
        assertFalse(s.copy);
        assertEquals(2, s.ranges.size());
        assertEquals(120, s.ranges.get(0).start);
        assertEquals(180, s.ranges.get(0).end);
        assertEquals(300, s.ranges.get(1).start);
        assertEquals(340, s.ranges.get(1).end);
    }

    @Test
    public void ackV2CopyFlagRidesBit7OfCountByte() {
        byte[] wire = SegmentCodec.encodeAckV2(0, 1, new ArrayList<Segment.AckRange>(), true);
        assertEquals(StreamConstants.ACK_V2_FLAG_COPY, wire[9] & 0xff);
        Segment s = SegmentCodec.parseSegment(wire);
        assertTrue(s.copy);
        assertEquals(0, s.ranges.size());
    }

    @Test
    public void ackV2MalformedRangesRejected() {
        // blen=0 非法
        byte[] bad = new byte[12];
        bad[0] = 4;
        Wire.putLe32(100, bad, 1);
        Wire.putLe32(4096, bad, 5);
        bad[9] = 1; // 1 个区间
        bad[10] = 20; // gap=20
        bad[11] = 0;  // len=0 → 非法
        assertNull(SegmentCodec.parseSegment(bad, bad.length));

        // 尾部多出字节 → 整体拒绝
        List<Segment.AckRange> blocks = new ArrayList<>();
        blocks.add(new Segment.AckRange(120, 180));
        byte[] wire = SegmentCodec.encodeAckV2(100, 1, blocks);
        byte[] padded = Arrays.copyOf(wire, wire.length + 1);
        assertNull(SegmentCodec.parseSegment(padded, padded.length));
    }

    @Test
    public void ackV2FiveByteUvarintBoundary() {
        // gap 需要 5 字节编码（≥ 2^28）时仍可往返
        int farStart = 100 + 0x10000000;
        List<Segment.AckRange> blocks = new ArrayList<>();
        blocks.add(new Segment.AckRange(farStart, farStart + 16));
        byte[] wire = SegmentCodec.encodeAckV2(100, 1, blocks);
        Segment s = SegmentCodec.parseSegment(wire);
        assertEquals(1, s.ranges.size());
        assertEquals(farStart, s.ranges.get(0).start);
        assertEquals(farStart + 16, s.ranges.get(0).end);
    }

    @Test
    public void ackV2NonCanonicalFifthByteRejected() {
        // 手工构造第 5 字节 > 0x0f 的非规范 u32 LEB128（wire.ts 同款修复的回归）
        byte[] bad = new byte[15];
        bad[0] = 4;
        Wire.putLe32(0, bad, 1);
        Wire.putLe32(1, bad, 5);
        bad[9] = 1;  // 1 个区间
        bad[10] = (byte) 0xff;
        bad[11] = (byte) 0xff;
        bad[12] = (byte) 0xff;
        bad[13] = (byte) 0xff;
        bad[14] = (byte) 0x7f; // 第 5 字节有效位 > 4 → 非规范
        assertNull(SegmentCodec.parseSegment(bad, bad.length));
    }

    @Test
    public void rstSegmentIsTwoBytes() {
        byte[] wire = SegmentCodec.encodeRst(StreamConstants.STREAM_RST_ABORT);
        assertArrayEquals(new byte[]{3, 1}, wire);
        Segment s = SegmentCodec.parseSegment(wire);
        assertEquals(StreamConstants.STREAM_TYPE_RST, s.type);
        assertEquals(StreamConstants.STREAM_RST_ABORT, s.code);
        assertNull(SegmentCodec.parseSegment(new byte[]{3}));
    }

    @Test
    public void unknownTypeIsRejected() {
        assertNull(SegmentCodec.parseSegment(new byte[]{99, 1, 2, 3}));
        assertNull(SegmentCodec.parseSegment(new byte[0], 0));
    }
}
