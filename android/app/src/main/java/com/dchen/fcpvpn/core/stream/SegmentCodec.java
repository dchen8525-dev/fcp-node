package com.dchen.fcpvpn.core.stream;

import com.dchen.fcpvpn.core.wire.Seq;
import com.dchen.fcpvpn.core.wire.Uvarint;
import com.dchen.fcpvpn.core.wire.Wire;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * FCP-STREAM v1 段编解码。移植自 fcp-node src/stream/segment.ts
 * （对应 C++ src/fcp/stream.h / stream.cc / stream_recv.cc / stream_send.cc）。
 * 整数一律小端；ACK v2 的区间是相对 cum 的 LEB128 uvarint (gap,len) 对（回绕安全）。
 */
public final class SegmentCodec {

    private SegmentCodec() {}

    public static byte[] encodeData(int seq, int flags, byte[] payload) {
        return encodeData(seq, flags, payload, 0, payload.length);
    }

    public static byte[] encodeData(int seq, int flags, byte[] payload, int off, int len) {
        byte[] out = new byte[StreamConstants.STREAM_DATA_HDR_LEN + len];
        out[0] = (byte) StreamConstants.STREAM_TYPE_DATA;
        Wire.putLe32(seq, out, 1);
        out[5] = (byte) (flags & 0xff);
        System.arraycopy(payload, off, out, StreamConstants.STREAM_DATA_HDR_LEN, len);
        return out;
    }

    public static byte[] encodeAck(int cum, int rwnd, int sackStart, int sackEnd) {
        byte[] out = new byte[StreamConstants.STREAM_ACK_LEN];
        out[0] = (byte) StreamConstants.STREAM_TYPE_ACK;
        Wire.putLe32(cum, out, 1);
        Wire.putLe32(rwnd, out, 5);
        Wire.putLe32(sackStart, out, 9);
        Wire.putLe32(sackEnd, out, 13);
        return out;
    }

    public static byte[] encodeAckV2(int cum, int rwnd, List<Segment.AckRange> blocks) {
        return encodeAckV2(cum, rwnd, blocks, false);
    }

    public static byte[] encodeAckV2(int cum, int rwnd, List<Segment.AckRange> blocks, boolean copy) {
        byte[] out = new byte[StreamConstants.STREAM_ACK_V2_MIN_LEN
                + StreamConstants.STREAM_ACK_V2_MAX_RANGES * 10];
        out[0] = (byte) StreamConstants.STREAM_TYPE_ACK_V2;
        Wire.putLe32(cum, out, 1);
        Wire.putLe32(rwnd, out, 5);
        int off = StreamConstants.STREAM_ACK_V2_MIN_LEN;
        int n = 0;
        int prevEnd = cum;
        for (Segment.AckRange b : blocks) {
            if (n >= StreamConstants.STREAM_ACK_V2_MAX_RANGES) break;
            int gap = Seq.seqDist(b.start, prevEnd);
            if (gap < 0) continue;
            off += Uvarint.putUvarint(gap, out, off);
            off += Uvarint.putUvarint(Seq.seqDist(b.end, b.start), out, off);
            prevEnd = b.end;
            ++n;
        }
        // range 计数的 bit7 标记这是另一条 ACK 的冗余拷贝；接收端若已处理过相同
        // 内容，不得把它当成新的丢包证据（DUP_ACK_THRESH=1，否则会虚假重传）。
        out[9] = (byte) (n | (copy ? StreamConstants.ACK_V2_FLAG_COPY : 0));
        return Arrays.copyOfRange(out, 0, off);
    }

    public static byte[] encodeRst() {
        return encodeRst(StreamConstants.STREAM_RST_ABORT);
    }

    public static byte[] encodeRst(int code) {
        return new byte[]{(byte) StreamConstants.STREAM_TYPE_RST, (byte) (code & 0xff)};
    }

    /** 解析失败返回 null（未知 type 也返回 null，由调用方计入 bad_segs）。 */
    public static Segment parseSegment(byte[] input) {
        return parseSegment(input, input.length);
    }

    @SuppressWarnings("IntegerDivisionInFloatingPointContext")
    public static Segment parseSegment(byte[] input, int len) {
        if (len < 1) return null;
        int type = input[0] & 0xff;
        if (type == StreamConstants.STREAM_TYPE_DATA) {
            if (len < StreamConstants.STREAM_DATA_HDR_LEN) return null;
            Segment s = new Segment();
            s.type = type;
            s.seq = Wire.getLe32(input, 1);
            s.flags = input[5] & 0xff;
            s.payload = Arrays.copyOfRange(input, StreamConstants.STREAM_DATA_HDR_LEN, len);
            return s;
        }
        if (type == StreamConstants.STREAM_TYPE_ACK) {
            if (len != StreamConstants.STREAM_ACK_LEN) return null;
            Segment s = new Segment();
            s.type = type;
            s.cum = Wire.getLe32(input, 1);
            s.rwnd = Wire.getLe32(input, 5);
            s.sackStart = Wire.getLe32(input, 9);
            s.sackEnd = Wire.getLe32(input, 13);
            return s;
        }
        if (type == StreamConstants.STREAM_TYPE_RST) {
            if (len != StreamConstants.STREAM_RST_LEN) return null;
            Segment s = new Segment();
            s.type = type;
            s.code = input[1] & 0xff;
            return s;
        }
        if (type == StreamConstants.STREAM_TYPE_ACK_V2) {
            if (len < StreamConstants.STREAM_ACK_V2_MIN_LEN) return null;
            Segment s = new Segment();
            s.type = type;
            s.cum = Wire.getLe32(input, 1);
            s.rwnd = Wire.getLe32(input, 5);
            int declared = Math.min(input[9] & ~StreamConstants.ACK_V2_FLAG_COPY,
                    StreamConstants.STREAM_ACK_V2_MAX_RANGES);
            s.copy = (input[9] & StreamConstants.ACK_V2_FLAG_COPY) != 0;
            int[] state = {StreamConstants.STREAM_ACK_V2_MIN_LEN};
            List<Segment.AckRange> ranges = new ArrayList<>();
            int prevEnd = s.cum;
            for (int i = 0; i < declared; ++i) {
                int gap = Uvarint.getUvarint(input, len, state);
                int blen = Uvarint.getUvarint(input, len, state);
                if (gap < 0 || blen < 0 || blen == 0) return null;
                int start = prevEnd + gap;
                int end = start + blen;
                // 区间校验：必须 ≥ cum、长度为正、且严格递增（不得与前区间重叠/回退）。
                if (!Seq.seqAtOrAfter(start, s.cum) || !Seq.seqAfter(end, start)
                        || (i > 0 && !Seq.seqAfter(start, ranges.get(ranges.size() - 1).end))) {
                    return null;
                }
                ranges.add(new Segment.AckRange(start, end));
                prevEnd = end;
            }
            if (state[0] != len) return null;
            s.ranges = ranges;
            return s;
        }
        return null; // 未知类型：忽略，计入 bad_segs
    }
}
