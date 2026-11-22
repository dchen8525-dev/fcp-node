package com.dchen.fcpvpn.core.stream;

import java.util.List;

/**
 * 解析后的 FCP-STREAM 段（segment.ts 的 Segment 联合类型）。
 * 按 type 字段判别；无关字段为默认值。
 */
public final class Segment {

    public static final class AckRange {
        public final int start;
        public final int end;

        public AckRange(int start, int end) {
            this.start = start;
            this.end = end;
        }
    }

    public int type;
    // DATA
    public int seq;
    public int flags;
    public byte[] payload = new byte[0];
    // ACK / ACK v2
    public int cum;
    public int rwnd;
    public int sackStart;
    public int sackEnd;
    public List<AckRange> ranges;
    public boolean copy;
    // RST
    public int code;

    public static Segment data(int seq, int flags, byte[] payload) {
        Segment s = new Segment();
        s.type = StreamConstants.STREAM_TYPE_DATA;
        s.seq = seq;
        s.flags = flags;
        s.payload = payload;
        return s;
    }
}
