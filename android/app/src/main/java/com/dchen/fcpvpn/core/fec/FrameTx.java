package com.dchen.fcpvpn.core.fec;

import java.util.ArrayList;

import com.dchen.fcpvpn.core.wire.Wire;

/**
 * FEC 数据面发送侧。移植自 fcp-node src/fec/frame.ts:24-252 的 FrameTx
 * （C++ frame_tx.{h,cc}）。
 *
 * 一条流 segment 恰好成为一个 data 符号和一个 UDP 数据报：
 * <pre>
 *   data 符号   = len(2 LE，含这 2 字节自身) | payload   （frame.ts:183-192）
 *   parity 符号 = 恰好 symbolMax 字节的 RS 输出；接收端可从任一 parity 反推 n = index − j
 *   oob 符号    = 原始 oob 消息（set_id = index = 0，见 packOobFrame）
 * </pre>
 * 每个符号经 {@link UdpSink} 以完整"待发送 UDP 载荷"（7 字节 FEC 头 v2 + 符号）
 * 字节数组回调输出；信封加密在 crypto/session 层完成，本层不做加密。
 *
 * 定时全部外部注入：onSegment / onTick 以 nowMillis 驱动，nextTimerMs 查询最近
 * 闭合期限；本层不起任何线程或调度器，保证无线程也能确定性单测。
 *
 * 封集条件：D 个数据符号凑满（closeLane full）或 flush 定时器
 * clamp(srtt, 25, 200) ms 到期（frame.ts:216-247），闭合时按
 * k_eff = max(1, min(k, ceil(k·n/D))) 发 parity——短组少交冗余，但线上
 * type_k 仍填计划的 k。
 */
public final class FrameTx {

    // ---- 常量（fcp-node src/constants.ts 对应行号） ----

    /** 信封开销 28B（constants.ts:335 FRAME_ENVELOPE_OVERHEAD）。 */
    public static final int FRAME_ENVELOPE_OVERHEAD = 28;
    /** data 符号线开销：envelope 28 + FEC 头 7 + len 前缀 2（constants.ts:336）。 */
    public static final int DATA_WIRE_OVERHEAD = 37;
    /** parity 符号线开销：envelope 28 + FEC 头 7（constants.ts:337）。 */
    public static final int PARITY_WIRE_OVERHEAD = 35;
    /** legacy KCP 头预留（constants.ts:338；本分支无 KCP 实现，纯保留）。 */
    public static final int KCP_HEADER_RESERVE = 24;
    /** flush 定时下限 ms（constants.ts:339 MIN_FLUSH_MS）。 */
    public static final int MIN_FLUSH_MS = 25;
    /** flush 定时上限 ms（constants.ts:340 MAX_FLUSH_MS）。 */
    public static final int MAX_FLUSH_MS = 200;
    /** 部分组冲刷系数：等待不超过填满一组所需时间的 1.5 倍（constants.ts:348）。 */
    public static final double FLUSH_DRAIN_FACTOR = 1.5;
    /** 默认 flush / srtt ms（constants.ts:252 DEFAULT_FLUSH_MS、:251 DEFAULT_SRTT_MS）。 */
    public static final int DEFAULT_FLUSH_MS = 200;
    public static final int DEFAULT_SRTT_MS = 200;
    /** 默认 MTU / IP 头长（constants.ts:240、:245）。 */
    public static final int DEFAULT_MTU = 1400;
    public static final int DEFAULT_IP_HEADER_LEN = 20;
    /** 交织深度上限：同时开放的修复组数（constants.ts:130 MAX_INTERLEAVE）。 */
    public static final int MAX_INTERLEAVE = 8;

    /** MTU 预算（frame.ts:24-26 MtuLimits）。 */
    public static final class MtuLimits {
        public final int mtu;
        public final int ipHdrLen;
        public final int payloadMax;
        public final int symbolMax;
        public final int mss;
        public final boolean valid;

        public MtuLimits(int mtu, int ipHdrLen, int payloadMax, int symbolMax, int mss, boolean valid) {
            this.mtu = mtu;
            this.ipHdrLen = ipHdrLen;
            this.payloadMax = payloadMax;
            this.symbolMax = symbolMax;
            this.mss = mss;
            this.valid = valid;
        }
    }

    /**
     * MTU 预算（frame.ts:28-40 computeMtuLimits）：
     * base = MTU − 20(IP) − 8(UDP)；payloadMax = base − 37；symbolMax = base − 35；
     * segment 上限 mss = payloadMax − 24（legacy KCP 预留）。
     */
    public static MtuLimits computeMtuLimits(int mtu, int ipHdrLen) {
        int base = mtu > ipHdrLen + 8 ? mtu - ipHdrLen - 8 : 0;
        if (base < DATA_WIRE_OVERHEAD + KCP_HEADER_RESERVE + 1) {
            return new MtuLimits(mtu, ipHdrLen, 0, 0, 0, false);
        }
        return new MtuLimits(mtu, ipHdrLen,
                base - DATA_WIRE_OVERHEAD,
                base - PARITY_WIRE_OVERHEAD,
                base - DATA_WIRE_OVERHEAD - KCP_HEADER_RESERVE,
                true);
    }

    public static MtuLimits computeMtuLimits(int mtu) {
        return computeMtuLimits(mtu, DEFAULT_IP_HEADER_LEN);
    }

    /** PMTUD 探测长度（frame.ts:41-43 pmtuProbeLen）。注意协议格式.md §8.2 写 −28−6
     *  是 v1 头的旧数字，以源码 −28−7 为准（AGENTS.md 铁律 1）。 */
    public static int pmtuProbeLen(int mtu, int ipHdrLen) {
        return (mtu - ipHdrLen - 8) - FRAME_ENVELOPE_OVERHEAD - FecHeader.FEC_HDR_LEN;
    }

    /**
     * 待发送 UDP 载荷（7 字节 FEC 头 + 符号）回调。加密由上层完成，
     * 实现方拿到的数组即信封加密前的明文数据报。
     */
    public interface UdpSink {
        void send(byte[] datagram);
    }

    /** 一个开放中的修复组（frame.ts:49-55 TxLane）。 */
    private static final class TxLane {
        int setId;
        int n;
        int k;
        int d;
        int symbolMax;
        final ArrayList<byte[]> symbols = new ArrayList<>();
        long tLastMs;

        void reset() {
            n = 0;
            k = 0;
            d = 0;
            symbolMax = 0;
            symbols.clear();
            tLastMs = 0;
        }
    }

    private int d;
    private MtuLimits limits;
    private final UdpSink sink;
    private final ArrayList<TxLane> lanes = new ArrayList<>();
    /** 控制段（ACK/RST）专用 lane：绝不与数据共用集合——延迟关键必须立即闭合，
     *  进轮转又会截断落进去的数据组（frame.ts:65-68）。 */
    private final TxLane ctl = new TxLane();
    private int cursor;
    private int nextSetId;
    private int nextK;
    private long flushMs = DEFAULT_FLUSH_MS;
    private long srttMs = DEFAULT_FLUSH_MS;
    /** 发送方按当前速率填满 D 个符号所需时间，-1 表示未知（保持 flush = sRTT 旧行为）。 */
    private long drainMs = -1;

    // 计数器（frame.ts:77），会话统计用。
    public int closedFull;
    public int closedIdle;
    public int abortedSets;
    public int dataSymbols;
    public int paritySymbols;
    public int mtuDrops;

    public FrameTx(int d, MtuLimits limits, UdpSink sink) {
        this.d = d;
        this.limits = limits;
        this.sink = sink;
        this.lanes.add(new TxLane());
    }

    /** 计划 parity 数（新集合生效；lane.k ≤ 3 位字段上限，frame.ts:82 setK）。 */
    public void setK(int k) {
        this.nextK = Math.min(k, FecHeader.MAX_PARITY);
    }

    public void setSrttMs(long srtt) {
        this.srttMs = srtt;
        recomputeFlush();
    }

    /** 新集合的组大小；已开放的 lane 保留自己被切组时的 d（随头上行，frame.ts:86-87）。 */
    public void setGroupD(int d) {
        if (d >= 1) this.d = d;
    }

    public int getGroupD() {
        return d;
    }

    /**
     * 交织深度（frame.ts:99-111 setInterleave）：L 条 lane 轮转摊段，把长度 B 的
     * 连续丢包摊成每组 ceil(B/L) 个，同样的 k 能扛 L 倍长的突发；冗余率不变。
     * 收缩时立即结算被丢弃的 lane（flush 定时器不会再照看它们）。
     */
    public void setInterleave(int n) {
        int want = Math.max(1, Math.min(MAX_INTERLEAVE, n));
        if (want == lanes.size()) return;
        if (want < lanes.size()) {
            for (int i = want; i < lanes.size(); ++i) closeLane(lanes.get(i), false);
            lanes.subList(want, lanes.size()).clear();
        } else {
            while (lanes.size() < want) lanes.add(new TxLane());
        }
        if (cursor >= lanes.size()) cursor = 0;
    }

    public int getInterleave() {
        return lanes.size();
    }

    /**
     * 填满一组（交织时是填满一条 lane，即 interleave × d 个符号）所需毫秒
     * （frame.ts:128 setGroupDrainMs）。>0 时以 max(25, ceil(ms·1.5)) 参与冲刷
     * 定时竞争，只缩短不延长等待。
     */
    public void setGroupDrainMs(long ms) {
        this.drainMs = ms > 0 ? ms : -1;
        recomputeFlush();
    }

    private void recomputeFlush() {
        long ms = Math.min(Math.max(srttMs, MIN_FLUSH_MS), MAX_FLUSH_MS);
        if (drainMs > 0) {
            long byRate = Math.max(MIN_FLUSH_MS, (long) Math.ceil(drainMs * FLUSH_DRAIN_FACTOR));
            if (byRate < ms) ms = byRate;
        }
        flushMs = ms;
    }

    /** 距最早需要闭合的开放组的毫秒数；无开放组返回 -1（frame.ts:138-149）。 */
    public long nextTimerMs(long nowMs) {
        long best = -1;
        for (TxLane lane : lanes) best = consider(lane, nowMs, best);
        return consider(ctl, nowMs, best);
    }

    private long consider(TxLane lane, long nowMs, long best) {
        if (lane.n < 1) return best;
        long due = lane.tLastMs + flushMs - nowMs;
        long ms = due < 1 ? 1 : due;
        return best < 0 || ms < best ? ms : best;
    }

    public void raiseLimits(MtuLimits l) {
        if (l.valid && l.payloadMax > limits.payloadMax) limits = l;
    }

    public void lowerLimits(MtuLimits l) {
        if (l.valid && l.payloadMax < limits.payloadMax) limits = l;
    }

    public MtuLimits limits() {
        return limits;
    }

    /** 当前滞留在各开放组里等待闭合的符号总数（frame.ts:154-158）。 */
    public int openN() {
        int n = ctl.n;
        for (TxLane lane : lanes) n += lane.n;
        return n;
    }

    public int openK() {
        for (TxLane lane : lanes) {
            if (lane.n > 0) return lane.k;
        }
        return ctl.n > 0 ? ctl.k : 0;
    }

    /** 下一个集合将使用的 set_id（frame.ts:163）。 */
    public int currentSetId() {
        return nextSetId;
    }

    /**
     * 加入一条 segment（frame.ts:172-198 onSegment）。
     * control=true 时进专用控制 lane 并立即闭合：ACK 不能等数据组填满，
     * 也不能截断数据组。
     */
    public void onSegment(byte[] seg, long nowMs) {
        onSegment(seg, nowMs, false);
    }

    public void onSegment(byte[] seg, long nowMs, boolean control) {
        if (seg.length > limits.payloadMax) {
            ++mtuDrops;
            return;
        }
        maybeFlush(nowMs);
        TxLane lane;
        if (control) {
            lane = ctl;
        } else {
            lane = lanes.get(cursor);
            cursor = (cursor + 1) % lanes.size();
        }
        if (lane.n == 0) openLane(lane);
        int symLen = seg.length + 2;
        byte[] symbol = new byte[symLen]; // len + payload 全部写满
        Wire.putLe16(symLen, symbol, 0);
        System.arraycopy(seg, 0, symbol, 2, seg.length);
        lane.symbolMax = Math.max(lane.symbolMax, symLen);
        lane.symbols.add(symbol);
        sink.send(packTxFrame(lane.setId, lane.n, lane.d,
                FecHeader.packTypeK(lane.k, 0, FecHeader.TYPE_DATA), symbol));
        ++dataSymbols;
        ++lane.n;
        lane.tLastMs = nowMs;
        if (lane.n >= lane.d) closeLane(lane, true);
        else if (control) closeLane(lane, false);
    }

    private void openLane(TxLane lane) {
        lane.setId = nextSetId;
        nextSetId = nextSetId + 1; // int 溢出即 u32 回绕
        lane.k = nextK;
        lane.d = d;
        lane.symbolMax = 0;
        lane.symbols.clear();
    }

    /** flush 定时器入口（frame.ts:209 onTick / 218-223 maybeFlush）。 */
    public void onTick(long nowMs) {
        maybeFlush(nowMs);
    }

    /** 会话复位：丢弃所有开放组，不发 parity（frame.ts:211-216 abort）。 */
    public void abort() {
        boolean any = false;
        for (TxLane lane : lanes) {
            if (lane.n > 0) {
                lane.reset();
                any = true;
            }
        }
        if (ctl.n > 0) {
            ctl.reset();
            any = true;
        }
        if (any) ++abortedSets;
    }

    private void maybeFlush(long nowMs) {
        for (TxLane lane : lanes) {
            if (lane.n >= 1 && nowMs - lane.tLastMs >= flushMs) closeLane(lane, false);
        }
        if (ctl.n >= 1 && nowMs - ctl.tLastMs >= flushMs) closeLane(ctl, false);
    }

    /** 闭合一个组并发 k_eff 个 parity（frame.ts:225-251 closeLane）。 */
    private void closeLane(TxLane lane, boolean full) {
        if (lane.n == 0) return;
        if (lane.d == 0) {
            lane.reset();
            ++abortedSets;
            return;
        }
        int d = lane.d;
        int kEff = 0;
        if (lane.k >= 1) kEff = Math.max(1, Math.min(lane.k, ceilDiv(lane.k * lane.n, d)));
        if (kEff >= 1) {
            // data 符号补零到 lane.symbolMax 再编码
            byte[][] padded = new byte[lane.n][];
            for (int i = 0; i < lane.n; ++i) {
                byte[] s = lane.symbols.get(i);
                byte[] row = new byte[lane.symbolMax];
                System.arraycopy(s, 0, row, 0, s.length);
                padded[i] = row;
            }
            byte[][] parities = Rs.rsEncode(padded, lane.n, kEff, lane.symbolMax);
            if (parities == null) kEff = 0;
            for (int j = 0; j < kEff && parities != null; ++j) {
                sink.send(packTxFrame(lane.setId, lane.n + j, d,
                        FecHeader.packTypeK(lane.k, j, FecHeader.TYPE_PARITY), parities[j]));
                ++paritySymbols;
            }
        }
        if (full) ++closedFull;
        else ++closedIdle;
        lane.reset();
    }

    private static int ceilDiv(int a, int b) {
        return (a + b - 1) / b;
    }

    /** 组装待发送 UDP 载荷：7 字节 FEC 头 + 符号（frame.ts:694-699 packTxFrame）。 */
    public static byte[] packTxFrame(int setId, int index, int d, int typeK, byte[] symbol) {
        byte[] out = new byte[FecHeader.FEC_HDR_LEN + symbol.length];
        FecHeader.putHdr(out, 0, new FecHeader.FecHdr(setId, index, d, typeK));
        System.arraycopy(symbol, 0, out, FecHeader.FEC_HDR_LEN, symbol.length);
        return out;
    }

    /** oob 帧：头 {set_id=0, index=0, type_k=0x02} + 原始消息（frame.ts:688-693，§4.7）。 */
    public static byte[] packOobFrame(byte[] msg) {
        byte[] out = new byte[FecHeader.FEC_HDR_LEN + msg.length];
        FecHeader.putHdr(out, 0,
                new FecHeader.FecHdr(0, 0, 0, FecHeader.packTypeK(0, 0, FecHeader.TYPE_OOB)));
        System.arraycopy(msg, 0, out, FecHeader.FEC_HDR_LEN, msg.length);
        return out;
    }
}
