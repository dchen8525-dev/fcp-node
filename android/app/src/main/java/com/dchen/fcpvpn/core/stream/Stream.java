package com.dchen.fcpvpn.core.stream;

import com.dchen.fcpvpn.core.wire.Bytes;
import com.dchen.fcpvpn.core.wire.Seq;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

/**
 * FCP-STREAM v1 可靠有序字节流。移植自 fcp-node src/stream/stream.ts
 * （对应 C++ src/fcp/stream*.cc），逐行为保真移植，所有调优过的启发式
 * （重传年龄门、RACK 式虚假重传检测、ACK 前缀规则、零窗探测、TLP 等）不得简化。
 *
 * 序号是字节偏移，收发方向各自从 0 独立编号。一个段恰好装进一个 data 符号 /
 * 一个 UDP 数据报，段边界在线上保持。FEC 只修复擦除不做重传：ARQ 全在这里。
 * FIN 是对端流末尾的伪字节，cum_ack 覆盖它，发送端无需第二个 ack 即可关闭。
 *
 * 无 socket、无时钟：宿主传入 nowMs 并驱动 onTick()；发出的段经回调送出。
 * 线程模型：单线程驱动（javadoc 契约，内部不加锁）。
 */
public final class Stream {

    public static final int STATE_OPEN = 0;
    public static final int STATE_SENDING_FIN = 1;
    public static final int STATE_PEER_CLOSED = 2;
    public static final int STATE_CLOSED = 3;

    private static final class SndSeg {
        int offset;
        byte[] bytes;
        boolean fin;
        int end;
        long sentMs;
        boolean acked;
        boolean sacked;
        int retransmits;
        /** TLP 探测重发过（不算丢包证据；RTT 采样必须跳过——两份拷贝在途，Karn 歧义）。 */
        boolean probed;
        /** 首份拷贝的发送时间，重传不改写；恢复耗时度量的唯一诚实分母。 */
        long firstSentMs;
    }

    private static final class RcvChunk {
        int offset;
        byte[] bytes;

        RcvChunk(int offset, byte[] bytes) {
            this.offset = offset;
            this.bytes = bytes;
        }
    }

    private final StreamConfig cfg;
    private final StreamCallbacks cb;

    public int state = STATE_OPEN;
    public String closeReason = "";
    public int badSegs = 0;
    public int segsSent = 0;
    public int retransmits = 0;
    public int dupBytes = 0;
    /** 因块数上限被丢弃的乱序段。 */
    public int oobDrops = 0;
    /** 按触发源分类的重传计数（仅诊断）。 */
    public int retxFast = 0;
    public int retxRto = 0;
    public int fastRounds = 0;
    /** 诊断为"乱序而非丢包"的快速重传轮数。 */
    public int spuriousFastRetx = 0;
    /** 被签名环去重掉的冗余 ACK 拷贝数。 */
    public int ackCopiesDropped = 0;
    public double srttMs;

    // 发送侧
    private final ArrayDeque<byte[]> pending = new ArrayDeque<>();
    private int pendingBytes = 0;
    private int sndUna = 0;
    private int sndNext = 0;
    private int sndMax = 0;
    private final List<SndSeg> tx = new ArrayList<>();
    private int peerRwnd;
    private boolean finPending = false;
    private boolean finSent = false;
    private int finOffset = 0;
    private int lastAckCum = 0;
    private boolean haveAckCum = false;
    private int dupAcks = 0;
    private final int[] ackSigRing = new int[StreamConstants.ACK_SIG_RING];
    private int ackSigFilled = 0;
    private int ackSigIdx = 0;
    private int ackTruncCount = 0;
    private int ackDropCount = 0;
    private int sackRotateCum = 0;
    private boolean sackRotateHave = false;
    /** 对端报告过的最高字节偏移（cum 或任一 SACK 块）；其下既未 ack 也未 sack 的段即"确凿缺失"。 */
    private int sackedHigh = 0;
    private double rtoMs;
    private double rttvarMs;
    /** 历史最优 RTT：锚定估计器，防止在洞里等待过的段抬高 srtt。 */
    private int minRttMs = 0;
    /** 单段"合法最差"RTT（滑动窗内）；重传年龄门的依据。 */
    private int rttPeakMs = 0;
    private long rttPeakAtMs = 0;
    private int tlpProbes = 0;
    private long lastSendMs = 0;
    private double retxRelax = 1;
    private double retxTighten = 1;
    private boolean fastRoundSpurious = false;
    private List<Segment.AckRange> sackRanges = new ArrayList<>();
    private long fastRoundMs = 0;
    private int fastRoundUna = 0;
    private int fastRoundSeq = -1;

    // 接收侧
    private int rcvNxt = 0;
    private final List<RcvChunk> oob = new ArrayList<>();
    private int oobBytes = 0;
    private int deliveryPending = 0;
    private boolean peerFin = false;
    private int peerFinAt = 0;
    private boolean eofDelivered = false;
    private boolean ackPending = false;
    private long lastAckMs = 0;
    private int sackRotate = 0;
    private int ackDebt = 0;
    private long lastInboundMs = 0;
    private long lastRttSampleMs = 0;
    private long lastZeroWinProbeMs = 0;
    private final int[] retxLat = new int[StreamConstants.RETX_LAT_SAMPLES];
    private int retxLatCount = 0;
    private int retxLatNext = 0;

    public Stream(StreamConfig config, StreamCallbacks cb) {
        this.cfg = config;
        this.cb = cb;
        this.srttMs = config.initialSrttMs > 0 ? config.initialSrttMs : StreamConstants.DEFAULT_SRTT_MS;
        // RFC 6298: RTO = SRTT + 4×RTTVAR，长路径上的抖动撑大定时器而不是往里重传。
        this.rttvarMs = Math.max(1, Math.round(this.srttMs / 2));
        this.rtoMs = rtoFor();
        this.peerRwnd = config.rcvBufBytes;
    }

    private double rtoFor() {
        return Math.min(Math.max(this.srttMs + 4 * this.rttvarMs, cfg.rtoMinMs), cfg.rtoMaxMs);
    }

    public void setAckV2(boolean on) {
        this.cfg.ackV2 = on;
    }

    /**
     * n 是整个流段大小（含 DATA 头）。PMTUD 回退缩小段尺寸后，已按大尺寸切好的段
     * 无法再发出（FrameTx 按超尺寸丢弃），重传将永远丢失——在此重新切分。
     * 字节偏移与队列内容不变，累计/SACK 记账不受影响。
     */
    public void setMaxSegment(int n) {
        if (n <= 0 || n == cfg.maxSegment) return;
        if (n > cfg.maxSegment) {
            cfg.maxSegment = n;
            return;
        }
        if (n <= StreamConstants.STREAM_DATA_HDR_LEN) return; // 装不下负载，保持旧切分
        cfg.maxSegment = n;
        int piece = n - StreamConstants.STREAM_DATA_HDR_LEN;
        List<SndSeg> recut = new ArrayList<>();
        for (SndSeg s : tx) {
            if (s.bytes.length <= piece) {
                recut.add(s);
                continue;
            }
            for (int off = 0; off < s.bytes.length; off += piece) {
                int len = Math.min(piece, s.bytes.length - off);
                boolean fin = s.fin && off + len == s.bytes.length;
                SndSeg part = new SndSeg();
                part.offset = s.offset + off;
                part.bytes = Arrays.copyOfRange(s.bytes, off, off + len);
                part.fin = fin;
                part.end = s.offset + off + len + (fin ? 1 : 0);
                // 已 SACK 的片段保持已送达；其余从未按新尺寸上线，RTO 必须重发。
                part.sentMs = s.sacked ? s.sentMs : 0;
                part.acked = false;
                part.sacked = s.sacked;
                part.retransmits = s.sacked ? s.retransmits : Math.max(1, s.retransmits);
                part.probed = s.probed;
                part.firstSentMs = s.firstSentMs;
                recut.add(part);
            }
        }
        tx.clear();
        tx.addAll(recut);
        dupAcks = 0;
    }

    /** 两个窗口一起动：window() = min(sendWindow, peerRwnd)，对端 rwnd 由这里公告的缓冲推导。 */
    public void setWindows(int sendBytes, int rcvBytes) {
        if (sendBytes > 0) cfg.sendWindowBytes = sendBytes;
        if (rcvBytes > 0) cfg.rcvBufBytes = rcvBytes;
    }

    public int getSendWindowBytes() { return cfg.sendWindowBytes; }
    public int getRcvBufBytes() { return cfg.rcvBufBytes; }
    /** 已排队尚未上线的字节。 */
    public int getPendingQueueBytes() { return pendingBytes; }
    /** 在线未累计确认的字节。 */
    public int getInflightBytes() { return Seq.seqDist(sndNext, sndUna); }
    /** 对端最近公告的窗口。 */
    public int getPeerWindowBytes() { return peerRwnd; }
    /** 下一个可按序交付的字节偏移（停滞 + 大量重排缓冲 = 一个洞卡住了一切）。 */
    public int getRecvNext() { return rcvNxt; }
    public int getReorderBytes() { return oobBytes; }
    public boolean isCanWrite() { return sendSpace() > 0 && !finPending; }
    public boolean isClosed() { return state == STATE_CLOSED; }
    public boolean isEofReceived() { return eofDelivered; }
    public int getCumAcked() { return sndUna; }
    public int getDeliveryPendingBytes() { return deliveryPending; }
    public boolean isAckV2Enabled() { return cfg.ackV2; }
    public int getSackedHighWater() { return sackedHigh; }

    private void recordRetxLatency(long ms) {
        retxLat[retxLatCount < StreamConstants.RETX_LAT_SAMPLES
                ? retxLatCount : retxLatNext] = (int) ms;
        if (retxLatCount < StreamConstants.RETX_LAT_SAMPLES) {
            retxLatCount++;
            retxLatNext = retxLatCount % StreamConstants.RETX_LAT_SAMPLES;
        } else {
            retxLatNext = (retxLatNext + 1) % StreamConstants.RETX_LAT_SAMPLES;
        }
    }

    /** 恢复延迟环的副本（会话级汇总用）。 */
    public int[] retxLatencySamples() {
        return Arrays.copyOf(retxLat, retxLatCount);
    }

    /** 环上的最近邻秩百分位（与 FEC 报告器同法）。 */
    private int retxLatPct(int pct) {
        if (retxLatCount == 0) return 0;
        int[] sorted = retxLatencySamples();
        Arrays.sort(sorted);
        int rank = (int) Math.min(sorted.length,
                Math.max(1, Math.ceil((pct / 100.0) * sorted.length)));
        return sorted[rank - 1];
    }

    public int getRetxLatencyP50Ms() { return retxLatPct(50); }
    public int getRetxLatencyP95Ms() { return retxLatPct(95); }
    public int getRetxLatencyCount() { return retxLatCount; }

    /** 宿主还可写入的字节。在途字节计入（C++ send_space() 扣的是 queued-acked）。 */
    private int sendSpace() {
        if (state == STATE_CLOSED) return 0;
        int used = pendingBytes + getInflightBytes();
        return cfg.sendWindowBytes > used ? cfg.sendWindowBytes - used : 0;
    }

    /** 宿主确认已消费 n 字节（背压释放）。 */
    public void consumed(int n) {
        deliveryPending = Math.max(0, deliveryPending - n);
    }

    /** 返回实际接受的字节数（0 = 拒绝）。 */
    public int write(byte[] data, int off, int len, long nowMs) {
        // FIN 发出后字节流终结于 finOffset：新数据会排在 fin 伪字节之后，
        // 被对端当 badSegs 丢弃而本地却以为已入队——直接拒绝。
        if (finPending || finSent || state == STATE_CLOSED) return 0;
        int room = sendSpace();
        int take = Math.min(len, room);
        if (take <= 0) return 0;
        pending.add(Arrays.copyOfRange(data, off, off + take));
        pendingBytes += take;
        pump(nowMs);
        return take;
    }

    public int write(byte[] data, long nowMs) {
        return write(data, 0, data.length, nowMs);
    }

    public void closeWrite(long nowMs) {
        // finSent 判断：FIN 已发出后 finPending 已复位，第二次 closeWrite 会
        // 再排一个 FIN（偏移 +1），对端按协议违例拒绝且永不应答 → 流卡死到空闲超时。
        if (finPending || finSent || state == STATE_CLOSED) return;
        finPending = true;
        state = STATE_SENDING_FIN;
        pump(nowMs);
    }

    public void sendRst() {
        cb.send(SegmentCodec.encodeRst());
        finish("reset");
    }

    private int window() {
        return Math.max(0, Math.min(cfg.sendWindowBytes, peerRwnd));
    }

    /**
     * DATA 段 = 6 字节头 + 至少 1 字节负载；对端窗口小于此值连一个段都装不下，
     * pump() 无从发送、RTO 无法起爆、0 窗探测若只看 window()==0 也没有截止期
     * → 传输卡死到 5 分钟空闲超时。C++ 同款探测条件。
     */
    private boolean windowBlocked() {
        return window() < StreamConstants.STREAM_DATA_HDR_LEN + 1;
    }

    private void pump(long nowMs) {
        // 突发预算必须覆盖一个完整 ACK 周期；固定字节预算在 PMTUD 把段撑大后
        // 会饿死补发循环（6 段 × 1430B > 6KiB → 稳态吞吐被钉在窗口/RTT 的 71.6%）。
        int burstBytes = Math.max(
                StreamConstants.PUMP_BURST_BYTES,
                StreamConstants.ACK_EVERY_SEGMENTS * Math.max(0, cfg.maxSegment - StreamConstants.STREAM_DATA_HDR_LEN));
        if (state == STATE_CLOSED) return;
        int guard = 0;
        int sentBytes = 0;
        while (guard++ < 4096) {
            int inflight = getInflightBytes();
            if (inflight >= window()) break;
            if (pendingBytes == 0 && !finPending) break;
            int room = Math.min(cfg.maxSegment, window() - inflight);
            int payloadRoom = Math.min(room, cfg.maxSegment) - StreamConstants.STREAM_DATA_HDR_LEN;
            if (payloadRoom <= 0 && !(finPending && pendingBytes == 0)) break;
            byte[] chunk = takePending(Math.max(0, payloadRoom));
            boolean fin = false;
            if (finPending && pendingBytes == 0) {
                fin = true;
                finSent = true;
                finPending = false;
            }
            if (chunk.length == 0 && !fin) break;
            int end = sndNext + chunk.length + (fin ? 1 : 0);
            SndSeg seg = new SndSeg();
            seg.offset = sndNext;
            seg.bytes = chunk;
            seg.fin = fin;
            seg.end = end;
            seg.sentMs = nowMs;
            seg.firstSentMs = nowMs;
            if (fin) finOffset = sndNext + chunk.length;
            tx.add(seg);
            sndNext = end;
            if (Seq.seqAfter(end, sndMax)) sndMax = end;
            emitData(seg, nowMs);
            if (fin) break;
            // 剩余部分交给下一次 tick/ACK：单次同步循环发满整窗正是
            // "路径丢掉每个突发尾部"的根源。
            sentBytes += chunk.length;
            if (sentBytes >= burstBytes) break;
        }
    }

    private byte[] takePending(int n) {
        if (n <= 0 || pendingBytes == 0) return new byte[0];
        byte[] out = new byte[Math.min(n, pendingBytes)];
        int off = 0;
        while (off < out.length && !pending.isEmpty()) {
            byte[] head = pending.peekFirst();
            int take = Math.min(head.length, out.length - off);
            System.arraycopy(head, 0, out, off, take);
            off += take;
            pending.pollFirst();
            if (take < head.length) {
                pending.addFirst(Arrays.copyOfRange(head, take, head.length));
            }
        }
        pendingBytes -= off;
        return out;
    }

    private void emitData(SndSeg s, long nowMs) {
        cb.send(SegmentCodec.encodeData(s.offset, s.fin ? StreamConstants.STREAM_FLAG_FIN : 0, s.bytes));
        ++segsSent;
        lastSendMs = nowMs;
    }

    public void onSegment(byte[] buf, long nowMs) {
        onSegment(buf, buf.length, nowMs);
    }

    public void onSegment(byte[] buf, int len, long nowMs) {
        if (state == STATE_CLOSED) return;
        Segment seg = SegmentCodec.parseSegment(buf, len);
        if (seg == null) {
            ++badSegs;
            return;
        }
        lastInboundMs = Math.max(lastInboundMs, nowMs);
        switch (seg.type) {
            case StreamConstants.STREAM_TYPE_DATA:
                onData(seg, nowMs);
                break;
            case StreamConstants.STREAM_TYPE_ACK: {
                List<Segment.AckRange> one = new ArrayList<>(1);
                one.add(new Segment.AckRange(seg.sackStart, seg.sackEnd));
                onAck(seg.cum, seg.rwnd, one, nowMs, false);
                break;
            }
            case StreamConstants.STREAM_TYPE_ACK_V2:
                onAck(seg.cum, seg.rwnd, seg.ranges, nowMs, seg.copy);
                break;
            case StreamConstants.STREAM_TYPE_RST:
                finish("reset");
                break;
            default:
                ++badSegs;
                break;
        }
    }

    private void onData(Segment seg, long nowMs) {
        int offset = seg.seq;
        boolean fin = (seg.flags & StreamConstants.STREAM_FLAG_FIN) != 0;
        int n = seg.payload.length;
        int dataEnd = offset + n;
        int segEnd = dataEnd + (fin ? 1 : 0);
        if (!Seq.seqAfter(segEnd, rcvNxt)) {
            dupBytes += n;
            emitAck(nowMs);
            return;
        }
        if (Seq.seqDist(offset, rcvNxt) > cfg.rcvBufBytes) return;
        if (deliveryPending >= cfg.rcvBufBytes) {
            emitAck(nowMs);
            return;
        }
        if (peerFin) {
            if (fin && dataEnd != peerFinAt) {
                ++badSegs;
                return;
            }
            if (!fin && Seq.seqAfter(dataEnd, peerFinAt)) {
                ++badSegs;
                return;
            }
        }
        int at = offset;
        byte[] payload = seg.payload;
        if (Seq.seqDist(at, rcvNxt) < 0) {
            int drop = -Seq.seqDist(at, rcvNxt);
            dupBytes += Math.min(drop, payload.length);
            if (drop >= payload.length) {
                payload = new byte[0];
            } else {
                payload = Arrays.copyOfRange(payload, drop, payload.length);
            }
            at += drop;
        }
        if (payload.length > 0) insertChunk(at, payload);
        if (fin) {
            peerFin = true;
            peerFinAt = dataEnd;
        }
        deliverPrefix(nowMs);
        // 有洞 → ACK 必须紧急：重复 ACK 是快速重传的燃料。FIN 即使恰好落在
        // rcvNxt 上也紧急：这个 ACK 让对端得以收尾而不必等它的空闲时钟。
        ackDue(nowMs, fin || rcvNxt != segEnd);
    }

    /**
     * 合并确认。线上的代价不是问题——突发才是：64KiB 窗口到达 ≈46 个数据报，
     * 逐个应答产生 46 个背靠背 ACK，大多被上行丢弃；发送端只见 cumAck 蠕动。
     */
    private void ackDue(long nowMs, boolean urgent) {
        ++ackDebt;
        // 洞必须立刻上报，但不必每来一个数据报报一次（800 段/s → 800 ACK/s，
        // 各自成包）。两个段即可证明洞存在，还能把 ACK 率减半；检测最多延一个段。
        int need = urgent ? 2 : cfg.ackEvery;
        if (ackDebt >= need) {
            ackDebt = 0;
            emitAck(nowMs);
            return;
        }
        ackPending = true;
    }

    private int oobMaxChunks() {
        return Math.min(StreamConstants.MAX_OOB_CHUNKS,
                Math.max(StreamConstants.MIN_OOB_CHUNKS, cfg.rcvBufBytes / 512));
    }

    private void insertChunk(int offset, byte[] bytes) {
        // 恰好落在 rcvNxt 上的段填补累计确认等待的洞，永不丢弃；其余受块数
        // 上限约束（仅字节上限会让对端把 256KiB 重排数据拆成 12.8 万个对象）。
        if (offset != rcvNxt && oob.size() >= oobMaxChunks()) {
            ++oobDrops;
            return;
        }
        // 与已缓冲区间裁剪重叠，再合并相邻。
        int end = offset + bytes.length;
        List<RcvChunk> kept = new ArrayList<>();
        for (RcvChunk c : oob) {
            int cEnd = c.offset + c.bytes.length;
            if (Seq.seqAtOrAfter(c.offset, end) || Seq.seqAtOrAfter(offset, cEnd)) {
                kept.add(c);
                continue;
            }
            // 重叠：只保留旧块的不重叠前缀/后缀
            //（TS 源条件 seqAfter(c.offset,offset)===false && seqDist(c.offset,offset)<0
            //  的合取等价于 seqDist(c.offset,offset)<0，即旧块起点按有符号序在 offset 之前）
            if (Seq.seqDist(c.offset, offset) < 0) {
                int headLen = Seq.seqDist(offset, c.offset);
                if (headLen > 0) {
                    kept.add(new RcvChunk(c.offset, Arrays.copyOfRange(c.bytes, 0, headLen)));
                }
            }
            if (Seq.seqAfter(cEnd, end)) {
                int tailOff = Seq.seqDist(end, c.offset);
                if (tailOff > 0 && tailOff < c.bytes.length) {
                    kept.add(new RcvChunk(end, Arrays.copyOfRange(c.bytes, tailOff, c.bytes.length)));
                }
            }
        }
        kept.add(new RcvChunk(offset, Arrays.copyOf(bytes, bytes.length)));
        Collections.sort(kept, new Comparator<RcvChunk>() {
            @Override
            public int compare(RcvChunk a, RcvChunk b) {
                return Seq.seqDist(a.offset, b.offset);
            }
        });
        List<RcvChunk> merged = new ArrayList<>();
        for (RcvChunk c : kept) {
            RcvChunk last = merged.isEmpty() ? null : merged.get(merged.size() - 1);
            if (last != null && last.offset + last.bytes.length == c.offset) {
                last.bytes = Bytes.concat(last.bytes, c.bytes);
            } else {
                merged.add(new RcvChunk(c.offset, c.bytes));
            }
        }
        oob.clear();
        oob.addAll(merged);
        int total = 0;
        for (RcvChunk c : oob) total += c.bytes.length;
        oobBytes = total;
        // 装不下的从尾部裁掉（最新到的字节先走），发送端 ARQ 会重传。
        // 上限同时计入宿主未取走的积压，接收侧才不会持有超过公告 rwnd 的量。
        int limit = Math.max(0, cfg.rcvBufBytes - deliveryPending);
        while (oobBytes > limit && !oob.isEmpty()) {
            RcvChunk last = oob.get(oob.size() - 1);
            int excess = Math.min(oobBytes - limit, last.bytes.length);
            last.bytes = Arrays.copyOfRange(last.bytes, 0, last.bytes.length - excess);
            oobBytes -= excess;
            if (last.bytes.length == 0) oob.remove(oob.size() - 1);
        }
    }

    /** 会话级聚合预算调用：把最重的流的乱序缓冲裁到 limit（尾部优先，同 insertChunk）。 */
    public void trimReorderTo(int limit) {
        while (oobBytes > limit && !oob.isEmpty()) {
            RcvChunk last = oob.get(oob.size() - 1);
            int excess = Math.min(oobBytes - limit, last.bytes.length);
            last.bytes = Arrays.copyOfRange(last.bytes, 0, last.bytes.length - excess);
            oobBytes -= excess;
            if (last.bytes.length == 0) oob.remove(oob.size() - 1);
        }
    }

    private void deliverPrefix(long nowMs) {
        int guard = 0;
        while (guard++ < 65536) {
            boolean advanced = false;
            for (int i = 0; i < oob.size(); ++i) {
                RcvChunk c = oob.get(i);
                int cEnd = c.offset + c.bytes.length;
                if (Seq.seqAtOrAfter(rcvNxt, c.offset) && Seq.seqAfter(cEnd, rcvNxt)) {
                    int skip = Seq.seqDist(rcvNxt, c.offset);
                    byte[] part = Arrays.copyOfRange(c.bytes, skip, c.bytes.length);
                    // 先摘除再交付：read() 可能重入更多段，已不在队首的块
                    // 不得被下面的 splice 误删（C++：先 pop 并推进 rcv_nxt 再 read）。
                    oob.remove(i);
                    oobBytes -= c.bytes.length;
                    rcvNxt = cEnd;
                    deliveryPending += part.length;
                    cb.read(part);
                    // 宿主可能在 read() 里关闭了流：交付循环就此停止（与 C++ 一致）。
                    if (state == STATE_CLOSED) return;
                    advanced = true;
                    break;
                }
            }
            if (!advanced) break;
        }
        if (peerFin && !eofDelivered && rcvNxt == peerFinAt) {
            rcvNxt += 1; // fin 伪字节
            eofDelivered = true;
            state = STATE_PEER_CLOSED;
            cb.eof();
            // 对端的 FIN 可能晚于它对我们 FIN 的 ACK：handle_ack 已在那条 ACK 上
            // 跑过（当时 eof 还没交付），没有别的包能完成关闭，流会干等到空闲超时。
            if (finSent && Seq.seqAtOrAfter(sndUna, finOffset + 1)) {
                // 先 ACK 对端的 FIN 再 finish()：closed 回调可能拆掉宿主的发送路径，
                // 这是让对端完成其关闭的唯一一包。
                emitAck(nowMs);
                finish("peer_close");
            }
        }
    }

    private int cumOut() {
        return rcvNxt;
    }

    /**
     * 哪些已收区间进入本条 ACK：**前缀规则** —— 从 cum 向上填充，第一个装不下的
     * 区间终结列表，绝不报告跳过的区间之后的内容。发送端把 sackedHigh 之下未被
     * ACK 提及的段视为"确凿缺失"并重传；若 ACK 报告了它跳过的区间之上的内容，
     * 每个被跳过的区间都会被误判丢失（幻影洞 bug，tests/protocol.test.ts 有回归用例）。
     */
    private List<RcvChunk> keepAckRanges(List<RcvChunk> runs, int cum, int budget) {
        List<RcvChunk> picked = new ArrayList<>();
        int total = StreamConstants.STREAM_ACK_V2_MIN_LEN;
        int prev = cum;
        for (RcvChunk c : runs) {
            if (picked.size() >= StreamConstants.STREAM_ACK_V2_MAX_RANGES) break;
            int add = com.dchen.fcpvpn.core.wire.Uvarint.uvarintSize(Seq.seqDist(c.offset, prev))
                    + com.dchen.fcpvpn.core.wire.Uvarint.uvarintSize(c.bytes.length);
            // 前缀而非背包：装不下的区间同样终结列表——跳过它报告更高的区间
            // 正是幻影洞 bug。
            if (total + add > budget) break;
            total += add;
            prev = c.offset + c.bytes.length;
            picked.add(c);
        }
        return picked;
    }

    /** SACK 列表装不进数据报预算的 ACK 次数。 */
    public int getAckRangesTruncated() { return ackTruncCount; }

    /** 从未上报给对端的已收区间数。 */
    public int getAckRangesDropped() { return ackDropCount; }

    private int rwndOut() {
        int used = oobBytes + deliveryPending;
        return cfg.rcvBufBytes > used ? cfg.rcvBufBytes - used : 0;
    }

    private void emitAck(long nowMs) {
        ackPending = false;
        // 任何应答路径都清空合并欠账；留着会让接下来几段比 ACK_EVERY_SEGMENTS
        // 更早多出一条 ACK。
        ackDebt = 0;
        lastAckMs = nowMs;
        int cum = cumOut();
        int rwnd = rwndOut();
        if (cfg.ackV2) {
            // ACK 也是流段，必须装进与数据相同的数据报预算。ACK v2 变长：
            // 10B 固定 + 每区间最多 2×5B，64 区间最坏 650B。FrameTx 无声丢弃
            // 超过 payloadMax 的一切——小 MTU 下宽 ACK 直接消失，而 ACK 不到达
            // 与丢失无法区分，每个宽洞都变成 RTO 停顿。把区间数压到预算实际
            // 容纳的量；cum/rwnd 总是发出。被丢的是列表尾部，绝不是中间的区间。
            int budget = cfg.maxSegment;
            List<RcvChunk> picked = keepAckRanges(oob, cum, budget);
            List<Segment.AckRange> blocks = new ArrayList<>(picked.size());
            for (RcvChunk c : picked) {
                blocks.add(new Segment.AckRange(c.offset, c.offset + c.bytes.length));
            }
            byte[] ack = SegmentCodec.encodeAckV2(cum, rwnd, blocks);
            // 安全网：上面的字节记账是精确的，正常不应触发。若触发则从尾部丢弃，
            // 保持列表为前缀。
            while (ack.length > budget && !blocks.isEmpty()) {
                blocks.remove(blocks.size() - 1);
                ack = SegmentCodec.encodeAckV2(cum, rwnd, blocks);
            }
            if (ack.length > budget) return; // 连空 v2 ACK 都装不下
            if (blocks.size() < oob.size()) {
                ++ackTruncCount;
                ackDropCount += oob.size() - blocks.size();
            }
            cb.send(ack);
            return;
        }
        int sackStart = cum, sackEnd = cum;
        if (!oob.isEmpty()) {
            if (sackRotateHave && cum == sackRotateCum) ++sackRotate;
            else sackRotate = 0;
            sackRotateCum = cum;
            sackRotateHave = true;
            RcvChunk blk = oob.get(sackRotate % oob.size());
            sackStart = blk.offset;
            sackEnd = blk.offset + blk.bytes.length;
        } else {
            sackRotateHave = false;
            sackRotate = 0;
        }
        // v1 ACK 固定 17 字节，低于一切合法 payloadMax；静默丢弃比去掉 SACK 块
        // 发送更糟（cum 仍能推进对端窗口）。
        if (StreamConstants.STREAM_ACK_LEN > cfg.maxSegment) {
            if (10 > cfg.maxSegment) return;
            cb.send(SegmentCodec.encodeAckV2(cum, rwnd, new ArrayList<Segment.AckRange>()));
            return;
        }
        cb.send(SegmentCodec.encodeAck(cum, rwnd, sackStart, sackEnd));
    }

    private void onAck(int cum, int rwnd, List<Segment.AckRange> ranges, long nowMs, boolean copy) {
        if (Seq.seqAfter(cum, sndMax)) {
            ++badSegs;
            return;
        }
        // 冗余拷贝是对端为在 ACK 丢失下存活而发的。若原本（或更早的拷贝）已到达，
        // 这一条描述的是已处理过的状态：不得计为重复 ACK（DUP_ACK_THRESH=1 会
        // 在每条 ACK 上触发重传）。用环而不是单槽：交织会把拷贝分开，真 ACK 可能
        // 落在两条拷贝之间。
        int sig = ackSignature(cum, rwnd, ranges);
        if (copy && sigSeen(sig)) {
            ++ackCopiesDropped;
            return;
        }
        rememberAckSig(sig);
        peerRwnd = rwnd;
        // SACK 块永远不会描述本端未发送的字节：越过 sndMax 的区间丢弃不信
        // （过大的区间会抬高 sackedHigh 并把真实在途段标成已 SACK，压制其重传
        // → 永久丢失）。块还必须位于累计点之上（C++ stream_send.cc："忽略这种
        // ACK 的 SACK 半边但保留其累计点与窗口"）。起点低于 cum 的块覆盖洞前
        // 的段，把那个段标 SACK 会让它同时脱离快速重传与 RTO 路径 → 累计点
        // 永不推进，流挂到空闲超时。
        sackRanges = new ArrayList<>();
        for (Segment.AckRange r : ranges) {
            if (Seq.seqAfter(r.end, r.start)
                    && Seq.seqAtOrAfter(r.start, cum)
                    && Seq.seqAtOrAfter(sndMax, r.end)) {
                sackRanges.add(r);
            }
        }
        int prevUna = sndUna;
        // 不前移的累计点是重复或乱序迟到的旧 ACK；把 sndUna 往回移会虚增在途数
        // 并永久缩窗（C++ ack_advance_cum 同款守卫），SACK/dup-ack 半边照跑。
        boolean advanced = Seq.seqAfter(cum, prevUna);
        boolean newlyAcked = false;
        int sampleMs = -1;
        if (advanced) {
            for (SndSeg s : tx) {
                if (!s.acked && Seq.seqAtOrAfter(cum, s.end)) {
                    s.acked = true;
                    newlyAcked = true;
                    // Karn：重传过的段无法判断 ACK 对应哪份拷贝——采样量到的是
                    // 重传间隔而不是路径 RTT，RTO 缩到 rtoMin 又触发更多重传。
                    // 被探测的段即使 retransmits==0 也有两份在途：同样跳过。
                    if (sampleMs < 0 && s.retransmits == 0 && !s.probed) {
                        long delta = nowMs - s.sentMs;
                        // 时钟倒退说明不了路径：负样本进 srtt 会拖歪所有定时器
                        // （C++ 直接丢弃；clamp 到 0 会造出"完美 0ms RTT"）。
                        if (delta >= 0) sampleMs = (int) delta;
                    }
                    // 恢复延迟：对确实重传过的段，从首份拷贝到确认的耗时。
                    // 与 RTT 采样分开记录，两者不得互相污染。
                    if (s.retransmits > 0) {
                        recordRetxLatency(Math.max(0, nowMs - s.firstSentMs));
                    }
                    // 最后一份拷贝是到达的那份吗？拷贝需要一个完整 minRtt 才能
                    // 打来回；更早的确认来自旧拷贝 → 该轮是乱序误判（RACK 的
                    // 虚假检测）。这是放宽年龄门是否允许收窄的唯一诚实证据。
                    if (s.retransmits > 0 && minRttMs > 0 && nowMs - s.sentMs < minRttMs) {
                        ++spuriousFastRetx;
                        fastRoundSpurious = true;
                    }
                }
            }
            sndUna = cum;
        }
        // 送达速率计入此处（离开 ACK 时钟），反映对端实际确认的字节。
        if (newlyAcked) cb.acked(Seq.seqDist(cum, prevUna), nowMs);
        if (sampleMs >= 0 && sampleMs <= 1000 && (minRttMs == 0 || sampleMs < minRttMs)) {
            minRttMs = sampleMs;
        }
        // 远高于最优 RTT 的样本不是路径 RTT：是在序列洞里等到缺口修复的段。
        // 喂进估计器曾把 srtt 从 190ms 拖到 3.6s → RTO 数秒 → 一切恢复停摆。
        int rttCeiling = minRttMs > 0 ? (int) Math.max(4.0 * minRttMs, cfg.rtoMinMs) : 2000;
        boolean plausible = sampleMs >= 0 && sampleMs <= Math.min(rttCeiling, 2000);
        if (newlyAcked) {
            if (plausible && nowMs - lastRttSampleMs >= 10) {
                int err = (int) Math.abs(sampleMs - srttMs);
                rttvarMs = Math.round((3 * rttvarMs + err) / 4);
                srttMs = Math.max(1, Math.round((7 * srttMs + sampleMs) / 8));
                lastRttSampleMs = nowMs;
                cb.rtt(srttMs);
            }
            // 追踪最差的"合法"延迟。只有可信样本合格：洞延迟的段恰是这里不能
            // 学习的延迟，否则门会长到 RTO。衰减保证单次尖峰不会钉死整个会话。
            if (plausible && sampleMs > 0) {
                if (sampleMs >= rttPeakMs || nowMs - rttPeakAtMs >= StreamConstants.RTT_PEAK_DECAY_MS) {
                    rttPeakMs = sampleMs;
                    rttPeakAtMs = nowMs;
                }
            }
            // 钳制漂移：一批洞延迟样本不得把估计器永久卡在数秒。
            if (minRttMs > 0 && srttMs > rttCeiling) srttMs = rttCeiling;
            // 任何前向进度都结束退避，即使没有可用样本（全是重传）。否则一次
            // 突发丢包把 RTO 翻倍多次，恢复要花数秒。
            rtoMs = rtoFor();
        }
        for (Segment.AckRange r : sackRanges) {
            if (Seq.seqAfter(r.end, sackedHigh)) sackedHigh = r.end;
            for (SndSeg s : tx) {
                if (s.acked) continue;
                if (Seq.seqAtOrAfter(s.offset, r.start) && Seq.seqAtOrAfter(r.end, s.end)) {
                    s.sacked = true;
                }
            }
        }
        if (advanced && Seq.seqAfter(cum, sackedHigh)) sackedHigh = cum;
        tx.removeIf(new java.util.function.Predicate<SndSeg>() {
            @Override
            public boolean test(SndSeg s) {
                return s.acked;
            }
        });
        if (haveAckCum && cum == lastAckCum && !tx.isEmpty()) {
            if (++dupAcks >= StreamConstants.DUP_ACK_THRESH) {
                dupAcks = 0;
                fastRetransmit(nowMs);
            }
        } else {
            dupAcks = 0;
        }
        lastAckCum = cum;
        haveAckCum = true;
        if (advanced) {
            // 累计进度证明尾部没有丢：探测预算为下一个尾部重启。
            tlpProbes = 0;
            resolveFastRound(cum);
        }
        if (finSent && Seq.seqAtOrAfter(cum, finOffset + 1) && eofDelivered) {
            finish("local_eof");
            return;
        }
        // 每条 ACK 都 pump，不只累计推进时：重复 ACK 也携带新 rwnd，对端窗口
        // 一旦重开，这是下一个 tick 之前唯一的触发。
        pump(nowMs);
    }

    /** 重传年龄门的基准（毫秒）。 */
    private int retxAgeBaseMs() {
        int srtt = (int) Math.max(1, srttMs);
        if (minRttMs <= 0) return srtt;
        int floor = (int) Math.round(minRttMs * 1.25);
        int observed = rttPeakMs > 0 ? Math.min(rttPeakMs, StreamConstants.RTT_PEAK_MAX_MS) : 0;
        // rttvar < 5ms 是干净链路上的测量噪声，不据此放宽门。
        int fromVar = rttvarMs >= StreamConstants.RTTVAR_NOISE_FLOOR_MS
                ? (int) (srtt + 2 * rttvarMs) : 0;
        return Math.max(floor, Math.max(observed, fromVar));
    }

    /** 段在网络上存在多久之后才允许首次判失重传。（package-private：同包单测观测） */
    int retxAgeGateMs() {
        return (int) Math.max(StreamConstants.FAST_RETX_MIN_AGE_MS,
                Math.round(retxAgeBaseMs() * retxRelax * retxTighten));
    }

    /** 每个重复 ACK 轮次最多替换最旧的 FAST_RETX_SEGMENTS 个洞。 */
    private void fastRetransmit(long nowMs) {
        int repeatAfter = (int) Math.max(StreamConstants.MIN_RETX_INTERVAL_MS,
                Math.round(retxAgeBaseMs() * StreamConstants.RETX_RTT_FACTOR * 1.25));
        int firstAfter = retxAgeGateMs();
        int sent = 0;
        int firstSeq = -1;
        for (SndSeg s : tx) {
            if (s.acked || s.sacked) continue;
            // 未被证明缺失：对端尚未报告任何越过它的内容。
            if (!Seq.seqAtOrAfter(sackedHigh, s.end)) continue;
            int wait = s.retransmits != 0 ? repeatAfter : firstAfter;
            if (nowMs - s.sentMs < wait) continue;
            if (firstSeq < 0) firstSeq = s.offset;
            emitData(s, nowMs);
            ++s.retransmits; // Karn：这份拷贝不得进入 RTT 估计
            ++retransmits;
            ++retxFast;
            s.sentMs = nowMs;
            if (++sent >= StreamConstants.FAST_RETX_SEGMENTS) break;
        }
        if (sent > 0) {
            // 只在实际上了线的轮次计数：DUP_ACK_THRESH=1 时本函数对每条重复
            // ACK 都会跑，把空跑也算上会让 retxFast/fastRounds 虚高。
            ++fastRounds;
        }
        if (sent > 0 && fastRoundSeq < 0) {
            fastRoundMs = nowMs;
            fastRoundUna = sndUna;
            fastRoundSeq = firstSeq;
            fastRoundSpurious = false;
        }
    }

    /** 覆盖本轮首个重传段的累计 ACK 解决该轮。有证据才动门：乱序放宽，真丢收紧。 */
    private void resolveFastRound(int cum) {
        if (fastRoundSeq < 0) return;
        if (!Seq.seqAtOrAfter(cum, fastRoundSeq)) return;
        if (fastRoundSpurious) {
            retxRelax = Math.min(2, Math.round(retxRelax * 1.3 * 100) / 100.0);
            retxTighten = 1;
        } else {
            retxTighten = Math.max(StreamConstants.FAST_RETX_TIGHTEN_FLOOR,
                    Math.round(retxTighten * StreamConstants.FAST_RETX_TIGHTEN_STEP * 1000) / 1000.0);
            retxRelax = Math.max(1, Math.round(retxRelax * 0.8 * 100) / 100.0);
        }
        fastRoundSeq = -1;
        fastRoundSpurious = false;
    }

    /** 对开放洞重复 ACK 的间隔，按路径伸缩使重复落在发现洞的那一轮之内。 */
    private int holeDupAckMs() {
        int scaled = (int) Math.round(srttMs / StreamConstants.HOLE_DUP_ACK_DIVISOR);
        return Math.max(StreamConstants.HOLE_DUP_ACK_MIN_MS,
                Math.min(StreamConstants.HOLE_DUP_ACK_MS, scaled));
    }

    /**
     * 距下次本流需要自发做事的毫秒数，-1 = 无。只报告**未来**的截止期（≥1ms），
     * 宿主按此重调度不会自旋：每次唤醒必须清掉自己的截止期。
     */
    public long nextTimerMs(long nowMs) {
        if (state == STATE_CLOSED) return -1;
        long best = -1;
        long due;
        if (ackPending) {
            due = lastAckMs + StreamConstants.ACK_DELAY_MS - nowMs;
            if (due < 1) due = 1;
            best = best < 0 ? due : Math.min(best, due);
        } else if (oobBytes > 0) {
            due = lastAckMs + holeDupAckMs() - nowMs;
            if (due < 1) due = 1;
            best = best < 0 ? due : Math.min(best, due);
        }
        // 镜像 probeZeroWindow 的 tx 上限：超过 64 段在途时它拒绝探测，过期的
        // 零窗截止期会被钳到 1ms 造成忙循环；此时由 RTO 截止期驱动恢复。
        if ((pendingBytes > 0 || (finPending && !finSent)) && windowBlocked() && tx.size() <= 64) {
            due = lastZeroWinProbeMs + StreamConstants.ZERO_WINDOW_PROBE_MS - nowMs;
            if (due < 1) due = 1;
            best = best < 0 ? due : Math.min(best, due);
        }
        if (!tx.isEmpty() && tlpProbes < StreamConstants.TLP_MAX_PROBES && window() > 0
                && (pendingBytes == 0 || getInflightBytes() >= window())) {
            due = lastSendMs + Math.max(StreamConstants.TLP_MIN_PTO_MS,
                    Math.round(srttMs + 2 * rttvarMs)) - nowMs;
            if (due < 1) due = 1;
            best = best < 0 ? due : Math.min(best, due);
        }
        for (SndSeg s : tx) {
            if (s.acked || s.sacked) continue;
            due = s.sentMs + (long) (rtoMs * (1 << Math.min(s.retransmits, 5))) - nowMs;
            if (due < 1) due = 1;
            best = best < 0 ? due : Math.min(best, due);
            break; // RTO 循环只重发最旧的
        }
        return best;
    }

    public void onTick(long nowMs) {
        if (state == STATE_CLOSED) return;
        if (lastInboundMs == 0) lastInboundMs = nowMs;
        if (ackPending && nowMs - lastAckMs >= StreamConstants.ACK_DELAY_MS) {
            emitAck(nowMs);
        } else if (oobBytes > 0 && nowMs - lastAckMs >= holeDupAckMs()) {
            // 洞意味着入站流量停了、我们的 ACK 也停了：对端满窗干等，直到它
            // 的 RTO 起爆（VPS 链路上观察到的数秒停顿）。重复 ACK 让对端的
            // 重复 ACK 计数器动起来，缺失段一个往返内重发。同一条 ACK。
            emitAck(nowMs);
        }
        if (nowMs - lastInboundMs >= cfg.idleTimeoutMs) {
            finish("idle");
            return;
        }
        // 尾部丢失探测：尾部无人确认且其后不会再有重复 ACK，没有探测就要等满
        // 退避后的 RTO。提前重发尾部——重复包让接收端立即应答，cum 一动探测
        // 预算即重启。guard 覆盖"队列非空但窗口已满"（对端窗口缩到在途以下，
        // 队列无法排空）与队列为空两种停滞。
        boolean stalled = pendingBytes == 0 || getInflightBytes() >= window();
        if (!tx.isEmpty() && stalled && !finPending && window() > 0
                && tlpProbes < StreamConstants.TLP_MAX_PROBES) {
            int pto = (int) Math.max(StreamConstants.TLP_MIN_PTO_MS,
                    Math.round(srttMs + 2 * rttvarMs));
            if (nowMs - lastSendMs >= pto) {
                SndSeg tail = tx.get(tx.size() - 1);
                // 探测不是重传：不携带丢包证据，不消耗段的重传预算。它必须是
                // 真实上线的一份拷贝（这就是意义：让对端应答），并重启探测时钟。
                // 它移动 sentMs（RTO 从最新拷贝起算），并打 probed 标志让 RTT
                // 采样跳过（两份在途的 Karn 歧义）。
                emitData(tail, nowMs);
                tail.sentMs = nowMs;
                tail.probed = true;
                ++tlpProbes;
            }
        }
        // 1.5 sRTT 内一无所获的快速重传轮 → 乱序而非丢包：放宽下一轮的年龄
        // 基准（至多 2x）并停止收紧，因为收窄的门正是产生该轮的原因。
        if (fastRoundSeq >= 0 && nowMs - fastRoundMs >= Math.round(1.5 * srttMs)) {
            if (sndUna == fastRoundUna) {
                retxRelax = Math.min(2, Math.round(retxRelax * 1.3 * 100) / 100.0);
                retxTighten = 1;
            } else {
                retxTighten = Math.max(StreamConstants.FAST_RETX_TIGHTEN_FLOOR,
                        Math.round(retxTighten * StreamConstants.FAST_RETX_TIGHTEN_STEP * 1000) / 1000.0);
                retxRelax = Math.max(1, Math.round(retxRelax * 0.8 * 100) / 100.0);
            }
            fastRoundSeq = -1;
            fastRoundSpurious = false;
        }
        // 重传超时：重发最旧的未确认未 SACK 段。每段 2^retransmits 截止期就是
        // 退避；这里的全局 rtoMs 翻倍会让下一个段的首次 RTO 替这一次买单。
        for (SndSeg s : tx) {
            if (s.acked || s.sacked) continue;
            if (nowMs - s.sentMs >= rtoMs * (1 << Math.min(s.retransmits, 5))) {
                emitData(s, nowMs);
                ++s.retransmits;
                ++retransmits;
                ++retxRto;
                s.sentMs = nowMs;
            }
            break;
        }
        // 排空突发预算留下的部分。对端窗口关闭时 pump() 完全发不出东西
        // （inflight >= window()==0 首轮即 break），需要真实的单字节探测；
        // 只是小到装不下一段（1..6 字节）的窗口同样死锁，同样探测。
        if (windowBlocked()) {
            probeZeroWindow(nowMs);
        } else if (pendingBytes > 0 || finPending) {
            pump(nowMs);
        }
    }

    /** 零窗探测：一个字节的真数据是让对端带着新 rwnd 应答的唯一手段。 */
    private void probeZeroWindow(long nowMs) {
        boolean hasData = pendingBytes > 0;
        // 待发的 FIN 自己就能充当单字节 persist 探测（如 TCP）：全部数据确认后
        // 拒绝探测会让 FIN 滞留 SendingFin 直到空闲超时，两端均沉默。
        if (!hasData && !finPending) return;
        if (nowMs - lastZeroWinProbeMs < StreamConstants.ZERO_WINDOW_PROBE_MS) return;
        if (tx.size() > 64) return;
        lastZeroWinProbeMs = nowMs;
        byte[] chunk = hasData ? takePending(1) : new byte[0];
        boolean fin = !hasData && finPending;
        if (chunk.length == 0 && !fin) return;
        if (fin) {
            finSent = true;
            finPending = false;
        }
        int end = sndNext + chunk.length + (fin ? 1 : 0);
        SndSeg seg = new SndSeg();
        seg.offset = sndNext;
        seg.bytes = chunk;
        seg.fin = fin;
        seg.end = end;
        seg.sentMs = nowMs;
        seg.firstSentMs = nowMs;
        if (fin) finOffset = sndNext + chunk.length;
        tx.add(seg);
        sndNext = end;
        if (Seq.seqAfter(end, sndMax)) sndMax = end;
        emitData(seg, nowMs);
    }

    private void finish(String reason) {
        if (state == STATE_CLOSED) return;
        state = STATE_CLOSED;
        closeReason = reason;
        tx.clear();
        pending.clear();
        pendingBytes = 0;
        oob.clear();
        oobBytes = 0;
        cb.closed(reason);
    }

    // —— 测试钩子（package-private，仅供同包单测观测内部状态，不参与协议逻辑）——

    /** end > cum 的在途段数。 */
    int txCountAbove(int cum) {
        int n = 0;
        for (SndSeg s : tx) if (s.end > cum) ++n;
        return n;
    }

    /** end > cum 且已标记 SACK 的在途段数。 */
    int txSackedAbove(int cum) {
        int n = 0;
        for (SndSeg s : tx) if (s.end > cum && s.sacked) ++n;
        return n;
    }

    private boolean sigSeen(int sig) {
        for (int i = 0; i < ackSigFilled && i < StreamConstants.ACK_SIG_RING; ++i) {
            if (ackSigRing[i] == sig) return true;
        }
        return false;
    }

    private void rememberAckSig(int sig) {
        ackSigRing[ackSigIdx] = sig;
        if (ackSigFilled < StreamConstants.ACK_SIG_RING) ++ackSigFilled;
        ackSigIdx = (ackSigIdx + 1) % StreamConstants.ACK_SIG_RING;
    }

    /**
     * 单条 ACK 的内容指纹：相同 cum/窗口/SACK 区间的两条 ACK 语义完全相同，
     * 是忠实的"是否已处理过"判据。
     */
    private static int ackSignature(int cum, int rwnd, List<Segment.AckRange> ranges) {
        int h = 0x811c9dc5;
        h = mix(h, cum);
        h = mix(h, rwnd);
        h = mix(h, ranges == null ? 0 : ranges.size());
        if (ranges != null) {
            for (Segment.AckRange r : ranges) {
                h = mix(h, r.start);
                h = mix(h, r.end);
            }
        }
        return h;
    }

    private static int mix(int h, int v) {
        h ^= v & 0xff;
        h *= 0x01000193;
        h ^= (v >>> 8) & 0xff;
        h *= 0x01000193;
        h ^= (v >>> 16) & 0xff;
        h *= 0x01000193;
        h ^= (v >>> 24) & 0xff;
        h *= 0x01000193;
        return h;
    }
}
