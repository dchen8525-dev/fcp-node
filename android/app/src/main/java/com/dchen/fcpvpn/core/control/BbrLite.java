package com.dchen.fcpvpn.core.control;

import java.util.ArrayDeque;
import java.util.Deque;

/**
 * BBR-lite：只向反应器暴露 pacing/srtt 提示（controller.ts BbrLite 保真移植）。
 * 交付速率取窗口最大值而非最近一个 epoch——交付是突发的，按 epoch 取值会
 * 10 倍摆动，让流窗口每 250ms 在 262KiB 与 690KiB 之间震荡。
 */
public final class BbrLite {

    public int version = 2;
    public double srttMs;
    public double minRttMs = 0;
    public double bwBytesPerMs = 0;

    private long epochStartMs = 0;
    private long deliveredBytes = 0;
    private static final class Sample {
        final long ms;
        final double bw;
        Sample(long ms, double bw) { this.ms = ms; this.bw = bw; }
    }
    private final Deque<Sample> samples = new ArrayDeque<>();
    private final AdaptiveFec.TraceSink trace;

    public BbrLite(double initialSrttMs, AdaptiveFec.TraceSink trace) {
        this.srttMs = initialSrttMs > 0 ? initialSrttMs : ControlConstants.DEFAULT_SRTT_MS;
        this.trace = trace;
    }

    public void onRtt(double srttMs) {
        this.srttMs = srttMs;
        if (minRttMs == 0 || srttMs < minRttMs) minRttMs = srttMs;
    }

    public void onDelivery(long bytes, long nowMs) {
        if (epochStartMs == 0) epochStartMs = nowMs;
        deliveredBytes += bytes;
        long span = nowMs - epochStartMs;
        if (span >= srttMs) {
            double bw = deliveredBytes / Math.max(1, span);
            epochStartMs = nowMs;
            deliveredBytes = 0;
            // 窗口最大值：一个 epoch 可能整窗到达，下一个什么都没有。
            samples.addLast(new Sample(nowMs, bw));
            long cutoff = nowMs - ControlConstants.BBR_BW_WINDOW_MS;
            while (!samples.isEmpty() && samples.peekFirst().ms < cutoff) samples.pollFirst();
            double best = 0;
            for (Sample s : samples) if (s.bw > best) best = s.bw;
            bwBytesPerMs = best;
            if (trace != null) {
                trace.trace("{\"t\":\"bbr\",\"v\":" + version + ",\"srtt\":" + srttMs
                        + ",\"bw\":" + bwBytesPerMs + "}");
            }
        }
    }

    public double pacingGapMs(long bytes) {
        if (bwBytesPerMs <= 0) return 0;
        return Math.max(0, bytes / bwBytesPerMs);
    }
}
