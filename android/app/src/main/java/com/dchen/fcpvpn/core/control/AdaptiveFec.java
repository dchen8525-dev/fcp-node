package com.dchen.fcpvpn.core.control;

/**
 * FEC 冗余控制器（controller.ts AdaptiveFec 保真移植）。
 * 由**直接测量的分片丢失率**驱动 k（每组纠错符号数），无死区：
 * target = ceil(d × loss × FEC_HEADROOM)，钳位到 [kMin, 协商的 parity 上限]。
 */
public final class AdaptiveFec {

    private int k;
    private final int pinnedK;
    /** 会话允许 parity 时 k 至少为 1：丢报期间 k 归 0 会让每个丢包都拖到 RTO。 */
    private int kMin;
    /** 协商的 parity 上限（k 不得超过：超出会被对端按 IndexPastS 拒收）。 */
    private int p;
    /** 组大小：把分片丢失率换算成每组 k 时需要。 */
    private int d;
    private long lastLocalMs = 0;
    /** 连续低丢失样本数（降 k 需 FEC_DROP_STREAK 个）。 */
    private int lowStreak = 0;
    private double lossRate = 0;
    /** 收到过可用 FECSTAT 后本地台账仅作回退；对端 3 个周期未上报则交还控制权。 */
    private boolean peerReports = false;
    private long lastPeerReportMs = 0;
    /** 低于噪声地板的样本跨周期累加，凑够 FEC_LOSS_MIN_SHARDS 再一起评估。 */
    private int pendExpected = 0;
    private int pendOrig = 0;
    private final TraceSink trace;

    /** 轻量 trace 钩子（可为 null）。 */
    public interface TraceSink {
        void trace(String line);
    }

    public AdaptiveFec(int d, int p, int pinnedK, TraceSink trace) {
        this.p = Math.max(0, Math.min(ControlConstants.MAX_PARITY, p));
        this.d = Math.max(1, d);
        this.pinnedK = pinnedK;
        this.kMin = Math.min(1, this.p);
        this.k = pinnedK > 0 ? Math.min(pinnedK, this.p) : Math.min(3, this.p);
        this.trace = trace;
    }

    public int currentK() { return k; }

    /** 协商的 parity 上限。 */
    public int currentParityCeiling() { return p; }

    public double currentLoss() { return lossRate; }

    /** 收窄上限到握手实际协商的 parity。 */
    public void setParityCeiling(int p) {
        this.p = Math.max(0, Math.min(ControlConstants.MAX_PARITY, p));
        this.kMin = Math.min(1, this.p);
        if (k > this.p) k = this.p;
    }

    /** 组大小对齐到线上协商值。 */
    public void setGroupSize(int d) {
        if (d > 0) this.d = d;
    }

    /** 接收端本地回退：仅当对端不发送 FECSTAT 时使用（整会话口径，FECSTAT 节奏采样）。 */
    public void noteLocalCounters(long expectedShards, long rxOrig, long nowMs) {
        if (pinnedK > 0) return;
        if (peerReports) {
            // 对端 3 个 FECSTAT 周期未上报 = 快速路径失效，交还本地台账。
            if (lastPeerReportMs > 0
                    && nowMs - lastPeerReportMs >= ControlConstants.FECSTAT_INTERVAL_MS * 3L) {
                peerReports = false;
            }
            return;
        }
        if (lastLocalMs == 0) {
            lastLocalMs = nowMs;
            return;
        }
        if (nowMs - lastLocalMs < ControlConstants.FECSTAT_INTERVAL_MS) return;
        lastLocalMs = nowMs;
        if (expectedShards < ControlConstants.FEC_LOSS_MIN_SHARDS) return;
        long lost = Math.max(0, Math.min(expectedShards, expectedShards - rxOrig));
        adjust((double) lost / expectedShards, "fec_k_local");
    }

    /** 对端 FECSTAT 驱动本端发送侧 k：loss = 1 - dataRxOrig / dataExpected（分母是发送的分片数）。 */
    public void onFecstat(com.dchen.fcpvpn.core.fec.FecstatBlock.FecstatPacket stat, long nowMs) {
        if (nowMs > 0) lastPeerReportMs = nowMs;
        // 对端在上报 → 本地台账让位（两套控制器同时驱动会互相打架：台账测的是
        // 入方向，k 管的是出方向）。
        peerReports = true;
        Double loss = sampleLoss(stat);
        if (loss == null) return;
        // 钉住的是 k 的取值，不是测量本身：提前返回会让 pinned 腿永远报 loss=0。
        if (pinnedK > 0) {
            lossRate = loss;
            return;
        }
        adjust(loss, "fecstat_loss");
    }

    /** 单份对端报告的丢失率；低于分片地板的样本跨报告累加后统一评估。 */
    private Double sampleLoss(com.dchen.fcpvpn.core.fec.FecstatBlock.FecstatPacket stat) {
        int expected = stat.dataExpected;
        int rxOrig = stat.dataRxOrig;
        if (expected < ControlConstants.FEC_LOSS_MIN_SHARDS) {
            pendExpected += expected;
            pendOrig += rxOrig;
            if (pendExpected < ControlConstants.FEC_LOSS_MIN_SHARDS) return null;
            int evalExpected = pendExpected;
            int evalOrig = pendOrig;
            pendExpected = 0;
            pendOrig = 0;
            long lost = Math.max(0, Math.min(evalExpected, evalExpected - evalOrig));
            return (double) lost / evalExpected;
        }
        pendExpected = 0;
        pendOrig = 0;
        long lost = Math.max(0, Math.min(expected, expected - rxOrig));
        return (double) lost / expected;
    }

    /** 无死区：每个样本都有目标值。立即上调，下调需持续证据，持平即清零计数。 */
    private void adjust(double loss, String event) {
        lossRate = loss;
        int need = (int) Math.ceil(d * loss * ControlConstants.FEC_HEADROOM);
        int target = Math.min(p, Math.max(kMin, need));
        if (target > k) {
            k = target;
            lowStreak = 0;
        } else if (target < k) {
            if (++lowStreak >= ControlConstants.FEC_DROP_STREAK) {
                lowStreak = 0;
                --k;
            }
        } else {
            lowStreak = 0;
        }
        if (trace != null) {
            trace.trace("{\"t\":\"" + event + "\",\"k\":" + k + ",\"target\":" + target
                    + ",\"loss\":" + loss + ",\"cap\":" + p
                    + ",\"ceiling\":" + (k == p && need > p ? 1 : 0) + "}");
        }
    }
}
