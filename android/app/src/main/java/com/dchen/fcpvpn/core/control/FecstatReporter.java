package com.dchen.fcpvpn.core.control;

import com.dchen.fcpvpn.core.fec.FecstatBlock;
import com.dchen.fcpvpn.core.fec.FrameRx;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * 每 FECSTAT 周期由接收端计数器构造一份 128 字节报告
 * （controller.ts FecstatReporter 保真移植）。所有字段都是区间增量——
 * 没有上次快照的话同一分片会永远留在 data_rx_orig 里，对端的
 * 1 - data_rx_orig/data_expected 会收敛到会话平均值。
 */
public final class FecstatReporter {

    private final byte[] salt;
    private long lastMs = 0;
    private int authFail = 0;
    private int structFail = 0;
    private long dataBytes = 0;
    private long parityBytes = 0;
    private final List<Integer> latencies = new ArrayList<>();
    private final int direction;
    private Snapshot prev = null;

    private static final class Snapshot {
        final int setsExpected;
        final int dataExpected;
        final int dataRxOrig;
        final int recovered;
        final int recoveredLate;
        final int dataDelivered;
        final int parityRx;
        final int parityExpected;
        final int setsKUnknown;
        final int setsFull;
        final int lateDup;
        final int structFail;
        final int setsTailDropped;
        final int dataLateRx;
        final int setsPartial;
        final int ledgerGroups;
        final int ledgerFailed;
        final int[] ledgerKHist;

        Snapshot(FrameRx.RxCounters c) {
            this.setsExpected = c.setsExpected;
            this.dataExpected = c.dataExpected;
            this.dataRxOrig = c.dataRxOrig;
            this.recovered = c.recovered;
            this.recoveredLate = c.recoveredLate;
            this.dataDelivered = c.dataDelivered;
            this.parityRx = c.parityRx;
            this.parityExpected = c.parityExpected;
            this.setsKUnknown = c.setsKUnknown;
            this.setsFull = c.setsFull;
            this.lateDup = c.lateDup;
            this.structFail = c.structFail;
            this.setsTailDropped = c.setsTailDropped;
            this.dataLateRx = c.dataLateRx;
            this.setsPartial = c.setsPartial;
            this.ledgerGroups = c.ledgerGroups;
            this.ledgerFailed = c.ledgerFailed;
            this.ledgerKHist = Arrays.copyOf(c.ledgerKHist, c.ledgerKHist.length);
        }
    }

    private static int delta(int now, int before) {
        return now - before; // u32 回绕语义
    }

    public FecstatReporter(byte[] salt, int direction) {
        this.salt = Arrays.copyOf(salt, salt.length);
        this.direction = direction;
    }

    public void addDataBytes(long n) {
        dataBytes += n;
    }

    public void addParityBytes(long n) {
        parityBytes += n;
    }

    public void recordRepairLatency(long ms) {
        latencies.add((int) (ms & 0xffff));
    }

    public void noteAuthFail() {
        ++authFail;
    }

    public void noteStructFail() {
        ++structFail;
    }

    /** 返回本周期应发送的 128 字节报告，未到周期返回 null。 */
    public byte[] onTick(long nowMs, FrameRx.RxCounters counters, int accountedThroughSetId) {
        if (lastMs == 0) {
            lastMs = nowMs;
            prev = new Snapshot(counters);
            return null;
        }
        if (nowMs - lastMs < ControlConstants.FECSTAT_INTERVAL_MS) return null;
        long interval = Math.min(ControlConstants.FECSTAT_MAX_INTERVAL_MS, nowMs - lastMs);
        lastMs = nowMs;
        Snapshot cur = new Snapshot(counters);
        Snapshot before = prev != null ? prev : cur;
        prev = cur;
        FecstatBlock.FecstatPacket p = FecstatBlock.makeFecstatPacket(salt);
        p.intervalMs = (int) interval;
        p.flg = ControlConstants.FLG_DIRECTION; // 接收端报告"你→我"方向
        p.accountedThroughSetId = accountedThroughSetId;
        p.setsExpected = delta(cur.setsExpected, before.setsExpected);
        p.dataExpected = delta(cur.dataExpected, before.dataExpected);
        p.dataRxOrig = delta(cur.dataRxOrig, before.dataRxOrig);
        p.dataRecoveredDl = delta(cur.recovered, before.recovered);
        p.dataRecoveredLate = delta(cur.recoveredLate, before.recoveredLate);
        p.dataDelivered = delta(cur.dataDelivered, before.dataDelivered);
        p.parityRx = delta(cur.parityRx, before.parityRx);
        p.parityExpected = delta(cur.parityExpected, before.parityExpected);
        p.setsKUnknown = delta(cur.setsKUnknown, before.setsKUnknown);
        p.setsFull = delta(cur.setsFull, before.setsFull);
        p.setsPartial = delta(cur.setsPartial, before.setsPartial);
        p.setsTailDropped = delta(cur.setsTailDropped, before.setsTailDropped);
        p.lateDup = delta(cur.lateDup, before.lateDup);
        p.dataLateRx = delta(cur.dataLateRx, before.dataLateRx);
        p.structFail = delta(cur.structFail, before.structFail) + structFail;
        p.authFail = authFail;
        p.dataBytesRx = (int) dataBytes;
        p.parityBytesRx = (int) parityBytes;
        if (p.dataRecoveredLate > 0) p.flg |= ControlConstants.FLG_LATE_RECOVERY;
        if (p.setsTailDropped > 0) p.flg |= ControlConstants.FLG_TAIL_DROPPED;
        List<Integer> lats = new ArrayList<>(latencies);
        Collections.sort(lats);
        if (!lats.isEmpty()) {
            // 最近邻秩，对齐 reporter.cc 的 percentile()。
            p.repairLatP50Ms = at(lats, 50);
            p.repairLatP95Ms = at(lats, 95);
        }
        int ledgerGroups = delta(cur.ledgerGroups, before.ledgerGroups);
        if (ledgerGroups > 0) {
            int failed = delta(cur.ledgerFailed, before.ledgerFailed);
            p.ledgerGroups = ledgerGroups;
            p.ledgerFailPpm = (int) Math.min(1000000, Math.round(1e6 * failed / ledgerGroups));
            int bestK = 0;
            int bestN = 0;
            for (int k = 1; k <= 7; ++k) {
                int n = delta(cur.ledgerKHist[k], before.ledgerKHist[k]);
                if (n > bestN) {
                    bestN = n;
                    bestK = k;
                }
            }
            p.ledgerMeta = bestK;
            p.flg |= ControlConstants.FLG_LEDGER;
        }
        authFail = 0;
        structFail = 0;
        dataBytes = 0;
        parityBytes = 0;
        latencies.clear();
        return FecstatBlock.encodeFecstat(p);
    }

    private static int at(List<Integer> sorted, int pct) {
        int rank = (int) Math.min(sorted.size(),
                Math.max(1, Math.ceil(pct * sorted.size() / 100.0)));
        return sorted.get(rank - 1) & 0xffff;
    }
}
