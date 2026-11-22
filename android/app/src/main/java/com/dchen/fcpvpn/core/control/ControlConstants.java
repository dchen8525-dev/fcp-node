package com.dchen.fcpvpn.core.control;

/** control 层常量（constants.ts 摘录，勿改值）。 */
public final class ControlConstants {

    private ControlConstants() {}

    public static final int DEFAULT_D = 10;
    public static final int DEFAULT_P = 6;
    public static final int DEFAULT_SRTT_MS = 200;
    public static final int FECSTAT_INTERVAL_MS = 1000;
    public static final int FECSTAT_MAX_INTERVAL_MS = 60000;
    public static final int MAX_PARITY = 7;
    public static final int BBR_BW_WINDOW_MS = 2000;
    public static final double FEC_HEADROOM = 3.0;
    public static final int FEC_DROP_STREAK = 4;
    public static final int FEC_LOSS_MIN_SHARDS = 256;
    public static final int D_FLOOR = 4;
    public static final int MAX_SETS_PER_SECOND = 256 / 2;
    public static final int MAX_INTERLEAVE = 8;
    public static final int D_STEP_MIN = 2;
    public static final int D_ADAPT_INTERVAL_MS = 2000;

    public static final int FLG_DIRECTION = 0x01;
    public static final int FLG_TAIL_DROPPED = 0x02;
    public static final int FLG_LATE_RECOVERY = 0x04;
    public static final int FLG_LEDGER = 0x08;
}
