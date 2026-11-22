package com.dchen.fcpvpn.core.control;

/**
 * 下一修复组的组大小（controller.ts chooseGroupD 保真移植）。
 *
 * k = ceil(d × loss × HEADROOM) 是每组计数，d 决定冗余能瞄准多细、以及是否
 * 瞄得准。两个约束打架：
 * - 尾部覆盖：d×loss×HEADROOM 达到协商上限 p 后公式饱和，再加大 d 只稀释 k/d
 *   ——缩小 d 直到 k 落回 p 以下恢复比例（20% 丢包下 10:6 优于 20:6）。
 * - 结算速率：接收端 1s 结算、2s 淘汰；组产出快过 MAX_SETS_PER_SECOND 会把
 *   活跃集合挤爆、半解码即被驱逐。这是正确性界限，压过上面那条。
 * p==0（只组帧不修复）时不动 d。
 */
public final class GroupSize {

    private GroupSize() {}

    public static int chooseGroupD(int dMax, int p, double loss, double symPerSec) {
        int max = Math.max(1, dMax);
        int d = max;
        if (p > 0 && loss > 0) {
            // epsilon 防止 0.4×3=1.2000000000000002 把精确的 6/1.2=5 变成 4。
            int byTail = (int) Math.floor(p / (loss * ControlConstants.FEC_HEADROOM) + 1e-9);
            if (byTail < d) d = Math.max(ControlConstants.D_FLOOR, byTail);
        }
        if (symPerSec > 0) {
            int byRate = (int) Math.ceil(symPerSec / ControlConstants.MAX_SETS_PER_SECOND);
            if (byRate > d) d = byRate;
        }
        if (d > max) d = max;
        // D_FLOOR 是偏好，不是突破协商上限的许可（--fec-data=2 时会话就跑 d=2）。
        return Math.max(1, Math.min(max, d));
    }
}
