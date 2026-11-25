package com.dchen.fcpvpn.core.fec;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.dchen.fcpvpn.core.wire.Seq;
import com.dchen.fcpvpn.core.wire.Wire;

/**
 * FEC 数据面接收侧。移植自 fcp-node src/fec/frame.ts:255-685 的 FrameRx
 * （C++ frame_rx.cc / frame_rx_decode.cc / settle.cc）。
 *
 * 按 set_id 聚合集合、RS 重建、len 自校验（declared == 符号总字节数）、
 * oob 分路；乱序/重复符号处理与源码一致。集合自描述（d 随头上行），
 * 接收端从任一 parity 的 index − j 反推 n，并按与发送端相同的公式推导
 * 短组 k_eff，避免用错误的码长解线性方程组。
 *
 * 结算时钟（1 s 记账 / 2 s 退役，settle.cc）由调用方通过 onTick(nowMs) 驱动；
 * 本层不起任何线程，保证无线程也能确定性单测。
 */
public final class FrameRx {

    // ---- 常量（fcp-node src/constants.ts FrameRx 段） ----

    /** 活跃集合表容量（constants.ts:351 MAX_ACTIVE_SETS）。 */
    public static final int MAX_ACTIVE_SETS = 256;
    /** set_id 跳变允许创建的空隙占位集合数上限（constants.ts:352）。 */
    public static final int MAX_GAP_PLACEHOLDERS = 64;
    /** 孤立远前 set_id 的确认超时（constants.ts:353 AHEAD_CONFIRM_TIMEOUT_MS）。 */
    public static final int AHEAD_CONFIRM_TIMEOUT_MS = 2000;
    /** 全部活跃集合符号字节总量的会话上限（constants.ts:358 MAX_RX_SYMBOL_BYTES）。 */
    public static final int MAX_RX_SYMBOL_BYTES = 8 * 1024 * 1024;
    /** 结算/退役时钟（frame.ts:617-632 onTick，settle.cc 的 1 s / 2 s）。 */
    static final int SETTLE_AFTER_MS = 1000;
    static final int RETIRE_AFTER_MS = 2000;

    /** 交付回调（frame.ts:288 deliver）：payload 已剥掉 2 字节 len 前缀。 */
    public interface DeliverFn {
        void onPayload(byte[] payload, boolean recovered, boolean late);
    }

    /** oob 回调（frame.ts:289）：收到原始 oob 消息。 */
    public interface OobFn {
        void onOob(byte[] payload, long nowMs);
    }

    /** 诊断事件（frame.ts:255 RxEventInfo）：repairMs &lt; 0 表示该事件无此字段。 */
    public interface EventFn {
        void onEvent(String event, int setId, long repairMs);
    }

    /** 接收计数器（frame.ts:271-284 RxCounters）。u32 语义，Java int 位保真。 */
    public static final class RxCounters {
        public int structFail;
        public int stale;
        public int lateDup;
        public int recovered;
        public int recoveredLate;
        public int dataRxOrig;
        public int parityRx;
        public int dataDelivered;
        public int dataLateRx;
        public int retiredDropped;
        public int aheadDropped;
        public int setsPartial;
        public int setsFull;
        public int setsTailDropped;
        public int decodeAttempts;
        public int badRecon;
        public int symbolBudgetDrops;
        /** 结算视图（FECSTAT 用）：已记账集合数与其期望承载的 data 片数 Σ n_used。 */
        public int setsExpected;
        public int dataExpected;
        public int parityExpected;
        public int setsKUnknown;
        /** M3 R(k) 台账：满组且 k 已知，其中失败数。 */
        public int ledgerGroups;
        public int ledgerFailed;
        public final int[] ledgerKHist = new int[8];
    }

    /** 单个 FEC 集合的接收状态（frame.ts:257-269 RxSet）；字段开放给同包测试/诊断。 */
    public static final class RxSet {
        public int setId;
        public int n;
        public boolean nKnown;
        public int k;
        public boolean kKnown;
        /** 本集合被切组时的 d（取自第一个符号的头）。 */
        public int d;
        public boolean dKnown;
        public int symbolMax;
        public int maxDataIndex;
        public final HashMap<Integer, byte[]> data = new HashMap<>();
        public final HashMap<Integer, byte[]> parity = new HashMap<>();
        public final HashSet<Integer> orig = new HashSet<>();
        public final HashSet<Integer> recov = new HashSet<>();
        public long tFirstMs;
        public boolean accounted;
        public long tombstoneUntilMs;
        public boolean hasAnySymbol;
        public int decodeAttempts;
    }

    private final int dMax;
    private final int p;
    private final DeliverFn deliverFn;
    private final OobFn oobFn;
    private final EventFn eventFn;
    private int maxSymbolLen;

    /** 集合表必须保持插入序：容量驱逐选"第一个未记账集合"依赖它（对应 TS Map 插入序）。 */
    private final LinkedHashMap<Integer, RxSet> sets = new LinkedHashMap<>();
    private final LinkedHashSet<Integer> retired = new LinkedHashSet<>();
    private final HashMap<Integer, Integer> accountBoundary = new HashMap<>();
    private int anchor;
    private boolean anchorValid;
    private int pendingAhead;
    private boolean pendingAheadValid;
    private long pendingAheadMs;
    /** FECSTAT 会话级单调键，不得从活跃集合表推导：退役集合 2 s 后被删除，
     *  静默间隔若重算会回落，对端校验器会把后续报告判 stale（frame.ts:309-314）。 */
    private int accountedThrough;
    private boolean haveAccounted;
    /** 所有活跃集合符号字节总量预算（frame.ts:315）。包级可见供回归测试。 */
    int symbolBytes;

    public final RxCounters counters = new RxCounters();

    public FrameRx(int d, int p, DeliverFn deliver, OobFn oob) {
        this(d, p, deliver, oob, null, 65535);
    }

    /** maxSymbolLen 缺省 65535（frame.ts:330）。 */
    public FrameRx(int d, int p, DeliverFn deliver, OobFn oob, EventFn event, int maxSymbolLen) {
        this.dMax = d;
        this.p = p;
        this.deliverFn = deliver;
        this.oobFn = oob;
        this.eventFn = event;
        this.maxSymbolLen = maxSymbolLen;
    }

    public void setMaxSymbolLen(int n) {
        if (n > 0) this.maxSymbolLen = n;
    }

    public List<Integer> activeSetIds() {
        return new ArrayList<>(sets.keySet());
    }

    public RxSet view(int setId) {
        return sets.get(setId);
    }

    /** 已记账的最高 set_id（FECSTAT 会话级单调键，frame.ts:682-684）。 */
    public int accountedThroughSetId() {
        return accountedThrough;
    }

    private void emit(String event, int setId, long repairMs) {
        if (eventFn != null) eventFn.onEvent(event, setId, repairMs);
    }

    /**
     * 处理一个已解密的 FEC 数据报（头 + 符号）（frame.ts:342-447 onDatagram）。
     * 校验链：parseHdr → oob 分路 → 过期集合（半窗）→ d 上限 → validateHdr
     * → 符号长度 → data 的 len 自校验 / parity 的 n 一致性 → retired 守卫
     * → A8 远前确认 → k/d 先到先得 → 落库 → tryDecode。
     */
    public void onDatagram(byte[] plain, long nowMs) {
        FecHeader.FecHdr hdr = FecHeader.parseHdr(plain);
        if (hdr == null) {
            ++counters.structFail;
            return;
        }
        byte[] symbol = Arrays.copyOfRange(plain, FecHeader.FEC_HDR_LEN, plain.length);
        int type = FecHeader.hdrType(hdr.typeK);
        if (type == FecHeader.TYPE_OOB) {
            oobFn.onOob(symbol, nowMs);
            return;
        }
        if (!FecHeader.validSymbolType(type)) {
            ++counters.structFail;
            return;
        }

        // 过期集合：只有结构合法的头才能移动锚点。TS 用无符号区间
        // (behind > 256 && behind < 2^31) 判断；Java 有符号 int 比较与之一一对应
        //（负差值 ⟺ 无符号 ≥ 2^31，天然落进"不过期"分支）。
        if (anchorValid) {
            int behind = anchor - hdr.setId;
            if (behind > MAX_ACTIVE_SETS) {
                ++counters.stale;
                return;
            }
        }

        // 集合自带组大小；超过协商上限即协议违约：发送端只调小不调大，
        // 此边界防止伪造头声称 d = 255（frame.ts:356-359）。
        if (hdr.d < 1 || hdr.d > dMax) {
            ++counters.structFail;
            return;
        }
        RxSet existing = sets.get(hdr.setId);
        boolean nKnown = existing != null && existing.nKnown;
        int n = existing != null ? existing.n : 0;
        if (FecHeader.validateHdr(hdr, p, nKnown, n) != FecHeader.OK) {
            ++counters.structFail;
            return;
        }
        if (symbol.length < 2 || symbol.length > maxSymbolLen) {
            ++counters.structFail;
            return;
        }
        int kField = FecHeader.hdrK(hdr.typeK);
        int jField = FecHeader.hdrJ(hdr.typeK);
        int nNew = 0;
        if (type == FecHeader.TYPE_DATA) {
            int declared = Wire.getLe16(symbol, 0);
            if (declared != symbol.length) {
                ++counters.structFail;
                return;
            }
        } else {
            nNew = hdr.index - jField;
            if (nKnown && n != nNew) {
                ++counters.structFail;
                return;
            }
        }
        if (retired.contains(hdr.setId)) {
            ++counters.retiredDropped;
            return;
        }

        // A8：孤立的远前 set_id 不得独自重锚窗口（frame.ts:377-392）。
        if (anchorValid && Seq.seqAfter(hdr.setId, anchor)
                && hdr.setId - anchor > MAX_GAP_PLACEHOLDERS) {
            boolean same = pendingAheadValid && hdr.setId == pendingAhead;
            boolean consecutive = pendingAheadValid && Seq.seqAfter(hdr.setId, pendingAhead)
                    && hdr.setId - pendingAhead <= MAX_GAP_PLACEHOLDERS;
            boolean expired = pendingAheadValid && nowMs - pendingAheadMs >= AHEAD_CONFIRM_TIMEOUT_MS;
            if (same || consecutive || expired) {
                anchor = hdr.setId;
                pendingAheadValid = false;
                pruneRetired();
            } else {
                pendingAhead = hdr.setId;
                pendingAheadValid = true;
                pendingAheadMs = nowMs;
                ++counters.aheadDropped;
                return;
            }
        } else {
            pendingAheadValid = false;
        }
        boolean hadAnchor = anchorValid;
        int prevAnchor = anchor;
        if (!anchorValid || Seq.seqAfter(hdr.setId, anchor)) {
            anchor = hdr.setId;
            anchorValid = true;
            pruneRetired();
        }
        if (hadAnchor && Seq.seqAfter(hdr.setId, prevAnchor + 1)) {
            createPlaceholders(prevAnchor + 1, hdr.setId, nowMs);
        }

        RxSet set = getOrCreate(hdr.setId, nowMs);
        if (set == null) {
            ++counters.structFail;
            return;
        }
        // k 先到先得并钳到协商 parity 上限（C++ A9）。一旦已知，声明不同 k 的符号
        // 是结构违约：用错误几何解码可能重构出损坏数据（frame.ts:400-407）。
        int kClamped = Math.min(kField, p);
        if (!set.kKnown) {
            set.k = kClamped;
            set.kKnown = true;
        } else if (set.k != kClamped) {
            ++counters.structFail;
            return;
        }
        // d 同规则：同一集合内混用几何会按错误码长解码（frame.ts:409-412）。
        if (!set.dKnown) {
            set.d = hdr.d;
            set.dKnown = true;
        } else if (set.d != hdr.d) {
            ++counters.structFail;
            return;
        }

        if (type == FecHeader.TYPE_DATA) {
            int idx = hdr.index;
            if (set.orig.contains(idx) || set.recov.contains(idx)) {
                ++counters.lateDup;
                emit("data_duplicate", hdr.setId, -1);
                return;
            }
            set.orig.add(idx);
            set.maxDataIndex = Math.max(set.maxDataIndex, idx);
            store(set, idx, symbol);
            boolean late = set.accounted;
            Integer boundary = accountBoundary.get(hdr.setId);
            boolean lateUnexpected = late && (boundary == null || idx >= boundary);
            // 分片计数按结算制（见 accountSet）：这里只累计交付数。
            ++counters.dataDelivered;
            // data_late_rx 记账后仍落在已记账码长内的唯一原件（C++ settle.cc:188）。
            if (late && !lateUnexpected) ++counters.dataLateRx;
            deliverFn.onPayload(Arrays.copyOfRange(symbol, 2, symbol.length), false,
                    late || lateUnexpected);
            tryDecode(set, nowMs);
            return;
        }

        // parity：n = index − j 是 n 的唯一来源（frame.ts:438-446）。
        if (set.parity.containsKey(hdr.index)) return;
        if (!set.nKnown && set.maxDataIndex >= nNew) {
            ++counters.structFail;
            return;
        }
        set.n = nNew;
        set.nKnown = true;
        // 字节预算拒收时不登记 parity，否则退役时会减去从未入账的字节（frame.ts:443-445）。
        if (store(set, hdr.index, symbol)) set.parity.put(hdr.index, symbol);
        tryDecode(set, nowMs);
    }

    private boolean store(RxSet set, int idx, byte[] symbol) {
        set.hasAnySymbol = true;
        set.symbolMax = Math.max(set.symbolMax, symbol.length);
        byte[] old = set.data.get(idx);
        int oldLen = old != null ? old.length : 0;
        if (symbolBytes - oldLen + symbol.length > MAX_RX_SYMBOL_BYTES) {
            // 与 frame_rx.cc 同一策略：丢弃由对端 ARQ 补救，堆膨胀不能补救。
            // 索引掩码（orig）保持置位，与 C++ 一致。
            ++counters.symbolBudgetDrops;
            return false;
        }
        symbolBytes += symbol.length - oldLen;
        set.data.put(idx, symbol);
        return true;
    }

    /**
     * 重构符号入账：集合表与会话字节预算必须同时登记（frame.ts:478-493
     * storeRecovered）。缺失此检查时重构行占着堆却不计入 symbolBytes，
     * 退役扣减会把预算打成负数，MAX_RX_SYMBOL_BYTES 从此失效。
     * 拒收是安全的：调用方仍交付本次重构，后续 parity 可再次修补该槽位。
     * 包级可见供回归测试（bytes/protocol 测试经 (rx as any) 访问）。
     */
    void storeRecovered(RxSet set, int idx, byte[] symbol) {
        byte[] old = set.data.get(idx);
        int oldLen = old != null ? old.length : 0;
        if (symbolBytes - oldLen + symbol.length > MAX_RX_SYMBOL_BYTES) {
            ++counters.symbolBudgetDrops;
            return;
        }
        symbolBytes += symbol.length - oldLen;
        set.data.put(idx, symbol);
    }

    private int setBytes(RxSet set) {
        int n = 0;
        for (byte[] b : set.data.values()) n += b.length;
        return n;
    }

    /** RS 重建尝试（frame.ts:501-557 tryDecode）。 */
    private void tryDecode(RxSet set, long nowMs) {
        if (!set.nKnown || !set.kKnown || set.k == 0) return;
        List<Integer> missing = new ArrayList<>();
        for (int i = 0; i < set.n; ++i) {
            if (!set.orig.contains(i) && !set.recov.contains(i)) missing.add(i);
        }
        // 码长不是头里的 k：短组按 k_eff = max(1, min(k, ceil(k·n/d))) 发 parity，
        // 而 Cauchy 系数依赖 k，必须推导出与发送端相同的 k_eff 再解方程
        //（frame.ts:507-519）。parity 只在闭合时发出，此刻 n 已最终。
        int dSet = set.dKnown ? set.d : dMax;
        int kUsed = dSet > 0
                ? Math.max(1, Math.min(set.k, ceilDiv(set.k * set.n, dSet)))
                : set.k;
        if (missing.isEmpty() || missing.size() > kUsed || set.symbolMax < 2) return;
        int n = set.n;
        int k = kUsed;
        if (n + k > 256) return;
        int size = set.symbolMax;
        byte[][] shards = new byte[n + k][];
        for (int i = 0; i < n; ++i) {
            byte[] s = set.data.get(i);
            if (s == null) continue;
            if (!set.orig.contains(i) && !set.recov.contains(i)) continue;
            byte[] row = new byte[size];
            System.arraycopy(s, 0, row, 0, Math.min(s.length, size));
            shards[i] = row;
        }
        for (int r = 0; r < k; ++r) {
            int idx = n + r;
            byte[] s = set.parity.get(idx);
            if (s == null) continue;
            byte[] row = new byte[size];
            System.arraycopy(s, 0, row, 0, Math.min(s.length, size));
            shards[idx] = row;
        }
        ++set.decodeAttempts;
        ++counters.decodeAttempts;
        byte[][] recovered = Rs.rsDecode(shards, n, k, size);
        if (recovered == null) return;
        for (int i : missing) {
            byte[] s = recovered[i];
            if (s == null || s.length != size) {
                ++counters.badRecon;
                continue;
            }
            // len 自校验：声明长度落在 [2, size] 且尾部补零全为 0。
            int declared = Wire.getLe16(s, 0);
            boolean ok = declared >= 2 && declared <= size;
            if (ok) {
                for (int b = declared; b < size; ++b) {
                    if (s[b] != 0) {
                        ok = false;
                        break;
                    }
                }
            }
            if (!ok) {
                ++counters.badRecon;
                continue;
            }
            set.recov.add(i);
            storeRecovered(set, i, s);
            long repairMs = Math.min(0xffff, Math.max(0, nowMs - set.tFirstMs));
            boolean late = set.accounted;
            if (late) ++counters.recoveredLate;
            else ++counters.recovered;
            ++counters.dataDelivered;
            emit("recovered", set.setId, repairMs);
            deliverFn.onPayload(Arrays.copyOfRange(s, 2, declared), true, late);
        }
    }

    private RxSet getOrCreate(int setId, long nowMs) {
        RxSet found = sets.get(setId);
        if (found != null) return found;
        if (sets.size() >= MAX_ACTIVE_SETS) {
            Integer victim = null;
            for (Map.Entry<Integer, RxSet> e : sets.entrySet()) {
                if (!e.getValue().accounted) {
                    victim = e.getKey();
                    break;
                }
            }
            if (victim == null) {
                for (Integer id : sets.keySet()) {
                    victim = id;
                    break;
                }
            }
            if (victim == null) return null;
            RxSet victimSet = sets.get(victim);
            if (victimSet != null) {
                symbolBytes -= setBytes(victimSet);
                if (!victimSet.accounted) {
                    ++counters.setsTailDropped;
                } else {
                    // 已记账集合是最终态：退役其 id，迟到符号不得重建并二次结算
                    //（C++ frame_rx.cc:415 "Evicted after accounting"）。仅做 1 s
                    // 启发式判定的 tail-dropped 集合刻意不退役：迟到 parity 仍可
                    // 合法重建它（frame.ts:570-579）。
                    retired.add(victim);
                    pruneRetired();
                }
            }
            sets.remove(victim);
            accountBoundary.remove(victim);
        }
        RxSet set = new RxSet();
        set.setId = setId;
        set.tFirstMs = nowMs;
        sets.put(setId, set);
        return set;
    }

    /** set_id 跳变处创建空隙占位集合（frame.ts:594-607 createPlaceholders）。 */
    private void createPlaceholders(int first, int last, long nowMs) {
        int gap = last - first; // 调用点已由半窗比较保证 last 在 first 之前方
        if (gap == 0 || gap > MAX_GAP_PLACEHOLDERS || sets.size() + gap >= MAX_ACTIVE_SETS) return;
        for (int id = first; id != last; id = id + 1) { // int 加法回绕与 u32 一致
            if (sets.containsKey(id)) continue;
            RxSet set = new RxSet();
            set.setId = id;
            set.tFirstMs = nowMs;
            sets.put(id, set);
        }
    }

    private void pruneRetired() {
        // TS 遍历快照删除；Java 收集后统一移除。
        List<Integer> doomed = null;
        for (Integer id : retired) {
            int behind = anchor - id;
            if (behind > MAX_ACTIVE_SETS) {
                if (doomed == null) doomed = new ArrayList<>();
                doomed.add(id);
            }
        }
        if (doomed != null) retired.removeAll(doomed);
    }

    /** 结算已安静的集合（frame.ts:617-633 onTick；settle.cc 的 1 s / 2 s 时钟）。 */
    public void onTick(long nowMs) {
        List<Integer> ids = new ArrayList<>(sets.keySet());
        for (Integer id : ids) {
            RxSet set = sets.get(id);
            if (set == null) continue;
            int boundary = set.hasAnySymbol ? (set.nKnown ? set.n : set.maxDataIndex + 1) : 0;
            if (!set.accounted && nowMs - set.tFirstMs >= SETTLE_AFTER_MS) {
                set.accounted = true;
                accountBoundary.put(id, boundary);
                accountSet(set);
                emit("accounted", id, -1);
            }
            if (nowMs - set.tFirstMs >= RETIRE_AFTER_MS) {
                symbolBytes -= setBytes(set);
                if (set.accounted) {
                    retired.add(id);
                    pruneRetired();
                }
                sets.remove(id);
                accountBoundary.remove(id);
            }
        }
    }

    /**
     * 把一个结算完成的集合计入累计计数器（frame.ts:641-679 accountSet；
     * C++ FcpSettle::account）。data_rx_orig / parity_rx 按结算后的码长统计，
     * 让周期的分子分母描述同一批组。
     */
    private void accountSet(RxSet set) {
        if (!set.hasAnySymbol) {
            // 空隙占位：整组从未产生符号（只以 set_id 跳变可见）。C++ settle.cc:127
            // 计 sets_k_unknown，不是 tail drop（那是"有 data 无 parity"的 1 s 启发式）。
            ++counters.setsKUnknown;
            return;
        }
        // 单调键先推进：即使这个集合被下面判成尾巴丢弃，它也已经被结算过了，
        // 迟到的符号不得再让它进入结算（frame.ts:663-666）。
        if (!haveAccounted || Seq.seqAfter(set.setId, accountedThrough)) {
            accountedThrough = set.setId;
            haveAccounted = true;
        }
        // 结算钟响时只有 data、始终没有 parity 声明的集合是不完整的尾巴：它没有
        // n，只能按 maxDataIndex+1 猜一个码长，计进 setsExpected/dataExpected 会
        // 把控制器的分母撑大（frame.ts:667-672）。k 未知的集合不走这条：
        // 那连组大小都没有依据（空隙占位在上面已单列）。
        if (!set.nKnown && set.kKnown && set.k > 0) {
            ++counters.setsTailDropped;
            return;
        }
        int nUsed = set.nKnown ? set.n : set.maxDataIndex + 1;
        int orig = 0;
        int recov = 0;
        for (int i = 0; i < nUsed; ++i) {
            if (set.orig.contains(i)) ++orig;
            if (set.recov.contains(i)) ++recov;
        }
        ++counters.setsExpected;
        counters.dataExpected += nUsed;
        counters.dataRxOrig += orig;
        counters.parityRx += set.parity.size();
        if (set.kKnown && set.k > 0) counters.parityExpected += set.k;
        if (orig + recov >= nUsed) ++counters.setsFull;
        // C++ 语义："partial" 是短码（D 个之前就 flush），不是未修复组，
        // 因此 setsFull/setsPartial 交叠。标尺是本集合声明的 d 而非会话上限。
        int dSet = set.dKnown ? set.d : dMax;
        if (nUsed < dSet) ++counters.setsPartial;
        if (set.kKnown && set.k > 0 && set.k <= 7 && nUsed == dSet) {
            ++counters.ledgerGroups;
            counters.ledgerKHist[set.k]++;
            if (orig + recov < nUsed) ++counters.ledgerFailed;
        }
    }

    private static int ceilDiv(int a, int b) {
        return (a + b - 1) / b;
    }
}
