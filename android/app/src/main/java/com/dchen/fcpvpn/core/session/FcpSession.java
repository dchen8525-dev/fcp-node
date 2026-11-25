package com.dchen.fcpvpn.core.session;

import com.dchen.fcpvpn.core.control.AdaptiveFec;
import com.dchen.fcpvpn.core.control.BbrLite;
import com.dchen.fcpvpn.core.control.ControlConstants;
import com.dchen.fcpvpn.core.control.FecstatReporter;
import com.dchen.fcpvpn.core.control.GroupSize;
import com.dchen.fcpvpn.core.crypto.Envelope;
import com.dchen.fcpvpn.core.crypto.FcpKeys;
import com.dchen.fcpvpn.core.crypto.Handshake;
import com.dchen.fcpvpn.core.fec.FecHeader;
import com.dchen.fcpvpn.core.fec.FecstatBlock;
import com.dchen.fcpvpn.core.fec.FrameRx;
import com.dchen.fcpvpn.core.fec.FrameTx;
import com.dchen.fcpvpn.core.stream.Stream;
import com.dchen.fcpvpn.core.stream.StreamCallbacks;
import com.dchen.fcpvpn.core.stream.StreamConfig;
import com.dchen.fcpvpn.core.wire.Bytes;
import com.dchen.fcpvpn.core.wire.Wire;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * FCP v7 会话：密钥两个 epoch、握手、FEC 组帧、FCP-STREAM ARQ、oob 分派与控制面。
 * 移植自 fcp-node src/session/session.ts（保真，客户端优先；PathProbe/prewarm v1 未移植，
 * 客户端不提供 TLV 6 → 探测特性按 TLV 协商自然关闭，线上兼容）。
 *
 * 无 socket 无时钟：宿主传入 nowMs 并驱动 onWire()/onTick()。
 */
public final class FcpSession {

    // ---- 会话级常量（constants.ts 摘录）----
    public static final int NAT_KEEPALIVE_MS = 45000;
    public static final long PEER_ALIVE_GRACE_MS = 3L * 45000;
    /**
     * 换路径后等待对端回音的窗口。正常切换（两端跟随地址漂移）一两秒内就有回音；
     * 等不到说明这条路径黑掉了，尽快关会话让引擎重连，不要干等 135 秒的静默判死。
     */
    public static final long PATH_VERIFY_MS = 10000;
    public static final int HANDSHAKE_SEND_BUDGET = 1 << 16;
    public static final int BOOTSTRAP_PROBES_PER_SECOND = 64;
    public static final int DATA_WIRE_OVERHEAD = 37;
    public static final int DEFAULT_MTU_MIN = 1040;
    public static final int DEFAULT_IP_HEADER_LEN = 20;
    public static final int DEFAULT_PMTU_MAX_MTU = 1500;
    public static final int PMTU_ABSOLUTE_MAX_MTU = 9000;
    public static final int PMTU_PROBE_STEP = 100;
    public static final long PMTU_BACKOFF_MAX_MS = 60000;
    public static final int PMTU_HEADER_LEN = 16;
    public static final int PMTU_TYPE_PROBE = 0;
    public static final int PMTU_TYPE_ACK = 1;
    public static final int DEFAULT_WINDOW_MIN_BYTES = 128 * 1024;
    public static final int DEFAULT_WINDOW_CEILING_BYTES = 1024 * 1024;
    public static final int DEFAULT_WINDOW_MAX_CEILING = 4 * 1024 * 1024;
    public static final int DEFAULT_RCV_BUF_FLOOR_BYTES = 1024 * 1024;
    public static final int RCV_BUF_BDP_FACTOR = 4;
    public static final int WINDOW_BDP_FACTOR = 2;
    public static final int WINDOW_UPDATE_INTERVAL_MS = 250;
    public static final double WINDOW_CHANGE_RATIO = 1.25;
    public static final int SESSION_STREAM_BUDGET_BYTES = 16 * 1024 * 1024;
    public static final int MUX_MAX_STREAMS = 255;
    public static final int MAX_ACK_COPIES = 4;

    private static final byte[] PMTU_MAGIC = "FCP_PMTU".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    private static final byte[] KEEPALIVE_MAGIC = "FCPKAL1\0".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    private static final int KEEPALIVE_LEN = 8;
    /** 对端会应答的最小 PMTU 探测尺寸（session.ts pmtuHandle 的 PROBE 下界）。 */
    private static final int PMTU_MIN_PROBE_MTU = 576;
    /** 窗口内重发回音探针的间隔：探测本身丢了不能被当成"路径不通"。 */
    private static final long PATH_PROBE_RETRY_MS = 1000;

    // ---- 协议内 DNS（oob FCP_DNS1）----
    // 与 fcp-node constants.ts 逐字节对齐：magic8 | type1 | token4 LE | dns payload。
    // 服务端用自身 resolver 解析——与 OPEN(domain) 的解析路径完全一致，
    // 因此不需要额外端口、额外流，也不受客户端本地网络限制。
    private static final byte[] DNS_MAGIC = "FCP_DNS1".getBytes(java.nio.charset.StandardCharsets.US_ASCII);
    private static final int DNS_TYPE_QUERY = 0;
    private static final int DNS_TYPE_RESPONSE = 1;
    private static final int DNS_HDR_LEN = 13;
    /** 与 fcp-node DNS_MAX_PAYLOAD 一致：最小 MTU（1040）的符号预算之内。 */
    private static final int DNS_MAX_PAYLOAD = 900;

    /** 会话配置（SessionConfig 的客户端子集）。 */
    public static final class Config {
        public byte[] psk;
        public byte[] salt;
        public int sendDirection = FcpKeys.DIRECTION_C2S;
        public int recvDirection = FcpKeys.DIRECTION_S2C;
        public int role = FcpHandshake.ROLE_CLIENT;
        public int d = ControlConstants.DEFAULT_D;
        public int p = ControlConstants.DEFAULT_P;
        public int interleave = 1;
        public int ackCopies = 1;
        public boolean keyUpdate = false;
        public boolean ackV2 = true;
        public boolean pmtud = true;
        public int mtu = DEFAULT_MTU_MIN;
        public int ipHdrLen = DEFAULT_IP_HEADER_LEN;
        public int pmtuMaxMtu = DEFAULT_PMTU_MAX_MTU;
        public int initialSrttMs = ControlConstants.DEFAULT_SRTT_MS;
        public int pinnedK = 0;
        public final LogSink log = new LogSink();
        public final DebugSink debug = new DebugSink();
    }

    /** 日志/调试收集（转发给宿主日志系统）。 */
    public static final class LogSink {
        public interface Sink { void log(String line); }
        public Sink sink;
        public void log(String line) {
            if (sink != null) sink.log(line);
        }
    }

    public static final class DebugSink {
        public interface Sink { void debug(String line); }
        public Sink sink;
        public void debug(String line) {
            if (sink != null) sink.debug(line);
        }
    }

    /** 会话回调（SessionCallbacks 子集；mux 服务端的 inboundStream 钩子保留）。 */
    public interface Listener {
        void sendWire(byte[] wire, int symbolType);
        void read(byte[] bytes);
        void closed(String reason);
        default void eof() {}
        default void log(String line) {}
        /** 服务端：收到对端的协议内 DNS 查询（oob FCP_DNS1）。客户端不实现。 */
        default void onDnsQuery(int token, byte[] query) {}
    }

    /** mux 主机钩子（服务器侧：OPEN 到达的入站流；客户端不使用）。 */
    public interface StreamHost {
        StreamCallbacks inboundStream(int sid);
        void streamClosed(int sid, String reason);
    }

    private final Config cfg;
    private final Listener cb;
    private final DebugSink dbg;
    private final Envelope env;
    private final Envelope hsEnv;
    private final FcpHandshake hs;
    private FrameTx.MtuLimits limits;
    private FrameTx tx = null;
    private FrameRx rx = null;
    private final Stream stream;
    private final AdaptiveFec strategy;
    private final BbrLite bbr;
    private final BbrLite sndBbr;
    private final FecstatReporter reporter;
    private boolean configured = false;
    private long nowMs = 0;
    private int groupD;
    private int dMax;
    private int interleave = 1;
    private int ackCopies = 1;
    private long lastDChangeMs = 0;
    private long bootstrapWindowMs = -1;
    private int bootstrapProbes = 0;
    private long lastWireOutMs = 0;
    private long lastPeerInMs = 0;
    private long lastWindowUpdateMs = 0;
    public boolean resetByPeer = false;
    public int authFail = 0;
    public int structFail = 0;
    public long dataTx = 0;
    public long dataRx = 0;
    private int pmtuToken;
    private int pmtuMtu;
    private int pmtuMaxMtu;
    private long pmtuLastProbeMs = 0;
    private int pmtuProbesSent = 0;
    private int pmtuProbesLost = 0;
    private int pmtuAckedMtu;
    private long pmtuBackoffMs = 0;
    private boolean pmtuCeilingLogged = false;
    private int pmtuStartMtu;
    private int pmtuCeiling = 0;
    private final List<Integer> pmtuPending = new ArrayList<>();
    /** 换路径后的回音窗口：路径一变上膛，换网后发出的探测被应答才解除，超时判死。 */
    private final PathVerifyWindow pathVerify = new PathVerifyWindow(PATH_VERIFY_MS);
    /** 最近一次回音探针的发出时刻（窗口内每秒重发一枚）。 */
    private long pathProbeLastMs = 0;
    /** 本次会话累计发出的回音探针数（诊断/测试观察）。 */
    private int pathProbeSent = 0;
    private int rxSymbolMax = 65535;
    private boolean closeNotified = false;
    private boolean mux = false;
    private final Map<Integer, Stream> streams = new LinkedHashMap<>();
    private StreamHost streamHost = null;
    /** 在途的协议内 DNS 查询：token → 等待者。线程安全（任意线程注册，引擎线程投递）。 */
    private final java.util.concurrent.ConcurrentHashMap<Integer, PendingDns> dnsPending =
            new java.util.concurrent.ConcurrentHashMap<>();
    private final java.util.concurrent.atomic.AtomicInteger dnsToken =
            new java.util.concurrent.atomic.AtomicInteger(1);
    private final String tag;
    private final SecureRandom random = new SecureRandom();

    public FcpSession(Config cfg, Listener listener) {
        this.cfg = cfg;
        this.cb = listener;
        this.dbg = cfg.debug;
        this.tag = hex(cfg.salt).substring(0, Math.min(8, hex(cfg.salt).length()));
        this.streamHost = null;
        this.pinnedInternal(cfg.pinnedK);
        int ipHdrLen = cfg.ipHdrLen;
        pmtuMaxMtu = Math.min(cfg.pmtuMaxMtu, PMTU_ABSOLUTE_MAX_MTU);
        int mtu = Math.min(cfg.mtu, pmtuMaxMtu);
        this.limits = FrameTx.computeMtuLimits(mtu, ipHdrLen);
        this.pmtuMtu = mtu;
        this.pmtuAckedMtu = mtu;
        this.pmtuStartMtu = mtu;
        FrameTx.MtuLimits rxLimits = FrameTx.computeMtuLimits(pmtuMaxMtu, ipHdrLen);
        this.rxSymbolMax = rxLimits.valid ? rxLimits.symbolMax : PMTU_ABSOLUTE_MAX_MTU;
        this.pmtuToken = random.nextInt();

        this.env = new Envelope(cfg.psk, cfg.salt, cfg.sendDirection, cfg.recvDirection);
        this.hsEnv = new Envelope(cfg.psk, cfg.salt, cfg.sendDirection, cfg.recvDirection);
        this.hsEnv.initBootstrapNonce(HANDSHAKE_SEND_BUDGET);

        this.groupD = cfg.d;
        this.dMax = cfg.d;
        this.strategy = new AdaptiveFec(cfg.d, cfg.p, cfg.pinnedK, null);
        this.bbr = new BbrLite(cfg.initialSrttMs, null);
        this.sndBbr = new BbrLite(cfg.initialSrttMs, null);
        this.reporter = new FecstatReporter(cfg.salt, cfg.recvDirection);

        int flags = Handshake.LOCAL_FLAGS_M1;
        if (cfg.pmtud) flags |= Handshake.CAP_PMTUD;
        this.hs = new FcpHandshake(cfg.role, cfg.d, cfg.p, flags, msg -> sendOob(msg, true));

        this.stream = new Stream(streamConfig(limits.payloadMax), new StreamCallbacks() {
            @Override
            public void send(byte[] seg) {
                sendStreamSegment(0, seg);
            }

            @Override
            public void read(byte[] bytes) {
                bbr.onDelivery(bytes.length, nowMs);
                cb.read(bytes);
            }

            @Override
            public void closed(String reason) {
                // mux 下默认流可空闲退出而 sid 流仍活着；只有默认流关闭且没有
                // 存活的 sid 流才结束会话。
                if (mux && !streams.isEmpty()) {
                    dbg.debug("[" + tag() + "] default stream closed (" + reason + ") with live sid streams; session stays");
                    return;
                }
                notifyClosed(reason);
            }

            @Override
            public void eof() {
                if (mux && !streams.isEmpty()) return;
                cb.eof();
            }

            @Override
            public void rtt(double ms) {
                bbr.onRtt(ms);
                sndBbr.onRtt(ms);
                if (tx != null) tx.setSrttMs((long) ms);
            }

            @Override
            public void acked(long bytes, long nowMs) {
                sndBbr.onDelivery(bytes, nowMs);
            }
        });
    }

    private static StreamConfig streamConfig(int maxSegment) {
        StreamConfig sc = new StreamConfig(maxSegment);
        sc.initialSrttMs = ControlConstants.DEFAULT_SRTT_MS;
        return sc;
    }

    private void pinnedInternal(int pinnedK) {
        // pinnedK 只进控制器；这里保留占位以便与 TS 字段一一对应。
    }

    private String tag() {
        return tag;
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    public boolean isClosed() { return closeNotified; }
    /**
     * 已关闭的会话不算"已建立"。握手对象在关闭后仍停留在 established 状态，
     * 只看 hs 会让引擎在会话刚死掉的那一 tick 又把它记回"已建立"，把死亡计数
     * 抵消掉——池里 4 条全灭时引擎就永远判不出断链，重连也就不会发生。
     */
    public boolean isEstablished() { return hs.isEstablished() && !closeNotified; }
    public boolean isMuxActive() { return mux; }
    public int currentK() { return strategy.currentK(); }
    public int getGroupD() { return groupD; }
    public Stream streamRef() { return stream; }
    public double srttMs() { return bbr.srttMs; }
    public double fecLoss() { return strategy.currentLoss(); }

    private void notifyClosed(String reason) {
        if (closeNotified) return;
        closeNotified = true;
        env.destroy();
        hsEnv.destroy();
        cb.closed(reason);
    }

    /**
     * 主动关闭（引擎停机）。走与对端断开相同的清理路径：销毁密钥并回调 closed，
     * 让宿主释放 sid 流与本地连接——否则停机后调用方只能等各自的超时。
     */
    public void closeNow(String reason) {
        notifyClosed(reason);
    }

    /**
     * 底层网络路径变了（宿主在 ConnectivityManager 回调里触发，必须在引擎线程上调用）。
     *
     * <p>客户端 socket 不重连，所以这里要主动做两件事：</p>
     * <ol>
     *   <li>立刻发一次认证保活：让服务端把回程地址改到新源地址（它只跟随认证报文），
     *       不必等最多 45 秒的空闲保活；</li>
     *   <li>路径确实换了（{@code reset}）时把 PMTU 打回起点重测，并上膛回音窗口：
     *       新路径的 MTU 可能更小，沿用旧值会整段黑洞；窗口则用"换网后发出的
     *       PMTU 探测有没有被应答"判断这条路径通不通。</li>
     * </ol>
     *
     * @param reset true = 网络上下线（Wi-Fi↔蜂窝），需要重测 MTU；false = 只是能力
     *              变化（带宽提示之类），做一次轻量探测即可。
     */
    public void onPathChanged(long nowMs, boolean reset) {
        if (closeNotified || resetByPeer || !hs.isEstablished()) return;
        boolean probing = reset && cfg.pmtud && pmtuStartMtu >= PMTU_MIN_PROBE_MTU;
        if (probing) {
            // 顺序不能变：重置（同时轮换 token）→ 上膛 → 发探测。宿主 sendWire 可能
            // 同步重入 onWire，应答必须落在已经上膛的窗口里；而 token 必须在发出
            // 探测之前轮换，换网前发出的探测的 ACK 才不会被当成新路径的回音。
            pmtuResetForNewPath();
            pathVerify.arm(nowMs);
            sendPathProbe(nowMs);
        }
        sendOob(KEEPALIVE_MAGIC);
        if (!reset) return;
        // 没有 PMTUD（或起点低于对端会应答的最小探测尺寸）就没有可靠的路径回音：
        // 保活是单向的、对端不回，此时退回 135 秒的静默判死，别拿一个等不到的回音
        // 把好会话误杀。日志只看"有没有探测"——宿主可能同步回了音，窗口此刻已经
        // 解除，用 armed() 判断会打出相反的话。
        if (probing) {
            cb.log("FCP path changed: PMTU reset to " + pmtuStartMtu + "B, probing new path");
        } else {
            cb.log("FCP path changed: no path echo available, relying on the idle timeout");
        }
    }

    /** 当前发送侧 MTU（换路径后会回到起点重测）；供日志与测试观察。 */
    public int currentMtu() {
        return pmtuMtu;
    }

    /** 是否仍在等待新路径的回音；引擎在窗口期间冻结未验证的对端地址。 */
    boolean isPathVerifyArmed() {
        return pathVerify.armed();
    }

    /** 回音前后都冻结未验证地址，直到本次换路径窗口结束。 */
    boolean isPathAddressFrozen(long nowMs) {
        return pathVerify.addressFrozen(nowMs);
    }

    /** 当前回音探测的 token（换网时轮换）；供引擎日志与测试观察。 */
    int pathProbeToken() {
        return pmtuToken;
    }

    /** 换路径后已发出的回音探针数（窗口内每秒补一枚）。 */
    int pathProbesSent() {
        return pathProbeSent;
    }

    /** 发起握手（返回 false = 配置非法）。 */
    public boolean start(long nowMs) {
        this.nowMs = nowMs;
        if (!limits.valid) {
            cb.log("FCP config invalid: MTU leaves no room for a data symbol");
            return false;
        }
        int d = cfg.d;
        int p = cfg.p;
        if (d < 1 || d > 256 || p < 0 || p > 7 || d + p > 256) return false;
        if (hs.isFailed()) {
            cb.log("FCP handshake refused: error=" + hs.getError());
            return false;
        }
        List<Handshake.Tlv> tlvs = new ArrayList<>();
        if (cfg.ackV2) tlvs.add(new Handshake.Tlv(Handshake.TLV_TYPE_ACK_V2, new byte[0]));
        // 广告而非假设：不协商就对滚密钥，对端还在用会话密钥解密 → 静默死亡。
        if (cfg.keyUpdate) tlvs.add(new Handshake.Tlv(Handshake.TLV_TYPE_KEY_UPDATE, new byte[0]));
        // M1 恒提供：对端不回显则保持单流线格式（sid 分帧只在双端提供时启用）。
        tlvs.add(new Handshake.Tlv(Handshake.TLV_TYPE_MULTIPLEX, new byte[0]));
        // v1 不提供 TLV 6（PathProbe 未移植）：双端协商关掉该特性即线上兼容。
        hs.setLocalTlvs(tlvs);
        hs.start(nowMs);
        return true;
    }

    /**
     * 喂一个 UDP 数据报。返回 false = 认证失败。
     *
     * <p>换路径的回音判定不依赖来源地址：它由 {@link #sendPathProbe} 发出探测、
     * 在 PMTU ACK 分支里凭换网时轮换的 token 识别（见 {@link #pmtuHandle}）。</p>
     */
    public boolean onWire(byte[] wire, long nowMs) {
        this.nowMs = nowMs;
        if (closeNotified) return false;
        // 无状态复位按形状先判：它用 bootstrap 密钥封装，同时也是合法的 bootstrap
        // 信封。env.open() 之后再判会漏掉（rekey 前）能解密的情形。
        if (!resetByPeer && wire.length == Envelope.ENVELOPE_OVERHEAD + Envelope.RESET_MAGIC_LEN
                && hsEnv.openReset(wire) != null) {
            resetByPeer = true;
            cb.log("FCP stateless reset: the peer has no session for this salt");
            notifyClosed("stateless_reset");
            return true;
        }
        byte[] plain = env.open(wire);
        boolean bootstrap = false;
        if (plain == null) {
            boolean mayProbe = true;
            if (hs.isEstablished()) {
                if (bootstrapWindowMs < 0 || nowMs - bootstrapWindowMs >= 1000) {
                    bootstrapWindowMs = nowMs;
                    bootstrapProbes = 0;
                }
                mayProbe = bootstrapProbes < BOOTSTRAP_PROBES_PER_SECOND;
                if (mayProbe) ++bootstrapProbes;
            }
            if (mayProbe) {
                plain = hsEnv.open(wire);
                bootstrap = plain != null;
            }
        }
        if (plain == null) {
            ++authFail;
            reporter.noteAuthFail();
            dbg.debug("[" + tag() + "] wire rx " + wire.length + "B REJECT auth-fail");
            return false;
        }
        lastPeerInMs = nowMs;
        if (bootstrap) {
            onWireBootstrap(plain, nowMs);
            return true;
        }
        return onWireData(plain, nowMs, wire.length);
    }

    private void onWireBootstrap(byte[] plain, long nowMs) {
        if (plain.length < FecHeader.FEC_HDR_LEN) {
            ++structFail;
            return;
        }
        FecHeader.FecHdr hdr = FecHeader.parseHdr(plain);
        byte[] symbol = java.util.Arrays.copyOfRange(plain, FecHeader.FEC_HDR_LEN, plain.length);
        if (hdr != null && FecHeader.hdrType(hdr.typeK) == FecHeader.TYPE_OOB
                && (Handshake.isHello(symbol) || Handshake.isHelloAck(symbol))) {
            onOob(symbol, nowMs);
        } else {
            ++structFail;
        }
    }

    private boolean onWireData(byte[] plain, long nowMs, int wireLen) {
        FecHeader.FecHdr hdr = FecHeader.parseHdr(plain);
        if (hdr != null) {
            int type = FecHeader.hdrType(hdr.typeK);
            if (type == FecHeader.TYPE_DATA) {
                dataRx += Math.max(0, wireLen - DATA_WIRE_OVERHEAD);
                reporter.addDataBytes(wireLen);
            } else if (type == FecHeader.TYPE_PARITY) {
                reporter.addParityBytes(wireLen);
            }
        }
        if (rx != null) {
            rx.onDatagram(plain, nowMs);
            return true;
        }
        // 协商前只有 oob 可行动；入站数据不得回显进握手缓存。
        if (hdr != null && FecHeader.hdrType(hdr.typeK) == FecHeader.TYPE_OOB) {
            onOob(java.util.Arrays.copyOfRange(plain, FecHeader.FEC_HDR_LEN, plain.length), nowMs);
        } else {
            ++structFail;
            reporter.noteStructFail();
        }
        return true;
    }

    private void onOob(byte[] payload, long nowMs) {
        if (payload.length == KEEPALIVE_LEN && Bytes.bytesEqual(KEEPALIVE_MAGIC, payload)) {
            return;
        }
        if (payload.length == KEEPALIVE_LEN && Bytes.bytesEqual(Envelope.RESET_MAGIC, payload)) {
            if (!resetByPeer) {
                resetByPeer = true;
                cb.log("FCP stateless reset: the peer has no session for this salt");
                notifyClosed("stateless_reset");
            }
            return;
        }
        if (dispatchHandshake(payload, nowMs)) return;
        if (dispatchDns(payload)) return;
        if (isPmtuFrame(payload) && pmtuHandle(payload, nowMs)) return;
        handleFecstat(payload, nowMs);
    }

    /** oob DNS 分派：查询交给宿主（服务端），应答唤醒等待者（客户端）。 */
    private boolean dispatchDns(byte[] payload) {
        if (payload.length < DNS_HDR_LEN) return false;
        if (!Bytes.bytesEqual(DNS_MAGIC, payload, DNS_MAGIC.length)) return false;
        int type = payload[8] & 0xff;
        int token = Wire.getLe32(payload, 9);
        byte[] body = java.util.Arrays.copyOfRange(payload, DNS_HDR_LEN, payload.length);
        if (type == DNS_TYPE_QUERY) {
            if (body.length == 0 || body.length > DNS_MAX_PAYLOAD) return true;
            cb.onDnsQuery(token, body);
            return true;
        }
        if (type == DNS_TYPE_RESPONSE) {
            PendingDns p = dnsPending.remove(token);
            if (p != null) {
                p.answer = body;
                p.latch.countDown();
            }
            return true;
        }
        ++structFail;
        return true;
    }

    /** 一次在途 DNS 查询：应答由 dispatchDns 落进来。 */
    private static final class PendingDns {
        final java.util.concurrent.CountDownLatch latch =
                new java.util.concurrent.CountDownLatch(1);
        volatile byte[] answer;
    }

    /**
     * 请求服务端解析 DNS 报文（协议内 oob）。
     *
     * 线程模型：本方法可从任意线程调用，但**发包必须由引擎线程执行**
     * （FcpSession 单写者），因此 {@code engineThread} 用于提交发送动作；
     * 等待在调用线程上进行，不会与引擎线程互相阻塞。
     *
     * @return 原始 DNS 应答；超时/不可发送返回 null
     */
    public byte[] queryDns(byte[] query, long timeoutMs, java.util.concurrent.Executor engineThread) {
        // 握手未完成时数据面密钥还没派生：发出去也只会被对端当未知 oob 丢弃，
        // 白白让调用方等满超时。
        if (closeNotified || !hs.isEstablished()
                || query.length == 0 || query.length > DNS_MAX_PAYLOAD) {
            return null;
        }
        final int token = dnsToken.getAndIncrement();
        final PendingDns pending = new PendingDns();
        dnsPending.put(token, pending);
        final byte[] msg = new byte[DNS_HDR_LEN + query.length];
        System.arraycopy(DNS_MAGIC, 0, msg, 0, DNS_MAGIC.length);
        msg[8] = (byte) DNS_TYPE_QUERY;
        Wire.putLe32(token, msg, 9);
        System.arraycopy(query, 0, msg, DNS_HDR_LEN, query.length);
        engineThread.execute(() -> sendOob(msg));
        try {
            if (!pending.latch.await(timeoutMs, java.util.concurrent.TimeUnit.MILLISECONDS)) {
                dnsPending.remove(token);
                return null;
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            dnsPending.remove(token);
            return null;
        }
        return pending.answer;
    }

    /** 服务端：回答一条查询（引擎线程调用）。 */
    public boolean sendDnsResponse(int token, byte[] answer) {
        if (closeNotified || answer.length == 0 || answer.length > DNS_MAX_PAYLOAD) return false;
        byte[] msg = new byte[DNS_HDR_LEN + answer.length];
        System.arraycopy(DNS_MAGIC, 0, msg, 0, DNS_MAGIC.length);
        msg[8] = (byte) DNS_TYPE_RESPONSE;
        Wire.putLe32(token, msg, 9);
        System.arraycopy(answer, 0, msg, DNS_HDR_LEN, answer.length);
        sendOob(msg);
        return true;
    }

    private boolean dispatchHandshake(byte[] payload, long nowMs) {
        if (payload.length < 36 || (!Handshake.isHello(payload) && !Handshake.isHelloAck(payload))) {
            return false;
        }
        int status = hs.onOob(payload, nowMs);
        if (status == FcpHandshake.PROTOCOL_FAILURE) {
            cb.log("FCP handshake failed: error=" + hs.getError());
            notifyClosed("handshake_failure");
        }
        if (hs.isEstablished() && !configured) configure(nowMs);
        return true;
    }

    private void configure(long nowMs) {
        Handshake.Negotiated np = hs.params;
        byte[] sessionKey = FcpKeys.deriveSessionKeyV7(cfg.psk, cfg.salt,
                hs.getClientNonce(), hs.getServerNonce());
        env.rekey(sessionKey);
        env.setKeyUpdate(hs.tlvAgreed(Handshake.TLV_TYPE_KEY_UPDATE));
        mux = hs.tlvAgreed(Handshake.TLV_TYPE_MULTIPLEX);
        // 1 字节 sid 前缀占用符号负载，每流必须比 payloadMax 少切 1 字节，
        // 否则 FrameTx 会把满尺寸段按超尺寸丢弃。
        stream.setMaxSegment(mux ? limits.payloadMax - 1 : limits.payloadMax);
        dMax = np.d;
        groupD = np.d;
        interleave = Math.max(1, Math.min(ControlConstants.MAX_INTERLEAVE, cfg.interleave));
        tx = new FrameTx(np.d, limits, wire -> emitWire(wire, false));
        tx.setInterleave(interleave);
        tx.setSrttMs((long) bbr.srttMs);
        // 跟随协商出的 parity（对端可能提供更低的 P）。
        strategy.setParityCeiling(np.p);
        strategy.setGroupSize(np.d);
        tx.setK(strategy.currentK());
        boolean ackV2 = hs.tlvAgreed(Handshake.TLV_TYPE_ACK_V2);
        ackCopies = ackV2 ? Math.max(1, Math.min(MAX_ACK_COPIES, cfg.ackCopies)) : 1;
        rx = new FrameRx(np.d, np.p,
                (bytes, recovered, late) -> deliverStreamFrame(bytes),
                (msg, t) -> onOob(msg, t),
                null,
                rxSymbolMax);
        stream.setAckV2(ackV2);
        configured = true;
        cb.log("FCP established: D=" + np.d + " P=" + np.p + " L=" + interleave
                + " ackCopies=" + ackCopies + " ackv2=" + ackV2
                + " mtu=" + pmtuMtu + (cfg.pmtud ? "->" + pmtuMaxMtu + " (pmtud)" : " (fixed)")
                + " payloadMax=" + limits.payloadMax);
        // 建立前排队的数据按未分帧缓存（mux 未知）；直接回放会把流类型放到
        // offset 0，mux 对端会把它读成 sid 字节路由到幻影 sid —— 先补 sid 前缀。
        for (byte[] seg : hs.takeCachedData()) {
            tx.onSegment(mux ? frameSid(0, seg) : seg, nowMs);
        }
    }

    private void handleFecstat(byte[] payload, long nowMs) {
        FecstatBlock.Decoded r = FecstatBlock.decodeFecstat(payload, cfg.salt);
        if (r.status == FecstatBlock.DUPLICATE) return;
        if (r.status != FecstatBlock.OK || r.packet == null) {
            if (r.status == FecstatBlock.STALE) {
                // stale 只计诊断
            }
            return;
        }
        strategy.onFecstat(r.packet, nowMs);
        if (tx != null) tx.setK(strategy.currentK());
    }

    private boolean isPmtuFrame(byte[] payload) {
        return payload.length >= PMTU_MAGIC.length && Bytes.bytesEqual(PMTU_MAGIC, payload, PMTU_MAGIC.length);
    }

    private boolean pmtuHandle(byte[] payload, long nowMs) {
        if (payload.length < PMTU_HEADER_LEN) return false;
        int type = payload[8] & 0xff;
        int token = Wire.getLe32(payload, 10);
        int mtu = Wire.getLe16(payload, 14);
        if (type == PMTU_TYPE_ACK) {
            // 换路径的回音判定：token 在换网时轮换过（pmtuResetForNewPath），所以
            // 带着当前 token 回来的 ACK 只可能是对"换网后我们发出的探测"的应答
            // ——它证明新路径的上行与下行都通了。普通数据/保活做不到这一点：
            // 它们可能只是换网前就在途的旧路径报文。
            if (token == pmtuToken && pathVerify.armed()) {
                pathVerify.noteInbound();
                cb.log("FCP path verified: peer answered the post-change probe (" + mtu + "B)");
            }
            // ACK 命名超过自身上限的尺寸必须钳位：否则恶意对端能把发送预算
            // 吹到 65KB 数据报 → 每次 send EMSGSIZE，探测步进永久卡死。
            if (token == pmtuToken && mtu > pmtuAckedMtu && mtu <= pmtuMaxMtu) {
                pmtuAckedMtu = mtu;
                pmtuMtu = mtu;
                pmtuProbesLost = 0;
                pmtuBackoffMs = 0;
                if (pmtuCeiling > 0 && mtu >= pmtuCeiling) pmtuCeiling = 0;
                pmtuPending.removeIf(t -> t <= mtu);
                applyPmtuMtu(mtu);
                if (mtu >= pmtuMaxMtu && !pmtuCeilingLogged) {
                    pmtuCeilingLogged = true;
                    cb.log("FCP PMTUD: path carries " + mtu + "B (ceiling reached, started at "
                            + pmtuStartMtu + "B)");
                }
            }
            return true;
        }
        if (type != PMTU_TYPE_PROBE || mtu > pmtuMaxMtu || mtu < 576) return true;
        // 探测数据报加上 IP/UDP 头后恰为 mtu 字节 → 路径确实承载该尺寸。
        // 用相同 token 应答——无论我们自己的探索走到哪一步，否则两端同时
        // 探测会互相把对方的探测敲掉。
        byte[] ack = new byte[PMTU_HEADER_LEN];
        System.arraycopy(PMTU_MAGIC, 0, ack, 0, PMTU_MAGIC.length);
        ack[8] = PMTU_TYPE_ACK;
        ack[9] = 0;
        Wire.putLe32(token, ack, 10);
        Wire.putLe16(mtu, ack, 14);
        sendOob(ack);
        return true;
    }

    private void applyPmtuMtu(int mtu) {
        FrameTx.MtuLimits l = FrameTx.computeMtuLimits(mtu, cfg.ipHdrLen);
        if (!l.valid) return;
        boolean up = mtu > limits.mtu;
        limits = l;
        if (up) tx.raiseLimits(l);
        else tx.lowerLimits(l);
        stream.setMaxSegment(l.payloadMax - (mux ? 1 : 0));
        if (mux) {
            for (Stream st : streams.values()) st.setMaxSegment(l.payloadMax - 1);
        }
    }

    /**
     * 换路径后把 PMTU 打回起点重新爬。旧上限是按旧路径测出来的，新路径更小时
     * 沿用它等于整段黑洞；而 pmtuCeiling 一旦"到顶"就不再探测，所以必须清零。
     * 与新建会话的初始状态一致，另外两处是换路径专有的：
     * <ul>
     *   <li>pmtuLastProbeMs 归零，让下一 tick 立刻发出第一枚探测；</li>
     *   <li>token 轮换，使换网前发出的探测的 ACK 无法冒充新路径的回音。</li>
     * </ul>
     */
    private void pmtuResetForNewPath() {
        if (!cfg.pmtud) return;
        pmtuMtu = pmtuStartMtu;
        pmtuAckedMtu = pmtuStartMtu;
        pmtuCeiling = 0;
        pmtuCeilingLogged = false;
        pmtuProbesSent = 0;
        pmtuProbesLost = 0;
        pmtuBackoffMs = 0;
        pmtuPending.clear();
        pmtuLastProbeMs = 0;
        pmtuToken = random.nextInt();
        applyPmtuMtu(pmtuStartMtu);
    }

    /**
     * 换路径后的回音探针：用换网时刚轮换的 token 发一枚 PMTU PROBE。
     *
     * <p>对端对任何合法探测都无条件应答（session.ts pmtuHandle 的 PROBE 分支只校验
     * 尺寸，不校验 token），所以收到同 token 的 ACK 就证明"我们换网后发出的报文走到了
     * 对端并原路返回"。这是普通数据报文给不了的证据——它们可能只是换网前就在途的
     * 旧路径报文，先到的那一枚会把窗口误判成通。</p>
     *
     * <p>窗口内由 {@code onTick} 每秒重发一枚：探测或 ACK 本身丢了，不应该被当成
     * "路径不通"。</p>
     */
    private void sendPathProbe(long nowMs) {
        int target = pmtuStartMtu;
        int len = FrameTx.pmtuProbeLen(target, cfg.ipHdrLen);
        if (len < PMTU_HEADER_LEN) return;
        byte[] msg = new byte[len];
        System.arraycopy(PMTU_MAGIC, 0, msg, 0, PMTU_MAGIC.length);
        msg[8] = PMTU_TYPE_PROBE;
        msg[9] = 0;
        Wire.putLe32(pmtuToken, msg, 10);
        Wire.putLe16(target, msg, 14);
        pathProbeLastMs = nowMs;
        ++pathProbeSent;
        sendOob(msg);
    }

    private void sendPmtuProbe(long nowMs) {
        if (!cfg.pmtud) return;
        long gap = Math.max(1000, (long) (5 * bbr.srttMs)) + pmtuBackoffMs;
        if (nowMs - pmtuLastProbeMs < gap) return;
        // 下一个探测发出时仍未被应答的待定探测即超时（它现在这个还没机会被应答，
        // 不计为丢失）。
        if (!pmtuPending.isEmpty()) {
            int timedOut = pmtuPending.remove(0);
            if (++pmtuProbesLost >= 3) {
                pmtuProbesLost = 0;
                pmtuBackoffMs = Math.min(PMTU_BACKOFF_MAX_MS,
                        Math.max(1000, pmtuBackoffMs * 2));
                // 上限是路径被怀疑承载不了的最小尺寸。
                if (pmtuCeiling == 0 || timedOut < pmtuCeiling) pmtuCeiling = timedOut;
                if (pmtuMtu != pmtuAckedMtu) {
                    pmtuMtu = pmtuAckedMtu;
                    applyPmtuMtu(pmtuMtu);
                }
            }
        }
        // 已到已证实上限一步以内：继续探测只是烧数据报。
        if (pmtuCeiling > 0 && pmtuCeiling - pmtuAckedMtu <= PMTU_PROBE_STEP) return;
        int target = pmtuCeiling > 0
                ? (pmtuAckedMtu + pmtuCeiling) / 2
                : Math.min(pmtuMaxMtu, pmtuMtu + PMTU_PROBE_STEP);
        if (target <= pmtuAckedMtu) return;
        int len = FrameTx.pmtuProbeLen(target, cfg.ipHdrLen);
        if (len < PMTU_HEADER_LEN) return;
        byte[] msg = new byte[len];
        System.arraycopy(PMTU_MAGIC, 0, msg, 0, PMTU_MAGIC.length);
        msg[8] = PMTU_TYPE_PROBE;
        msg[9] = 0;
        Wire.putLe32(pmtuToken, msg, 10);
        Wire.putLe16(target, msg, 14);
        sendOob(msg);
        pmtuLastProbeMs = nowMs;
        ++pmtuProbesSent;
        pmtuPending.add(target);
    }

    /** 每个方向按自己的 BDP 定窗口（发送窗 2×BDP，接收缓冲 4×BDP 且只升不降）。 */
    private void updateStreamWindows(long nowMs) {
        if (nowMs - lastWindowUpdateMs < WINDOW_UPDATE_INTERVAL_MS) return;
        lastWindowUpdateMs = nowMs;
        double srtt = Math.max(1, bbr.srttMs);
        int sendWant = bdpWindow(sndBbr.bwBytesPerMs, stream.getSendWindowBytes(),
                WINDOW_BDP_FACTOR, DEFAULT_WINDOW_MIN_BYTES, srtt);
        int rcvWant = bdpWindow(bbr.bwBytesPerMs, stream.getRcvBufBytes(),
                RCV_BUF_BDP_FACTOR, DEFAULT_RCV_BUF_FLOOR_BYTES, srtt);
        int rcvNext = Math.max(stream.getRcvBufBytes(), rcvWant);
        boolean changed = sendWant != stream.getSendWindowBytes() || rcvNext != stream.getRcvBufBytes();
        if (changed) {
            stream.setWindows(sendWant, rcvNext);
        }
        // 必须在默认流目标未变时也跑：预算挤压把某流的接收窗缩到 1 字节后，
        // 只有这里能把它抬回来。
        if (mux) {
            for (Stream st : streams.values()) st.setWindows(sendWant, rcvNext);
        }
    }

    /** factor × BDP，带比例迟滞避免公告窗口随估计抖动而摆动。 */
    private int bdpWindow(double bwPerMs, int cur, int factor, int floor, double srtt) {
        if (bwPerMs <= 0) return cur;
        double bdp = bwPerMs * srtt;
        int target = (int) Math.min(DEFAULT_WINDOW_CEILING_BYTES,
                Math.max(floor, Math.round(factor * bdp)));
        boolean changed = target > cur * WINDOW_CHANGE_RATIO || target * WINDOW_CHANGE_RATIO < cur;
        return changed ? target : cur;
    }

    private void onStreamSegment(byte[] seg) {
        if (!hs.isEstablished()) {
            hs.cacheData(seg);
            return;
        }
        if (hs.isFailed() || closeNotified) return;
        if (tx == null) return;
        // mux 下每个段（含控制段）带 1 字节 sid 前缀，流类型在 offset 1。
        int kind = mux ? (seg.length > 1 ? seg[1] & 0xff : 0)
                : (seg.length > 0 ? seg[0] & 0xff : 0);
        boolean control = kind == com.dchen.fcpvpn.core.stream.StreamConstants.STREAM_TYPE_ACK
                || kind == com.dchen.fcpvpn.core.stream.StreamConstants.STREAM_TYPE_ACK_V2
                || kind == com.dchen.fcpvpn.core.stream.StreamConstants.STREAM_TYPE_RST;
        tx.onSegment(seg, nowMs, control);
        ++dataTx;
        // ACK 冗余拷贝走数据 lane（interleave 分散 + 共享 parity）；拷贝位告诉
        // 对端不要当成重复 ACK 证据。
        if (kind == com.dchen.fcpvpn.core.stream.StreamConstants.STREAM_TYPE_ACK_V2) {
            for (int i = 1; i < ackCopies; ++i) {
                byte[] copy = markAckCopy(seg);
                if (copy != null) tx.onSegment(copy, nowMs, false);
            }
        }
    }

    /** 复制一条 ACK v2 段并置冗余拷贝位。 */
    private byte[] markAckCopy(byte[] seg) {
        int at = mux ? 1 : 0;
        if (seg.length < at + 10) return null;
        if ((seg[at] & 0xff) != com.dchen.fcpvpn.core.stream.StreamConstants.STREAM_TYPE_ACK_V2) {
            return null;
        }
        byte[] out = java.util.Arrays.copyOf(seg, seg.length);
        out[at + 9] |= com.dchen.fcpvpn.core.stream.StreamConstants.ACK_V2_FLAG_COPY;
        return out;
    }

    /** mux 会话的宿主侧流（客户端：本地连接分配 sid）。 */
    public Stream openStream(int sid, StreamCallbacks cb) {
        if (!mux || sid == 0 || sid > MUX_MAX_STREAMS || streams.containsKey(sid)) return null;
        return makeStream(sid, cb);
    }

    /** 该 sid 是否已被占用（引擎分配空闲 sid 时用）。 */
    public boolean hasStream(int sid) {
        return streams.containsKey(sid);
    }

    private Stream makeStream(int sid, StreamCallbacks cb) {
        StreamConfig sc = streamConfig(limits.payloadMax - (mux ? 1 : 0));
        sc.ackV2 = hs.tlvAgreed(Handshake.TLV_TYPE_ACK_V2);
        Stream st = new Stream(sc, new StreamCallbacks() {
            @Override
            public void send(byte[] seg) {
                sendStreamSegment(sid, seg);
            }

            @Override
            public void read(byte[] bytes) {
                bbr.onDelivery(bytes.length, nowMs);
                cb.read(bytes);
            }

            @Override
            public void closed(String reason) {
                streams.remove(sid);
                cb.closed(reason);
                if (streamHost != null) streamHost.streamClosed(sid, reason);
            }

            @Override
            public void eof() {
                cb.eof();
            }

            @Override
            public void rtt(double ms) {
                bbr.onRtt(ms);
                sndBbr.onRtt(ms);
                if (tx != null) tx.setSrttMs((long) ms);
            }

            @Override
            public void acked(long bytes, long nowMs) {
                sndBbr.onDelivery(bytes, nowMs);
            }
        });
        streams.put(sid, st);
        return st;
    }

    /** 把交付的 DATA 符号负载路由到对应流（mux 前缀 1 字节 sid；旧线格式的全量负载）。 */
    private void deliverStreamFrame(byte[] bytes) {
        if (!mux) {
            stream.onSegment(bytes, nowMs);
            return;
        }
        // 零长符号带不了 sid 字节（FrameRx 可能合法产出声明长度 2 的重建符号）。
        if (bytes.length == 0) {
            ++structFail;
            return;
        }
        int sid = bytes[0] & 0xff;
        Stream st = sid == 0 ? stream : streams.get(sid);
        if (st == null) {
            if (sid == 0) {
                ++structFail;
                return;
            }
            StreamCallbacks host = streamHost != null ? streamHost.inboundStream(sid) : null;
            if (host == null) return;
            st = makeStream(sid, host);
        }
        st.onSegment(java.util.Arrays.copyOfRange(bytes, 1, bytes.length), nowMs);
    }

    private void sendStreamSegment(int sid, byte[] seg) {
        onStreamSegment(mux ? frameSid(sid, seg) : seg);
    }

    private byte[] frameSid(int sid, byte[] seg) {
        byte[] framed = new byte[1 + seg.length];
        framed[0] = (byte) sid;
        System.arraycopy(seg, 0, framed, 1, seg.length);
        return framed;
    }

    /** FrameTx 的 sink 直接给出"7 字节 FEC 头 + 符号"的完整明文数据报；会话层只负责加密。 */
    private void emitWire(byte[] plain, boolean bootstrap) {
        Envelope e = bootstrap ? hsEnv : env;
        byte[] wire = e.seal(plain);
        if (wire == null) {
            cb.log("FCP session exhausted nonce space");
            return;
        }
        lastWireOutMs = nowMs;
        cb.sendWire(wire, FecHeader.hdrType(plain[6]));
    }

    private void sendOob(byte[] msg, boolean bootstrap) {
        byte[] plain = FrameTx.packOobFrame(msg);
        Envelope e = bootstrap ? hsEnv : env;
        byte[] wire = e.seal(plain);
        if (wire == null) return;
        lastWireOutMs = nowMs;
        cb.sendWire(wire, FecHeader.TYPE_OOB);
    }

    private void sendOob(byte[] msg) {
        sendOob(msg, false);
    }

    /** #86：为本 salt 构造带认证的无状态复位数据报（counter 从高位取避免撞握手 nonce）。 */
    public byte[] makeReset() {
        long c = Envelope.NONCE_LIMIT - 1 - random.nextInt(65536);
        return Envelope.sealReset(cfg.psk, cfg.salt, cfg.sendDirection, cfg.recvDirection, c);
    }

    public int write(byte[] data, int off, int len) {
        return stream.write(data, off, len, nowMs);
    }

    public void closeWrite() {
        stream.closeWrite(nowMs);
    }

    public void consumed(int n) {
        stream.consumed(n);
    }

    public int inflightBytes() {
        int total = stream.getInflightBytes();
        for (Stream st : streams.values()) total += st.getInflightBytes();
        return total;
    }

    public int queuedBytes() {
        int total = stream.getPendingQueueBytes();
        for (Stream st : streams.values()) total += st.getPendingQueueBytes();
        return total;
    }

    /** 会话级堆上限：超出预算先裁最重的流的乱序尾部，再饿死超份额的流。 */
    private void enforceStreamBytesBudget() {
        List<long[]> rows = new ArrayList<>();
        List<Stream> rowStreams = new ArrayList<>();
        long total = 0;
        collectBudget(stream, rows, rowStreams);
        for (Stream st : streams.values()) collectBudget(st, rows, rowStreams);
        if (total <= SESSION_STREAM_BUDGET_BYTES) return;
        // 简单选择排序按 bytes 降序（行数极少）
        int n = rows.size();
        for (int i = 0; i < n; ++i) {
            int maxIdx = i;
            for (int j = i + 1; j < n; ++j) {
                if (rows.get(j)[0] > rows.get(maxIdx)[0]) maxIdx = j;
            }
            long[] tmpRow = rows.get(i);
            rows.set(i, rows.get(maxIdx));
            rows.set(maxIdx, tmpRow);
            Stream tmpS = rowStreams.get(i);
            rowStreams.set(i, rowStreams.get(maxIdx));
            rowStreams.set(maxIdx, tmpS);
        }
        long over = total - SESSION_STREAM_BUDGET_BYTES;
        for (int i = 0; i < n && over > 0; ++i) {
            Stream s = rowStreams.get(i);
            long bytes = rows.get(i)[0];
            int reorder = s.getReorderBytes();
            if (reorder <= 0) continue;
            int cut = (int) Math.min(over, reorder);
            s.trimReorderTo(reorder - cut);
            bytes -= cut;
            rows.get(i)[0] = bytes;
            over -= cut;
        }
        if (over > 0) {
            int share = (int) Math.max(1, SESSION_STREAM_BUDGET_BYTES / Math.max(1, rows.size()));
            for (int i = 0; i < n; ++i) {
                if (rows.get(i)[0] > share) {
                    Stream s = rowStreams.get(i);
                    s.setWindows(s.getSendWindowBytes(), 1);
                }
            }
        }
    }

    private long collectBudget(Stream s, List<long[]> rows, List<Stream> rowStreams) {
        long b = s.getReorderBytes() + (long) s.getDeliveryPendingBytes();
        if (b > 0) {
            rows.add(new long[]{b});
            rowStreams.add(s);
        }
        return b;
    }

    private void syncFecControl(long nowMs) {
        if (rx != null) {
            FrameRx.RxCounters c = rx.counters;
            strategy.noteLocalCounters(c.dataExpected, c.dataRxOrig, nowMs);
        }
        adaptGroupD(nowMs);
        if (tx != null) tx.setK(strategy.currentK());
        if (tx != null) tx.setGroupDrainMs(groupDrainMs());
    }

    private void adaptGroupD(long nowMs) {
        int target = pickGroupD();
        if (target == groupD) return;
        if (nowMs - lastDChangeMs < ControlConstants.D_ADAPT_INTERVAL_MS) return;
        if (Math.abs(target - groupD) < ControlConstants.D_STEP_MIN
                && target != ControlConstants.D_FLOOR && target != dMax) return;
        lastDChangeMs = nowMs;
        groupD = target;
        if (tx != null) tx.setGroupD(target);
        strategy.setGroupSize(target);
    }

    private int pickGroupD() {
        double bw = sndBbr.bwBytesPerMs;
        double symPerSec = bw > 0 && limits.payloadMax > 0 ? (bw * 1000) / limits.payloadMax : 0;
        return GroupSize.chooseGroupD(dMax, strategy.currentParityCeiling(),
                strategy.currentLoss(), symPerSec);
    }

    private long groupDrainMs() {
        double bw = sndBbr.bwBytesPerMs;
        if (bw <= 0 || groupD <= 0) return -1;
        return (long) ((interleave * (double) groupD * limits.payloadMax) / bw);
    }

    /** 距最近的自驱截止期的毫秒数，-1 = 无。 */
    public long nextTimerMs(long nowMs) {
        if (closeNotified) return -1;
        long best = -1;
        if (hs.isEstablished() && tx != null) {
            long t = tx.nextTimerMs(nowMs);
            if (t >= 0 && (best < 0 || t < best)) best = t;
            t = stream.nextTimerMs(nowMs);
            if (t >= 0 && (best < 0 || t < best)) best = t;
            if (mux) {
                for (Stream st : streams.values()) {
                    t = st.nextTimerMs(nowMs);
                    if (t >= 0 && (best < 0 || t < best)) best = t;
                }
            }
        }
        return best;
    }

    public void onTick(long nowMs) {
        this.nowMs = nowMs;
        if (closeNotified) return;
        if (!hs.isEstablished()) hs.onTick(nowMs);
        if (hs.isEstablished() && !configured) configure(nowMs);
        if (hs.isFailed()) {
            notifyClosed("handshake_failure");
            return;
        }
        if (hs.isEstablished()) {
            if (tx != null) tx.onTick(nowMs);
            if (rx != null) rx.onTick(nowMs);
            syncFecControl(nowMs);
            updateStreamWindows(nowMs);
            stream.onTick(nowMs);
            if (mux) {
                for (Stream st : streams.values()) st.onTick(nowMs);
            }
            enforceStreamBytesBudget();
            byte[] report = reporter.onTick(nowMs, rx != null ? rx.counters : new FrameRx.RxCounters(),
                    rx != null ? rx.accountedThroughSetId() : 0);
            if (report != null) {
                // FECSTAT 是 oob 且永不重传：发两份，丢一份不至于盲掉对端的控制器。
                sendOob(report);
                sendOob(report);
            }
            sendPmtuProbe(nowMs);
            // 回音窗口内持续重发探针：单枚探测或它的 ACK 丢了，不能算路径不通。
            if (pathVerify.armed() && nowMs - pathProbeLastMs >= PATH_PROBE_RETRY_MS) {
                sendPathProbe(nowMs);
            }
        }
        if (lastWireOutMs == 0) lastWireOutMs = nowMs;
        if (nowMs - lastWireOutMs >= NAT_KEEPALIVE_MS) {
            sendOob(KEEPALIVE_MAGIC);
        }
        // 换路径后的回音窗口先判：它比 135 秒的静默判死短得多，且只在刚换过路径
        // 时上膛。窗口内连一枚 PMTU ACK 都没等到，说明新路径根本不通。
        if (pathVerify.expired(nowMs) && !resetByPeer) {
            resetByPeer = true;
            cb.log("FCP path lost: no reply within " + PATH_VERIFY_MS + "ms of network change");
            notifyClosed("path_lost");
            return;
        }
        if (lastPeerInMs != 0 && nowMs - lastPeerInMs >= PEER_ALIVE_GRACE_MS && !resetByPeer) {
            resetByPeer = true;
            notifyClosed("peer_dead");
        }
    }
}
