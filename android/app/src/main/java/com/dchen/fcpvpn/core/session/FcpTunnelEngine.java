package com.dchen.fcpvpn.core.session;

import com.dchen.fcpvpn.core.crypto.Envelope;
import com.dchen.fcpvpn.core.crypto.FcpKeys;
import com.dchen.fcpvpn.core.proxy.ProxyCodec;
import com.dchen.fcpvpn.core.stream.Stream;
import com.dchen.fcpvpn.core.stream.StreamCallbacks;
import com.dchen.fcpvpn.core.wire.Wire;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/**
 * TunnelEngine 的真实实现：fcp-node TunnelClient 的会话池 + UDP 泵 + FCP OPEN
 * 语义（tunnel.ts:336-1161 的核心子集）。
 *
 * - 4 个共享会话（MUX_SESSION_POOL），start 时全部发起握手；open() 轮转选择
 *   已建立的会话，分配空闲 sid，以 FCP OPEN 为流首字节；OPEN_OK/ERR 由
 *   {@link OpenIntercept} 拦截后交给宿主。
 * - 单引擎线程泵：UDP 接收（按 8 字节 salt 路由到会话）、全部会话 onTick、
 *   用户动作队列——满足 FcpSession 单写者契约。
 * - 会话死亡自动换新盐重建（fcp-node 池行为）；全部会话死亡才回调 onDown
 *   （整体重连由 TunnelManager 决定）。
 * - 未知 salt 的数据报以 ≤1Hz 回无状态复位（#86）；认证数据报刷新对端地址
 *   （NAT 重绑定），但路径验证期间冻结地址，避免旧路径报文冒充新路径。
 */
public final class FcpTunnelEngine implements TunnelEngine {

    private static final int POOL_SIZE = 4;
    private static final long STATS_INTERVAL_MS = 500;

    private final SecureRandom random = new SecureRandom();
    private final AtomicInteger cursor = new AtomicInteger(0);
    private final AtomicInteger nextSid = new AtomicInteger(1);
    private final AtomicBoolean running = new AtomicBoolean(false);
    private final ConcurrentLinkedQueue<Runnable> actions = new ConcurrentLinkedQueue<>();
    private final ConcurrentLinkedQueue<PendingOpen> pendingOpens = new ConcurrentLinkedQueue<>();
    private final Map<String, PoolSlot> slotsBySalt = new HashMap<>();
    /**
     * 写操作只在引擎线程（建槽/回收死槽），但 queryDns 会从调用线程按索引读，
     * 所以用写时复制：迭代/取下标不会撞上并发修改。
     */
    private final List<PoolSlot> slots = new java.util.concurrent.CopyOnWriteArrayList<>();
    private int establishedCount = 0;
    /** onDown 只报一次，直到池里再次有会话建立（防多条会话同时死时重复重连）。 */
    private volatile boolean downNotified = false;
    private long startRealMs = 0;
    private long totalUpBytes = 0;
    private long totalDownBytes = 0;
    private long lastStatsMs = 0;
    private long lastUpTotal = 0;
    private long lastDownTotal = 0;
    private long lastResetMs = 0;

    private volatile EngineConfig config;
    private volatile EngineListener listener;
    private DatagramSocket udpSocket;
    private volatile InetAddress peerAddress;
    private volatile int peerPort;
    private Thread pumpThread;

    /** 一个池槽：会话 + 其盐 + 生命周期标记。 */
    private static final class PoolSlot {
        final byte[] salt;
        FcpSession session;
        volatile boolean established;
        volatile boolean dead;

        PoolSlot(byte[] salt) {
            this.salt = salt;
        }
    }

    private static final class PendingOpen {
        final OpenTarget target;
        final OpenCallback callback;

        PendingOpen(OpenTarget target, OpenCallback callback) {
            this.target = target;
            this.callback = callback;
        }
    }

    @Override
    public void start(EngineConfig cfg, SocketProtector protector, EngineListener l) throws Exception {
        this.config = cfg;
        this.listener = l;
        this.peerAddress = InetAddress.getByName(cfg.peerHost);
        this.peerPort = cfg.peerPort;
        this.startRealMs = System.currentTimeMillis();
        this.lastStatsMs = startRealMs;

        udpSocket = new DatagramSocket();
        udpSocket.setReceiveBufferSize(1 << 20);
        udpSocket.setSendBufferSize(1 << 20);
        if (protector != null) {
            protector.protect(udpSocket);
        }

        running.set(true);
        for (int i = 0; i < POOL_SIZE; ++i) {
            createSlot(System.currentTimeMillis());
        }

        pumpThread = new Thread(this::pump, "fcp-engine");
        pumpThread.setDaemon(true);
        pumpThread.start();
    }

    /** 创建一个池槽并立即发起握手（新盐）。在引擎线程上调用。 */
    private void createSlot(long now) {
        byte[] salt = new byte[8];
        random.nextBytes(salt);
        PoolSlot slot = new PoolSlot(salt);
        FcpSession.Config sc = new FcpSession.Config();
        sc.psk = hexToBytes(config.pskHex32);
        sc.salt = salt;
        sc.d = config.fecData;
        sc.p = config.fecParityMax;
        sc.mtu = config.mtuMin > 0 ? config.mtuMin : 1040;
        sc.pmtud = true;
        sc.keyUpdate = false;
        sc.ackV2 = true;
        sc.initialSrttMs = 200;
        FcpSession session = new FcpSession(sc, new FcpSession.Listener() {
            @Override
            public void sendWire(byte[] wire, int symbolType) {
                sendToPeer(wire);
            }

            @Override
            public void read(byte[] bytes) {
                // 默认流（sid 0）：服务端故意不接线，客户端不应收到数据。
            }

            @Override
            public void closed(String reason) {
                onSessionDead(slot, reason);
            }

            @Override
            public void log(String line) {
                if (listener != null) listener.onStatsLine(line);
            }
        });
        slot.session = session;
        slotsBySalt.put(saltKey(salt), slot);
        slots.add(slot);
        session.start(now);
    }

    private static byte[] hexToBytes(String hex32) {
        byte[] out = new byte[16];
        for (int i = 0; i < 16; ++i) {
            out[i] = (byte) Integer.parseInt(hex32.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    private static String saltKey(byte[] salt) {
        StringBuilder sb = new StringBuilder(16);
        for (byte b : salt) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    /** 引擎线程主泵：动作 → 接收 → tick → 建立检测 → 统计。 */
    private void pump() {
        byte[] buf = new byte[65536];
        DatagramPacket pkt = new DatagramPacket(buf, buf.length);
        long lastTickMs = 0;
        while (running.get()) {
            long now = System.currentTimeMillis();
            try {
                // 1. 用户动作
                Runnable action;
                while ((action = actions.poll()) != null) {
                    try {
                        action.run();
                    } catch (Exception ignored) {
                        // 单个动作失败不拖垮泵
                    }
                }
                // 2. UDP 接收（1ms 超时）
                try {
                    udpSocket.setSoTimeout(1);
                    udpSocket.receive(pkt);
                    int n = pkt.getLength();
                    if (n >= Envelope.SALT_LEN + Envelope.NONCE_LEN + 1) {
                        byte[] datagram = new byte[n];
                        System.arraycopy(buf, 0, datagram, 0, n);
                        totalDownBytes += n;
                        handleDatagram(datagram, pkt.getAddress(), pkt.getPort(), now);
                    }
                } catch (java.net.SocketTimeoutException ignore) {
                    // 无包
                }
                // 3. 全会话 tick（2ms 节流）+ 建立检测
                if (now - lastTickMs >= 2) {
                    lastTickMs = now;
                    for (PoolSlot slot : slots) {
                        if (slot.dead || slot.session == null) continue;
                        slot.session.onTick(now);
                        // onTick 里可能刚判死这一槽（换路径超时/静默超时）：dead 复检，
                        // 否则会把刚清掉的 established 又记回来，抵消死亡计数。
                        if (!slot.dead && !slot.established && slot.session.isEstablished()) {
                            slot.established = true;
                            // 池里 4 条会话各自建立：只有第一条代表"隧道可用"，
                            // 否则上层会收到 4 次 CONNECTED 与 4 次广播。
                            if (++establishedCount == 1) {
                                downNotified = false;
                                if (listener != null) {
                                    listener.onEstablished(saltKey(slot.salt));
                                }
                            }
                        }
                    }
                    flushPendingOpens();
                }
                // 4. 统计行（500ms）
                if (now - lastStatsMs >= STATS_INTERVAL_MS) {
                    emitStats(now);
                }
                Thread.sleep(1);
            } catch (InterruptedException e) {
                break;
            } catch (Exception ignored) {
                // 泵级异常：会话层有自己的失败语义，泵继续
            }
        }
    }

    private void handleDatagram(byte[] datagram, InetAddress from, int fromPort, long now) {
        String key = saltKey(java.util.Arrays.copyOfRange(datagram, 0, Envelope.SALT_LEN));
        PoolSlot slot = slotsBySalt.get(key);
        if (slot == null || slot.dead || slot.session == null) {
            // 未知盐：≤1Hz 回无状态复位（#86）。复位以数据报自己的盐封装。
            if (now - lastResetMs >= 1000) {
                lastResetMs = now;
                byte[] peerSalt = java.util.Arrays.copyOfRange(datagram, 0, Envelope.SALT_LEN);
                byte[] reset = Envelope.sealReset(hexToBytes(config.pskHex32), peerSalt,
                        FcpKeys.DIRECTION_C2S, FcpKeys.DIRECTION_S2C,
                        Envelope.NONCE_LIMIT - 1 - random.nextInt(65536));
                sendToPeer(reset);
            }
            return;
        }
        boolean ok = slot.session.onWire(datagram, now);
        if (ok && from != null) {
            // NAT 重绑定：认证数据报刷新对端地址（tunnel.ts:1379-1391）。但换路径
            // 验证窗口内不能把旧 socket/旧 IP 的来包设成当前地址：回音要凭换网后
            // 发出的探测（PMTU token）判定，地址一漂走，探测的 ACK 也会被当成
            // 另一个对端。窗口结束（到期或已证明）后恢复正常跟随。
            if (!anyPathAddressFrozen(now)) {
                if (!from.equals(peerAddress) || fromPort != peerPort) {
                    peerAddress = from;
                    peerPort = fromPort;
                }
            }
        }
    }

    private void sendToPeer(byte[] wire) {
        try {
            udpSocket.send(new DatagramPacket(wire, wire.length, peerAddress, peerPort));
            totalUpBytes += wire.length;
        } catch (Exception ignored) {
            // 发送失败（网络切换等）：会话超时语义接管
        }
    }

    private void onSessionDead(PoolSlot slot, String reason) {
        slot.dead = true;
        if (slot.established) --establishedCount;
        slot.established = false;
        slotsBySalt.remove(saltKey(slot.salt));
        // 死槽必须从池里摘掉：否则每次死一条就留一个闭包引用（FcpSession 的收发
        // 缓冲还在），长连接反复断链时是实打实的内存泄漏，stats 也会越报越多。
        slots.remove(slot);
        // 换新盐重建该槽（池保持 4 个活跃会话）
        actions.add(() -> {
            if (running.get()) createSlot(System.currentTimeMillis());
        });
        // 会话全灭才算断链；只报一次（多条会话同时死会依次走到这里）。
        if (establishedCount <= 0 && running.get() && !downNotified) {
            downNotified = true;
            if (listener != null) listener.onDown(reason);
        }
    }

    private void flushPendingOpens() {
        if (pendingOpens.isEmpty() || !anyEstablished()) return;
        PendingOpen p;
        while ((p = pendingOpens.poll()) != null) {
            doOpen(p.target, p.callback);
        }
    }

    private boolean anyEstablished() {
        for (PoolSlot slot : slots) {
            if (slot.established && !slot.dead) return true;
        }
        return false;
    }

    /** 任一池会话仍在验证或地址冻结窗口内时，拒绝旧路径报文改写全局对端地址。 */
    private boolean anyPathAddressFrozen(long nowMs) {
        for (PoolSlot slot : slots) {
            if (!slot.dead && slot.session != null && slot.session.isPathAddressFrozen(nowMs)) return true;
        }
        return false;
    }

    /** 选一个已建立的会话（轮转），分配空闲 sid，发 OPEN 并拦截 OPEN_OK/ERR。 */
    private void doOpen(OpenTarget target, OpenCallback callback) {
        PoolSlot chosen = null;
        int n = slots.size();
        for (int i = 0; i < n; ++i) {
            PoolSlot s = slots.get((cursor.getAndIncrement() & 0x7fffffff) % n);
            if (s.established && !s.dead && s.session != null && s.session.isMuxActive()) {
                chosen = s;
                break;
            }
        }
        if (chosen == null) {
            callback.onFailed(ProxyCodec.OPEN_ERR_TOO_MANY_SESSIONS, "no established session");
            return;
        }
        int sid = 0;
        // sid 1..255 由同一会话上的所有连接共享，轮转指针可能与在用的 sid 撞上：
        // 逐个试到空闲为止，而不是撞一次就判失败。
        for (int attempt = 0; attempt < FcpSession.MUX_MAX_STREAMS; ++attempt) {
            int candidate = nextSid.getAndUpdate(v -> (v >= 255 ? 1 : v + 1));
            if (candidate < 1 || candidate > 255) candidate = 1;
            if (!chosen.session.hasStream(candidate)) {
                sid = candidate;
                break;
            }
        }
        if (sid == 0) {
            callback.onFailed(ProxyCodec.OPEN_ERR_TOO_MANY_SESSIONS, "no free sid");
            return;
        }

        byte[] addr = target.address != null ? target.address
                : target.host == null ? new byte[0]
                : target.host.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        byte[] openBytes = ProxyCodec.openWriteRequest(
                new ProxyCodec.ProxyTarget(target.atyp, addr, target.port));
        if (openBytes == null) {
            callback.onFailed(-1, "bad target");
            return;
        }

        OpenIntercept intercept = new OpenIntercept(callback, engineExecutor());
        Stream stream = chosen.session.openStream(sid, intercept.callbacks);
        if (stream == null) {
            callback.onFailed(ProxyCodec.OPEN_ERR_TOO_MANY_SESSIONS, "session not mux");
            return;
        }
        intercept.stream = stream;
        stream.write(openBytes, 0, openBytes.length, System.currentTimeMillis());
    }

    /**
     * OPEN_OK/ERR 拦截器：流的首批字节先过 openParseReply；OK 后剩余字节交给
     * 宿主（listener 尚未 set 时先缓冲）；ERR → onFailed 并回收流。
     */
    private static final class OpenIntercept {
        final OpenCallback user;
        final java.util.concurrent.Executor engine;
        Stream stream;
        private final List<byte[]> pendingBeforeListener = new ArrayList<>();
        private final java.io.ByteArrayOutputStream pending = new java.io.ByteArrayOutputStream();
        private boolean decided = false;
        private final AtomicReference<StreamHandle.Listener> handle = new AtomicReference<>();

        OpenIntercept(OpenCallback user, java.util.concurrent.Executor engine) {
            this.user = user;
            this.engine = engine;
        }

        private final StreamCallbacks callbacks = new StreamCallbacks() {
            @Override
            public void send(byte[] seg) {
            }

            @Override
            public void read(byte[] bytes) {
                if (decided) {
                    deliver(bytes);
                    return;
                }
                pending.write(bytes, 0, bytes.length);
                byte[] all = pending.toByteArray();
                ProxyCodec.ParseResult r = ProxyCodec.openParseReply(all, all.length);
                if (r.status == ProxyCodec.NEED_MORE) return;
                decided = true;
                if (r.status == ProxyCodec.OK && r.boolValue) {
                    int consumed = r.consumed;
                    byte[] rest = pending.size() > consumed
                            ? java.util.Arrays.copyOfRange(all, consumed, all.length) : null;
                    pending.reset();
                    user.onOpened(wrap());
                    if (rest != null && rest.length > 0) deliver(rest);
                } else {
                    int code = r.status == ProxyCodec.OK ? r.intValue : -1;
                    user.onFailed(code, "OPEN_ERR");
                    engine.execute(() -> stream.sendRst());
                }
            }

            @Override
            public void closed(String reason) {
                if (!decided) {
                    decided = true;
                    user.onFailed(-1, reason);
                } else if ("reset".equals(reason)) {
                    deliverReset(1);
                } else {
                    deliverReset(0);
                }
            }

            @Override
            public void eof() {
                StreamHandle.Listener l = handle.get();
                if (l != null) l.onFin();
            }
        };

        private void deliver(byte[] bytes) {
            StreamHandle.Listener l = handle.get();
            if (l != null) {
                l.onData(bytes, 0, bytes.length);
            } else {
                pendingBeforeListener.add(bytes);
            }
        }

        private void deliverReset(int code) {
            StreamHandle.Listener l = handle.get();
            if (l != null) l.onReset(code);
        }

        private StreamHandle wrap() {
            return new StreamHandle() {
                @Override
                public void setListener(Listener l) {
                    handle.set(l);
                    // 刷出 setListener 之前到达的数据（罕见：宿主必须同步 set）。
                    for (byte[] b : pendingBeforeListener) {
                        l.onData(b, 0, b.length);
                    }
                    pendingBeforeListener.clear();
                }

                @Override
                public void write(byte[] data, int offset, int len) {
                    engine.execute(() -> stream.write(data, offset, len,
                            System.currentTimeMillis()));
                }

                @Override
                public void closeWrite() {
                    engine.execute(() -> stream.closeWrite(System.currentTimeMillis()));
                }

                @Override
                public void abort() {
                    engine.execute(stream::sendRst);
                }

                @Override
                public void consumed(int n) {
                    engine.execute(() -> stream.consumed(n));
                }
            };
        }
    }

    private java.util.concurrent.Executor engineExecutor() {
        return actions::add;
    }

    @Override
    public void stop() {
        running.set(false);
        if (pumpThread != null) pumpThread.interrupt();
        // 未完成的 OPEN 必须回调失败：调用方（代理监听/路由器）在等 onOpened 或
        // onFailed，少一次回调就有一个本地 socket 永久悬挂。
        PendingOpen p;
        while ((p = pendingOpens.poll()) != null) {
            try {
                p.callback.onFailed(-1, "engine stopped");
            } catch (RuntimeException ignored) {
                // 回调自身的异常不影响其余清理
            }
        }
        // 主动关闭会话：触发 closed → onSessionDead 释放槽位（running 已 false，
        // 不会重建，也不会再回调 onDown）。
        for (PoolSlot slot : slots) {
            if (slot.session != null) {
                slot.session.closeNow("engine_stopped");
            }
        }
        slots.clear();
        slotsBySalt.clear();
        if (udpSocket != null && !udpSocket.isClosed()) {
            udpSocket.close();
        }
    }

    @Override
    public void open(OpenTarget target, OpenCallback callback) {
        actions.add(() -> {
            if (!anyEstablished()) {
                pendingOpens.add(new PendingOpen(target, callback));
                return;
            }
            doOpen(target, callback);
        });
    }

    @Override
    public DatagramSocket socket() {
        return udpSocket;
    }

    /**
     * 底层网络换了：把"探测新路径"投递到引擎线程（FcpSession 是单写者）。
     * 每个会话各自发认证保活、重测 PMTU、上膛回音窗口；socket 本身不重建——
     * 它不 connect、不绑网络，换网后自然从新网卡发出。
     */
    @Override
    public void onPathChanged(boolean reset) {
        actions.add(() -> {
            if (!running.get()) return;
            long now = System.currentTimeMillis();
            for (PoolSlot slot : slots) {
                if (slot.dead || slot.session == null) continue;
                slot.session.onPathChanged(now, reset);
            }
        });
    }

    @Override
    public boolean isEstablished() {
        return anyEstablished();
    }

    /** 选一个已建立会话做协议内 DNS 解析（优先本端发起的会话，失败换下一个）。 */
    @Override
    public byte[] queryDns(byte[] dnsQuery, int timeoutMs) {
        if (!running.get()) return null;
        for (int i = 0; i < slots.size(); ++i) {
            PoolSlot s = slots.get((cursor.getAndIncrement() & 0x7fffffff) % slots.size());
            if (!s.established || s.dead || s.session == null) continue;
            byte[] answer = s.session.queryDns(dnsQuery, timeoutMs, engineExecutor());
            if (answer != null) return answer;
        }
        return null;
    }

    private void emitStats(long now) {
        long dt = now - lastStatsMs;
        if (dt <= 0) return;
        long upRate = (totalUpBytes - lastUpTotal) * 1000 / dt;
        long downRate = (totalDownBytes - lastDownTotal) * 1000 / dt;
        lastUpTotal = totalUpBytes;
        lastDownTotal = totalDownBytes;
        lastStatsMs = now;
        if (listener != null) {
            listener.onStatsLine("stats up=" + upRate + "B/s down=" + downRate + "B/s"
                    + " sessions=" + establishedCount + "/" + POOL_SIZE
                    + " uptime=" + ((now - startRealMs) / 1000) + "s");
        }
    }
}
