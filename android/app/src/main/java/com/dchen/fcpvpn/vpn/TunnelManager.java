package com.dchen.fcpvpn.vpn;

import android.content.Context;
import android.content.Intent;

import androidx.localbroadcastmanager.content.LocalBroadcastManager;

import com.dchen.fcpvpn.core.proxy.MixedProxyListener;
import com.dchen.fcpvpn.core.session.EngineConfig;
import com.dchen.fcpvpn.core.session.FcpTunnelEngine;
import com.dchen.fcpvpn.core.session.OpenCallback;
import com.dchen.fcpvpn.core.session.OpenTarget;
import com.dchen.fcpvpn.core.session.SocketProtector;
import com.dchen.fcpvpn.core.session.TunnelEngine;
import com.dchen.fcpvpn.log.LogConfig;
import com.dchen.fcpvpn.log.Logger;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;

/**
 * 隧道管理器 —— {@link TunnelEngine} 实例的生命周期管理（参考 kcp 同名类的
 * 重连策略骨架，改为面向 FCP 的引擎接口）。
 *
 * <p>职责：</p>
 * <ul>
 *   <li>持有唯一的引擎实例（应用级单例，VPN 模式与仅代理模式共用）；</li>
 *   <li>把引擎回调映射为 {@link VpnConnectionState} 并广播给 UI / 通知栏；</li>
 *   <li>在引擎回调 onDown 时按指数退避（1s→2s→4s→…→max 60s）自动重连，
 *       onEstablished 时复位退避；用户显式 stop 后不再复活。</li>
 * </ul>
 *
 * <p>引擎自身的握手级重试（HELLO 9 次等）属于引擎内部行为，与本层的会话级
 * 重连互不替代。仅代理模式下 protector 传 null，真实引擎需容忍无保护 socket
 * （不在 VPN 内时 protect 本来就是无意义操作）。</p>
 */
public class TunnelManager {

    private static final int INITIAL_DELAY_MS = 1000;
    private static final int MAX_DELAY_MS = 60000;
    private static final int DELAY_FACTOR = 2;

    private static volatile TunnelManager sInstance;

    /** 应用级单例：VPN 服务与 ViewModel 共用同一个引擎生命周期。 */
    public static TunnelManager get(Context context) {
        if (sInstance == null) {
            synchronized (TunnelManager.class) {
                if (sInstance == null) {
                    sInstance = new TunnelManager(context.getApplicationContext());
                }
            }
        }
        return sInstance;
    }

    private final Context appContext;

    private volatile TunnelEngine engine;
    private volatile EngineConfig config;
    private volatile SocketProtector protector;
    private volatile VpnConnectionState state = VpnConnectionState.DISCONNECTED;
    private volatile long establishedAtMs;
    private volatile String lastStatsLine;

    /** 用户/外部已请求停止：stop 之后任何 down 回调都不再触发重连。 */
    private final AtomicBoolean stopped = new AtomicBoolean(true);

    /** 本机混合代理监听（proxyPort > 0 时随首个会话建立启动）。 */
    private volatile MixedProxyListener proxyListener;

    private final AtomicInteger reconnectAttempts = new AtomicInteger(0);
    private final AtomicInteger reconnectDelayMs = new AtomicInteger(INITIAL_DELAY_MS);
    private ScheduledFuture<?> reconnectFuture;

    /** 单线程调度器：引擎启动（阻塞握手）与重连任务串行执行，天然互斥。 */
    private final ScheduledExecutorService scheduler =
            Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "Fcp-Engine-Exec");
                t.setDaemon(true);
                return t;
            });

    /** 通知栏状态回调（FcpVpnService 设置，引擎线程上回调）。 */
    private volatile Consumer<VpnConnectionState> stateListener;
    /** 引擎 stats 行转发（FcpVpnService 设置）。 */
    private volatile Consumer<String> statsListener;

    private TunnelManager(Context appContext) {
        this.appContext = appContext;
    }

    public void setStateListener(Consumer<VpnConnectionState> listener) {
        this.stateListener = listener;
    }

    public void setStatsListener(Consumer<String> listener) {
        this.statsListener = listener;
    }

    /**
     * 启动引擎。若已有引擎在跑（如运行模式切换），先静默停掉旧的。
     * 引擎实例同步创建并赋值给 engine 字段（保证 start() 返回后 getEngine()
     * 非 null），阻塞的握手在调度线程上进行。
     */
    public synchronized void start(EngineConfig config, SocketProtector protector) {
        stopInternalQuietly();

        this.config = config;
        this.protector = protector;
        stopped.set(false);
        reconnectAttempts.set(0);
        reconnectDelayMs.set(INITIAL_DELAY_MS);

        Logger.info(LogConfig.MODULE_VPN, "TunnelManager.start host=" + config.peerHost
                + ":" + config.peerPort + " fecData=" + config.fecData
                + " parityMax=" + config.fecParityMax + " mtuMin=" + config.mtuMin
                + " probe=" + config.probeIntervalSec + "s protector=" + (protector != null));

        connectNow();
    }

    /** 用户请求停止：不再重连，拆除引擎。 */
    public synchronized void stop() {
        stopped.set(true);
        cancelReconnect();
        stopProxyListener();
        TunnelEngine e = engine;
        engine = null;
        if (e != null) {
            try {
                e.stop();
            } catch (RuntimeException ex) {
                Logger.error(LogConfig.MODULE_VPN, "engine stop failed: " + ex.getMessage());
            }
        }
        establishedAtMs = 0;
        lastStatsLine = null;
        updateState(VpnConnectionState.DISCONNECTED);
        Logger.info(LogConfig.MODULE_VPN, "TunnelManager stopped");
    }

    /**
     * 建立隧道内连接（转发给当前引擎）。隧道未就绪时直接本地失败（code=-1），
     * 保证回调恰好一次——与 TunnelEngine.open 契约一致。
     */
    public void open(OpenTarget target, OpenCallback callback) {
        TunnelEngine e = engine;
        if (e == null || !e.isEstablished()) {
            callback.onFailed(-1, "隧道未建立");
            return;
        }
        e.open(target, callback);
    }

    /** 当前配置的对端地址（隧道内 DNS 等场景需要）。 */
    public String getPeerHost() {
        EngineConfig c = config;
        return c != null ? c.peerHost : null;
    }

    public int getPeerPort() {
        EngineConfig c = config;
        return c != null ? c.peerPort : 0;
    }

    public TunnelEngine getEngine() {
        return engine;
    }

    /** 协议内 DNS 解析（走隧道 oob，不开新端口）。 */
    public byte[] queryDns(byte[] dnsQuery, int timeoutMs) {
        TunnelEngine e = engine;
        return e != null ? e.queryDns(dnsQuery, timeoutMs) : null;
    }

    public boolean isEstablished() {
        TunnelEngine e = engine;
        return e != null && e.isEstablished();
    }

    public VpnConnectionState getState() {
        return state;
    }

    public long getEstablishedAtMs() {
        return establishedAtMs;
    }

    public String getLastStatsLine() {
        return lastStatsLine;
    }

    // ------------------------------------------------------------------ 内部

    /** 真实 FCP 引擎（M4 集成完成：壳层全部面向 TunnelEngine 接口）。 */
    private TunnelEngine createEngine() {
        return new FcpTunnelEngine();
    }

    private void connectNow() {
        if (stopped.get()) {
            return;
        }
        updateState(VpnConnectionState.CONNECTING);

        TunnelEngine newEngine = createEngine();
        engine = newEngine;

        final EngineConfig cfg = config;
        final SocketProtector prot = protector;
        scheduler.execute(() -> {
            if (stopped.get()) {
                return;
            }
            try {
                newEngine.start(cfg, prot, engineListener);
            } catch (Exception e) {
                Logger.error(LogConfig.MODULE_VPN, "engine start error: " + e.getMessage());
                engineListener.onDown(e.getMessage() != null ? e.getMessage() : "start error");
            }
        });
    }

    private final TunnelEngine.EngineListener engineListener = new TunnelEngine.EngineListener() {
        @Override
        public void onEstablished(String salt) {
            if (stopped.get()) {
                return;
            }
            Logger.info(LogConfig.MODULE_VPN, "引擎已建立会话 salt=" + salt);
            reconnectAttempts.set(0);
            reconnectDelayMs.set(INITIAL_DELAY_MS);
            establishedAtMs = System.currentTimeMillis();
            updateState(VpnConnectionState.CONNECTED);
            startProxyListenerIfNeeded();
        }

        @Override
        public void onDown(String reason) {
            if (stopped.get()) {
                return;
            }
            Logger.warning(LogConfig.MODULE_VPN, "引擎断链: " + reason);
            establishedAtMs = 0;
            stopProxyListener();
            updateState(VpnConnectionState.RECONNECTING);
            scheduleReconnect();
        }

        @Override
        public void onStatsLine(String line) {
            lastStatsLine = line;
            Logger.debug(LogConfig.MODULE_VPN, "stats: " + line);
            Consumer<String> l = statsListener;
            if (l != null) {
                try {
                    l.accept(line);
                } catch (RuntimeException ex) {
                    Logger.error(LogConfig.MODULE_VPN, "stats listener error: " + ex.getMessage());
                }
            }
            Intent intent = new Intent(VpnStateBroadcast.ACTION_STATE_CHANGED);
            intent.putExtra(VpnStateBroadcast.EXTRA_STATE, state.name());
            intent.putExtra(VpnStateBroadcast.EXTRA_STATS_LINE, line);
            LocalBroadcastManager.getInstance(appContext).sendBroadcast(intent);
        }
    };

    /** 首个会话建立后按配置启动本机混合代理监听（幂等）。 */
    private void startProxyListenerIfNeeded() {
        EngineConfig cfg = config;
        if (cfg == null || cfg.proxyPort <= 0 || proxyListener != null) {
            return;
        }
        TunnelEngine e = engine;
        if (e == null) {
            return;
        }
        try {
            MixedProxyListener listener = new MixedProxyListener(cfg.proxyPort,
                    e::open, Runnable::run,
                    line -> Logger.info(LogConfig.MODULE_VPN, line));
            listener.start();
            proxyListener = listener;
            Logger.info(LogConfig.MODULE_VPN,
                    "本机混合代理已启动 127.0.0.1:" + cfg.proxyPort
                            + "（SOCKS5 / HTTP CONNECT / 正向代理）");
        } catch (Exception ex) {
            Logger.error(LogConfig.MODULE_VPN, "混合代理启动失败: " + ex.getMessage());
        }
    }

    private void stopProxyListener() {
        MixedProxyListener l = proxyListener;
        proxyListener = null;
        if (l != null) {
            l.stop();
        }
    }

    private void scheduleReconnect() {
        if (stopped.get()) {
            return;
        }
        cancelReconnect();
        int attempts = reconnectAttempts.incrementAndGet();
        int delay = reconnectDelayMs.get();
        Logger.info(LogConfig.MODULE_RECONNECT, "第 " + attempts + " 次重连，" + delay + "ms 后发起");
        reconnectFuture = scheduler.schedule(this::connectNow, delay, TimeUnit.MILLISECONDS);
        reconnectDelayMs.set(Math.min(delay * DELAY_FACTOR, MAX_DELAY_MS));
    }

    private void cancelReconnect() {
        ScheduledFuture<?> f = reconnectFuture;
        reconnectFuture = null;
        if (f != null) {
            f.cancel(false);
        }
    }

    /** start(新配置) 前的静默清理：不发 DISCONNECTED 广播（马上会进 CONNECTING）。 */
    private void stopInternalQuietly() {
        stopped.set(true);
        cancelReconnect();
        stopProxyListener();
        TunnelEngine e = engine;
        engine = null;
        if (e != null) {
            try {
                e.stop();
            } catch (RuntimeException ex) {
                Logger.error(LogConfig.MODULE_VPN, "old engine stop failed: " + ex.getMessage());
            }
        }
    }

    private void updateState(VpnConnectionState newState) {
        state = newState;
        Logger.info(LogConfig.MODULE_VPN, "Tunnel state -> " + newState.getDisplayText());
        Consumer<VpnConnectionState> l = stateListener;
        if (l != null) {
            try {
                l.accept(newState);
            } catch (RuntimeException ex) {
                Logger.error(LogConfig.MODULE_VPN, "state listener error: " + ex.getMessage());
            }
        }
        Intent intent = new Intent(VpnStateBroadcast.ACTION_STATE_CHANGED);
        intent.putExtra(VpnStateBroadcast.EXTRA_STATE, newState.name());
        intent.putExtra(VpnStateBroadcast.EXTRA_DURATION, -1L);
        intent.putExtra(VpnStateBroadcast.EXTRA_SESSIONS, -1);
        LocalBroadcastManager.getInstance(appContext).sendBroadcast(intent);
    }
}
