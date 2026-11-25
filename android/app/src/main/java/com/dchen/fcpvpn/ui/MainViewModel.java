package com.dchen.fcpvpn.ui;

import android.app.Application;
import android.os.Handler;
import android.os.Looper;

import androidx.lifecycle.AndroidViewModel;
import androidx.lifecycle.LiveData;
import androidx.lifecycle.MutableLiveData;

import com.dchen.fcpvpn.R;
import com.dchen.fcpvpn.core.session.EngineConfig;
import com.dchen.fcpvpn.log.LogConfig;
import com.dchen.fcpvpn.log.Logger;
import com.dchen.fcpvpn.util.ServiceUtil;
import com.dchen.fcpvpn.vpn.TunnelManager;
import com.dchen.fcpvpn.vpn.VpnConnectionState;

import java.util.concurrent.atomic.AtomicBoolean;

/**
 * 一次性事件包装器，防止配置变化时重复消费（kcp 同款）。
 */
class Event<T> {
    private final T content;
    private final AtomicBoolean handled = new AtomicBoolean(false);

    public Event(T content) {
        this.content = content;
    }

    public T getContentIfNotHandled() {
        if (handled.compareAndSet(false, true)) {
            return content;
        }
        return null;
    }

    public boolean wasHandled() {
        return handled.get();
    }
}

/**
 * 主界面 ViewModel —— 连接状态、速率 chips 数据、时长计时。
 * 状态来源：FcpVpnService / TunnelManager 的本地广播。
 */
public class MainViewModel extends AndroidViewModel {

    private final MutableLiveData<VpnConnectionState> connectionState =
            new MutableLiveData<>(VpnConnectionState.DISCONNECTED);
    private final MutableLiveData<Long> uploadBytes = new MutableLiveData<>(0L);
    private final MutableLiveData<Long> downloadBytes = new MutableLiveData<>(0L);
    private final MutableLiveData<Long> duration = new MutableLiveData<>(0L);
    private final MutableLiveData<Integer> sessions = new MutableLiveData<>(-1);
    private final MutableLiveData<Event<String>> messages = new MutableLiveData<>();

    /** 已连接时刻（时长计时基准）；广播携带的时长会反向校准它。 */
    private volatile long connectedAtMs;
    private final Handler mainHandler = new Handler(Looper.getMainLooper());
    private final AtomicBoolean ticking = new AtomicBoolean(false);

    /** 代理模式启动被推迟：等还活着的 VpnService 停下来。 */
    private final AtomicBoolean pendingProxyStart = new AtomicBoolean(false);
    /** 兜底：DISCONNECTED 广播没送达（界面不在前台）时的延时启动。 */
    private static final long PROXY_START_FALLBACK_MS = 2000;
    /** 等 VpnService 退出的最大重试次数（每次 2s）。 */
    private static final int PROXY_START_MAX_RETRIES = 5;
    private int proxyStartRetries;
    private final Runnable proxyStartFallback = new Runnable() {
        @Override
        public void run() {
            startPendingProxyEngine();
        }
    };

    private final Runnable durationTicker = new Runnable() {
        @Override
        public void run() {
            if (connectedAtMs <= 0) {
                ticking.set(false);
                return;
            }
            duration.setValue((System.currentTimeMillis() - connectedAtMs) / 1000);
            mainHandler.postDelayed(this, 1000);
        }
    };

    public MainViewModel(Application application) {
        super(application);
    }

    // ------------------------------------------------------------ 动作

    /** 连接：VPN 模式启动前台服务；仅代理模式直接拉起引擎（当前为 Stub）。 */
    public void connect() {
        Application app = getApplication();
        if (!ConfigStore.isConfigured(app)) {
            messages.setValue(new Event<>(app.getString(R.string.fcp_msg_not_configured)));
            return;
        }
        EngineConfig config = ConfigStore.buildEngineConfig(app);
        if (config == null) {
            messages.setValue(new Event<>(app.getString(R.string.fcp_msg_psk_missing)));
            return;
        }

        String mode = ConfigStore.getRunMode(app);
        Logger.info(LogConfig.MODULE_UI, "Connect requested, mode=" + mode);
        connectionState.setValue(VpnConnectionState.CONNECTING);

        // 任何一次新的连接请求都作废之前"等 VPN 服务退出后再起代理引擎"的意图：
        // 否则残留的兜底定时器会在 VPN 模式连上之后触发，把服务刚建的引擎停掉。
        clearPendingProxyStart();

        if (ConfigStore.RUN_MODE_PROXY.equals(mode)) {
            // 代理端口模式：不走 VpnService、不接管流量，只管理引擎与 1080 监听。
            // protector 传 null（不在 VPN 内无需保护）。
            if (ServiceUtil.isVpnServiceRunning(app)) {
                // 从 VPN 模式切过来：还活着的 VpnService 必须先停。它的拆除是
                // 异步的，而且会顺带停掉同一个 TunnelManager 的引擎——所以这里
                // 先记下意图，等它报 DISCONNECTED 之后再拉引擎（见
                // updateConnectionState），否则刚起的引擎会被它一起停掉。
                Logger.info(LogConfig.MODULE_UI,
                        "Proxy mode requested while VPN service still running; stopping it first");
                pendingProxyStart.set(true);
                proxyStartRetries = 0;
                ServiceUtil.stopVpnService(app);
                mainHandler.removeCallbacks(proxyStartFallback);
                mainHandler.postDelayed(proxyStartFallback, PROXY_START_FALLBACK_MS);
                return;
            }
            TunnelManager.get(app).start(config, null);
        } else {
            ServiceUtil.startVpnService(app, config, ConfigStore.getProxyPort(app));
        }
    }

    /** 断开：两条路径都要停。运行模式可以在设置里改，只按"当前模式"停会把另一条
     * 留在运行状态——例如 VPN 模式连着、切到代理模式再断开，VpnService 还活着，
     * 流量照样走 VPN，用户以为已经断开了。 */
    public void disconnect() {
        Application app = getApplication();
        Logger.info(LogConfig.MODULE_UI, "Disconnect requested");
        connectionState.setValue(VpnConnectionState.DISCONNECTING);
        clearPendingProxyStart();

        if (ServiceUtil.isVpnServiceRunning(app)) {
            ServiceUtil.stopVpnService(app);
        }
        TunnelManager.get(app).stop();
    }

    // ------------------------------------------------------------ 广播驱动

    /** VPN 状态广播 → 状态与统计数据更新（MainActivity 的接收器调用）。 */
    public void updateConnectionState(VpnConnectionState state) {
        Logger.info(LogConfig.MODULE_UI, "ViewModel state updated: " + state.getDisplayText());
        connectionState.setValue(state);
        if (state == VpnConnectionState.DISCONNECTED && pendingProxyStart.get()) {
            // VpnService 已经停下（它停引擎时广播的 DISCONNECTED）：现在可以
            // 安全地拉起代理模式的引擎了。
            startPendingProxyEngine();
        }
        if (state == VpnConnectionState.CONNECTED && connectedAtMs == 0) {
            connectedAtMs = System.currentTimeMillis();
            startTicker();
        } else if (state == VpnConnectionState.DISCONNECTED
                || state == VpnConnectionState.DISCONNECTING) {
            connectedAtMs = 0;
            duration.setValue(0L);
            sessions.setValue(-1);
        } else if (state == VpnConnectionState.CONNECTING) {
            connectedAtMs = 0;
            duration.setValue(0L);
        }
        // RECONNECTING：保留旧计时，重连成功后继续累计
    }

    /** 统计广播 → chips 数据。 */
    public void updateStats(long up, long down, long durationSec, int sessionCount) {
        uploadBytes.setValue(up);
        downloadBytes.setValue(down);
        if (durationSec >= 0) {
            duration.setValue(durationSec);
            if (connectedAtMs > 0) {
                // 用服务端时长反向校准本地计时基准，两处计时保持一致
                connectedAtMs = System.currentTimeMillis() - durationSec * 1000;
            }
        }
        if (sessionCount >= 0) {
            sessions.setValue(sessionCount);
        }
    }

    public void showMessage(String message) {
        messages.setValue(new Event<>(message));
    }

    /**
     * 启动被推迟的代理模式引擎（VpnService 已停）。
     *
     * <p>两条触发路径（DISCONNECTED 广播 / 延时兜底）都会进来，所以先确认
     * VpnService 真的退了再动引擎：它退出时会调 TunnelManager.stop()，我们在那
     * 之前启动的引擎会被一起停掉，界面就停在"连接中"但没有任何流量。</p>
     */
    private void startPendingProxyEngine() {
        if (!pendingProxyStart.get()) {
            return;
        }
        Application app = getApplication();
        if (ServiceUtil.isVpnServiceRunning(app)) {
            if (proxyStartRetries < PROXY_START_MAX_RETRIES) {
                ++proxyStartRetries;
                Logger.info(LogConfig.MODULE_UI,
                        "VPN service still running, delaying proxy start (attempt "
                                + proxyStartRetries + ")");
                mainHandler.removeCallbacks(proxyStartFallback);
                mainHandler.postDelayed(proxyStartFallback, PROXY_START_FALLBACK_MS);
                return;
            }
            // 退出得比预期慢：放弃这次自动启动，让用户手动重连，好过起一个
            // 几秒后就被拆掉的引擎。
            pendingProxyStart.set(false);
            proxyStartRetries = 0;
            mainHandler.removeCallbacks(proxyStartFallback);
            Logger.warning(LogConfig.MODULE_UI,
                    "VPN service still running after retries; proxy start aborted");
            return;
        }
        if (!pendingProxyStart.compareAndSet(true, false)) {
            return;
        }
        proxyStartRetries = 0;
        mainHandler.removeCallbacks(proxyStartFallback);

        EngineConfig config = ConfigStore.buildEngineConfig(app);
        if (config == null) {
            messages.setValue(new Event<>(app.getString(R.string.fcp_msg_psk_missing)));
            return;
        }
        Logger.info(LogConfig.MODULE_UI, "Starting proxy-mode engine after VPN service stopped");
        TunnelManager.get(app).start(config, null);
    }

    /** 作废"等 VPN 服务退出后再起代理引擎"的意图。 */
    private void clearPendingProxyStart() {
        pendingProxyStart.set(false);
        proxyStartRetries = 0;
        mainHandler.removeCallbacks(proxyStartFallback);
    }

    // ------------------------------------------------------------ 计时

    private void startTicker() {
        if (ticking.compareAndSet(false, true)) {
            mainHandler.removeCallbacks(durationTicker);
            mainHandler.postDelayed(durationTicker, 1000);
        }
    }

    // ------------------------------------------------------------ Getters

    public LiveData<VpnConnectionState> getConnectionState() {
        return connectionState;
    }

    public LiveData<Long> getUploadBytes() {
        return uploadBytes;
    }

    public LiveData<Long> getDownloadBytes() {
        return downloadBytes;
    }

    public LiveData<Long> getDuration() {
        return duration;
    }

    public LiveData<Integer> getSessions() {
        return sessions;
    }

    public LiveData<Event<String>> getMessages() {
        return messages;
    }

    @Override
    protected void onCleared() {
        super.onCleared();
        ticking.set(false);
        clearPendingProxyStart();
        mainHandler.removeCallbacks(durationTicker);
    }
}
