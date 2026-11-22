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

        if (ConfigStore.RUN_MODE_PROXY.equals(mode)) {
            // 仅本机代理：不走 VpnService，直接管理引擎生命周期。
            // protector 传 null（不在 VPN 内无需保护）。
            TunnelManager.get(app).start(config, null);
        } else {
            ServiceUtil.startVpnService(app, config, ConfigStore.getProxyPort(app));
        }
    }

    /** 断开：VPN 模式发 ACTION_STOP；仅代理模式直接停引擎。 */
    public void disconnect() {
        Application app = getApplication();
        Logger.info(LogConfig.MODULE_UI, "Disconnect requested");
        connectionState.setValue(VpnConnectionState.DISCONNECTING);

        if (ConfigStore.RUN_MODE_PROXY.equals(ConfigStore.getRunMode(app))) {
            TunnelManager.get(app).stop();
        } else {
            ServiceUtil.stopVpnService(app);
        }
    }

    // ------------------------------------------------------------ 广播驱动

    /** VPN 状态广播 → 状态与统计数据更新（MainActivity 的接收器调用）。 */
    public void updateConnectionState(VpnConnectionState state) {
        Logger.info(LogConfig.MODULE_UI, "ViewModel state updated: " + state.getDisplayText());
        connectionState.setValue(state);
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
        mainHandler.removeCallbacks(durationTicker);
    }
}
