package com.dchen.fcpvpn.ui;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.Bundle;

import androidx.activity.OnBackPressedCallback;
import androidx.appcompat.app.AppCompatActivity;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentManager;
import androidx.fragment.app.FragmentTransaction;
import androidx.lifecycle.ViewModelProvider;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;

import com.dchen.fcpvpn.R;
import com.dchen.fcpvpn.log.LogConfig;
import com.dchen.fcpvpn.log.Logger;
import com.dchen.fcpvpn.util.ServiceUtil;
import com.dchen.fcpvpn.vpn.VpnConnectionState;
import com.dchen.fcpvpn.vpn.VpnStateBroadcast;

/**
 * 主 Activity —— 单主页极简架构：容器承载 主页 / 日志 两个目的地，
 * 设置为独立 Activity（从主页齿轮进入）。
 */
public class MainActivity extends AppCompatActivity {

    private MainViewModel viewModel;
    private Fragment activeFragment;
    /** 日志页在前时拦截返回键先回主页；主页在前时放行（退出应用）。 */
    private OnBackPressedCallback logBackCallback;

    private BroadcastReceiver stateReceiver;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Logger.info(LogConfig.MODULE_UI, "MainActivity onCreate");

        viewModel = new ViewModelProvider(this).get(MainViewModel.class);

        initFragments();
        registerStateReceiver();
        setupBackHandling();
        syncVpnServiceState();

        // 首次启动无配置 → 自动进设置页并聚焦服务器地址
        if (!ConfigStore.isConfigured(this)) {
            Logger.info(LogConfig.MODULE_UI, "No config, jumping to Settings");
            Intent intent = new Intent(this, SettingsActivity.class);
            intent.putExtra(SettingsActivity.EXTRA_FOCUS_HOST, true);
            startActivity(intent);
        }
    }

    private void initFragments() {
        FragmentManager fm = getSupportFragmentManager();
        HomeFragment main = (HomeFragment) fm.findFragmentByTag("home");
        LogFragment log = (LogFragment) fm.findFragmentByTag("log");

        if (main == null) {
            main = new HomeFragment();
        }
        if (log == null) {
            log = new LogFragment();
        }

        if (!main.isAdded()) {
            FragmentTransaction transaction = fm.beginTransaction();
            transaction.add(R.id.fragment_container, main, "home");
            if (!log.isAdded()) {
                transaction.add(R.id.fragment_container, log, "log");
                transaction.hide(log);
            }
            transaction.commitNow();
        } else if (!log.isAdded()) {
            FragmentTransaction transaction = fm.beginTransaction();
            transaction.add(R.id.fragment_container, log, "log");
            transaction.hide(log);
            transaction.commitNow();
        }

        // 恢复（旋转/进程重建）后确定当前显示的 Fragment
        if (main.isVisible()) {
            activeFragment = main;
        } else if (log.isVisible()) {
            activeFragment = log;
        } else {
            activeFragment = main;
        }
    }

    /** 系统返回键：日志页先回主页，主页才退出应用。 */
    private void setupBackHandling() {
        logBackCallback = new OnBackPressedCallback(false) {
            @Override
            public void handleOnBackPressed() {
                showHome();
            }
        };
        getOnBackPressedDispatcher().addCallback(this, logBackCallback);
        logBackCallback.setEnabled(activeFragment instanceof LogFragment);
    }

    /** 主页 → 日志（由 HomeFragment 的"日志"入口调用）。 */
    public void openLog() {
        if (activeFragment instanceof LogFragment) {
            return;
        }
        switchTo("log");
    }

    private void showHome() {
        switchTo("home");
    }

    private void switchTo(String tag) {
        FragmentManager fm = getSupportFragmentManager();
        Fragment target = fm.findFragmentByTag(tag);
        Fragment other = fm.findFragmentByTag("home".equals(tag) ? "log" : "home");
        if (target == null || other == null || target == activeFragment) {
            return;
        }
        if (fm.isStateSaved()) {
            return;
        }
        fm.beginTransaction()
                .hide(other)
                .show(target)
                .commitNowAllowingStateLoss();
        activeFragment = target;
        if (logBackCallback != null) {
            logBackCallback.setEnabled(activeFragment instanceof LogFragment);
        }
    }

    private void registerStateReceiver() {
        stateReceiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                if (!VpnStateBroadcast.ACTION_STATE_CHANGED.equals(intent.getAction())) {
                    return;
                }
                String stateName = intent.getStringExtra(VpnStateBroadcast.EXTRA_STATE);
                if (stateName == null || stateName.isEmpty()) {
                    Logger.error(LogConfig.MODULE_UI, "Broadcast received with null state");
                    return;
                }
                try {
                    VpnConnectionState state = VpnConnectionState.valueOf(stateName);
                    long upload = intent.getLongExtra(VpnStateBroadcast.EXTRA_UPLOAD_BYTES, 0);
                    long download = intent.getLongExtra(VpnStateBroadcast.EXTRA_DOWNLOAD_BYTES, 0);
                    long durationSec = intent.getLongExtra(VpnStateBroadcast.EXTRA_DURATION, -1);
                    int sessionsCount = intent.getIntExtra(VpnStateBroadcast.EXTRA_SESSIONS, -1);
                    viewModel.updateConnectionState(state);
                    viewModel.updateStats(upload, download, durationSec, sessionsCount);
                } catch (IllegalArgumentException e) {
                    Logger.error(LogConfig.MODULE_UI, "Unknown VPN state: " + stateName);
                }
            }
        };
        IntentFilter filter = new IntentFilter(VpnStateBroadcast.ACTION_STATE_CHANGED);
        LocalBroadcastManager.getInstance(this).registerReceiver(stateReceiver, filter);
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        if (stateReceiver != null) {
            LocalBroadcastManager.getInstance(this).unregisterReceiver(stateReceiver);
        }
    }

    /** 同步 VPN 服务的真实状态（进程死亡后恢复时调用）。 */
    private void syncVpnServiceState() {
        if (ServiceUtil.isVpnServiceRunning(this)) {
            Logger.info(LogConfig.MODULE_UI,
                    "VPN service is running in background, syncing UI state");
            viewModel.updateConnectionState(VpnConnectionState.CONNECTED);
        }
    }
}
