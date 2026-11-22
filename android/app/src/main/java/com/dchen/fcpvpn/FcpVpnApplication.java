package com.dchen.fcpvpn;

import android.app.Application;

import com.dchen.fcpvpn.log.LogLevel;
import com.dchen.fcpvpn.log.Logger;

/**
 * 应用入口 —— 初始化日志系统；Android 12+ 应用 Material You 动态取色
 * （低版本自动回退到 themes.xml 里的固定青绿品牌色）。
 */
public class FcpVpnApplication extends Application {

    @Override
    public void onCreate() {
        super.onCreate();

        // 日志系统最先初始化（kcp 同款）
        Logger.init(getApplicationContext());
        Logger.getInstance().setMinLevel(LogLevel.fromName(BuildConfig.DEFAULT_LOG_LEVEL));

        // Material 3 dynamic color：S+ 上随壁纸取色，<S 上此调用内部自动跳过
        com.google.android.material.color.DynamicColors.applyToActivitiesIfAvailable(this);
    }
}
