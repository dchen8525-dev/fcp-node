package com.dchen.fcpvpn;

import android.app.Application;

import com.dchen.fcpvpn.log.LogLevel;
import com.dchen.fcpvpn.log.Logger;

/**
 * 应用入口 —— 初始化日志系统。
 *
 * <p>配色固定走 themes.xml / colors.xml 的青绿品牌体系，<b>不启用 Material You
 * 动态取色</b>：S+ 上随壁纸取色会把品牌色替换成壁纸强调色（模拟器上是靛蓝），
 * 同一界面在不同壁纸下完全不同，也无法保证「连接/连接中/断开」三类状态色与
 * 品牌色的层次关系。</p>
 */
public class FcpVpnApplication extends Application {

    @Override
    public void onCreate() {
        super.onCreate();

        // 日志系统最先初始化（kcp 同款）
        Logger.init(getApplicationContext());
        Logger.getInstance().setMinLevel(LogLevel.fromName(BuildConfig.DEFAULT_LOG_LEVEL));
    }
}
