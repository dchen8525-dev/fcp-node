package com.dchen.fcpvpn.util;

import android.app.ActivityManager;
import android.content.Context;
import android.content.Intent;
import android.net.VpnService;

import com.dchen.fcpvpn.core.session.EngineConfig;
import com.dchen.fcpvpn.vpn.FcpVpnService;
import com.dchen.fcpvpn.vpn.VpnConfig;

/**
 * VPN 服务工具类（已按 FCP 语义调整：extras 携带完整引擎参数）。
 */
public class ServiceUtil {

    /**
     * 检查 VPN 授权状态
     * @return Intent 需要授权时返回授权 Intent，已授权返回 null
     */
    public static Intent checkVpnAuthorization(Context context) {
        return VpnService.prepare(context);
    }

    /**
     * 启动 VPN 服务（VPN 全局模式）。extras 携带完整引擎参数，
     * 键名与 {@link FcpVpnService} 的 EXTRA_* 常量一致。
     */
    public static void startVpnService(Context context, EngineConfig config, int proxyPort) {
        Intent intent = new Intent(context, FcpVpnService.class);
        intent.putExtra(FcpVpnService.EXTRA_SERVER_HOST, config.peerHost);
        intent.putExtra(FcpVpnService.EXTRA_SERVER_PORT, config.peerPort);
        intent.putExtra(FcpVpnService.EXTRA_PSK, config.pskHex32);
        intent.putExtra(FcpVpnService.EXTRA_FEC_DATA, config.fecData);
        intent.putExtra(FcpVpnService.EXTRA_FEC_PARITY_MAX, config.fecParityMax);
        intent.putExtra(FcpVpnService.EXTRA_MTU_MIN, config.mtuMin);
        intent.putExtra(FcpVpnService.EXTRA_PROBE_INTERVAL, config.probeIntervalSec);
        intent.putExtra(FcpVpnService.EXTRA_PROXY_PORT, proxyPort);

        // minSdk 30，恒走 startForegroundService
        context.startForegroundService(intent);
    }

    /**
     * 停止 VPN 服务。停服务用普通 startService：ACTION_STOP 路径不会调用
     * startForeground，若用 startForegroundService 会触发"5 秒内未进入前台"
     * 的系统异常（kcp 同款处理；停止总是用户在前台发起的）。
     */
    public static void stopVpnService(Context context) {
        Intent intent = new Intent(context, FcpVpnService.class);
        intent.setAction(FcpVpnService.ACTION_STOP);
        context.startService(intent);
    }

    /**
     * 检查 VPN 服务是否运行
     * 注意：这只是检查服务是否启动，不是 VPN 是否已建立会话
     */
    public static boolean isVpnServiceRunning(Context context) {
        // 通过查询服务状态来判断
        ActivityManager manager = (ActivityManager) context.getSystemService(Context.ACTIVITY_SERVICE);
        if (manager != null) {
            for (ActivityManager.RunningServiceInfo service : manager.getRunningServices(Integer.MAX_VALUE)) {
                if (FcpVpnService.class.getName().equals(service.service.getClassName())) {
                    return true;
                }
            }
        }
        return false;
    }

    /** 默认引擎配置（对齐 fcp-node CLI 默认值；PSK 为空时由调用方填充）。 */
    public static EngineConfig defaultEngineConfig(String host, int port, String psk) {
        return new EngineConfig(host, port, psk,
                VpnConfig.DEFAULT_FEC_DATA, VpnConfig.DEFAULT_FEC_PARITY_MAX,
                VpnConfig.DEFAULT_MTU_MIN, VpnConfig.DEFAULT_PROBE_INTERVAL_SEC,
                "info");
    }
}
