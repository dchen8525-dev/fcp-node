package com.dchen.fcpvpn.util;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkInfo;
import android.os.Build;

/**
 * 网络工具类
 */
public class NetworkUtil {

    /**
     * 检查网络是否可用
     */
    public static boolean isNetworkAvailable(Context context) {
        ConnectivityManager manager = (ConnectivityManager)
                context.getSystemService(Context.CONNECTIVITY_SERVICE);

        if (manager == null) {
            return false;
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            Network network = manager.getActiveNetwork();
            if (network == null) {
                return false;
            }

            NetworkCapabilities capabilities = manager.getNetworkCapabilities(network);
            if (capabilities == null) {
                return false;
            }

            // 必须包含 TRANSPORT_VPN：有 VPN 活动时 getActiveNetwork() 返回的就是
            // 那个 VPN 网络，它的能力位是 TRANSPORT_VPN 而不是底层承载。只认
            // WIFI/CELLULAR/ETHERNET 会让"本机已有 VPN（本应用的隧道、always-on
            // VPN 或第三方 VPN）"被误判成"网络不可用"，界面直接拒绝连接。
            return capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
                    || capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)
                    || capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)
                    || capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN);
        } else {
            NetworkInfo info = manager.getActiveNetworkInfo();
            return info != null && info.isConnected();
        }
    }

    /**
     * 获取网络类型名称
     */
    public static String getNetworkTypeName(Context context) {
        ConnectivityManager manager = (ConnectivityManager)
                context.getSystemService(Context.CONNECTIVITY_SERVICE);

        if (manager == null) {
            return "Unknown";
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            Network network = manager.getActiveNetwork();
            if (network == null) {
                return "None";
            }

            NetworkCapabilities capabilities = manager.getNetworkCapabilities(network);
            if (capabilities == null) {
                return "Unknown";
            }

            if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
                return "WiFi";
            }
            if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) {
                return "Mobile";
            }
            if (capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) {
                return "Ethernet";
            }
            return "Other";
        } else {
            NetworkInfo info = manager.getActiveNetworkInfo();
            if (info == null) {
                return "None";
            }

            switch (info.getType()) {
                case ConnectivityManager.TYPE_WIFI:
                    return "WiFi";
                case ConnectivityManager.TYPE_MOBILE:
                    return "Mobile";
                case ConnectivityManager.TYPE_ETHERNET:
                    return "Ethernet";
                default:
                    return "Other";
            }
        }
    }
}
