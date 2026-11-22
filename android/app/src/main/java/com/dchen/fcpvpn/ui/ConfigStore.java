package com.dchen.fcpvpn.ui;

import android.content.Context;
import android.content.SharedPreferences;

import com.dchen.fcpvpn.BuildConfig;
import com.dchen.fcpvpn.R;
import com.dchen.fcpvpn.core.session.EngineConfig;
import com.dchen.fcpvpn.util.SecretPrefs;
import com.dchen.fcpvpn.vpn.VpnConfig;

import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 连接配置的持久化与校验（UI 层存储）。
 * PSK 走 {@link SecretPrefs}（Keystore 包裹加密落盘）；其余参数明文。
 */
public final class ConfigStore {

    public static final String RUN_MODE_VPN = "vpn";
    public static final String RUN_MODE_PROXY = "proxy";

    private static final String PREFS_NAME = "fcp_config";
    private static final String KEY_SERVER_HOST = "server_host";
    private static final String KEY_SERVER_PORT = "server_port";
    private static final String KEY_REMEMBER_PSK = "remember_psk";
    private static final String KEY_RUN_MODE = "run_mode";
    private static final String KEY_FEC_DATA = "fec_data";
    private static final String KEY_FEC_PARITY_MAX = "fec_parity_max";
    private static final String KEY_MTU_MIN = "mtu_min";
    private static final String KEY_PROBE_INTERVAL = "probe_interval";
    private static final String KEY_PROXY_PORT = "proxy_port";
    /** 分应用代理白名单（VPN 模式）：空集合 = 全部应用。 */
    private static final String KEY_VPN_APPS = "vpn_apps";

    private static final Pattern IPV4_PATTERN =
            Pattern.compile("^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})$");
    private static final Pattern HOSTNAME_PATTERN =
            Pattern.compile("^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$");
    private static final Pattern IPV6_PATTERN =
            Pattern.compile("^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$");
    private static final Pattern PSK_PATTERN =
            Pattern.compile("^[0-9a-fA-F]{32}$");
    private static final Pattern NUMBER_PATTERN = Pattern.compile("^\\d{1,9}$");

    private ConfigStore() {
    }

    private static SharedPreferences prefs(Context context) {
        return context.getApplicationContext()
                .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
    }

    // ------------------------------------------------------------ 读取

    public static String getHost(Context context) {
        return prefs(context).getString(KEY_SERVER_HOST, "");
    }

    public static int getPort(Context context) {
        return prefs(context).getInt(KEY_SERVER_PORT, VpnConfig.DEFAULT_PEER_PORT);
    }

    /** PSK（已通过 SecretPrefs 解密）；未记住或解密失败返回空串。 */
    public static String getPsk(Context context) {
        if (!isRememberPsk(context)) {
            return "";
        }
        String psk = SecretPrefs.load(prefs(context));
        return psk == null ? "" : psk;
    }

    public static boolean isRememberPsk(Context context) {
        return prefs(context).getBoolean(KEY_REMEMBER_PSK, true);
    }

    public static String getRunMode(Context context) {
        return prefs(context).getString(KEY_RUN_MODE, RUN_MODE_VPN);
    }

    public static int getFecData(Context context) {
        return prefs(context).getInt(KEY_FEC_DATA, VpnConfig.DEFAULT_FEC_DATA);
    }

    public static int getFecParityMax(Context context) {
        return prefs(context).getInt(KEY_FEC_PARITY_MAX, VpnConfig.DEFAULT_FEC_PARITY_MAX);
    }

    public static int getMtuMin(Context context) {
        return prefs(context).getInt(KEY_MTU_MIN, VpnConfig.DEFAULT_MTU_MIN);
    }

    public static int getProbeIntervalSec(Context context) {
        return prefs(context).getInt(KEY_PROBE_INTERVAL, VpnConfig.DEFAULT_PROBE_INTERVAL_SEC);
    }

    public static int getProxyPort(Context context) {
        return prefs(context).getInt(KEY_PROXY_PORT, VpnConfig.DEFAULT_PROXY_PORT);
    }

    /**
     * 分应用代理白名单（仅 VPN 模式使用）。
     * 空集合 = 不启用白名单，全部应用走 VPN；非空 = 只有这些包名走 VPN。
     */
    public static java.util.Set<String> getVpnApps(Context context) {
        java.util.Set<String> stored = prefs(context).getStringSet(KEY_VPN_APPS, null);
        return stored == null
                ? new java.util.HashSet<String>()
                : new java.util.HashSet<String>(stored);
    }

    public static void setVpnApps(Context context, java.util.Set<String> apps) {
        prefs(context).edit()
                .putStringSet(KEY_VPN_APPS,
                        apps == null ? new java.util.HashSet<String>()
                                : new java.util.HashSet<String>(apps))
                .apply();
    }

    /** 服务器地址是否已配置完整（host + port + PSK）。 */
    public static boolean isConfigured(Context context) {
        return !getHost(context).trim().isEmpty()
                && isPortValid(getPort(context))
                && !getPsk(context).trim().isEmpty();
    }

    /** 由存储的配置构建引擎配置（PSK 未记住时返回 null，由调用方提示）。 */
    public static EngineConfig buildEngineConfig(Context context) {
        String psk = getPsk(context).trim();
        if (psk.isEmpty()) {
            return null;
        }
        return new EngineConfig(
                getHost(context).trim(),
                getPort(context),
                psk,
                getFecData(context),
                getFecParityMax(context),
                getMtuMin(context),
                getProbeIntervalSec(context),
                BuildConfig.DEFAULT_LOG_LEVEL.toLowerCase(Locale.US));
    }

    // ------------------------------------------------------------ 保存

    public static void save(Context context, String host, int port, String psk,
                            boolean rememberPsk, String runMode,
                            int fecData, int fecParityMax, int mtuMin,
                            int probeIntervalSec, int proxyPort) {
        SharedPreferences p = prefs(context);
        SharedPreferences.Editor editor = p.edit()
                .putString(KEY_SERVER_HOST, host == null ? "" : host.trim())
                .putInt(KEY_SERVER_PORT, port)
                .putBoolean(KEY_REMEMBER_PSK, rememberPsk)
                .putString(KEY_RUN_MODE, runMode)
                .putInt(KEY_FEC_DATA, fecData)
                .putInt(KEY_FEC_PARITY_MAX, fecParityMax)
                .putInt(KEY_MTU_MIN, mtuMin)
                .putInt(KEY_PROBE_INTERVAL, probeIntervalSec)
                .putInt(KEY_PROXY_PORT, proxyPort);
        if (rememberPsk && psk != null && !psk.trim().isEmpty()) {
            SecretPrefs.save(p, psk.trim());
        } else {
            // 不记住 / 清空：把密文也清掉
            SecretPrefs.clear(p);
        }
        editor.apply();
    }

    // ------------------------------------------------------------ 校验（返回 null 合法，否则错误文案）

    public static String validateHost(Context context, String input) {
        String host = input == null ? "" : input.trim();
        if (host.isEmpty()) {
            return context.getString(R.string.fcp_error_host_empty);
        }
        if (host.length() > 253) {
            return context.getString(R.string.fcp_error_host_invalid);
        }
        Matcher m = IPV4_PATTERN.matcher(host);
        if (m.matches()) {
            for (int i = 1; i <= 4; i++) {
                if (Integer.parseInt(m.group(i)) > 255) {
                    return context.getString(R.string.fcp_error_host_invalid);
                }
            }
            return null;
        }
        if (host.contains(":")) {
            // IPv6 字面量粗校验：只允许 hex 与冒号
            if (IPV6_PATTERN.matcher(host).matches()) {
                return null;
            }
            return context.getString(R.string.fcp_error_host_invalid);
        }
        if (HOSTNAME_PATTERN.matcher(host).matches()) {
            return null;
        }
        return context.getString(R.string.fcp_error_host_invalid);
    }

    public static String validatePort(Context context, String input) {
        Integer v = parseIntOrNull(input);
        if (v == null || !isPortValid(v)) {
            return context.getString(R.string.fcp_error_port);
        }
        return null;
    }

    /** PSK：必须恰好 32 位十六进制。 */
    public static String validatePsk(Context context, String input) {
        String psk = input == null ? "" : input.trim();
        if (psk.isEmpty()) {
            return context.getString(R.string.fcp_error_psk_empty);
        }
        if (!PSK_PATTERN.matcher(psk).matches()) {
            return context.getString(R.string.fcp_error_psk_invalid);
        }
        return null;
    }

    /** 数值范围校验（fec-data / parity / mtu / probe / 代理端口）。 */
    public static String validateIntRange(Context context, String input, int min, int max) {
        Integer v = parseIntOrNull(input);
        if (v == null) {
            return context.getString(R.string.fcp_error_number);
        }
        if (v < min || v > max) {
            return context.getString(R.string.fcp_error_range, min, max);
        }
        return null;
    }

    static Integer parseIntOrNull(String input) {
        String s = input == null ? "" : input.trim();
        if (!NUMBER_PATTERN.matcher(s).matches()) {
            return null;
        }
        try {
            return Integer.parseInt(s);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    private static boolean isPortValid(int v) {
        return v >= 1 && v <= 65535;
    }
}
