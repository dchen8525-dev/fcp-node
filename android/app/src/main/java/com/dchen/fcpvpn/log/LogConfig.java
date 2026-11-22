package com.dchen.fcpvpn.log;

/**
 * 日志配置常量
 */
public class LogConfig {
    // 内存缓冲区大小
    public static final int BUFFER_SIZE = 500;

    // 文件存储配置
    public static final int MAX_FILE_SIZE = 5 * 1024 * 1024;  // 5MB
    public static final int TOTAL_SIZE = 10 * 1024 * 1024;     // 10MB
    public static final String LOG_FILE_1 = "kcpvpn_part1.log";
    public static final String LOG_FILE_2 = "kcpvpn_part2.log";

    // 日志格式
    public static final String FORMAT = "[%s] [%s] [%s] %s";

    // 模块标识
    public static final String MODULE_VPN = "vpn";
    public static final String MODULE_KCP_CLIENT = "kcp_client";
    public static final String MODULE_KCP_SERVER = "kcp_server";
    public static final String MODULE_CRYPTO = "crypto";
    public static final String MODULE_SOCKS5 = "socks5";
    public static final String MODULE_UI = "ui";
    public static final String MODULE_RECONNECT = "reconnect";
}
