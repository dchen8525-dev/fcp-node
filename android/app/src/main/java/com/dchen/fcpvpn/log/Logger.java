package com.dchen.fcpvpn.log;

import android.content.Context;

import com.dchen.fcpvpn.BuildConfig;

/**
 * 日志管理器 - 统一日志接口
 * 支持分级日志、实时显示、文件持久化
 */
public class Logger {

    private static Logger instance;
    private static Context appContext;

    private final LogBuffer buffer;
    private LogWriter writer;
    private LogLevel minLevel = LogLevel.INFO;

    /**
     * 初始化日志系统
     * @param context 应用上下文
     */
    public static synchronized void init(Context context) {
        appContext = context.getApplicationContext();
        instance = new Logger();
    }

    /**
     * 获取实例
     */
    public static Logger getInstance() {
        if (instance == null) {
            throw new IllegalStateException("Logger not initialized");
        }
        return instance;
    }

    private Logger() {
        buffer = new LogBuffer();
        if (appContext != null) {
            writer = new LogWriter(appContext);
        }
    }

    /**
     * 设置最低日志级别
     */
    public void setMinLevel(LogLevel level) {
        this.minLevel = level;
    }

    /**
     * 记录日志
     */
    private void log(LogLevel level, String module, String message) {
        if (level.getValue() < minLevel.getValue()) {
            return;
        }

        LogEntry entry = new LogEntry(level, module, message);

        // 添加到缓冲区
        buffer.add(entry);

        // 写入文件
        if (writer != null) {
            writer.write(entry);
        }

        // 同时输出到 Android Logcat
        String tag = "KCPVPN_" + module;
        switch (level) {
            case DEBUG:
                android.util.Log.d(tag, message);
                break;
            case INFO:
                android.util.Log.i(tag, message);
                break;
            case WARNING:
                android.util.Log.w(tag, message);
                break;
            case ERROR:
                android.util.Log.e(tag, message);
                break;
        }
    }

    /**
     * Debug 级别日志
     */
    public static void debug(String module, String message) {
        Logger logger = instance;
        if (logger != null) {
            logger.log(LogLevel.DEBUG, module, message);
        }
    }

    /**
     * Info 级别日志
     */
    public static void info(String module, String message) {
        Logger logger = instance;
        if (logger != null) {
            logger.log(LogLevel.INFO, module, message);
        }
    }

    /**
     * 逐包诊断日志：每个 TUN 报文一条，量级远大于普通 DEBUG。
     * 由 BuildConfig.PACKET_TRACE_ENABLED 单独控制（debug 构建开启，release 关闭），
     * 因此即使临时把 release 调到 DEBUG 级别也不会泄漏逐包数据。
     * 用 Supplier 延迟拼装，关闭时不产生字符串开销。
     */
    public static void packetTrace(String module, java.util.function.Supplier<String> message) {
        if (!BuildConfig.PACKET_TRACE_ENABLED) {
            return;
        }
        Logger logger = instance;
        if (logger != null) {
            logger.log(LogLevel.DEBUG, module, message.get());
        }
    }

    /**
     * Warning 级别日志
     */
    public static void warning(String module, String message) {
        Logger logger = instance;
        if (logger != null) {
            logger.log(LogLevel.WARNING, module, message);
        }
    }

    /**
     * Error 级别日志
     */
    public static void error(String module, String message) {
        Logger logger = instance;
        if (logger != null) {
            logger.log(LogLevel.ERROR, module, message);
        }
    }

    /**
     * 获取内存缓冲区
     */
    public LogBuffer getBuffer() {
        return buffer;
    }

    /**
     * 清空日志
     */
    public void clear() {
        buffer.clear();
        if (writer != null) {
            writer.clear();
        }
    }

    /**
     * 关闭日志系统
     */
    public void close() {
        if (writer != null) {
            writer.close();
        }
    }

    /**
     * 获取日志目录
     */
    public String getLogDirectory() {
        if (writer != null) {
            return writer.getLogDirectory();
        }
        return "";
    }

    /**
     * 添加日志监听器
     */
    public void addListener(java.util.function.Consumer<LogEntry> listener) {
        buffer.addListener(listener);
    }

    /**
     * 移除日志监听器
     */
    public void removeListener(java.util.function.Consumer<LogEntry> listener) {
        buffer.removeListener(listener);
    }
}
