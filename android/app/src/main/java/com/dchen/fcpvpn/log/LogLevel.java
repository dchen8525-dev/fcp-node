package com.dchen.fcpvpn.log;

/**
 * 日志级别枚举
 */
public enum LogLevel {
    DEBUG(0, "DEBUG"),
    INFO(1, "INFO"),
    WARNING(2, "WARNING"),
    ERROR(3, "ERROR");

    private final int value;
    private final String name;

    LogLevel(int value, String name) {
        this.value = value;
        this.name = name;
    }

    public int getValue() {
        return value;
    }

    public String getName() {
        return name;
    }

    /**
     * 根据值获取级别
     */
    public static LogLevel fromValue(int value) {
        for (LogLevel level : values()) {
            if (level.value == value) {
                return level;
            }
        }
        return DEBUG;
    }

    public static LogLevel fromName(String name) {
        if (name == null) {
            return INFO;
        }
        for (LogLevel level : values()) {
            if (level.name.equalsIgnoreCase(name)) {
                return level;
            }
        }
        return INFO;
    }
}
