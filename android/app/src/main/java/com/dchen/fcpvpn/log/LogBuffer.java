package com.dchen.fcpvpn.log;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

/**
 * 日志内存缓冲区 - 环形缓冲区，用于实时显示
 * 使用 ArrayDeque 替代 CopyOnWriteArrayList，避免每次 add 都复制整个数组
 */
public class LogBuffer {

    private final int maxSize;
    private final Deque<LogEntry> entries;
    private final List<Consumer<LogEntry>> listeners;

    public LogBuffer() {
        this.maxSize = LogConfig.BUFFER_SIZE;
        this.entries = new ArrayDeque<>(maxSize);
        this.listeners = new CopyOnWriteArrayList<>();
    }

    /**
     * 添加日志条目
     */
    public void add(LogEntry entry) {
        synchronized (this) {
            if (entries.size() >= maxSize) {
                entries.removeFirst();
            }
            entries.addLast(entry);
        }

        for (Consumer<LogEntry> listener : listeners) {
            listener.accept(entry);
        }
    }

    /**
     * 获取所有条目
     */
    public synchronized List<LogEntry> getAll() {
        return new ArrayList<>(entries);
    }

    /**
     * 获取指定级别的条目
     */
    public synchronized List<LogEntry> getByLevel(LogLevel level) {
        List<LogEntry> result = new ArrayList<>();
        for (LogEntry entry : entries) {
            if (entry.getLevel().getValue() >= level.getValue()) {
                result.add(entry);
            }
        }
        return result;
    }

    /**
     * 清空缓冲区
     */
    public synchronized void clear() {
        entries.clear();
    }

    /**
     * 获取条目数量
     */
    public synchronized int size() {
        return entries.size();
    }

    /**
     * 添加监听器
     */
    public void addListener(Consumer<LogEntry> listener) {
        listeners.add(listener);
    }

    /**
     * 移除监听器
     */
    public void removeListener(Consumer<LogEntry> listener) {
        listeners.remove(listener);
    }
}
