package com.dchen.fcpvpn.log;

import android.content.Context;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 日志文件写入器 - 循环存储
 */
public class LogWriter {

    private static final int BUFFER_SIZE = 8 * 1024;
    // 距上次落盘超过这个时间才 flush：把"每条日志一次 write+flush 系统调用"摊薄
    // 成至多每秒一次。日志在调用者线程上同步写盘，而调用者可能是网络接收线程甚至
    // 主线程，逐条 flush 会直接把存储延迟压到数据路径上。代价是进程被强杀时最多丢
    // 这一小段时间的调试日志，close() 会做最后一次 flush。
    private static final long FLUSH_INTERVAL_MS = 1000;

    private final Context context;
    private final AtomicLong currentFileSize;
    private final AtomicInteger currentFileIndex;
    private BufferedOutputStream currentOutputStream;
    private long lastFlushMs;

    private volatile boolean writing;

    public LogWriter(Context context) {
        this.context = context;
        this.currentFileSize = new AtomicLong(0);
        this.currentFileIndex = new AtomicInteger(1);
        this.writing = false;

        initFile();
    }

    private File logDir() {
        File dir = context.getExternalFilesDir(null);
        return dir != null ? dir : context.getFilesDir();
    }

    /**
     * 初始化日志文件。
     * 必须挑出"上次运行真正在写的那个文件"再追加，而不是固定追加 LOG_FILE_1：
     * 轮转是"写满就切到另一个、并清空它"，所以两个文件里 lastModified 更新的
     * 那个才是当前的。旧实现固定追加 file1 且把 index 固定为 1，重启后第一次写满
     * 就 switchFile() 切到 file2 并把它删掉——那正是最近的一段日志。
     */
    private void initFile() {
        try {
            File logDir = logDir();
            File file1 = new File(logDir, LogConfig.LOG_FILE_1);
            File file2 = new File(logDir, LogConfig.LOG_FILE_2);

            File current;
            int index;
            if (file1.exists() && file2.exists()) {
                boolean oneIsNewer = file1.lastModified() >= file2.lastModified();
                current = oneIsNewer ? file1 : file2;
                index = oneIsNewer ? 1 : 2;
            } else {
                current = file1;
                index = 1;
            }

            if (!current.exists()) {
                current.createNewFile();
            }

            currentFileSize.set(current.length());
            currentOutputStream = new BufferedOutputStream(
                    new FileOutputStream(current, true), BUFFER_SIZE);
            currentFileIndex.set(index);
            lastFlushMs = System.currentTimeMillis();
            writing = true;

        } catch (IOException e) {
            writing = false;
            android.util.Log.e("KCPVPN", "Log file init failed: " + e.getMessage());
        }
    }

    /**
     * 写入日志
     */
    public synchronized void write(LogEntry entry) {
        BufferedOutputStream out = currentOutputStream;
        if (!writing || out == null) {
            return;
        }

        try {
            String line = entry.format() + "\n";
            byte[] data = line.getBytes(StandardCharsets.UTF_8);

            // 检查文件大小
            if (currentFileSize.get() + data.length > LogConfig.MAX_FILE_SIZE) {
                switchFile();
                out = currentOutputStream;
                if (out == null) {
                    return;
                }
            }

            out.write(data);
            currentFileSize.addAndGet(data.length);

            long now = System.currentTimeMillis();
            if (now - lastFlushMs >= FLUSH_INTERVAL_MS) {
                out.flush();
                lastFlushMs = now;
            }

        } catch (IOException e) {
            // 写失败：停用文件日志，避免此后每条日志都在死流上抛异常又被吞掉。
            writing = false;
            android.util.Log.e("KCPVPN", "Log write failed, file logging disabled: " + e.getMessage());
        }
    }

    /**
     * 切换日志文件
     */
    private void switchFile() {
        // 先把字段清空再动 I/O：任何一步抛异常时 currentOutputStream 必须是 null，
        // 而不是指向一个已经关闭的流——否则后续每次 write 都抛 IOException 又被吞掉，
        // 文件日志在进程剩余生命周期里静默失效。
        BufferedOutputStream old = currentOutputStream;
        currentOutputStream = null;

        try {
            if (old != null) {
                old.flush();
                old.close();
            }

            // 切换到另一个文件
            int nextIndex = (currentFileIndex.get() == 1) ? 2 : 1;
            String nextFileName = (nextIndex == 1) ? LogConfig.LOG_FILE_1 : LogConfig.LOG_FILE_2;

            File nextFile = new File(logDir(), nextFileName);

            // 清空目标文件
            if (nextFile.exists()) {
                nextFile.delete();
            }
            nextFile.createNewFile();

            currentOutputStream = new BufferedOutputStream(
                    new FileOutputStream(nextFile, false), BUFFER_SIZE);
            currentFileSize.set(0);
            currentFileIndex.set(nextIndex);
            lastFlushMs = System.currentTimeMillis();

        } catch (IOException e) {
            writing = false;
            android.util.Log.e("KCPVPN", "Log rotation failed, file logging disabled: " + e.getMessage());
        }
    }

    /**
     * 清空所有日志文件
     */
    public synchronized void clear() {
        try {
            if (currentOutputStream != null) {
                currentOutputStream.flush();
                currentOutputStream.close();
                currentOutputStream = null;
            }

            File logDir = logDir();
            File file1 = new File(logDir, LogConfig.LOG_FILE_1);
            File file2 = new File(logDir, LogConfig.LOG_FILE_2);

            if (file1.exists()) {
                file1.delete();
                file1.createNewFile();
            }
            if (file2.exists()) {
                file2.delete();
            }

            // 重新打开文件1
            currentOutputStream = new BufferedOutputStream(
                    new FileOutputStream(file1, false), BUFFER_SIZE);
            currentFileSize.set(0);
            currentFileIndex.set(1);
            lastFlushMs = System.currentTimeMillis();
            writing = true;

        } catch (IOException e) {
            writing = false;
            android.util.Log.e("KCPVPN", "Log clear failed: " + e.getMessage());
        }
    }

    /**
     * 关闭写入器
     */
    public synchronized void close() {
        writing = false;
        try {
            if (currentOutputStream != null) {
                currentOutputStream.flush();
                currentOutputStream.close();
                currentOutputStream = null;
            }
        } catch (IOException e) {
            android.util.Log.e("KCPVPN", "Log close failed: " + e.getMessage());
        }
    }

    /**
     * 获取日志目录路径
     */
    public String getLogDirectory() {
        return logDir().getAbsolutePath();
    }
}
