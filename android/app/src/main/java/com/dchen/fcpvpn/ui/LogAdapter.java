package com.dchen.fcpvpn.ui;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;
import androidx.annotation.NonNull;
import androidx.core.content.ContextCompat;
import androidx.recyclerview.widget.RecyclerView;

import com.dchen.fcpvpn.R;
import com.dchen.fcpvpn.log.LogEntry;
import com.dchen.fcpvpn.log.LogLevel;

import java.util.ArrayList;
import java.util.List;

/**
 * 日志列表适配器 —— 深色控制台风格：级别着色 + 等宽字体（布局层控制）。
 */
public class LogAdapter extends RecyclerView.Adapter<LogAdapter.LogViewHolder> {

    private final List<LogEntry> logs;
    private final Handler mainHandler = new Handler(Looper.getMainLooper());

    private static final int MAX_LOGS = 500;

    public LogAdapter(List<LogEntry> logs) {
        this.logs = logs != null ? logs : new ArrayList<>();
    }

    @NonNull
    @Override
    public LogViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View view = LayoutInflater.from(parent.getContext())
                .inflate(R.layout.item_log, parent, false);
        return new LogViewHolder(view);
    }

    @Override
    public void onBindViewHolder(@NonNull LogViewHolder holder, int position) {
        holder.bind(logs.get(position));
    }

    @Override
    public int getItemCount() {
        return logs.size();
    }

    /** 添加日志（线程安全，自动切换到主线程） */
    public void addLog(LogEntry entry) {
        if (Looper.myLooper() == Looper.getMainLooper()) {
            addLogInternal(entry);
        } else {
            mainHandler.post(() -> addLogInternal(entry));
        }
    }

    private void addLogInternal(LogEntry entry) {
        if (logs.size() >= MAX_LOGS) {
            logs.remove(0);
            notifyItemRemoved(0);
        }
        logs.add(entry);
        notifyItemInserted(logs.size() - 1);
    }

    /** 更新所有日志（线程安全，自动切换到主线程） */
    public void updateLogs(List<LogEntry> newLogs) {
        Runnable task = () -> {
            logs.clear();
            logs.addAll(newLogs);
            notifyDataSetChanged();
        };
        if (Looper.myLooper() == Looper.getMainLooper()) {
            task.run();
        } else {
            mainHandler.post(task);
        }
    }

    /** 清空（线程安全） */
    public void clear() {
        Runnable task = () -> {
            logs.clear();
            notifyDataSetChanged();
        };
        if (Looper.myLooper() == Looper.getMainLooper()) {
            task.run();
        } else {
            mainHandler.post(task);
        }
    }

    /** 获取所有日志的格式化文本（用于复制） */
    public String getLogsText() {
        StringBuilder sb = new StringBuilder();
        for (LogEntry entry : logs) {
            sb.append(entry.format()).append("\n");
        }
        return sb.toString();
    }

    /** 日志条目 ViewHolder */
    static class LogViewHolder extends RecyclerView.ViewHolder {

        private final TextView tvLogLevel;
        private final TextView tvLogContent;

        public LogViewHolder(@NonNull View itemView) {
            super(itemView);
            tvLogLevel = itemView.findViewById(R.id.tv_log_level);
            tvLogContent = itemView.findViewById(R.id.tv_log_content);
        }

        public void bind(LogEntry entry) {
            tvLogLevel.setText(entry.getLevel().getName());
            tvLogLevel.setTextColor(levelColor(tvLogLevel.getContext(), entry.getLevel()));
            tvLogContent.setText(entry.getMessage());
        }

        /** 控制台级别配色：针对深色卡片底调校，两种主题下都可读。 */
        private static int levelColor(Context context, LogLevel level) {
            switch (level) {
                case INFO:
                    return ContextCompat.getColor(context, R.color.log_info);
                case WARNING:
                    return ContextCompat.getColor(context, R.color.log_warning);
                case ERROR:
                    return ContextCompat.getColor(context, R.color.log_error);
                case DEBUG:
                default:
                    return ContextCompat.getColor(context, R.color.log_debug);
            }
        }
    }
}
