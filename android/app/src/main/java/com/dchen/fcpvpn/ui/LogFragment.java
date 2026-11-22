package com.dchen.fcpvpn.ui;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.dchen.fcpvpn.R;
import com.dchen.fcpvpn.databinding.FragmentLogBinding;
import com.dchen.fcpvpn.log.LogEntry;
import com.dchen.fcpvpn.log.LogLevel;
import com.dchen.fcpvpn.log.Logger;
import com.google.android.material.snackbar.Snackbar;

import java.lang.ref.WeakReference;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.function.Consumer;

/**
 * 日志页 —— 顶部过滤 chips（全部/信息/警告/错误）+ 深色控制台风格 RecyclerView。
 */
public class LogFragment extends Fragment {

    private FragmentLogBinding binding;
    private LogAdapter logAdapter;
    private RecyclerView recyclerView;

    // 初始显示所有日志，使用最低级别 DEBUG（value=0）作为"全部"
    private LogLevel currentLogLevel = LogLevel.DEBUG;
    private Consumer<LogEntry> logListener;
    private final List<LogEntry> pendingUiLogs = Collections.synchronizedList(new ArrayList<>());
    private final android.os.Handler uiLogHandler =
            new android.os.Handler(android.os.Looper.getMainLooper());
    private volatile boolean uiFlushScheduled;

    public LogFragment() {
        // Required empty public constructor
    }

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        binding = FragmentLogBinding.inflate(inflater, container, false);
        return binding.getRoot();
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        recyclerView = binding.recyclerLog;
        logAdapter = new LogAdapter(new ArrayList<>());
        recyclerView.setLayoutManager(new LinearLayoutManager(requireContext()));
        recyclerView.setAdapter(logAdapter);

        binding.chipFilterAll.setOnClickListener(v -> setFilter(LogLevel.DEBUG));
        binding.chipFilterInfo.setOnClickListener(v -> setFilter(LogLevel.INFO));
        binding.chipFilterWarning.setOnClickListener(v -> setFilter(LogLevel.WARNING));
        binding.chipFilterError.setOnClickListener(v -> setFilter(LogLevel.ERROR));

        binding.btnCopyLog.setOnClickListener(v -> copyLogsToClipboard());
        binding.btnClearLog.setOnClickListener(v -> {
            Logger.getInstance().clear();
            if (logAdapter != null) {
                logAdapter.clear();
            }
        });
    }

    @Override
    public void onResume() {
        super.onResume();
        // 先移除再添加，防止 onResume 重复调用导致监听器堆积
        removeLogListener();
        createLogListener();
        Logger.getInstance().addListener(logListener);
        refreshLogs();
    }

    @Override
    public void onPause() {
        super.onPause();
        removeLogListener();
        uiLogHandler.removeCallbacksAndMessages(null);
        pendingUiLogs.clear();
        uiFlushScheduled = false;
    }

    @Override
    public void onDestroyView() {
        super.onDestroyView();
        binding = null;
        recyclerView = null;
    }

    private void setFilter(LogLevel level) {
        currentLogLevel = level;
        refreshLogs();
    }

    private void removeLogListener() {
        if (logListener != null) {
            Logger.getInstance().removeListener(logListener);
        }
    }

    /** 日志监听器（WeakReference 防泄漏），按当前过滤级别入队。 */
    private void createLogListener() {
        if (logListener == null) {
            WeakReference<LogFragment> weakThis = new WeakReference<>(this);
            logListener = entry -> {
                LogFragment fragment = weakThis.get();
                if (fragment != null && fragment.isAdded() && !fragment.isRemoving()
                        && fragment.getActivity() != null
                        && !fragment.getActivity().isFinishing()) {
                    if (entry.getLevel().getValue() >= fragment.currentLogLevel.getValue()) {
                        fragment.enqueueLogEntry(entry);
                    }
                }
            };
        }
    }

    private void copyLogsToClipboard() {
        if (logAdapter == null || logAdapter.getItemCount() == 0) {
            showSnackbar(getString(R.string.fcp_log_nothing_to_copy));
            return;
        }
        String logsText = logAdapter.getLogsText();
        ClipboardManager clipboard = (ClipboardManager) requireContext()
                .getSystemService(Context.CLIPBOARD_SERVICE);
        if (clipboard != null) {
            ClipData clip = ClipData.newPlainText("FCP VPN Logs", logsText);
            clipboard.setPrimaryClip(clip);
            showSnackbar(getString(R.string.fcp_log_copied, logAdapter.getItemCount()));
        }
    }

    private void showSnackbar(String message) {
        View view = binding != null ? binding.getRoot() : null;
        if (view != null && isAdded() && !isRemoving()) {
            android.app.Activity activity = getActivity();
            if (activity != null && !activity.isFinishing() && !activity.isDestroyed()) {
                Snackbar.make(view, message, Snackbar.LENGTH_SHORT).show();
            }
        }
    }

    /** 300ms 批量刷新，避免高频日志把 RecyclerView 打爆（kcp 同款节流）。 */
    private void enqueueLogEntry(LogEntry entry) {
        android.app.Activity activity = getActivity();
        if (activity == null || !isAdded() || isRemoving() || activity.isFinishing()) {
            return;
        }
        pendingUiLogs.add(entry);
        if (!uiFlushScheduled) {
            uiFlushScheduled = true;
            uiLogHandler.postDelayed(this::flushPendingLogs, 300);
        }
    }

    private void flushPendingLogs() {
        uiFlushScheduled = false;
        List<LogEntry> batch;
        synchronized (pendingUiLogs) {
            if (pendingUiLogs.isEmpty()) {
                return;
            }
            batch = new ArrayList<>(pendingUiLogs);
            pendingUiLogs.clear();
        }

        for (LogEntry entry : batch) {
            if (logAdapter == null || !isAdded() || isRemoving()) {
                return;
            }
            logAdapter.addLog(entry);
        }
        if (recyclerView != null && logAdapter != null && logAdapter.getItemCount() > 0) {
            recyclerView.scrollToPosition(logAdapter.getItemCount() - 1);
        }
    }

    private void refreshLogs() {
        if (logAdapter == null || recyclerView == null) {
            return;
        }
        List<LogEntry> logs = Logger.getInstance().getBuffer().getByLevel(currentLogLevel);
        logAdapter.updateLogs(logs);
        if (!logs.isEmpty()) {
            recyclerView.scrollToPosition(logs.size() - 1);
        }
    }
}
