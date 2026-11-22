package com.dchen.fcpvpn.ui;

import android.Manifest;
import android.animation.ValueAnimator;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.Fragment;
import androidx.lifecycle.ViewModelProvider;

import com.dchen.fcpvpn.R;
import com.dchen.fcpvpn.databinding.FragmentHomeBinding;
import com.dchen.fcpvpn.log.LogConfig;
import com.dchen.fcpvpn.log.Logger;
import com.dchen.fcpvpn.util.ServiceUtil;
import com.dchen.fcpvpn.vpn.VpnConnectionState;
import com.google.android.material.color.MaterialColors;
import com.google.android.material.snackbar.Snackbar;

import java.util.Locale;

/**
 * 主页 —— 一张状态英雄卡 + 速率 chips + 次要操作行（M3 Expressive 极简风）。
 * 五个状态（无配置/已配置/连接中/已连接/断开）都只在英雄卡内表达。
 */
public class HomeFragment extends Fragment {

    private MainViewModel viewModel;
    private FragmentHomeBinding binding;

    private boolean waitingVpnAuth = false;

    private ActivityResultLauncher<Intent> vpnAuthLauncher;
    private ActivityResultLauncher<String> notificationPermissionLauncher;

    @Override
    public void onCreate(@Nullable Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        vpnAuthLauncher = registerForActivityResult(
                new ActivityResultContracts.StartActivityForResult(),
                result -> {
                    waitingVpnAuth = false;
                    if (result.getResultCode() == android.app.Activity.RESULT_OK) {
                        Logger.info(LogConfig.MODULE_UI, "VPN authorization granted");
                        viewModel.connect();
                    } else {
                        // 授权被拒：Snackbar 引导，不弹错误对话框
                        Logger.warning(LogConfig.MODULE_UI, "VPN authorization denied");
                        showMessage(getString(R.string.fcp_vpn_denied));
                    }
                });
        notificationPermissionLauncher = registerForActivityResult(
                new ActivityResultContracts.RequestPermission(),
                granted -> {
                    if (!granted) {
                        Logger.warning(LogConfig.MODULE_UI, "Notification permission denied");
                        showMessage(getString(R.string.fcp_notif_denied));
                    }
                    // 无论通知权限结果如何，继续走 VPN 授权流程
                    requestVpnAuthOrStart();
                });
    }

    @Nullable
    @Override
    public View onCreateView(@NonNull LayoutInflater inflater, @Nullable ViewGroup container,
                             @Nullable Bundle savedInstanceState) {
        binding = FragmentHomeBinding.inflate(inflater, container, false);
        return binding.getRoot();
    }

    @Override
    public void onViewCreated(@NonNull View view, @Nullable Bundle savedInstanceState) {
        super.onViewCreated(view, savedInstanceState);

        viewModel = new ViewModelProvider(requireActivity()).get(MainViewModel.class);

        binding.btnMain.setOnClickListener(v -> onMainButtonClicked());
        binding.btnLog.setOnClickListener(v -> {
            android.app.Activity activity = getActivity();
            if (activity instanceof MainActivity) {
                ((MainActivity) activity).openLog();
            }
        });
        binding.btnSettings.setOnClickListener(v ->
                startActivity(new Intent(requireContext(), SettingsActivity.class)));
        binding.vpnAppsCard.setOnClickListener(v ->
                startActivity(new Intent(requireContext(), AppPickerActivity.class)));

        renderServerInfo();
        observeViewModel();
    }

    @Override
    public void onResume() {
        super.onResume();
        // 从设置页回来后刷新服务器行
        renderServerInfo();
        VpnConnectionState state = viewModel.getConnectionState().getValue();
        if (state != null) {
            renderState(state);
        }
    }

    @Override
    public void onDestroyView() {
        super.onDestroyView();
        binding = null;
    }

    // ------------------------------------------------------------ 交互

    private void onMainButtonClicked() {
        VpnConnectionState state = viewModel.getConnectionState().getValue();
        if (state == VpnConnectionState.CONNECTED
                || state == VpnConnectionState.CONNECTING
                || state == VpnConnectionState.RECONNECTING
                || state == VpnConnectionState.DISCONNECTING) {
            viewModel.disconnect();
            return;
        }
        startConnectionFlow();
    }

    private void startConnectionFlow() {
        if (!ConfigStore.isConfigured(requireContext())) {
            showMessage(getString(R.string.fcp_msg_not_configured));
            return;
        }
        if (ConfigStore.RUN_MODE_PROXY.equals(ConfigStore.getRunMode(requireContext()))) {
            // 代理端口模式：不建 TUN，只管理引擎生命周期（1080 监听由 TunnelManager 拉起）
            viewModel.connect();
            return;
        }
        // VPN 模式：通知权限（Android 13+）→ VPN 授权 → 启动服务
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU
                && ContextCompat.checkSelfPermission(requireContext(),
                Manifest.permission.POST_NOTIFICATIONS)
                != android.content.pm.PackageManager.PERMISSION_GRANTED) {
            notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS);
            return;
        }
        requestVpnAuthOrStart();
    }

    private void requestVpnAuthOrStart() {
        if (waitingVpnAuth) {
            return;
        }
        Intent prepare = ServiceUtil.checkVpnAuthorization(requireContext());
        if (prepare != null) {
            waitingVpnAuth = true;
            vpnAuthLauncher.launch(prepare);
        } else {
            viewModel.connect();
        }
    }

    private void showMessage(String message) {
        View root = binding != null ? binding.getRoot() : null;
        if (root != null && isAdded() && !isRemoving()) {
            Snackbar.make(root, message, Snackbar.LENGTH_SHORT).show();
        }
    }

    // ------------------------------------------------------------ 渲染

    private void renderServerInfo() {
        String host = ConfigStore.getHost(requireContext()).trim();
        if (host.isEmpty()) {
            binding.serverText.setText(R.string.fcp_server_unconfigured);
        } else {
            binding.serverText.setText(host + ":" + ConfigStore.getPort(requireContext()));
        }
        binding.proxyHint.setText(getString(R.string.fcp_mixed_proxy_hint,
                ConfigStore.getProxyPort(requireContext())));

        boolean proxyMode = ConfigStore.RUN_MODE_PROXY.equals(
                ConfigStore.getRunMode(requireContext()));
        binding.modeBadge.setText(proxyMode
                ? R.string.fcp_mode_proxy : R.string.fcp_mode_vpn);
        // 按应用代理只在 VPN 模式有意义：代理服务模式不接管流量，白名单没有作用对象。
        if (proxyMode) {
            binding.vpnAppsSub.setText(R.string.fcp_apps_proxy_mode_hint);
        } else {
            int apps = ConfigStore.getVpnApps(requireContext()).size();
            binding.vpnAppsSub.setText(apps == 0
                    ? getString(R.string.fcp_apps_all)
                    : getString(R.string.fcp_apps_selected, apps));
        }
    }

    private void observeViewModel() {
        viewModel.getConnectionState().observe(getViewLifecycleOwner(), this::renderState);
        viewModel.getUploadBytes().observe(getViewLifecycleOwner(),
                v -> renderRates());
        viewModel.getDownloadBytes().observe(getViewLifecycleOwner(),
                v -> renderRates());
        viewModel.getSessions().observe(getViewLifecycleOwner(), v -> {
            VpnConnectionState state = viewModel.getConnectionState().getValue();
            if (state == VpnConnectionState.CONNECTED && v != null && v >= 0) {
                binding.chipSessionsValue.setText(String.valueOf(v));
            } else {
                binding.chipSessionsValue.setText("—");
            }
        });
        viewModel.getDuration().observe(getViewLifecycleOwner(), v -> {
            VpnConnectionState state = viewModel.getConnectionState().getValue();
            if (state == VpnConnectionState.CONNECTED && v != null && v > 0) {
                binding.chipDurationValue.setText(formatDuration(v));
            } else {
                binding.chipDurationValue.setText("—");
            }
        });
        viewModel.getMessages().observe(getViewLifecycleOwner(), event -> {
            String msg = event != null ? event.getContentIfNotHandled() : null;
            if (msg != null) {
                showMessage(msg);
            }
        });
        // 初始渲染
        VpnConnectionState state = viewModel.getConnectionState().getValue();
        renderState(state != null ? state : VpnConnectionState.DISCONNECTED);
    }

    /**
     * 速率渲染：下行拆成「大数字 + 单位」两段（本屏的视觉焦点），上行是普通文本。
     * 未连接时两处都回到占位符。
     */
    private void renderRates() {
        if (binding == null) return;
        VpnConnectionState state = viewModel.getConnectionState().getValue();
        boolean on = state == VpnConnectionState.CONNECTED;
        Long down = viewModel.getDownloadBytes().getValue();
        Long up = viewModel.getUploadBytes().getValue();

        if (on) {
            // 连接状态下始终显示数值（0 也显示）：占位符会让人以为统计没在工作。
            long d = down == null ? 0 : down;
            String[] r = splitRate(d);
            binding.chipDownValue.setText(r[0]);
            binding.rateUnit.setText(r[1]);
            long u = up == null ? 0 : up;
            binding.chipUpValue.setText(formatRate(u));
        } else {
            // 断开时回到「0.00 MB/s」的静止读数，并整体弱化：42sp 等宽粗体的「—」
            // 渲染出来是一根粗黑条，容易被当成控件坏了。
            binding.chipDownValue.setText("0.00");
            binding.rateUnit.setText(R.string.fcp_unit_mb_s);
            binding.chipUpValue.setText("—");
        }
        int strong = androidx.core.content.ContextCompat.getColor(requireContext(),
                on ? R.color.fcp_text_primary : R.color.fcp_text_faint);
        binding.chipDownValue.setTextColor(strong);
        binding.chipUpValue.setTextColor(strong);
    }

    /** 速率拆成 [数值, 单位]：MB/s 保留两位，KB/s 取整，避免大数字过长。 */
    static String[] splitRate(long bps) {
        if (bps < 1024) return new String[]{String.valueOf(bps), "B/s"};
        double kb = bps / 1024.0;
        if (kb < 1024) return new String[]{String.format(Locale.US, "%.0f", kb), "KB/s"};
        double mb = kb / 1024.0;
        if (mb < 1024) {
            return new String[]{String.format(Locale.US, mb >= 100 ? "%.0f" : "%.2f", mb), "MB/s"};
        }
        return new String[]{String.format(Locale.US, "%.2f", mb / 1024.0), "GB/s"};
    }

    /** 单行速率文本，例如 "86 KB/s"。 */
    static String formatRate(long bps) {
        String[] r = splitRate(bps);
        return r[0] + " " + r[1];
    }

    /** 五个状态在英雄卡内的完整表达：状态点、状态文案、主按钮、进度环、chips。 */
    private void renderState(VpnConnectionState state) {
        if (binding == null || !isAdded()) {
            return;
        }

        String statusText;
        String buttonText;
        int buttonIcon;
        int buttonBgRes;
        int buttonFgRes;
        boolean showProgress;
        boolean buttonEnabled = true;

        switch (state) {
            case CONNECTED:
                statusText = getString(R.string.fcp_state_connected);
                buttonText = getString(R.string.fcp_disconnect);
                buttonIcon = R.drawable.ic_stop;
                // 断开是常规操作，用柔和红底而不是高饱和红，别抢走速率的视觉焦点
                buttonBgRes = R.color.fcp_danger_bg;
                buttonFgRes = R.color.fcp_danger_text;
                showProgress = false;
                break;
            case CONNECTING:
            case RECONNECTING:
                statusText = state == VpnConnectionState.RECONNECTING
                        ? getString(R.string.fcp_state_reconnecting)
                        : getString(R.string.fcp_state_connecting);
                buttonText = getString(R.string.fcp_state_connecting);
                buttonIcon = R.drawable.ic_play_arrow;
                buttonBgRes = R.color.fcp_status_connecting;
                buttonFgRes = android.R.color.white;
                showProgress = true;
                break;
            case DISCONNECTING:
                statusText = getString(R.string.fcp_state_disconnecting);
                buttonText = getString(R.string.fcp_state_disconnecting);
                buttonIcon = R.drawable.ic_stop;
                buttonBgRes = R.color.fcp_danger_bg;
                buttonFgRes = R.color.fcp_danger_text;
                showProgress = false;
                buttonEnabled = false;
                break;
            case DISCONNECTED:
            default:
                boolean configured = ConfigStore.isConfigured(requireContext());
                statusText = configured
                        ? getString(R.string.fcp_state_disconnected)
                        : getString(R.string.fcp_state_unconfigured);
                buttonText = getString(R.string.fcp_connect);
                buttonIcon = R.drawable.ic_play_arrow;
                buttonBgRes = R.color.fcp_btn_dark_2;
                buttonFgRes = android.R.color.white;
                showProgress = false;
                break;
        }

        binding.statusDot.setImageResource(
                state == VpnConnectionState.CONNECTED
                        ? R.drawable.bg_status_dot_connected
                        : state == VpnConnectionState.CONNECTING
                        || state == VpnConnectionState.RECONNECTING
                        ? R.drawable.bg_status_dot_connecting
                        : R.drawable.bg_status_dot_disconnected);
        binding.statusText.setText(statusText);

        binding.progressRing.setVisibility(showProgress ? View.VISIBLE : View.GONE);

        binding.btnMain.setEnabled(buttonEnabled);
        animateButtonColors(
                androidx.core.content.ContextCompat.getColor(requireContext(), buttonBgRes),
                androidx.core.content.ContextCompat.getColor(requireContext(), buttonFgRes));
        binding.btnMain.setText(buttonText);
        binding.btnMain.setIconResource(buttonIcon);

        // chips：未连接时会话/时长置占位；速率文本与配色统一由 renderRates 负责
        // （那里连接中也会显示 0.00，断开时用弱化的静止读数）。
        boolean connected = state == VpnConnectionState.CONNECTED;
        if (!connected) {
            binding.chipSessionsValue.setText("—");
            binding.chipDurationValue.setText("—");
        }
        renderRates();
    }

    /**
     * 主按钮配色过渡：250ms ArgbEvaluator，避免状态切换时颜色硬跳。
     * 背景与前景（文字 + 图标）一起切：深色底配白字，浅色底配深字。
     */
    private void animateButtonColors(int bg, int fg) {
        binding.btnMain.setTextColor(fg);
        binding.btnMain.setIconTint(android.content.res.ColorStateList.valueOf(fg));

        android.content.res.ColorStateList currentTint = binding.btnMain.getBackgroundTintList();
        int from = currentTint != null ? currentTint.getDefaultColor() : bg;
        if (from == bg) {
            binding.btnMain.setBackgroundTintList(android.content.res.ColorStateList.valueOf(bg));
            return;
        }
        ValueAnimator animator = ValueAnimator.ofObject(new android.animation.ArgbEvaluator(), from, bg);
        animator.setDuration(250);
        animator.addUpdateListener(anim -> binding.btnMain.setBackgroundTintList(
                android.content.res.ColorStateList.valueOf((int) anim.getAnimatedValue())));
        animator.start();
    }

    // ------------------------------------------------------------ 格式化

    static String formatBytes(long bytes) {
        if (bytes < 1024) {
            return bytes + "B";
        }
        double kb = bytes / 1024.0;
        if (kb < 1024) {
            return String.format(Locale.US, "%.1fKB", kb);
        }
        double mb = kb / 1024.0;
        if (mb < 1024) {
            return String.format(Locale.US, "%.1fMB", mb);
        }
        return String.format(Locale.US, "%.1fGB", mb / 1024.0);
    }

    static String formatDuration(long seconds) {
        long h = seconds / 3600;
        long m = (seconds % 3600) / 60;
        long s = seconds % 60;
        if (h > 0) {
            return String.format(Locale.US, "%d:%02d:%02d", h, m, s);
        }
        return String.format(Locale.US, "%02d:%02d", m, s);
    }
}
