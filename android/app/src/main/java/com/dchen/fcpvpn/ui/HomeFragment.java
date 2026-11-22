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
    }

    private void observeViewModel() {
        viewModel.getConnectionState().observe(getViewLifecycleOwner(), this::renderState);
        viewModel.getUploadBytes().observe(getViewLifecycleOwner(),
                v -> renderChip(binding.chipUpValue, v));
        viewModel.getDownloadBytes().observe(getViewLifecycleOwner(),
                v -> renderChip(binding.chipDownValue, v));
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

    private void renderChip(android.widget.TextView view, Long bytes) {
        VpnConnectionState state = viewModel.getConnectionState().getValue();
        if (state == VpnConnectionState.CONNECTED && bytes != null && bytes > 0) {
            view.setText(formatBytes(bytes));
        } else {
            view.setText("—");
        }
    }

    /** 五个状态在英雄卡内的完整表达：状态点、状态文案、主按钮、进度环、chips。 */
    private void renderState(VpnConnectionState state) {
        if (binding == null || !isAdded()) {
            return;
        }

        String statusText;
        String buttonText;
        int buttonIcon;
        int buttonColorAttr;
        boolean showProgress;
        boolean buttonEnabled = true;

        switch (state) {
            case CONNECTED:
                statusText = getString(R.string.fcp_state_connected);
                buttonText = getString(R.string.fcp_disconnect);
                buttonIcon = R.drawable.ic_stop;
                buttonColorAttr = com.google.android.material.R.attr.colorError;
                showProgress = false;
                break;
            case CONNECTING:
            case RECONNECTING:
                statusText = state == VpnConnectionState.RECONNECTING
                        ? getString(R.string.fcp_state_reconnecting)
                        : getString(R.string.fcp_state_connecting);
                buttonText = getString(R.string.fcp_state_connecting);
                buttonIcon = R.drawable.ic_play_arrow;
                buttonColorAttr = com.google.android.material.R.attr.colorPrimary;
                showProgress = true;
                break;
            case DISCONNECTING:
                statusText = getString(R.string.fcp_state_disconnecting);
                buttonText = getString(R.string.fcp_state_disconnecting);
                buttonIcon = R.drawable.ic_stop;
                buttonColorAttr = com.google.android.material.R.attr.colorError;
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
                buttonColorAttr = com.google.android.material.R.attr.colorPrimary;
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
        animateButtonColor(buttonColorAttr);
        binding.btnMain.setText(buttonText);
        binding.btnMain.setIconResource(buttonIcon);

        // chips：未连接时全部占位 "—"（Stub 阶段引擎无 stats，同样显示占位）
        boolean connected = state == VpnConnectionState.CONNECTED;
        if (!connected) {
            binding.chipDownValue.setText("—");
            binding.chipUpValue.setText("—");
            binding.chipSessionsValue.setText("—");
            binding.chipDurationValue.setText("—");
        }
    }

    /**
     * 主按钮颜色渐变（连接=primary，断开=error），250ms ArgbEvaluator 过渡，
     * 避免状态切换时生硬跳变。
     */
    private void animateButtonColor(int colorAttr) {
        int target = MaterialColors.getColor(binding.btnMain, colorAttr);
        int onTarget = MaterialColors.getColor(binding.btnMain,
                colorAttr == com.google.android.material.R.attr.colorError
                        ? com.google.android.material.R.attr.colorOnError
                        : com.google.android.material.R.attr.colorOnPrimary);
        android.content.res.ColorStateList currentTint = binding.btnMain.getBackgroundTintList();
        int current = currentTint != null
                ? currentTint.getDefaultColor()
                : target;
        if (current == target) {
            binding.btnMain.setTextColor(onTarget);
            return;
        }
        ValueAnimator animator = ValueAnimator.ofObject(new android.animation.ArgbEvaluator(),
                current, target);
        animator.setDuration(250);
        animator.addUpdateListener(anim -> {
            int color = (int) anim.getAnimatedValue();
            binding.btnMain.setBackgroundTintList(
                    android.content.res.ColorStateList.valueOf(color));
        });
        animator.start();
        binding.btnMain.setTextColor(onTarget);
        binding.btnMain.setIconTint(android.content.res.ColorStateList.valueOf(onTarget));
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
