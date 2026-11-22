package com.dchen.fcpvpn.ui;

import android.content.Context;
import android.content.Intent;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.MenuItem;
import android.view.View;
import android.view.inputmethod.InputMethodManager;

import androidx.appcompat.app.AppCompatActivity;

import com.dchen.fcpvpn.R;
import com.dchen.fcpvpn.databinding.ActivitySettingsBinding;
import com.dchen.fcpvpn.log.LogConfig;
import com.dchen.fcpvpn.log.Logger;
import com.google.android.material.snackbar.Snackbar;
import com.google.android.material.textfield.TextInputEditText;
import com.google.android.material.textfield.TextInputLayout;

/**
 * 设置页 —— 分组卡片：服务器 → 密钥 → 运行模式 → 高级（默认折叠）。
 * 即时校验：错误时红边 + helperText，保存按钮禁用；保存成功给 Snackbar。
 */
public class SettingsActivity extends AppCompatActivity {

    public static final String EXTRA_FOCUS_HOST = "focus_host";

    private ActivitySettingsBinding binding;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        binding = ActivitySettingsBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        Logger.info(LogConfig.MODULE_UI, "SettingsActivity onCreate");

        setSupportActionBar(binding.settingsToolbar);
        if (getSupportActionBar() != null) {
            getSupportActionBar().setDisplayHomeAsUpEnabled(true);
            getSupportActionBar().setTitle(R.string.fcp_settings_title);
        }

        loadConfig();
        setupValidation();
        setupAdvancedToggle();

        binding.btnSave.setOnClickListener(v -> save());

        // 首次启动引导：聚焦服务器地址输入框并弹出键盘
        Intent intent = getIntent();
        if (intent != null && intent.getBooleanExtra(EXTRA_FOCUS_HOST, false)) {
            binding.inputServerHost.post(() -> {
                binding.inputServerHost.requestFocus();
                InputMethodManager imm =
                        (InputMethodManager) getSystemService(Context.INPUT_METHOD_SERVICE);
                if (imm != null) {
                    imm.showSoftInput(binding.inputServerHost, InputMethodManager.SHOW_IMPLICIT);
                }
            });
        }
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        if (item.getItemId() == android.R.id.home) {
            finish();
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    // ------------------------------------------------------------ 数据装载

    private void loadConfig() {
        binding.inputServerHost.setText(ConfigStore.getHost(this));
        binding.inputServerPort.setText(String.valueOf(ConfigStore.getPort(this)));
        binding.inputPsk.setText(ConfigStore.getPsk(this));
        binding.switchRememberPsk.setChecked(ConfigStore.isRememberPsk(this));
        if (ConfigStore.RUN_MODE_PROXY.equals(ConfigStore.getRunMode(this))) {
            binding.btnModeProxy.setChecked(true);
        } else {
            binding.btnModeVpn.setChecked(true);
        }
        binding.inputFecData.setText(String.valueOf(ConfigStore.getFecData(this)));
        binding.inputFecParityMax.setText(String.valueOf(ConfigStore.getFecParityMax(this)));
        binding.inputMtuMin.setText(String.valueOf(ConfigStore.getMtuMin(this)));
        binding.inputProbeInterval.setText(String.valueOf(ConfigStore.getProbeIntervalSec(this)));
        binding.inputProxyPort.setText(String.valueOf(ConfigStore.getProxyPort(this)));
    }

    // ------------------------------------------------------------ 即时校验

    private void setupValidation() {
        addValidator(binding.inputServerHost, binding.layoutServerHost, s ->
                ConfigStore.validateHost(this, s));
        addValidator(binding.inputServerPort, binding.layoutServerPort, s ->
                ConfigStore.validatePort(this, s));
        addValidator(binding.inputPsk, binding.layoutPsk, s ->
                ConfigStore.validatePsk(this, s));
        addValidator(binding.inputFecData, binding.layoutFecData, s ->
                ConfigStore.validateIntRange(this, s, 1, 200));
        addValidator(binding.inputFecParityMax, binding.layoutFecParityMax, s ->
                ConfigStore.validateIntRange(this, s, 0, 200));
        addValidator(binding.inputMtuMin, binding.layoutMtuMin, s ->
                ConfigStore.validateIntRange(this, s, 576, 1500));
        addValidator(binding.inputProbeInterval, binding.layoutProbeInterval, s ->
                ConfigStore.validateIntRange(this, s, 0, 86400));
        addValidator(binding.inputProxyPort, binding.layoutProxyPort, s ->
                ConfigStore.validateIntRange(this, s, 1024, 65535));
        binding.switchRememberPsk.setOnCheckedChangeListener((b, checked) -> validateAll());
    }

    private interface FieldValidator {
        String validate(String text);
    }

    /** 给输入框挂 TextWatcher：即时红边 + 错误文案，并联动保存按钮可用性。 */
    private void addValidator(TextInputEditText input, TextInputLayout layout,
                              FieldValidator validator) {
        input.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
            }

            @Override
            public void afterTextChanged(Editable s) {
                String error = validator.validate(s != null ? s.toString() : "");
                layout.setError(error);
                validateAll();
            }
        });
    }

    /** 全量校验：任何错误 → 保存按钮禁用。 */
    private void validateAll() {
        boolean allValid =
                ConfigStore.validateHost(this, text(binding.inputServerHost)) == null
                && ConfigStore.validatePort(this, text(binding.inputServerPort)) == null
                && ConfigStore.validatePsk(this, text(binding.inputPsk)) == null
                && ConfigStore.validateIntRange(this, text(binding.inputFecData), 1, 200) == null
                && ConfigStore.validateIntRange(this, text(binding.inputFecParityMax), 0, 200) == null
                && ConfigStore.validateIntRange(this, text(binding.inputMtuMin), 576, 1500) == null
                && ConfigStore.validateIntRange(this, text(binding.inputProbeInterval), 0, 86400) == null
                && ConfigStore.validateIntRange(this, text(binding.inputProxyPort), 1024, 65535) == null;
        binding.btnSave.setEnabled(allValid);
    }

    private static String text(TextInputEditText input) {
        return input.getText() != null ? input.getText().toString() : "";
    }

    // ------------------------------------------------------------ 高级折叠

    private void setupAdvancedToggle() {
        binding.advancedHeader.setOnClickListener(v -> {
            boolean expand = binding.advancedContent.getVisibility() != View.VISIBLE;
            binding.advancedContent.setVisibility(expand ? View.VISIBLE : View.GONE);
            binding.advancedChevron.animate()
                    .rotation(expand ? 180f : 0f)
                    .setDuration(200)
                    .start();
        });
    }

    // ------------------------------------------------------------ 保存

    private void save() {
        String host = text(binding.inputServerHost).trim();
        Integer port = ConfigStore.parseIntOrNull(text(binding.inputServerPort));
        Integer fecData = ConfigStore.parseIntOrNull(text(binding.inputFecData));
        Integer parity = ConfigStore.parseIntOrNull(text(binding.inputFecParityMax));
        Integer mtuMin = ConfigStore.parseIntOrNull(text(binding.inputMtuMin));
        Integer probe = ConfigStore.parseIntOrNull(text(binding.inputProbeInterval));
        Integer proxyPort = ConfigStore.parseIntOrNull(text(binding.inputProxyPort));
        if (port == null || fecData == null || parity == null || mtuMin == null
                || probe == null || proxyPort == null) {
            validateAll();
            return;
        }

        String runMode = binding.btnModeProxy.isChecked()
                ? ConfigStore.RUN_MODE_PROXY
                : ConfigStore.RUN_MODE_VPN;
        boolean rememberPsk = binding.switchRememberPsk.isChecked();
        String psk = text(binding.inputPsk).trim();

        ConfigStore.save(this, host, port, psk, rememberPsk, runMode,
                fecData, parity, mtuMin, probe, proxyPort);
        Logger.info(LogConfig.MODULE_UI, "Config saved host=" + host + ":" + port
                + " mode=" + runMode);

        Snackbar.make(binding.getRoot(), R.string.fcp_saved, Snackbar.LENGTH_SHORT).show();
    }
}
