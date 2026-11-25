package com.dchen.fcpvpn.ui;

import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.graphics.drawable.Drawable;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.LayoutInflater;
import android.view.ViewGroup;

import androidx.activity.OnBackPressedCallback;
import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.dchen.fcpvpn.R;
import com.dchen.fcpvpn.core.session.EngineConfig;
import com.dchen.fcpvpn.databinding.ActivityAppPickerBinding;
import com.dchen.fcpvpn.databinding.ItemAppBinding;
import com.dchen.fcpvpn.log.LogConfig;
import com.dchen.fcpvpn.log.Logger;
import com.dchen.fcpvpn.util.ServiceUtil;
import com.google.android.material.dialog.MaterialAlertDialogBuilder;
import com.google.android.material.snackbar.Snackbar;

import java.text.Collator;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * 分应用代理：勾选哪些应用走 VPN。
 *
 * <p>语义（与 VpnService.Builder 一致）：勾选集合为空时不做白名单，全部应用走 VPN；
 * 非空时只有这些应用走 VPN，其余直连。</p>
 *
 * <p>白名单只在建立 TUN（{@code VpnService.Builder.establish()}）时生效，所以
 * 改完必须重建隧道：这里在保存时若发现 VPN 正在运行，就重新下发一次启动命令，
 * 由 {@code FcpVpnService} 拆旧建新（等价于"断开再连接"，但不用用户手动做）。</p>
 */
public class AppPickerActivity extends AppCompatActivity {

    private static final String STATE_SELECTED = "selected_pkgs";

    /** 一行可选应用。 */
    private static final class AppRow {
        final String pkg;
        final String label;
        Drawable icon;

        AppRow(String pkg, String label) {
            this.pkg = pkg;
            this.label = label;
        }
    }

    private ActivityAppPickerBinding binding;
    private final List<AppRow> all = new ArrayList<>();
    private final List<AppRow> filtered = new ArrayList<>();
    private final Set<String> selected = new HashSet<>();
    private final ExecutorService loader = Executors.newSingleThreadExecutor();
    private final Handler main = new Handler(Looper.getMainLooper());
    private AppAdapter adapter;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        binding = ActivityAppPickerBinding.inflate(getLayoutInflater());
        setContentView(binding.getRoot());

        // 屏幕旋转会重建 Activity：勾选状态必须跟着走，否则用户转个屏就没了。
        if (savedInstanceState != null) {
            ArrayList<String> saved = savedInstanceState.getStringArrayList(STATE_SELECTED);
            if (saved != null) {
                selected.addAll(saved);
            }
        } else {
            selected.addAll(ConfigStore.getVpnApps(this));
        }

        binding.pickerToolbar.setNavigationOnClickListener(v -> confirmExit());
        getOnBackPressedDispatcher().addCallback(this, new OnBackPressedCallback(true) {
            @Override
            public void handleOnBackPressed() {
                confirmExit();
            }
        });

        adapter = new AppAdapter();
        binding.pickerList.setLayoutManager(new LinearLayoutManager(this));
        binding.pickerList.setAdapter(adapter);

        binding.pickerSearch.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int a, int b, int c) { }

            @Override
            public void onTextChanged(CharSequence s, int a, int b, int c) {
                applyFilter(s == null ? "" : s.toString());
            }

            @Override
            public void afterTextChanged(Editable s) { }
        });
        binding.pickerClear.setOnClickListener(v -> {
            selected.clear();
            adapter.notifyDataSetChanged();
            updateCount();
        });
        binding.pickerSave.setOnClickListener(v -> save());

        loadAppsAsync();
    }

    @Override
    protected void onSaveInstanceState(Bundle outState) {
        super.onSaveInstanceState(outState);
        outState.putStringArrayList(STATE_SELECTED, new ArrayList<>(selected));
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        loader.shutdownNow();
        binding = null;
    }

    /**
     * 返回/左上角箭头：改动没保存时先问一句。旧实现直接 finish()，用户的勾选
     * 被无声丢弃——这是"选了应用却没生效"的一个来源。
     */
    private void confirmExit() {
        if (!isDirty()) {
            finish();
            return;
        }
        new MaterialAlertDialogBuilder(this)
                .setTitle(R.string.fcp_apps_discard_title)
                .setMessage(R.string.fcp_apps_discard_message)
                .setPositiveButton(R.string.fcp_apps_save, (d, w) -> save())
                .setNegativeButton(R.string.fcp_apps_discard, (d, w) -> finish())
                .setNeutralButton(R.string.fcp_apps_cancel, null)
                .show();
    }

    /** 当前勾选是否与已保存的白名单不同。 */
    private boolean isDirty() {
        return !selected.equals(ConfigStore.getVpnApps(this));
    }

    /**
     * 加载"能从桌面启动"的应用（<queries> 只声明了这个 intent）。
     * 图标读取在后台线程逐条完成，避免一次性 getApplicationIcon 卡住 UI。
     */
    private void loadAppsAsync() {
        final PackageManager pm = getPackageManager();
        loader.execute(() -> {
            Intent launcher = new Intent(Intent.ACTION_MAIN)
                    .addCategory(Intent.CATEGORY_LAUNCHER);
            List<ResolveInfo> infos = pm.queryIntentActivities(launcher, 0);
            List<AppRow> rows = new ArrayList<>();
            Set<String> seen = new HashSet<>();
            String self = getPackageName();
            for (ResolveInfo info : infos) {
                if (info.activityInfo == null) continue;
                String pkg = info.activityInfo.packageName;
                if (pkg == null || pkg.equals(self) || !seen.add(pkg)) continue;
                CharSequence label = info.loadLabel(pm);
                rows.add(new AppRow(pkg, label == null ? pkg : label.toString()));
            }
            // 中文按拼音、其他按本地化规则排序
            final Collator collator = Collator.getInstance(Locale.getDefault());
            rows.sort((a, b) -> collator.compare(a.label, b.label));

            main.post(() -> {
                if (binding == null) return;
                all.clear();
                all.addAll(rows);
                applyFilter(binding.pickerSearch.getText() == null
                        ? "" : binding.pickerSearch.getText().toString());
                loadIcons();
            });
        });
    }

    /** 图标按需异步加载：列表先出现，图标随后补齐。 */
    private void loadIcons() {
        final PackageManager pm = getPackageManager();
        loader.execute(() -> {
            for (final AppRow row : new ArrayList<>(all)) {
                final Drawable icon;
                try {
                    icon = pm.getApplicationIcon(row.pkg);
                } catch (Exception e) {
                    continue;
                }
                main.post(() -> {
                    if (binding == null) return;
                    row.icon = icon;
                    int idx = filtered.indexOf(row);
                    if (idx >= 0) adapter.notifyItemChanged(idx);
                });
            }
        });
    }

    private void applyFilter(String query) {
        String q = query.trim().toLowerCase(Locale.ROOT);
        filtered.clear();
        if (q.isEmpty()) {
            filtered.addAll(all);
        } else {
            for (AppRow r : all) {
                if (r.label.toLowerCase(Locale.ROOT).contains(q)
                        || r.pkg.toLowerCase(Locale.ROOT).contains(q)) {
                    filtered.add(r);
                }
            }
        }
        adapter.notifyDataSetChanged();
        updateCount();
    }

    private void updateCount() {
        if (selected.isEmpty()) {
            binding.pickerCount.setText(R.string.fcp_apps_all);
        } else {
            binding.pickerCount.setText(getString(R.string.fcp_apps_selected, selected.size()));
        }
    }

    /**
     * 保存白名单。
     *
     * <p>三件事：① 丢掉已卸载/已禁用的包名；② 但绝不能让清理把白名单变成空集合
     * ——空集合的语义是"全部应用走 VPN"，那和用户"只代理这几个应用"的意图正好
     * 相反，所以这种情况要用户确认；③ 白名单真的变了、且 VPN 正在运行时重建隧道。</p>
     */
    private void save() {
        Set<String> effective = purgeMissing(selected);
        if (effective.isEmpty() && !selected.isEmpty()) {
            confirmWidenToAllApps();
            return;
        }
        persist(effective);
    }

    /** 清理会把白名单清空：明确问一次，别把"只代理银行 App"悄悄变成"全代理"。 */
    private void confirmWidenToAllApps() {
        new MaterialAlertDialogBuilder(this)
                .setTitle(R.string.fcp_apps_none_usable_title)
                .setMessage(getString(R.string.fcp_apps_none_usable_message, selected.size()))
                .setPositiveButton(R.string.fcp_apps_all, (d, w) -> {
                    selected.clear();
                    adapter.notifyDataSetChanged();
                    updateCount();
                    persist(new LinkedHashSet<String>());
                })
                .setNegativeButton(R.string.fcp_apps_cancel, null)
                .show();
    }

    /** 落盘；只有白名单真的变了才重建隧道（无改动的保存不该掐断现有连接）。 */
    private void persist(Set<String> effective) {
        int dropped = selected.size() - effective.size();
        boolean changed = !purgeMissing(ConfigStore.getVpnApps(this)).equals(effective);
        ConfigStore.setVpnApps(this, new LinkedHashSet<>(effective));
        Logger.info(LogConfig.MODULE_UI, "分应用代理保存 apps=" + effective.size()
                + (effective.isEmpty() ? " (全部应用)" : "")
                + (dropped > 0 ? " dropped=" + dropped : "")
                + (changed ? "" : " unchanged"));

        boolean applied = changed && rebuildTunnelIfRunning();
        Snackbar.make(binding.getRoot(),
                applied ? R.string.fcp_apps_saved_applied : R.string.fcp_apps_saved,
                Snackbar.LENGTH_SHORT).show();
        binding.getRoot().postDelayed(this::finish, 600);
    }

    /** 清掉已卸载/已禁用的包名。 */
    private Set<String> purgeMissing(Set<String> pkgs) {
        Set<String> out = new LinkedHashSet<>();
        PackageManager pm = getPackageManager();
        for (String pkg : pkgs) {
            try {
                if (pm.getApplicationInfo(pkg, 0).enabled) {
                    out.add(pkg);
                }
            } catch (PackageManager.NameNotFoundException e) {
                // 已卸载：直接丢掉
            }
        }
        return out;
    }

    /**
     * VPN 正在运行时，按新白名单重建隧道：重新下发一次启动命令，服务会拆旧建新
     * （见 {@code FcpVpnService.restartVpn}）。返回是否成功触发。
     */
    private boolean rebuildTunnelIfRunning() {
        if (!ConfigStore.RUN_MODE_VPN.equals(ConfigStore.getRunMode(this))) {
            return false;   // 代理服务模式下白名单不适用
        }
        if (!ServiceUtil.isVpnServiceRunning(this)) {
            return false;   // 没在跑，下次连接时自然生效
        }
        if (ServiceUtil.checkVpnAuthorization(this) != null) {
            return false;   // 授权已被撤销：让用户自己重新连
        }
        EngineConfig cfg = ConfigStore.buildEngineConfig(this);
        if (cfg == null) {
            return false;   // PSK 没记住：重建不了，让用户手动重连
        }
        ServiceUtil.startVpnService(this, cfg, ConfigStore.getProxyPort(this));
        return true;
    }

    /** 列表适配器：整行可点，勾选框只反映状态。 */
    private final class AppAdapter extends RecyclerView.Adapter<AppAdapter.Holder> {

        final class Holder extends RecyclerView.ViewHolder {
            final ItemAppBinding b;

            Holder(ItemAppBinding b) {
                super(b.getRoot());
                this.b = b;
            }
        }

        @NonNull
        @Override
        public Holder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
            return new Holder(ItemAppBinding.inflate(
                    LayoutInflater.from(parent.getContext()), parent, false));
        }

        @Override
        public void onBindViewHolder(@NonNull Holder h, int position) {
            final AppRow row = filtered.get(position);
            h.b.itemName.setText(row.label);
            h.b.itemPackage.setText(row.pkg);
            if (row.icon != null) {
                h.b.itemIcon.setImageDrawable(row.icon);
            } else {
                h.b.itemIcon.setImageResource(R.drawable.ic_vpn);
            }
            h.b.itemCheck.setChecked(selected.contains(row.pkg));
            h.b.getRoot().setOnClickListener(v -> {
                if (selected.contains(row.pkg)) {
                    selected.remove(row.pkg);
                } else {
                    selected.add(row.pkg);
                }
                h.b.itemCheck.setChecked(selected.contains(row.pkg));
                updateCount();
            });
        }

        @Override
        public int getItemCount() {
            return filtered.size();
        }
    }
}
