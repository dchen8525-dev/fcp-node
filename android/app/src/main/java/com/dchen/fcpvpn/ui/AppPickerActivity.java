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

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.dchen.fcpvpn.R;
import com.dchen.fcpvpn.databinding.ActivityAppPickerBinding;
import com.dchen.fcpvpn.databinding.ItemAppBinding;
import com.dchen.fcpvpn.log.LogConfig;
import com.dchen.fcpvpn.log.Logger;
import com.google.android.material.snackbar.Snackbar;

import java.text.Collator;
import java.util.ArrayList;
import java.util.Comparator;
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
 * 语义（与 VpnService.Builder 一致）：勾选集合为空时不做白名单，全部应用走 VPN；
 * 非空时只有这些应用走 VPN，其余直连。改动在重新连接 VPN 后生效。
 */
public class AppPickerActivity extends AppCompatActivity {

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

        selected.addAll(ConfigStore.getVpnApps(this));
        binding.pickerToolbar.setNavigationOnClickListener(v -> finish());

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
    protected void onDestroy() {
        super.onDestroy();
        loader.shutdownNow();
        binding = null;
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

    private void save() {
        ConfigStore.setVpnApps(this, new LinkedHashSet<>(selected));
        Logger.info(LogConfig.MODULE_UI, "分应用代理保存 apps=" + selected.size()
                + (selected.isEmpty() ? " (全部应用)" : ""));
        Snackbar.make(binding.getRoot(), R.string.fcp_apps_saved, Snackbar.LENGTH_SHORT).show();
        binding.getRoot().postDelayed(this::finish, 600);
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
