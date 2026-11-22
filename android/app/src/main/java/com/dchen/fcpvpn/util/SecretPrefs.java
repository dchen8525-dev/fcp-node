package com.dchen.fcpvpn.util;

import android.content.SharedPreferences;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import com.dchen.fcpvpn.log.LogConfig;
import com.dchen.fcpvpn.log.Logger;

import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * PSK 落盘：用 Android Keystore 中不可导出的 AES 密钥做 AES-GCM 包裹后再写入
 * SharedPreferences，明文密钥不再直接出现在 prefs 文件里。Keystore 密钥绑定
 * 应用与设备（卸载即销毁、无法导出），即使 prefs 文件被拉走也拿不到明文。
 *
 * 为什么仍要落盘：START_STICKY 重启（进程被杀后系统拉起）必须能拿到 PSK 才能
 * 自动恢复 VPN，否则只能要求用户手动重连。这里的取舍是"密钥留在硬件支持的
 * Keystore 里、盘上只有密文"。
 *
 * 兼容旧版明文 "key" 条目：restore 优先读加密条目；没有时回退旧明文值（由调用
 * 方转存为加密形式），save 总是写加密条目并删除旧明文。
 */
public final class SecretPrefs {
    private static final String ANDROID_KEYSTORE = "AndroidKeyStore";
    private static final String WRAP_KEY_ALIAS = "kcp_vpn_psk_wrap";
    private static final String PREF_CIPHER_TEXT = "key_enc";
    private static final String PREF_IV = "key_iv";
    private static final int GCM_IV_BYTES = 12;
    private static final int GCM_TAG_BITS = 128;

    private SecretPrefs() {
    }

    /**
     * 以加密形式保存；同时删除旧版明文条目。加密失败时不落盘任何密钥内容
     * （宁可重启后要求用户重新输入，也不把明文写回盘上），错误走日志。
     */
    public static void save(SharedPreferences prefs, String plain) {
        SharedPreferences.Editor editor = prefs.edit();
        if (plain == null || plain.isEmpty()) {
            editor.remove(PREF_CIPHER_TEXT).remove(PREF_IV);
        } else {
            try {
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(Cipher.ENCRYPT_MODE, getOrCreateWrapKey());
                byte[] iv = cipher.getIV();
                byte[] cipherText = cipher.doFinal(plain.getBytes(StandardCharsets.UTF_8));
                editor.putString(PREF_CIPHER_TEXT, Base64.encodeToString(cipherText, Base64.NO_WRAP));
                editor.putString(PREF_IV, Base64.encodeToString(iv, Base64.NO_WRAP));
            } catch (Exception e) {
                editor.remove(PREF_CIPHER_TEXT).remove(PREF_IV);
                Logger.error(LogConfig.MODULE_VPN,
                        "SecretPrefs save failed (key not persisted): " + e.getMessage());
            }
        }
        editor.remove("key");
        editor.apply();
    }

    /** 读取加密保存的明文；不存在或解密失败返回 null。 */
    public static String load(SharedPreferences prefs) {
        String cipherB64 = prefs.getString(PREF_CIPHER_TEXT, null);
        String ivB64 = prefs.getString(PREF_IV, null);
        if (cipherB64 == null || ivB64 == null) {
            return null;
        }
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, getOrCreateWrapKey(),
                    new GCMParameterSpec(GCM_TAG_BITS, Base64.decode(ivB64, Base64.NO_WRAP)));
            byte[] plain = cipher.doFinal(Base64.decode(cipherB64, Base64.NO_WRAP));
            return new String(plain, StandardCharsets.UTF_8);
        } catch (Exception e) {
            Logger.error(LogConfig.MODULE_VPN,
                    "SecretPrefs load failed: " + e.getMessage());
            return null;
        }
    }

    public static void clear(SharedPreferences prefs) {
        prefs.edit()
                .remove(PREF_CIPHER_TEXT)
                .remove(PREF_IV)
                .remove("key")
                .apply();
    }

    private static SecretKey getOrCreateWrapKey() throws Exception {
        KeyStore keyStore = KeyStore.getInstance(ANDROID_KEYSTORE);
        keyStore.load(null);
        KeyStore.Entry entry = keyStore.getEntry(WRAP_KEY_ALIAS, null);
        if (entry instanceof KeyStore.SecretKeyEntry) {
            return ((KeyStore.SecretKeyEntry) entry).getSecretKey();
        }
        KeyGenerator generator = KeyGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE);
        generator.init(new KeyGenParameterSpec.Builder(WRAP_KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build());
        return generator.generateKey();
    }
}
