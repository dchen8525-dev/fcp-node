package com.dchen.fcpvpn.core.crypto;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.GCMParameterSpec;

/**
 * AES-128 原语。移植自 fcp-node src/crypto/aes.ts（aes.ts:1-53），其底层用 Node
 * 内置 OpenSSL 实现；Java 侧用 javax.crypto，线结果逐字节一致：
 * 标准 AES-128-ECB 单块 + AES-128-GCM（12 字节 IV、空 AAD、12 字节 tag）。
 *
 * <p>注意 <b>tag 必须是 12 字节（非 16）</b>（constants.ts:32 TAG_LEN=12），
 * IV 长度 12 字节（constants.ts:40 GCM_IV_LEN=12）。</p>
 *
 * <p>线程模型：本类所有方法为无状态静态方法（每次调用自建 Cipher），可并发调用；
 * 调用方持有的密钥数组由调用方自行保护。</p>
 */
public final class AesGcm {

    /** AES-128 密钥长度（aes.ts:12）。 */
    public static final int KEY_LEN = 16;
    /** GCM IV 长度 = 12 字节（constants.ts:40）。 */
    public static final int GCM_IV_LEN = 12;
    /** GCM 认证 tag 长度 = 12 字节，非 16（constants.ts:32）。 */
    public static final int TAG_LEN = 12;

    /** OS CSPRNG（aes.ts:43-45 randomBytes 对应物）。nextBytes 线程安全。 */
    private static final SecureRandom CSPRNG = new SecureRandom();

    private AesGcm() {}

    /** gcmSeal 的返回结构（aes.ts:19 返回 {cipher, tag}）。 */
    public static final class Sealed {
        /** 密文（不含 tag），长度等于明文。 */
        public final byte[] cipher;
        /** 12 字节认证 tag。 */
        public final byte[] tag;

        public Sealed(byte[] cipher, byte[] tag) {
            this.cipher = cipher;
            this.tag = tag;
        }
    }

    /**
     * 单块 AES-128-ECB 加密（无填充）。引导密钥派生（FcpKeys）使用。
     * 移植自 aes.ts:11-17 aes128EncryptBlock；对应 FIPS-197 黄金向量
     * （golden.test.ts:25-29：00112233.. → 69c4e0d8..）。
     *
     * @param key   16 字节密钥
     * @param block 16 字节明文块
     * @return 16 字节密文块（新数组）
     * @throws IllegalArgumentException key 或 block 长度不是 16
     */
    public static byte[] aes128EncryptBlock(byte[] key, byte[] block) {
        if (key.length != 16) throw new IllegalArgumentException("aes128: key must be 16 bytes");
        if (block.length != 16) throw new IllegalArgumentException("aes128: block must be 16 bytes");
        try {
            Cipher c = Cipher.getInstance("AES/ECB/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
            return c.doFinal(block);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("aes128: JCE failure", e);
        }
    }

    /**
     * AES-128-GCM 封装（aes.ts:19-29 gcmSeal）。AAD 可为 null/空（等价于不设 AAD）。
     *
     * @param key   16 字节密钥
     * @param iv    12 字节 IV
     * @param plain 明文（可为空）
     * @param aad   附加认证数据，null/空 表示无
     * @return cipher + 12 字节 tag；参数非法或 JCE 失败返回 null
     */
    public static Sealed gcmSeal(byte[] key, byte[] iv, byte[] plain, byte[] aad) {
        if (key == null || key.length != KEY_LEN) return null;
        if (iv == null || iv.length != GCM_IV_LEN) return null;
        try {
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(TAG_LEN * 8, iv));
            if (aad != null && aad.length > 0) c.updateAAD(aad);
            // SunJCE 在 doFinal 输出尾部追加 tag；拆成 cipher 与 tag 两段，
            // 与 aes.ts 的 {cipher, tag} 结构一致。
            byte[] ctAndTag = c.doFinal(plain == null ? new byte[0] : plain);
            int ctLen = ctAndTag.length - TAG_LEN;
            byte[] cipher = new byte[ctLen];
            byte[] tag = new byte[TAG_LEN];
            System.arraycopy(ctAndTag, 0, cipher, 0, ctLen);
            System.arraycopy(ctAndTag, ctLen, tag, 0, TAG_LEN);
            return new Sealed(cipher, tag);
        } catch (GeneralSecurityException e) {
            return null;
        }
    }

    /**
     * AES-128-GCM 解封（aes.ts:31-41 gcmOpen）。AAD 可为 null/空。
     *
     * @return 明文；tag 验证失败（认证失败，调用方计入 auth_fail）、
     *         参数非法返回 null
     */
    public static byte[] gcmOpen(byte[] key, byte[] iv, byte[] cipher, byte[] tag, byte[] aad) {
        if (key == null || key.length != KEY_LEN) return null;
        if (iv == null || iv.length != GCM_IV_LEN) return null;
        if (tag == null || tag.length != TAG_LEN) return null;
        try {
            Cipher d = Cipher.getInstance("AES/GCM/NoPadding");
            d.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(TAG_LEN * 8, iv));
            if (aad != null && aad.length > 0) d.updateAAD(aad);
            // SunJCE 没有 setAuthTag 等价物（对应 aes.ts:36）：tag 必须拼接在
            // 密文尾部交给 doFinal，由 JCE 校验。
            byte[] ct = cipher == null ? new byte[0] : cipher;
            byte[] input = new byte[ct.length + TAG_LEN];
            System.arraycopy(ct, 0, input, 0, ct.length);
            System.arraycopy(tag, 0, input, ct.length, TAG_LEN);
            return d.doFinal(input);
        } catch (GeneralSecurityException e) {
            // AEADBadTagException 等：认证失败（aes.ts:38-40）
            return null;
        }
    }

    /** CSPRNG 随机字节（aes.ts:43-45）。 */
    public static byte[] cspRandomBytes(int len) {
        byte[] b = new byte[len];
        CSPRNG.nextBytes(b);
        return b;
    }

    /**
     * CSPRNG 随机 u64，按位保真存入 long（aes.ts:50-52 cspRandomU64，
     * readBigUInt64LE → LE 读入）。OS CSPRNG 不可用时 SecureRandom 抛异常，
     * 与 aes.ts "loudly fail" 契约一致。
     */
    public static long cspRandomU64() {
        byte[] b = cspRandomBytes(8);
        long v = 0;
        for (int i = 7; i >= 0; --i) v = (v << 8) | (b[i] & 0xffL);
        return v;
    }
}
