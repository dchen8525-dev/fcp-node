package com.dchen.fcpvpn.core.crypto;

import java.nio.charset.StandardCharsets;

/**
 * 会话密钥派生。移植自 fcp-node src/crypto/keys.ts（keys.ts:1-76，其本身移植自
 * src/fcp/envelope.cc）：
 * <ul>
 *   <li>{@link #deriveSessionKey} —— 引导密钥 X0（v6 bootstrap / 握手信封）</li>
 *   <li>{@link #deriveSessionKeyV7} —— 对 salt、client/server nonce 的 CBC-MAC 链（R3-1）</li>
 *   <li>{@link #deriveDirectionKeys} —— SP 800-108 计数器 KDF（AES-128 PRF）方向密钥</li>
 *   <li>{@link #deriveEpochDirectionKey} —— #84 epoch 密钥</li>
 * </ul>
 *
 * <p><b>最容易错的点</b>：SP 800-108 的 {@code L} 编码是 <b>bit 数且大端</b>
 * （keys.ts:25-31，L = outLen × 8 = 128，写入 8 字节大端）。</p>
 *
 * <p>线程模型：全部为无状态静态方法，可并发调用。</p>
 */
public final class FcpKeys {

    /** salt 长度 = 8 字节（constants.ts:30）。 */
    public static final int SALT_LEN = 8;
    /** 方向常量（constants.ts:43-46）：C2S = 0x01。 */
    public static final int DIRECTION_C2S = 0x01;
    /** 方向常量（constants.ts:43-46）：S2C = 0x02。 */
    public static final int DIRECTION_S2C = 0x02;

    private FcpKeys() {}

    /** deriveDirectionKeys 的返回结构（keys.ts:45-50 返回 {c2s, s2c}）。 */
    public static final class DirectionKeys {
        /** C2S 方向密钥（label "fcp-c2"）。 */
        public final byte[] c2s;
        /** S2C 方向密钥（label "fcp-s2"）。 */
        public final byte[] s2c;

        public DirectionKeys(byte[] c2s, byte[] s2c) {
            this.c2s = c2s;
            this.s2c = s2c;
        }
    }

    private static byte[] xor16(byte[] a, byte[] b) {
        byte[] out = new byte[16];
        for (int i = 0; i < 16; ++i) out[i] = (byte) (a[i] ^ b[i]);
        return out;
    }

    /**
     * 引导密钥：{@code session_key = AES128(psk, salt(8) || 0x00 × 8)}
     * （keys.ts:16-22 deriveSessionKey，对应 C++ derive_session_key）。
     *
     * @param psk  16 字节预共享密钥
     * @param salt 8 字节 salt
     * @return 16 字节引导密钥
     * @throws IllegalArgumentException psk/salt 长度非法
     */
    public static byte[] deriveSessionKey(byte[] psk, byte[] salt) {
        if (psk.length != 16 || salt.length != SALT_LEN) {
            throw new IllegalArgumentException("deriveSessionKey: bad lengths");
        }
        byte[] block = new byte[16];
        System.arraycopy(salt, 0, block, 0, SALT_LEN); // 其余 8 字节保持 0x00
        return AesGcm.aes128EncryptBlock(psk, block);
    }

    /**
     * NIST SP 800-108 Rev.1 §4.1 计数器 KDF（keys.ts:24-43 kdfCtrAes128）：
     * <pre>K(i) = AES(K_mr, [i]1 | label(6) | 0x00 | [L]8 大端)</pre>
     * 其中 L 以 <b>bit</b> 计、<b>大端</b>编码（keys.ts:31，L = outLen × 8）。
     * FCP 用 6 字节 label "fcp-c2"/"fcp-s2"，请求 128 bit（16 字节）。
     */
    private static byte[] kdfCtrAes128(byte[] key, String label, int outLen) {
        byte[] labelBytes = label.getBytes(StandardCharsets.ISO_8859_1);
        if (labelBytes.length != 6) throw new IllegalArgumentException("kdf: label must be 6 bytes");
        byte[] lBe = new byte[8];
        long lBits = (outLen & 0xffffffffL) * 8L; // L = outLen * 8，bits
        for (int i = 0; i < 8; ++i) lBe[i] = (byte) (lBits >>> (8 * (7 - i))); // 大端
        byte[] parts = new byte[outLen];
        int counter = 1;
        for (int done = 0; done < outLen; done += 16, ++counter) {
            byte[] block = new byte[16];
            block[0] = (byte) (counter & 0xff);
            System.arraycopy(labelBytes, 0, block, 1, 6);
            block[7] = 0x00;
            System.arraycopy(lBe, 0, block, 8, 8);
            byte[] ki = AesGcm.aes128EncryptBlock(key, block);
            System.arraycopy(ki, 0, parts, done, Math.min(16, outLen - done));
        }
        return parts;
    }

    /**
     * 方向密钥（keys.ts:45-50 deriveDirectionKeys）：label "fcp-c2"/"fcp-s2"，
     * 各取 16 字节。两个密钥必然不同（label 不同）。
     */
    public static DirectionKeys deriveDirectionKeys(byte[] sessionKey) {
        return new DirectionKeys(
                kdfCtrAes128(sessionKey, "fcp-c2", 16),
                kdfCtrAes128(sessionKey, "fcp-s2", 16));
    }

    /**
     * #84：epoch &gt;= 1 的方向密钥
     * {@code out = AES128(session_key, label(2) | epoch(2 LE) | 0^12)}
     * （keys.ts:52-60 deriveEpochDirectionKey）。label 两字节为
     * {@code 'c'/'s'} + {@code '2'}（0x63/0x73, 0x32）。
     *
     * @param dir   方向，{@link #DIRECTION_C2S} 或 {@link #DIRECTION_S2C}
     * @param epoch epoch 号（u16，&gt;= 1）
     */
    public static byte[] deriveEpochDirectionKey(byte[] sessionKey, int dir, int epoch) {
        byte[] block = new byte[16];
        block[0] = (byte) (dir == DIRECTION_C2S ? 0x63 : 0x73); // 'c' / 's'
        block[1] = 0x32;                                        // '2'
        block[2] = (byte) (epoch & 0xff);
        block[3] = (byte) ((epoch >>> 8) & 0xff);               // epoch u16 小端
        return AesGcm.aes128EncryptBlock(sessionKey, block);
    }

    /**
     * R3-1：三次定长 AES 块，CBC-MAC 风格（keys.ts:62-76 deriveSessionKeyV7）：
     * <pre>
     *   X0 = AES(psk, salt || 0^8)
     *   X1 = AES(psk, X0 xor client_nonce)
     *   X2 = AES(psk, X1 xor server_nonce)
     * </pre>
     * nonce 顺序敏感：交换 client/server nonce 得到不同密钥。
     *
     * @throws IllegalArgumentException psk/salt/nonce 长度非法
     */
    public static byte[] deriveSessionKeyV7(byte[] psk, byte[] salt, byte[] clientNonce, byte[] serverNonce) {
        if (psk.length != 16 || salt.length != SALT_LEN
                || clientNonce.length != 16 || serverNonce.length != 16) {
            throw new IllegalArgumentException("deriveSessionKeyV7: bad lengths");
        }
        byte[] x0 = deriveSessionKey(psk, salt);
        byte[] x1 = AesGcm.aes128EncryptBlock(psk, xor16(x0, clientNonce));
        return AesGcm.aes128EncryptBlock(psk, xor16(x1, serverNonce));
    }
}
