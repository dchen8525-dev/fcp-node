package com.dchen.fcpvpn.core.crypto;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

/**
 * 密钥派生测试。关系断言逐条抄自 fcp-node tests/bytes.test.ts:48-59
 * （"key derivation: determinism, direction separation, epoch separation"）与
 * tests/protocol.test.ts:100-103（client/server converge）。
 *
 * <p>除上述文件级断言外，本类附加了 <b>钉死向量</b>：由参考实现
 * {@code D:\work\fcp-node\src\crypto\keys.ts}（node ≥22.18 直接运行）对同一
 * PSK/salt/nonce 输入逐字节输出抄录，用于锁死最容易错的两个点——
 * SP 800-108 的 {@code L} 编码（<b>bits 且大端</b>，keys.ts:27-43）与
 * CBC-MAC 链的 nonce 顺序（keys.ts:66-76）。fcp-node 的两个测试文件对
 * 派生值只断言关系、未钉死字节，若不抄参考输出则方向颠倒类缺陷无法在此拦截。</p>
 */
public class KeysTest {

    /** bytes.test.ts:20-21 / protocol.test.ts:32-33 的 PSK 与 salt。 */
    private static final byte[] PSK = hx("00112233445566778899aabbccddeeff");
    private static final byte[] SALT = hx("0102030405060708");

    private static byte[] hx(String s) {
        byte[] out = new byte[s.length() / 2];
        for (int i = 0; i < out.length; ++i) {
            out[i] = (byte) Integer.parseInt(s.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }

    private static byte[] filled16(int v) {
        byte[] b = new byte[16];
        java.util.Arrays.fill(b, (byte) v);
        return b;
    }

    /** bytes.test.ts:48-59 —— 确定性、方向分离、epoch 分离（关系断言逐条转写）。 */
    @Test
    public void determinismDirectionSeparationEpochSeparation() {
        byte[] k0 = FcpKeys.deriveSessionKey(PSK, SALT);
        assertEquals(hex(k0), hex(FcpKeys.deriveSessionKey(PSK, SALT)));
        FcpKeys.DirectionKeys dk = FcpKeys.deriveDirectionKeys(k0);
        assertFalse(hex(dk.c2s).equals(hex(dk.s2c)));
        byte[] cn = filled16(1), sn = filled16(2);
        byte[] k7 = FcpKeys.deriveSessionKeyV7(PSK, SALT, cn, sn);
        assertFalse(hex(k7).equals(hex(k0)));
        assertEquals(hex(k7), hex(FcpKeys.deriveSessionKeyV7(PSK, SALT, cn, sn)));
        assertFalse(hex(k7).equals(hex(FcpKeys.deriveSessionKeyV7(PSK, SALT, sn, cn))));
        assertFalse(hex(FcpKeys.deriveEpochDirectionKey(k7, FcpKeys.DIRECTION_C2S, 1)).equals(hex(dk.c2s)));
    }

    /**
     * 钉死向量（见类 javadoc 的来源说明）：引导密钥、方向密钥、v7 会话密钥、
     * epoch 密钥。k7swapped 证明 CBC-MAC 链对 nonce 顺序敏感（keys.ts:74-75）。
     */
    @Test
    public void pinnedDerivationVectors() {
        byte[] k0 = FcpKeys.deriveSessionKey(PSK, SALT);
        assertEquals("a17b863d00c60d546537f953363b43db", hex(k0));
        FcpKeys.DirectionKeys dk = FcpKeys.deriveDirectionKeys(k0);
        assertEquals("6382dd845fe2a39792fabb59929759ce", hex(dk.c2s));
        assertEquals("463afa927e48c509d24bc2a95fec5e5f", hex(dk.s2c));
        byte[] cn = filled16(1), sn = filled16(2);
        byte[] k7 = FcpKeys.deriveSessionKeyV7(PSK, SALT, cn, sn);
        assertEquals("5176a10e4ea8a24a94ca50e5c9d06514", hex(k7));
        assertEquals("0546470e93243121a0f3fc90fa28e5b9",
                hex(FcpKeys.deriveSessionKeyV7(PSK, SALT, sn, cn)));
        assertEquals("6c76fd5ad6995a76d3b6128f41b76b1e",
                hex(FcpKeys.deriveEpochDirectionKey(k7, FcpKeys.DIRECTION_C2S, 1)));
        assertEquals("2a1b2422d2bd514a057d26f944f63c58",
                hex(FcpKeys.deriveEpochDirectionKey(k7, FcpKeys.DIRECTION_S2C, 1)));
        assertEquals("7fed465d19748cbfcc2b8d937f40b18a",
                hex(FcpKeys.deriveEpochDirectionKey(k7, FcpKeys.DIRECTION_C2S, 2)));
    }

    /** protocol.test.ts:100-103 —— 两侧由相同 nonce 对派生出相同 v7 会话密钥。 */
    @Test
    public void bothRolesConvergeOnSameV7Key() {
        byte[] clientKey = FcpKeys.deriveSessionKeyV7(PSK, SALT, filled16(0x11), filled16(0x22));
        byte[] serverKey = FcpKeys.deriveSessionKeyV7(PSK, SALT, filled16(0x11), filled16(0x22));
        assertArrayEquals(clientKey, serverKey);
    }

    /** keys.ts:18 / 69-71 —— 非法长度大声失败。 */
    @Test
    public void badLengthsThrow() {
        try {
            FcpKeys.deriveSessionKey(new byte[15], SALT);
            fail("psk must be 16 bytes");
        } catch (IllegalArgumentException expected) { /* ok */ }
        try {
            FcpKeys.deriveSessionKey(PSK, new byte[7]);
            fail("salt must be 8 bytes");
        } catch (IllegalArgumentException expected) { /* ok */ }
        try {
            FcpKeys.deriveSessionKeyV7(PSK, SALT, new byte[3], filled16(2));
            fail("clientNonce must be 16 bytes");
        } catch (IllegalArgumentException expected) { /* ok */ }
        try {
            FcpKeys.deriveSessionKeyV7(PSK, SALT, filled16(1), new byte[15]);
            fail("serverNonce must be 16 bytes");
        } catch (IllegalArgumentException expected) { /* ok */ }
    }

    /** constants.ts:43-46 —— 方向常量字节值。 */
    @Test
    public void directionValues() {
        assertEquals(0x01, FcpKeys.DIRECTION_C2S);
        assertEquals(0x02, FcpKeys.DIRECTION_S2C);
    }
}
