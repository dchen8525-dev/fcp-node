package com.dchen.fcpvpn.core.crypto;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Test;

/**
 * AES 原语黄金向量。期望值逐条抄自 fcp-node tests/golden.test.ts
 * （其来源为 D:\work\fcp\tests\aes_test.cc / gcm_test.cc 的 FIPS-197 与
 * NIST GCM tc1/tc2/tc3）及 tests/bytes.test.ts:30-34。
 */
public class AesGcmTest {

    private static byte[] bin(String s) {
        s = s.replaceAll("\\s+", "");
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

    /** golden.test.ts:25-29 —— FIPS-197 AES-128 单块（tests/aes_test.cc:9-13）。 */
    @Test
    public void fips197SingleBlock() {
        byte[] key = bin("000102030405060708090a0b0c0d0e0f");
        byte[] plain = bin("00112233445566778899aabbccddeeff");
        assertArrayEquals(bin("69c4e0d86a7b0430d8cdb78070b4c55a"),
                AesGcm.aes128EncryptBlock(key, plain));
    }

    /** aes.ts:12-13 —— 非法长度大声失败。 */
    @Test
    public void badLengthsThrow() {
        try {
            AesGcm.aes128EncryptBlock(new byte[15], new byte[16]);
            fail("key must be 16 bytes");
        } catch (IllegalArgumentException expected) { /* ok */ }
        try {
            AesGcm.aes128EncryptBlock(new byte[16], new byte[15]);
            fail("block must be 16 bytes");
        } catch (IllegalArgumentException expected) { /* ok */ }
    }

    /** golden.test.ts:33-35 —— NIST GCM tc1：空消息、全零 key/IV，12 字节 tag。 */
    @Test
    public void nistGcmTc1EmptyMessage() {
        AesGcm.Sealed t1 = AesGcm.gcmSeal(new byte[16], new byte[12], new byte[0], null);
        assertNotNull(t1);
        assertEquals("", hex(t1.cipher));
        assertEquals("58e2fccefa7e3061367f1d57", hex(t1.tag));
    }

    /** golden.test.ts:38-40 —— NIST GCM tc2：单个全零块。 */
    @Test
    public void nistGcmTc2SingleZeroBlock() {
        AesGcm.Sealed t2 = AesGcm.gcmSeal(new byte[16], new byte[12], new byte[16], null);
        assertNotNull(t2);
        assertEquals("0388dace60b6a392f328c2b971b2fe78", hex(t2.cipher));
        assertEquals("ab6e47d42cec13bdf53a67b2", hex(t2.tag));
    }

    /**
     * golden.test.ts:43-56 —— NIST GCM tc3：60 字节明文 + 20 字节 AAD；
     * 带 AAD 解封还原，不带 AAD 解封失败（AAD 参与认证）。
     */
    @Test
    public void nistGcmTc3WithAad() {
        byte[] key3 = bin("feffe9928665731c6d6a8f9467308308");
        byte[] iv3 = bin("cafebabefacedbaddecaf888");
        byte[] aad3 = bin("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        byte[] plain3 = bin(
                "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c"
                        + "95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39");
        AesGcm.Sealed t3 = AesGcm.gcmSeal(key3, iv3, plain3, aad3);
        assertNotNull(t3);
        assertEquals("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b2"
                        + "5466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
                hex(t3.cipher));
        assertEquals("5bc94fbc3221a5db94fae95a", hex(t3.tag));
        assertArrayEquals(plain3, AesGcm.gcmOpen(key3, iv3, t3.cipher, t3.tag, aad3));
        assertNull("AAD is authenticated", AesGcm.gcmOpen(key3, iv3, t3.cipher, t3.tag, null));
    }

    /** bytes.test.ts:30-34 —— tc1 解封往返：空密文 + 正确 tag → 空明文（非 null）。 */
    @Test
    public void openRoundTripTc1() {
        AesGcm.Sealed r = AesGcm.gcmSeal(new byte[16], new byte[12], new byte[0], null);
        assertNotNull(r);
        byte[] plain = AesGcm.gcmOpen(new byte[16], new byte[12], new byte[0], r.tag, null);
        assertNotNull(plain);
        assertEquals(0, plain.length);
    }

    /** aes.ts:20/32 —— key/iv/tag 长度不合格返回 null（不抛异常）。 */
    @Test
    public void lengthGatesReturnNull() {
        assertNull(AesGcm.gcmSeal(new byte[15], new byte[12], new byte[0], null));
        assertNull(AesGcm.gcmSeal(new byte[16], new byte[11], new byte[0], null));
        assertNull(AesGcm.gcmOpen(new byte[16], new byte[12], new byte[0], new byte[16], null));
        assertTrue(AesGcm.TAG_LEN == 12); // constants.ts:32：12 字节 tag，非 16
    }
}
