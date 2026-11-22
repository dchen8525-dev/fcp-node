package com.dchen.fcpvpn.core.crypto;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * 信封（Envelope）测试。用例逐条转写自 fcp-node tests/bytes.test.ts:61-92
 * 与 tests/golden.test.ts:94-106；钉死的线格式 hex 由参考实现
 * fcp-node src/crypto/envelope.ts 直接运行输出抄录（golden.test.ts 对
 * sealAt 结果只断言长度与方向分离，未钉死字节）。
 */
public class EnvelopeTest {

    /** bytes.test.ts:20-21 / golden.test.ts:95-96 的 PSK / salt / payload。 */
    private static final byte[] PSK = hx("00112233445566778899aabbccddeeff");
    private static final byte[] SALT = hx("0102030405060708");
    private static final byte[] PAYLOAD = hx("a0a1a2a3a4");

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

    /** golden.test.ts:94-106 —— 钉死 counter 的方向分离：方向字节在 IV 里。 */
    @Test
    public void directionSeparationAtPinnedNonce() {
        Envelope client = new Envelope(PSK, SALT, FcpKeys.DIRECTION_C2S, FcpKeys.DIRECTION_S2C);
        Envelope server = new Envelope(PSK, SALT, FcpKeys.DIRECTION_S2C, FcpKeys.DIRECTION_C2S);
        byte[] cw = client.sealAt(100L, PAYLOAD);
        byte[] sw = server.sealAt(100L, PAYLOAD);
        assertNotNull(cw);
        assertNotNull(sw);
        assertEquals(33, cw.length); // 28 开销 + 5 字节明文
        assertFalse("the direction byte is part of the IV", hex(cw).equals(hex(sw)));
        assertArrayEquals(PAYLOAD,
                new Envelope(PSK, SALT, FcpKeys.DIRECTION_S2C, FcpKeys.DIRECTION_C2S).open(cw));
        assertArrayEquals(PAYLOAD,
                new Envelope(PSK, SALT, FcpKeys.DIRECTION_C2S, FcpKeys.DIRECTION_S2C).open(sw));
        // 钉死向量（参考实现输出，counter=100 LE64 6400000000000000）
        assertEquals("01020304050607086400000000000000774f522fb958241826817a6b5f8ac2c4ef", hex(cw));
        assertEquals("010203040506070864000000000000009cb2dd79d0ba9b31c5f08068681a212de1", hex(sw));
    }

    /** bytes.test.ts:61-71 —— seal/open、重放、错误 salt、篡改。 */
    @Test
    public void sealOpenReplayWrongSaltTamper() {
        Envelope client = new Envelope(PSK, SALT, FcpKeys.DIRECTION_C2S, FcpKeys.DIRECTION_S2C);
        Envelope server = new Envelope(PSK, SALT, FcpKeys.DIRECTION_S2C, FcpKeys.DIRECTION_C2S);
        byte[] wire = client.seal("hello fcp".getBytes());
        assertNotNull(wire);
        assertEquals(28 + 9, wire.length);
        assertEquals("hello fcp", new String(server.open(wire)));
        assertNull("replay must be rejected", server.open(wire));
        assertNull(new Envelope(PSK, new byte[8], FcpKeys.DIRECTION_S2C, FcpKeys.DIRECTION_C2S).open(wire));
        byte[] tampered = wire.clone();
        tampered[30] ^= 1;
        assertNull(new Envelope(PSK, SALT, FcpKeys.DIRECTION_S2C, FcpKeys.DIRECTION_C2S).open(tampered));
        // 钉死向量（参考实现输出，counter=0）
        assertEquals("010203040506070800000000000000001487839468030b81a19c0da9a78d0d532376dfc0aa", hex(wire));
    }

    /**
     * bytes.test.ts:73-84 —— 1024 槽重放窗口：接受乱序、拒绝过期。
     * （先查窗口再解密，tag 通过才提交窗口状态。）
     */
    @Test
    public void replayWindow1024AcceptsOutOfOrderRejectsOld() {
        Envelope a = new Envelope(PSK, SALT, FcpKeys.DIRECTION_C2S, FcpKeys.DIRECTION_S2C);
        Envelope b = new Envelope(PSK, SALT, FcpKeys.DIRECTION_S2C, FcpKeys.DIRECTION_C2S);
        byte[][] w = new byte[1100][];
        for (int i = 0; i < 1100; ++i) w[i] = a.seal(new byte[]{(byte) (i & 0xff)});
        // 送达 0..1000 但留下 500：这个洞在最高位之后 500 个 counter 处。
        for (int i = 0; i <= 1000; ++i) {
            if (i != 500) assertNotNull("counter " + i, b.open(w[i]));
        }
        assertNotNull("a hole 500 back is inside the 1024-slot window", b.open(w[500]));
        assertNull("a second copy is a replay", b.open(w[500]));
        for (int i = 1001; i < 1100; ++i) assertNotNull(b.open(w[i]));
        assertNull("a counter 1099 back is stale", b.open(w[0]));
        // 钉死向量（参考实现输出）：首封 counter=0 与 counter=1000（明文 0xe8）
        assertEquals("010203040506070800000000000000007c18ea4cb18f71b3d211be32be", hex(w[0]));
        assertEquals("0102030405060708e8030000000000007a3f17e0166af4d3938d7bc4d8", hex(w[1000]));
    }

    /** bytes.test.ts:86-92 —— 无状态复位绕过重放窗口（设计上可重放）。 */
    @Test
    public void statelessResetBypassesReplayWindow() {
        Envelope a = new Envelope(PSK, SALT, FcpKeys.DIRECTION_C2S, FcpKeys.DIRECTION_S2C);
        Envelope b = new Envelope(PSK, SALT, FcpKeys.DIRECTION_S2C, FcpKeys.DIRECTION_C2S);
        byte[] wire = a.sealAt(123456789L, Envelope.RESET_MAGIC);
        assertNotNull(wire);
        assertEquals(28 + 8, wire.length);
        assertArrayEquals(Envelope.RESET_MAGIC, b.openReset(wire));
        assertArrayEquals("reset is replay-tolerant by design",
                Envelope.RESET_MAGIC, b.openReset(wire));
        // 钉死向量（参考实现输出，counter=123456789 LE64 15cd5b0700000000）
        assertEquals("010203040506070815cd5b070000000043292a4ec105c1500704a0653c23c67095cb29ef", hex(wire));
        // 静态 sealReset 助手（envelope.ts:301-306）产出同一数据报
        assertArrayEquals(wire, Envelope.sealReset(PSK, SALT,
                FcpKeys.DIRECTION_C2S, FcpKeys.DIRECTION_S2C, 123456789L));
        // 形状门（envelope.ts:284-285）：长度不符 / salt 不符
        assertNull(b.openReset(new byte[35]));
        assertNull(new Envelope(PSK, new byte[8], FcpKeys.DIRECTION_S2C, FcpKeys.DIRECTION_C2S).openReset(wire));
    }

    /**
     * 引导信封（envelope.ts:120-128）：nonce 起点 CSPRNG u64、发送预算
     * budget+1（会话层传 2^16，constants.ts:363）、counterCeiling = u64 上限。
     */
    @Test
    public void bootstrapEnvelopeBudgetAndCounter() {
        Envelope e = new Envelope(PSK, SALT, FcpKeys.DIRECTION_C2S, FcpKeys.DIRECTION_S2C);
        assertFalse(e.isBootstrap());
        assertTrue(e.initBootstrapNonce(1 << 16));
        assertTrue(e.isBootstrap());
        long n0 = e.nonce();
        // 预算内顶格：setSendNonce(n0+65536) 可行（span = 65537），再往上一格不行
        assertTrue(e.setSendNonce(n0 + 65536L));
        assertFalse(e.setSendNonce(n0 + 65537L));
        // 首封的 nonce_ctr 就是设定值；用尽后 seal 返回 null 且 exhausted
        byte[] wire = e.seal(new byte[]{1});
        assertNotNull(wire);
        assertEquals(n0 + 65536L, wireLe64(wire, 8));
        assertTrue(e.isExhausted());
        assertNull(e.seal(new byte[]{2}));
    }

    /** rekey（envelope.ts:98-101）：复位计数器/窗口并退出引导模式。 */
    @Test
    public void rekeyResetsCounterAndBootstrap() {
        Envelope a = new Envelope(PSK, SALT, FcpKeys.DIRECTION_C2S, FcpKeys.DIRECTION_S2C);
        Envelope b = new Envelope(PSK, SALT, FcpKeys.DIRECTION_S2C, FcpKeys.DIRECTION_C2S);
        assertTrue(a.initBootstrapNonce(1 << 16));
        a.rekey(FcpKeys.deriveSessionKeyV7(PSK, SALT, filled(0x11), filled(0x22)));
        b.rekey(FcpKeys.deriveSessionKeyV7(PSK, SALT, filled(0x11), filled(0x22)));
        assertFalse(a.isBootstrap());
        byte[] wire = a.seal(new byte[]{7});
        assertNotNull(wire);
        assertEquals("rekey 后计数器回到 0", 0L, wireLe64(wire, 8));
        assertArrayEquals(new byte[]{7}, b.open(wire));
    }

    /**
     * #84 epoch 轮换（envelope.ts:103-152 / 243-280）：keyUpdate 开启后第
     * FIRST_ROLL_AT(100) 个包触发轮换到 epoch 1（counter 跳到 2^24）；接收方
     * commitNext 换钥继续收；<b>未开启 keyUpdate 的接收方在轮换后必须丢弃</b>
     * （protocol.test.ts:505-521 的回归语义：单侧开启 = 双侧都不轮换）。
     */
    @Test
    public void epochRollOnFirstRollAt() {
        Envelope a = new Envelope(PSK, SALT, FcpKeys.DIRECTION_C2S, FcpKeys.DIRECTION_S2C);
        Envelope b = new Envelope(PSK, SALT, FcpKeys.DIRECTION_S2C, FcpKeys.DIRECTION_C2S);
        a.setKeyUpdate(true);
        b.setKeyUpdate(true);
        assertTrue(a.isKeyUpdate() && b.isKeyUpdate());
        byte[][] wires = new byte[101][];
        for (int i = 0; i < 100; ++i) wires[i] = a.seal(new byte[]{(byte) i});
        wires[100] = a.seal(new byte[]{100}); // 触发轮换
        assertEquals("轮换后 counter = EPOCH_SPAN", 1L << 24, wireLe64(wires[100], 8));
        assertEquals(1L, a.sendEpochValue());
        assertEquals((1L << 24) + 1, a.nonce());
        for (int i = 0; i <= 100; ++i) {
            assertArrayEquals("counter " + i, new byte[]{(byte) i}, b.open(wires[i]));
        }
        byte[] wNext = a.seal(new byte[]{101});
        assertArrayEquals(new byte[]{101}, b.open(wNext));
        // 未开启 keyUpdate 的接收方：轮换后的包 tag 校验失败被丢弃
        Envelope plain = new Envelope(PSK, SALT, FcpKeys.DIRECTION_S2C, FcpKeys.DIRECTION_C2S);
        assertNull(plain.open(wires[100]));
        // 钉死向量（参考实现输出）
        assertEquals("01020304050607080000000100000000367988775f640fe7461d635c41", hex(wires[100]));
        assertEquals("01020304050607080100000100000000ec309117bd103a58cbea41f4a1", hex(wNext));
    }

    /** envelope.ts:114-118 / 155-158 —— setSendNonce 与 sealAt 的上限门。 */
    @Test
    public void sendNonceBounds() {
        Envelope e = new Envelope(PSK, SALT, FcpKeys.DIRECTION_C2S, FcpKeys.DIRECTION_S2C);
        assertEquals(1L << 32, Envelope.NONCE_LIMIT);
        assertFalse(e.setSendNonce(1L << 32)); // counterCeiling = NONCE_LIMIT
        assertTrue(e.setSendNonce((1L << 32) - 1));
        assertNull(e.sealAt(1L << 32, new byte[]{0}));
        assertNotNull(e.sealAt((1L << 32) - 1, new byte[]{0}));
        // epoch 号 = nonce / EPOCH_SPAN（无符号除法，envelope.ts:110）
        assertEquals(255L, e.sendEpochValue());
        // 非 keyUpdate 时 seal 不触发轮换（envelope.ts:141-146）；
        // 新信封 nonce=0 → epoch 0
        Envelope f = new Envelope(PSK, SALT, FcpKeys.DIRECTION_S2C, FcpKeys.DIRECTION_C2S);
        assertEquals(0L, f.sendEpochValue());
        e.destroy();
        f.destroy();
    }

    private static long wireLe64(byte[] wire, int off) {
        long v = 0;
        for (int i = 7; i >= 0; --i) v = (v << 8) | (wire[off + i] & 0xffL);
        return v;
    }

    private static byte[] filled(int v) {
        byte[] b = new byte[16];
        java.util.Arrays.fill(b, (byte) v);
        return b;
    }
}
