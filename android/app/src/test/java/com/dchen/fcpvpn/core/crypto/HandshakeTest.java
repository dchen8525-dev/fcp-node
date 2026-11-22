package com.dchen.fcpvpn.core.crypto;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

/**
 * 握手编解码 + 协商测试。用例逐条转写自 fcp-node tests/protocol.test.ts:37-76、
 * 1070-1110、138-171 与 tests/adversarial.test.ts 的编解码相关断言；钉死的线
 * 格式 hex 由参考实现 fcp-node src/crypto/handshake.ts 直接运行输出抄录
 * （protocol.test.ts 对 buildHello/buildHelloAck 结果断言长度/magic/字段位置，
 * 本类逐条对应，另附整包 hex 以锁死字节）。
 */
public class HandshakeTest {

    private static final byte[] NONCE_C = filled(0x11);
    private static final byte[] NONCE_S = filled(0x22);
    /** constants.ts:59 LOCAL_FLAGS_M1 = FRAMING|FECSTAT|PER_SET_K = 0x07。 */
    private static final int LOCAL_FLAGS_M1 = Handshake.LOCAL_FLAGS_M1;
    private static final int CAP_TLV = Handshake.CAP_TLV;

    private static byte[] filled(int v) {
        byte[] b = new byte[16];
        java.util.Arrays.fill(b, (byte) v);
        return b;
    }

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

    private static Handshake.Caps caps(int data, int parity, int flags) {
        return new Handshake.Caps(Handshake.CAPS_VERSION, data, parity, flags);
    }

    /**
     * protocol.test.ts:37-56 —— HELLO/HELLO_ACK 线形状 36/52 字节、精确 magic、
     * nonce 位置、caps 字段往返、isHello/isHelloAck 互斥。
     */
    @Test
    public void helloAckWireShapes36and52() {
        Handshake.Caps c = caps(10, 3, LOCAL_FLAGS_M1);
        byte[] hello = Handshake.buildHello(c, NONCE_C, null);
        assertEquals(Handshake.HELLO_LEN, hello.length);
        assertEquals("FCP_HELLO_V1\0\0\0\0",
                new String(hello, 0, 16, java.nio.charset.StandardCharsets.ISO_8859_1));
        assertArrayEquals(NONCE_C, Arrays.copyOfRange(hello, 16, 32));
        Handshake.Caps parsed = Handshake.parseCaps(hello, 32);
        assertEquals(c.ver, parsed.ver);
        assertEquals(c.data, parsed.data);
        assertEquals(c.parity, parsed.parity);
        assertEquals(c.flags, parsed.flags);
        assertTrue(Handshake.isHello(hello));
        assertFalse(Handshake.isHelloAck(hello));
        // 钉死整包 hex（参考实现输出）
        assertEquals("4643505f48454c4c4f5f56310000000011111111111111111111111111111111010a0307", hex(hello));

        byte[] ack = Handshake.buildHelloAck(c, NONCE_C, NONCE_S, null, false);
        assertEquals(Handshake.HELLO_ACK_LEN, ack.length);
        assertEquals("FCP_HELLO_ACK_V1",
                new String(ack, 0, 16, java.nio.charset.StandardCharsets.ISO_8859_1));
        assertArrayEquals(NONCE_C, Arrays.copyOfRange(ack, 16, 32));
        assertArrayEquals(NONCE_S, Arrays.copyOfRange(ack, 32, 48));
        assertTrue(Handshake.isHelloAck(ack));
        assertEquals("4643505f48454c4c4f5f41434b5f563111111111111111111111111111111111"
                + "22222222222222222222222222222222010a0307", hex(ack));
    }

    /** protocol.test.ts:52-55 —— capsValid：版本、保留位、TLV 位。 */
    @Test
    public void capsValidMatrix() {
        assertTrue(Handshake.capsValid(caps(10, 3, LOCAL_FLAGS_M1)));
        assertFalse("ver != 1", Handshake.capsValid(new Handshake.Caps(2, 10, 3, LOCAL_FLAGS_M1)));
        assertFalse("bits 6..7 are reserved", Handshake.capsValid(caps(10, 3, 0x80)));
        assertTrue("bit5 = TLV is known", Handshake.capsValid(caps(10, 3, CAP_TLV | LOCAL_FLAGS_M1)));
        // 其余源码级边界（handshake.ts:43-45）：data >= 1、parity <= 7、d+p <= 256
        assertFalse(Handshake.capsValid(caps(0, 3, LOCAL_FLAGS_M1)));
        assertFalse(Handshake.capsValid(caps(10, 8, LOCAL_FLAGS_M1)));
        assertTrue(Handshake.capsValid(caps(249, 7, LOCAL_FLAGS_M1))); // d+p == 256
        assertFalse(Handshake.capsValid(caps(250, 7, LOCAL_FLAGS_M1))); // d+p == 257
    }

    /**
     * protocol.test.ts:58-76 —— TLV block 编码/解析、畸形拒绝、prewarm 车票。
     */
    @Test
    public void tlvBlockEncodeParse() {
        List<Handshake.Tlv> tlvs = new ArrayList<Handshake.Tlv>();
        tlvs.add(new Handshake.Tlv(Handshake.TLV_TYPE_ACK_V2, new byte[0]));
        Handshake.PrewarmTicket pt = new Handshake.PrewarmTicket();
        pt.initialK = 3;
        pt.srttMs = 120;
        pt.windowKb = 256;
        pt.bwKbps = 4096;
        pt.minRttMs = 40;
        tlvs.add(new Handshake.Tlv(Handshake.TLV_TYPE_PREWARM, Handshake.encodePrewarmTlv(pt)));
        Handshake.Caps c = caps(10, 3, LOCAL_FLAGS_M1 | CAP_TLV);
        byte[] ext = Handshake.buildHello(c, NONCE_C, tlvs);
        // 36 定长 + 2 block_len + 2 + 14（2+0 与 2+12）
        assertEquals(Handshake.HELLO_LEN + 2 + 2 + 14, ext.length);
        assertEquals("block_len", 16, le16(ext, Handshake.HELLO_LEN));
        List<Handshake.Tlv> parsed = Handshake.helloTlvs(ext, ext.length, false);
        assertNotNull(parsed);
        assertEquals(2, parsed.size());
        assertEquals(Handshake.TLV_TYPE_ACK_V2, parsed.get(0).type);
        Handshake.PrewarmTicket t = Handshake.decodePrewarmTlv(parsed.get(1).value);
        assertNotNull(t);
        assertEquals(3, t.initialK);
        assertEquals(120, t.srttMs);
        assertEquals(40, t.minRttMs);
        assertEquals(256, t.windowKb);
        assertEquals(4096, t.bwKbps);
        // 截断一字节 → block 声明与长度不符 → null
        assertNull(Handshake.helloTlvs(Arrays.copyOf(ext, ext.length - 1), ext.length - 1, false));
        // type 0 不可编码（handshake.ts:61）；value 越界解析失败（handshake.ts:88）
        assertEquals(0, Handshake.tlvEncode(
                java.util.Collections.singletonList(new Handshake.Tlv(0, new byte[0])), new byte[64], 0));
        assertNull(Handshake.tlvParse(new byte[]{1, 5, 0, 0}, 4));
        // 钉死整包 hex（参考实现输出）
        assertEquals("4643505f48454c4c4f5f56310000000011111111111111111111111111111111010a0327"
                + "10000200030c010378000001000010002800", hex(ext));
        assertEquals("010378000001000010002800", hex(Handshake.encodePrewarmTlv(pt)));
    }

    private static int le16(byte[] b, int off) {
        return (b[off] & 0xff) | ((b[off + 1] & 0xff) << 8);
    }

    /**
     * protocol.test.ts:1091-1099 —— 声明超过实际持有的 TLV block 是畸形。
     */
    @Test
    public void tlvBlockThatClaimsMoreThanItHoldsIsMalformed() {
        assertNull(Handshake.tlvParse(new byte[]{1, 5, 0, 0}, 10));
        assertNull("the value does not fit the block", Handshake.tlvParse(new byte[]{1, 5, 0, 0}, 4));
        List<Handshake.Tlv> ok = Handshake.tlvParse(new byte[]{1, 2, (byte) 0xaa, (byte) 0xbb}, 4);
        assertNotNull("a legal block still parses", ok);
        assertEquals(1, ok.size());
        assertArrayEquals(new byte[]{(byte) 0xaa, (byte) 0xbb}, ok.get(0).value);
    }

    /**
     * protocol.test.ts:1101-1110 + handshake.ts:165-167 —— k 不可能是测量值的
     * prewarm 车票是畸形：8..14 畸形、15 是"未知"标记（解码为 0）。
     */
    @Test
    public void prewarmTicketWithImpossibleKIsMalformed() {
        byte[] v = new byte[12];
        v[0] = 1;
        v[1] = (byte) 200;
        assertNull(Handshake.decodePrewarmTlv(v));
        byte[] ok = new byte[12];
        ok[0] = 1;
        ok[1] = 6;
        assertNotNull("a legal k still decodes", Handshake.decodePrewarmTlv(ok));
        // handshake.ts:166-167 的边界（3-bit 线字段的来源注释）
        byte[] low = new byte[12]; low[0] = 1; low[1] = 8;
        assertNull(Handshake.decodePrewarmTlv(low));
        byte[] high = new byte[12]; high[0] = 1; high[1] = 14;
        assertNull(Handshake.decodePrewarmTlv(high));
        byte[] marker = new byte[12]; marker[0] = 1; marker[1] = 15;
        Handshake.PrewarmTicket t = Handshake.decodePrewarmTlv(marker);
        assertNotNull(t);
        assertEquals(0, t.initialK);
        // 版本/长度门（handshake.ts:159）
        assertNull(Handshake.decodePrewarmTlv(new byte[11]));
        byte[] badVer = new byte[12]; badVer[0] = 2;
        assertNull(Handshake.decodePrewarmTlv(badVer));
    }

    /**
     * protocol.test.ts:1070-1089 的编解码部分 —— 短 nonce 必须在校验处拒绝；
     * 全零 nonce 也非法（handshake.ts:54-55）。
     */
    @Test
    public void shortNonceRefused() {
        assertFalse(Handshake.nonceValid(new byte[]{1, 2, 3}));
        assertFalse("全零 nonce", Handshake.nonceValid(new byte[16]));
        assertTrue(Handshake.nonceValid(filled(3)));
    }

    /**
     * handshake.ts:341-360 negotiate —— 必需位、flags AND、D'/P' 取 min、
     * TLV 双方提供、P'=0 进入纯统计模式。
     */
    @Test
    public void negotiateCombinations() {
        // 现代对端：双方 flags = M1|TLV → 协商出 TLV
        Handshake.Negotiated n = Handshake.negotiate(10, 3, LOCAL_FLAGS_M1 | CAP_TLV, true,
                caps(10, 3, LOCAL_FLAGS_M1 | CAP_TLV));
        assertNotNull(n);
        assertEquals(10, n.d);
        assertEquals(3, n.p);
        assertEquals(LOCAL_FLAGS_M1 | CAP_TLV, n.flags);
        assertEquals(Handshake.MODE_FRAMED_REPAIR, n.mode);
        assertTrue(Handshake.tlvNegotiated(n.flags));

        // 缺 FECSTAT（peer = FRAMING|TLV = 0x21）→ MissingCapability
        assertNull(Handshake.negotiate(10, 3, LOCAL_FLAGS_M1 | CAP_TLV, true, caps(10, 3, 0x21)));
        // 缺 FRAMING（peer = FECSTAT|TLV = 0x22）→ MissingCapability
        assertNull(Handshake.negotiate(10, 3, LOCAL_FLAGS_M1 | CAP_TLV, true, caps(10, 3, 0x22)));

        // flags = local & peer：本端 PMTUD（bit4）对端没有 → 协商结果无 PMTUD
        n = Handshake.negotiate(10, 3, LOCAL_FLAGS_M1 | Handshake.CAP_PMTUD | CAP_TLV, true,
                caps(10, 3, LOCAL_FLAGS_M1 | CAP_TLV));
        assertNotNull(n);
        assertEquals(LOCAL_FLAGS_M1 | CAP_TLV, n.flags);

        // D'/P' 取 min；P'=0 → FramedStats（constants.ts:103）
        n = Handshake.negotiate(10, 6, LOCAL_FLAGS_M1, false, caps(4, 2, LOCAL_FLAGS_M1));
        assertNotNull(n);
        assertEquals(4, n.d);
        assertEquals(2, n.p);
        n = Handshake.negotiate(10, 0, LOCAL_FLAGS_M1, false, caps(8, 0, LOCAL_FLAGS_M1));
        assertNotNull(n);
        assertEquals(0, n.p);
        assertEquals(Handshake.MODE_FRAMED_STATS, n.mode);

        // TLV 必须双方提供（handshake.ts:350 bothTlv 合取）：单侧提供都不带
        n = Handshake.negotiate(10, 3, LOCAL_FLAGS_M1 | CAP_TLV, true, caps(10, 3, LOCAL_FLAGS_M1));
        assertNotNull(n);
        assertFalse(Handshake.tlvNegotiated(n.flags));
        n = Handshake.negotiate(10, 3, LOCAL_FLAGS_M1, false, caps(10, 3, LOCAL_FLAGS_M1 | CAP_TLV));
        assertNotNull(n);
        assertFalse(Handshake.tlvNegotiated(n.flags));
    }

    /** handshake.ts:257-260 tlvAgreed —— 双方都提供同一 type 才生效。 */
    @Test
    public void tlvAgreedSemantics() {
        List<Handshake.Tlv> withAck = java.util.Collections.singletonList(
                new Handshake.Tlv(Handshake.TLV_TYPE_ACK_V2, new byte[0]));
        // flags 无 TLV 位 → 恒 false
        assertFalse(Handshake.tlvAgreed(LOCAL_FLAGS_M1, withAck, withAck, Handshake.TLV_TYPE_ACK_V2));
        // 双方都有 type 2
        assertTrue(Handshake.tlvAgreed(LOCAL_FLAGS_M1 | CAP_TLV, withAck, withAck, Handshake.TLV_TYPE_ACK_V2));
        // 对端没提供
        assertFalse(Handshake.tlvAgreed(LOCAL_FLAGS_M1 | CAP_TLV, withAck,
                new ArrayList<Handshake.Tlv>(), Handshake.TLV_TYPE_ACK_V2));
        // 本端没提供
        assertFalse(Handshake.tlvAgreed(LOCAL_FLAGS_M1 | CAP_TLV,
                new ArrayList<Handshake.Tlv>(), withAck, Handshake.TLV_TYPE_ACK_V2));
    }

    /**
     * handshake.ts:417-427 的编解码部分 + 钉死整包 hex —— HELLO_ACK 中的
     * ERROR TLV（type 1，1 字节 HandshakeError）：会话层见到即快速失败。
     */
    @Test
    public void errorTlvInHelloAck() {
        List<Handshake.Tlv> err = java.util.Collections.singletonList(
                new Handshake.Tlv(Handshake.TLV_TYPE_ERROR, new byte[]{Handshake.ERROR_BAD_CAPS}));
        byte[] ack = Handshake.buildHelloAck(new Handshake.Caps(1, 10, 3, CAP_TLV),
                NONCE_C, NONCE_S, err, false);
        assertTrue(Handshake.isHelloAck(ack));
        assertEquals("4643505f48454c4c4f5f41434b5f563111111111111111111111111111111111"
                + "22222222222222222222222222222222010a03200300010102", hex(ack));
        Handshake.HelloAck parsed = Handshake.parseHelloAck(ack, ack.length);
        assertNotNull(parsed);
        assertEquals(1, parsed.tlvs.size());
        assertEquals(Handshake.TLV_TYPE_ERROR, parsed.tlvs.get(0).type);
        assertEquals(1, parsed.tlvs.get(0).value.length); // handshake.ts:419
        assertEquals(Handshake.ERROR_BAD_CAPS, parsed.tlvs.get(0).value[0] & 0xff);
    }

    /**
     * protocol.test.ts:138-171 —— 空块 ACK：回显对端 CAP_TLV 但无自有 TLV 时
     * block_len=0 的块必须在场；裸 52 字节 ACK 带该位 = "声明了 block 但缺失"。
     */
    @Test
    public void emptyBlockAck() {
        byte[] ack = Handshake.buildHelloAck(caps(10, 3, LOCAL_FLAGS_M1 | CAP_TLV),
                NONCE_C, NONCE_S, new ArrayList<Handshake.Tlv>(), true);
        assertEquals(Handshake.HELLO_ACK_LEN + Handshake.TLV_BLOCK_LEN_BYTES, ack.length);
        assertEquals("block_len = 0", 0, le16(ack, Handshake.HELLO_ACK_LEN));
        List<Handshake.Tlv> tlvs = Handshake.helloTlvs(ack, ack.length, true);
        assertNotNull(tlvs);
        assertTrue(tlvs.isEmpty());
        // 钉死整包 hex（参考实现输出）
        assertEquals("4643505f48454c4c4f5f41434b5f563111111111111111111111111111111111"
                + "22222222222222222222222222222222010a03270000", hex(ack));

        // 裸 52 字节 ACK 带 CAP_TLV 位：isHelloAck 仍为 true（handshake.ts:108），
        // 但 helloTlvs 返回 null → 会话层按 BadCaps 处理（handshake.ts:429）
        byte[] bare = Handshake.buildHelloAck(caps(10, 3, LOCAL_FLAGS_M1 | CAP_TLV),
                NONCE_C, NONCE_S, null, false);
        assertEquals(Handshake.HELLO_ACK_LEN, bare.length);
        assertTrue(Handshake.isHelloAck(bare));
        assertNull(Handshake.helloTlvs(bare, bare.length, true));
        assertNull(Handshake.parseHelloAck(bare, bare.length));

        // plain 服务器 ACK（无 TLV 位、52 字节）→ 空列表（handshake.ts:107）
        byte[] plainAck = Handshake.buildHelloAck(caps(10, 3, LOCAL_FLAGS_M1),
                NONCE_C, NONCE_S, null, false);
        assertTrue(Handshake.helloTlvs(plainAck, plainAck.length, true).isEmpty());
    }

    /**
     * protocol.test.ts:44-45 与 handshake.ts:105-111 msgOk 分支 —— 非法 magic、
     * 长度截断、TLV 声明形状。
     */
    @Test
    public void illegalMagicAndShapes() {
        byte[] hello = Handshake.buildHello(caps(10, 3, LOCAL_FLAGS_M1), NONCE_C, null);
        byte[] ack = Handshake.buildHelloAck(caps(10, 3, LOCAL_FLAGS_M1), NONCE_C, NONCE_S, null, false);
        assertFalse(Handshake.isHelloAck(hello));
        assertFalse(Handshake.isHello(ack));
        byte[] junk = new byte[36]; // 全零 ≠ 任一 magic
        assertFalse(Handshake.isHello(junk));
        assertFalse(Handshake.isHelloAck(junk));
        // 截断到 35 字节
        assertFalse(Handshake.isHello(Arrays.copyOf(hello, 35)));
        // CAP_TLV 声明但块缺失：形状仍通过（handshake.ts:108），解析层拒绝
        byte[] tlvHello = Handshake.buildHello(caps(10, 3, LOCAL_FLAGS_M1 | CAP_TLV), NONCE_C, null);
        assertEquals(Handshake.HELLO_LEN, tlvHello.length);
        assertTrue(Handshake.isHello(tlvHello));
        assertNull(Handshake.helloTlvs(tlvHello, tlvHello.length, false));
        assertNull(Handshake.parseHello(tlvHello, tlvHello.length));
        // 块头只有 1 字节（len < fixed + 2）→ 形状直接失败（handshake.ts:109）
        byte[] halfHeader = Arrays.copyOf(tlvHello, Handshake.HELLO_LEN + 1);
        assertFalse(Handshake.isHello(halfHeader));
        // parseHello 正常路径：nonce / caps / tlvs 拆解
        Handshake.Hello h = Handshake.parseHello(hello, hello.length);
        assertNotNull(h);
        assertArrayEquals(NONCE_C, h.senderNonce);
        assertEquals(10, h.caps.data);
        assertTrue(h.tlvs.isEmpty());
        // parseHelloAck 正常路径：两个 nonce 拆解
        Handshake.HelloAck a = Handshake.parseHelloAck(ack, ack.length);
        assertNotNull(a);
        assertArrayEquals(NONCE_C, a.clientNonce);
        assertArrayEquals(NONCE_S, a.serverNonce);
    }

    /** handshake.ts:61-64/122 —— 不可编码的 TLV（超长 value / 超大 block）抛出。 */
    @Test
    public void unencodableTlvRejected() {
        byte[] big = new byte[256]; // value > 255
        List<Handshake.Tlv> one = java.util.Collections.singletonList(
                new Handshake.Tlv(Handshake.TLV_TYPE_ACK_V2, big));
        assertEquals(0, Handshake.tlvEncode(one, new byte[2048], 0));
        try {
            Handshake.buildHello(caps(10, 3, LOCAL_FLAGS_M1 | CAP_TLV), NONCE_C, one);
            fail("buildHello: TLV block unencodable");
        } catch (IllegalArgumentException expected) { /* ok */ }
        // 6 × (2 + 200) = 1212 > 1024 → block 超上限
        List<Handshake.Tlv> many = new ArrayList<Handshake.Tlv>();
        for (int i = 0; i < 6; ++i) many.add(new Handshake.Tlv(Handshake.TLV_TYPE_MULTIPLEX, new byte[200]));
        assertEquals(0, Handshake.tlvEncode(many, new byte[4096], 0));
        try {
            Handshake.buildHello(caps(10, 3, LOCAL_FLAGS_M1 | CAP_TLV), NONCE_C, many);
            fail("buildHello: TLV block unencodable");
        } catch (IllegalArgumentException expected) { /* ok */ }
    }

    /**
     * constants.ts:95-97 + handshake.ts:281-294 —— 9 次重试、间隔 250ms 倍增
     * 封顶 8s，累计时刻表 0/250/750/1750/3750/7750/15750/23750/31750ms。
     * （定时重试由会话层驱动；每次重发必须换新信封 counter——服务端 180s 内
     * 对相同 salt‖nonce 去重。）
     */
    @Test
    public void retrySchedule() {
        assertEquals(9, Handshake.HANDSHAKE_MAX_RETRIES);
        assertEquals(250, Handshake.HANDSHAKE_RETRY_MS);
        assertEquals(8000, Handshake.HANDSHAKE_RETRY_CAP_MS);
        assertArrayEquals(new int[]{0, 250, 750, 1750, 3750, 7750, 15750, 23750, 31750},
                Handshake.DEFAULT_RETRY_SCHEDULE_MS);
        // 间隔：250, 500, 1000, 2000, 4000, 8000（封顶）, ...
        assertEquals(250, Handshake.retryGapMs(250, 1));
        assertEquals(500, Handshake.retryGapMs(250, 2));
        assertEquals(1000, Handshake.retryGapMs(250, 3));
        assertEquals(2000, Handshake.retryGapMs(250, 4));
        assertEquals(4000, Handshake.retryGapMs(250, 5));
        assertEquals(8000, Handshake.retryGapMs(250, 6));
        assertEquals(8000, Handshake.retryGapMs(250, 9));
        // 累计时刻表与常量表一致
        long t = 0;
        for (int i = 0; i < Handshake.DEFAULT_RETRY_SCHEDULE_MS.length; ++i) {
            if (i > 0) t += Handshake.retryGapMs(Handshake.HANDSHAKE_RETRY_MS, i);
            assertEquals(Handshake.DEFAULT_RETRY_SCHEDULE_MS[i], (int) t);
        }
        // rtt 种子夹紧（handshake.ts:243-245：clamp(2×rtt, 250, 8000)）
        assertEquals(8000, Handshake.retryGapMs(9000, 1));
        assertEquals(250, Handshake.retryGapMs(0, 1));
    }
}
