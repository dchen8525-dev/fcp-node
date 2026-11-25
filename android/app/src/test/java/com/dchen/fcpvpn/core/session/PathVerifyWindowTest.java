package com.dchen.fcpvpn.core.session;

import com.dchen.fcpvpn.core.crypto.Envelope;
import com.dchen.fcpvpn.core.crypto.FcpKeys;
import com.dchen.fcpvpn.core.crypto.Handshake;
import com.dchen.fcpvpn.core.fec.FecHeader;
import com.dchen.fcpvpn.core.fec.FrameTx;
import com.dchen.fcpvpn.core.stream.SegmentCodec;
import com.dchen.fcpvpn.core.wire.Wire;

import org.junit.Test;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * 换路径后的回音窗口：Wi-Fi → 蜂窝切换时，客户端 socket 不重连，靠"对换网后发出的
 * 探测的应答"判断新路径通不通。原来只有 135 秒的静默判死，下载会毫无提示地冻住
 * 两分多钟。
 *
 * <p>回音判定必须是"换网后发出的探测被应答"（PMTU token 在换网时轮换），不能是
 * "收到任何认证报文"：换网那一刻仍在空中的旧路径报文与普通数据在帧层没有区别，
 * 先到的那一枚会把窗口误判成通，之后又退回 135 秒——正是这个窗口要消除的现象。</p>
 */
public class PathVerifyWindowTest {

    private static final int START_MTU = 1040;

    // ------------------------------------------------------------------ 纯状态机

    @Test
    public void expiresExactlyAtDeadline() {
        PathVerifyWindow w = new PathVerifyWindow(10000);
        w.arm(1000);
        assertTrue(w.armed());
        assertFalse("窗口内不应判死", w.expired(1000 + 9999));
        assertTrue("到期即判死", w.expired(1000 + 10000));
        assertEquals(11000, w.deadlineMs());
    }

    @Test
    public void inboundClearsWindow() {
        PathVerifyWindow w = new PathVerifyWindow(10000);
        w.arm(1000);
        w.noteInbound();
        assertFalse(w.armed());
        assertFalse("收到回音后不该再判死", w.expired(1000 + 600000));
        assertTrue("地址冻结应持续到窗口结束", w.addressFrozen(1000 + 9999));
        assertFalse("窗口结束后允许正常地址迁移", w.addressFrozen(1000 + 10000));
    }

    @Test
    public void rearmExtendsWindow() {
        // 网络连续抖动（Wi-Fi 掉→蜂窝起→又切回）时窗口跟着续期，
        // 不能按第一次上膛的时间算死。
        PathVerifyWindow w = new PathVerifyWindow(10000);
        w.arm(1000);
        w.arm(5000);
        assertFalse(w.expired(1000 + 10000));
        assertTrue(w.expired(5000 + 10000));
    }

    // ------------------------------------------------------------------ 会话层

    @Test
    public void sessionIgnoresPathChangeBeforeEstablished() {
        // 握手还没完成时换网（开机连网途中很常见）：不能发任何东西，
        // 也不能把 PMTU 状态搅乱——引擎会在握手阶段自己重试。
        AtomicReference<String> wireSent = new AtomicReference<>();
        FcpSession.Config cfg = new FcpSession.Config();
        cfg.psk = new byte[16];
        cfg.salt = new byte[8];
        cfg.d = 10;
        cfg.p = 6;
        cfg.mtu = START_MTU;
        cfg.pmtud = true;
        FcpSession session = new FcpSession(cfg, new FcpSession.Listener() {
            @Override
            public void sendWire(byte[] wire, int symbolType) {
                wireSent.set("sent");
            }

            @Override
            public void read(byte[] bytes) {
            }

            @Override
            public void closed(String reason) {
            }

            @Override
            public void log(String line) {
            }
        });

        session.onPathChanged(1000, true);

        assertNull("未建立时不应发包", wireSent.get());
        assertEquals("未建立时不应重置 PMTU", START_MTU, session.currentMtu());
        assertFalse(session.isPathVerifyArmed());
    }

    @Test
    public void pathChangeSendsAProbeAndRotatesToken() {
        SessionFixture f = new SessionFixture();
        f.session.onPathChanged(2000, true);

        assertTrue("换路径后窗口必须上膛", f.session.isPathVerifyArmed());
        assertEquals("换路径必须先发一枚探测", 1, f.session.pathProbesSent());
        assertEquals("探测尺寸是会话起点 MTU", START_MTU, f.session.currentMtu());
        int first = f.session.pathProbeToken();

        f.session.onPathChanged(5000, true); // 又一次换网
        assertEquals(2, f.session.pathProbesSent());
        assertFalse("每次换网都换 token：旧探测的 ACK 无法冒充新路径",
                first == f.session.pathProbeToken());
    }

    @Test
    public void windowResendsProbeEverySecond() {
        SessionFixture f = new SessionFixture();
        f.session.onPathChanged(2000, true);
        int token = f.session.pathProbeToken();
        assertEquals(1, f.session.pathProbesSent());

        f.session.onTick(2400);
        assertEquals("不到 1s 不补发", 1, f.session.pathProbesSent());
        f.session.onTick(3000);
        assertEquals("窗口内每秒补发一枚", 2, f.session.pathProbesSent());
        assertEquals("补发沿用同一 token（仍是同一轮换网）", token, f.session.pathProbeToken());
        assertTrue("有探针在飞时窗口不应判死", f.session.isPathVerifyArmed());
    }

    @Test
    public void pmtuAckForPostChangeProbeClearsWindow() {
        SessionFixture f = new SessionFixture();
        f.session.onPathChanged(2000, true);

        assertTrue(f.session.onWire(
                f.pmtuAckWire(f.session.pathProbeToken(), START_MTU), 2100));

        assertFalse("对换网后探测的应答是有效回音", f.session.isPathVerifyArmed());
        f.session.onTick(2000 + FcpSession.PATH_VERIFY_MS);
        assertNull("已有回音，不应判 path_lost", f.closeReason.get());
    }

    @Test
    public void ackForPreChangeProbeDoesNotClearWindow() {
        SessionFixture f = new SessionFixture();
        f.session.onPathChanged(2000, true);

        // 换网前发出的探测带的是旧 token；它的 ACK 无论何时到达都不能证明新路径。
        int staleToken = f.session.pathProbeToken() - 1;
        assertTrue(f.session.onWire(f.pmtuAckWire(staleToken, START_MTU), 2100));

        assertTrue("旧 token 的 ACK 不能解除窗口", f.session.isPathVerifyArmed());
        f.session.onTick(2000 + FcpSession.PATH_VERIFY_MS);
        assertEquals("没有新路径的回音仍必须判死", "path_lost", f.closeReason.get());
    }

    @Test
    public void inFlightSessionDataDoesNotClearWindow() {
        // 本次修复的核心断言：换网那一刻仍在空中的普通会话数据报与新鲜数据在帧层
        // 没有区别，它不能证明"我们换网后发出的报文能到对端"。
        SessionFixture f = new SessionFixture();
        f.session.onPathChanged(2000, true);

        assertTrue(f.session.onWire(f.sessionDataWire(), 2100));

        assertTrue("在途的旧路径数据不能解除窗口", f.session.isPathVerifyArmed());
        f.session.onTick(2000 + FcpSession.PATH_VERIFY_MS);
        assertEquals("path_lost", f.closeReason.get());
    }

    @Test
    public void keepaliveDoesNotClearWindow() {
        SessionFixture f = new SessionFixture();
        f.session.onPathChanged(2000, true);

        byte[] keepalive = "FCPKAL1\0".getBytes(StandardCharsets.US_ASCII);
        assertTrue(f.session.onWire(f.sessionOobWire(keepalive), 2100));

        assertTrue("保活是单向的，不能当回音", f.session.isPathVerifyArmed());
    }

    @Test
    public void peerPmtuProbeDoesNotClearWindow() {
        SessionFixture f = new SessionFixture();
        f.session.onPathChanged(2000, true);

        byte[] probe = new byte[16];
        System.arraycopy("FCP_PMTU".getBytes(StandardCharsets.US_ASCII), 0, probe, 0, 8);
        probe[8] = 0; // PMTU_TYPE_PROBE
        Wire.putLe32(1, probe, 10);
        Wire.putLe16(START_MTU, probe, 14);
        assertTrue(f.session.onWire(f.sessionOobWire(probe), 2100));

        assertTrue("对端的探测不是对我们探测的应答", f.session.isPathVerifyArmed());
    }

    @Test
    public void bootstrapEnvelopeDoesNotClearWindow() {
        SessionFixture f = new SessionFixture();
        f.session.onPathChanged(2000, true);

        assertTrue(f.session.onWire(f.bootstrapAckWire(), 2100));

        assertTrue("bootstrap 信封不是当前会话路径回音", f.session.isPathVerifyArmed());
        f.session.onTick(2000 + FcpSession.PATH_VERIFY_MS);
        assertEquals("bootstrap 不能压下 path_lost", "path_lost", f.closeReason.get());
    }

    @Test
    public void synchronousPathEchoClearsWindow() {
        // 宿主 sendWire 可能同步重入 onWire：窗口必须在上膛之后才发探测。
        SessionFixture f = new SessionFixture();
        int[] ackedProbes = {0};
        f.sendHook = () -> {
            int sent = f.session.pathProbesSent();
            if (sent == ackedProbes[0]) return;      // 不是探测就不回
            ackedProbes[0] = sent;
            assertTrue("探测发出时窗口必须已上膛", f.session.isPathVerifyArmed());
            assertTrue(f.session.onWire(
                    f.pmtuAckWire(f.session.pathProbeToken(), START_MTU), 2001));
        };

        f.session.onPathChanged(2000, true);

        assertFalse("sendWire 同步回音也必须落在已上膛的窗口内",
                f.session.isPathVerifyArmed());
    }

    @Test
    public void noWindowWithoutPmtud() {
        // 没有 PMTUD 就没有可靠的路径回音（保活单向、对端不回）：退回 135 秒判死，
        // 别拿一个等不到的回音把好会话误杀。
        SessionFixture f = new SessionFixture(false);
        f.session.onPathChanged(2000, true);

        assertFalse(f.session.isPathVerifyArmed());
        assertEquals("不发探测", 0, f.session.pathProbesSent());
    }

    // ------------------------------------------------------------------ 引擎层

    @Test
    public void engineKeepsStaleAddressFrozenDuringWindow() throws Exception {
        SessionFixture f = new SessionFixture();
        f.session.onPathChanged(2000, true);
        int token = f.session.pathProbeToken();

        FcpTunnelEngine engine = new FcpTunnelEngine();
        InetAddress currentAddress = InetAddress.getByName("127.0.0.1");
        InetAddress staleAddress = InetAddress.getByName("127.0.0.2");
        int currentPort = 4460;
        int stalePort = 4461;

        Class<?> slotClass = Class.forName("com.dchen.fcpvpn.core.session.FcpTunnelEngine$PoolSlot");
        Constructor<?> constructor = slotClass.getDeclaredConstructor(byte[].class);
        constructor.setAccessible(true);
        Object slot = constructor.newInstance((Object) f.salt);
        Field slotSession = slotClass.getDeclaredField("session");
        slotSession.setAccessible(true);
        slotSession.set(slot, f.session);

        Field slotsField = FcpTunnelEngine.class.getDeclaredField("slots");
        slotsField.setAccessible(true);
        @SuppressWarnings("unchecked")
        List<Object> slots = (List<Object>) slotsField.get(engine);
        slots.add(slot);
        Field bySaltField = FcpTunnelEngine.class.getDeclaredField("slotsBySalt");
        bySaltField.setAccessible(true);
        @SuppressWarnings("unchecked")
        Map<String, Object> bySalt = (Map<String, Object>) bySaltField.get(engine);
        StringBuilder key = new StringBuilder();
        for (byte b : f.salt) key.append(String.format("%02x", b));
        bySalt.put(key.toString(), slot);

        Field addressField = FcpTunnelEngine.class.getDeclaredField("peerAddress");
        addressField.setAccessible(true);
        addressField.set(engine, currentAddress);
        Field portField = FcpTunnelEngine.class.getDeclaredField("peerPort");
        portField.setAccessible(true);
        portField.setInt(engine, currentPort);
        Method handle = FcpTunnelEngine.class.getDeclaredMethod("handleDatagram",
                byte[].class, InetAddress.class, int.class, long.class);
        handle.setAccessible(true);

        // 旧 IP/端口的认证报文既不能改写当前对端地址，也不能解除窗口。
        handle.invoke(engine, f.sessionDataWire(), staleAddress, stalePort, 2100L);
        assertEquals("旧 IP/端口的认证报文不能改写当前对端地址",
                currentAddress, addressField.get(engine));
        assertEquals("旧端口不能改写当前对端端口", currentPort, portField.getInt(engine));
        assertTrue("数据报不能解除窗口", f.session.isPathVerifyArmed());

        // 当前地址上、带新 token 的探测应答才是回音。
        handle.invoke(engine, f.pmtuAckWire(token, START_MTU), currentAddress, currentPort, 2200L);
        assertFalse("当前地址的探测应答应解除窗口", f.session.isPathVerifyArmed());

        // 回音后紧邻的旧路径包仍不能改写地址（窗口到 deadline 前冻结）。
        handle.invoke(engine, f.sessionDataWire(), staleAddress, stalePort, 2300L);
        assertEquals("回音后紧邻的旧路径包仍不能改写地址",
                currentAddress, addressField.get(engine));
        assertEquals(currentPort, portField.getInt(engine));
    }

    /** 真实握手到 rekey，随后用对端方向密钥构造根 src 线格式的入站信封。 */
    private static final class SessionFixture {
        final byte[] psk = new byte[16];
        final byte[] salt = new byte[8];
        final FcpSession session;
        final Envelope peer;
        final AtomicReference<String> closeReason = new AtomicReference<>();
        final List<byte[]> sent = new ArrayList<>();
        /** 引导信封里多发的一枚 HELLO_ACK：用 bootstrap 密钥、counter 紧随第一枚。 */
        final byte[] bootstrapExtraWire;
        Runnable sendHook;
        /** 对端方向信封的下一个 counter（模拟在途顺序）。 */
        long nextCounter = 1;

        SessionFixture() {
            this(true);
        }

        SessionFixture(boolean pmtud) {
            byte[] clientNonce = new byte[16];
            byte[] serverNonce = new byte[16];
            for (int i = 0; i < psk.length; ++i) psk[i] = (byte) (i + 1);
            for (int i = 0; i < salt.length; ++i) salt[i] = (byte) (0x20 + i);
            for (int i = 0; i < clientNonce.length; ++i) clientNonce[i] = (byte) (i + 1);
            for (int i = 0; i < serverNonce.length; ++i) serverNonce[i] = (byte) (0x80 + i);

            FcpSession.Config cfg = new FcpSession.Config();
            cfg.psk = psk;
            cfg.salt = salt;
            cfg.d = 10;
            cfg.p = 6;
            cfg.mtu = START_MTU;
            cfg.pmtud = pmtud;
            session = new FcpSession(cfg, new FcpSession.Listener() {
                @Override
                public void sendWire(byte[] wire, int symbolType) {
                    sent.add(wire);
                    Runnable hook = sendHook;
                    if (hook != null) hook.run();
                }

                @Override
                public void read(byte[] bytes) {
                }

                @Override
                public void closed(String reason) {
                    closeReason.set(reason);
                }

                @Override
                public void log(String line) {
                }
            });

            peer = new Envelope(psk, salt, FcpKeys.DIRECTION_S2C, FcpKeys.DIRECTION_C2S);
            peer.initBootstrapNonce(0);
            assertTrue(session.start(1000));
            assertEquals(1, sent.size());
            byte[] helloFrame = peer.open(sent.get(0));
            assertNotNull("测试对端必须能解开客户端 HELLO", helloFrame);
            byte[] hello = Arrays.copyOfRange(helloFrame, FecHeader.FEC_HDR_LEN, helloFrame.length);
            Handshake.Hello parsed = Handshake.parseHello(hello, hello.length);
            assertNotNull(parsed);
            System.arraycopy(parsed.senderNonce, 0, clientNonce, 0, clientNonce.length);

            Handshake.Caps caps = new Handshake.Caps(Handshake.CAPS_VERSION, 10, 6,
                    Handshake.LOCAL_FLAGS_M1 | Handshake.CAP_PMTUD);
            byte[] ack = Handshake.buildHelloAck(caps, clientNonce, serverNonce,
                    new ArrayList<Handshake.Tlv>(), false);
            byte[] ackWire = peer.seal(FrameTx.packOobFrame(ack));
            assertNotNull(ackWire);
            // bootstrap 计数器是随机的：下一枚必须由同一个信封实例在同一密钥下封出，
            // 新建信封会得到一个远在重放窗口之外的 counter。
            bootstrapExtraWire = peer.sealAt(peer.nonce(), FrameTx.packOobFrame(ack));
            assertNotNull(bootstrapExtraWire);
            assertTrue(session.onWire(ackWire, 1001));
            assertTrue("测试前置：握手必须建立", session.isEstablished());
            peer.rekey(FcpKeys.deriveSessionKeyV7(psk, salt, clientNonce, serverNonce));
            sent.clear();
        }

        private long nextCounter() {
            return nextCounter++;
        }

        byte[] sessionDataWire() {
            byte[] segment = SegmentCodec.encodeData(0, 0, new byte[]{0x5a});
            byte[] symbol = new byte[2 + segment.length];
            Wire.putLe16(symbol.length, symbol, 0);
            System.arraycopy(segment, 0, symbol, 2, segment.length);
            byte[] plain = FrameTx.packTxFrame(1, 0, 10,
                    FecHeader.packTypeK(0, 0, FecHeader.TYPE_DATA), symbol);
            return peer.sealAt(nextCounter(), plain);
        }

        byte[] sessionOobWire(byte[] payload) {
            return peer.sealAt(nextCounter(), FrameTx.packOobFrame(payload));
        }

        /** 对端对探测的应答：type=ACK，带我们发出的 token。 */
        byte[] pmtuAckWire(int token, int mtu) {
            byte[] payload = new byte[16];
            System.arraycopy("FCP_PMTU".getBytes(StandardCharsets.US_ASCII), 0, payload, 0, 8);
            payload[8] = 1;   // PMTU_TYPE_ACK
            payload[9] = 0;
            Wire.putLe32(token, payload, 10);
            Wire.putLe16(mtu, payload, 14);
            return sessionOobWire(payload);
        }

        byte[] bootstrapAckWire() {
            return bootstrapExtraWire;
        }
    }
}
