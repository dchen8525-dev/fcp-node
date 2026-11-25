package com.dchen.fcpvpn.core.interop;

import com.dchen.fcpvpn.core.session.FcpSession;
import com.dchen.fcpvpn.core.session.OpenTarget;
import com.dchen.fcpvpn.core.stream.Stream;
import com.dchen.fcpvpn.core.stream.StreamCallbacks;
import com.dchen.fcpvpn.core.wire.Wire;

import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * M4 验收：Java FcpSession 客户端 ↔ 真实 fcp-node 服务端（Node 子进程，真实 UDP）。
 * 闭环：握手 → M1 mux 协商 → FCP OPEN(127.0.0.1 回环目标) → 双向字节完整性 →
 * FIN 半关闭。对拍 scripts/self-interop.mjs 的验收口径。
 *
 * 需要 PATH 上有 node ≥ 22.18（本机 v24.22.2）；不可用时跳过（assumeTrue）。
 * FcpSession 是单写者设计：UDP 接收、tick 驱动、用户写入全部串行在驱动线程上
 * （与生产 TunnelManager 的单线程调度器同构）。
 */
public class FcpSessionInteropTest {

    private static final int SERVER_PORT = 44610;

    private static String hex32(byte[] psk) {
        StringBuilder sb = new StringBuilder(32);
        for (byte b : psk) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    /** 启动 fcp-node 服务端子进程。 */
    /** 起服务端：仓库根自动探测（见 FcpServerProcess），不依赖本机绝对路径。 */
    private Process startServer(String keyHex) throws Exception {
        return FcpServerProcess.start(SERVER_PORT, keyHex);
    }

    /** 内嵌回环 TCP 目标：收多少回多少（echo）。 */
    private int startEchoServer() throws Exception {
        ServerSocket ss = new ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"));
        Thread t = new Thread(() -> {
            while (true) {
                try (Socket s = ss.accept()) {
                    InputStream in = s.getInputStream();
                    OutputStream out = s.getOutputStream();
                    byte[] buf = new byte[16384];
                    int n;
                    while ((n = in.read(buf)) != -1) {
                        out.write(buf, 0, n);
                        out.flush();
                    }
                } catch (Exception e) {
                    break;
                }
            }
        });
        t.setDaemon(true);
        t.start();
        return ss.getLocalPort();
    }

    @Test
    public void javaClientInteropWithRealFcpNodeServer() throws Exception {
        org.junit.Assume.assumeTrue("node 不可用则跳过互操作测试", nodeAvailable());
        SecureRandom rnd = new SecureRandom();
        byte[] psk = new byte[16];
        rnd.nextBytes(psk);
        byte[] salt = new byte[8];
        rnd.nextBytes(salt);

        int echoPort = startEchoServer();
        Process server = startServer(hex32(psk));
        try {
            DatagramSocket udp = new DatagramSocket(0, InetAddress.getByName("127.0.0.1"));
            udp.setReceiveBufferSize(1 << 20);
            udp.setSendBufferSize(1 << 20);

            FcpSession.Config cfg = new FcpSession.Config();
            cfg.psk = psk;
            cfg.salt = salt;
            cfg.d = 10;
            cfg.p = 6;
            cfg.mtu = 1040;
            cfg.pmtud = true;

            final AtomicReference<String> closeReason = new AtomicReference<>();

            FcpSession.Listener listener = new FcpSession.Listener() {
                @Override
                public void sendWire(byte[] wire, int symbolType) {
                    try {
                        udp.send(new DatagramPacket(wire, wire.length,
                                InetAddress.getByName("127.0.0.1"), SERVER_PORT));
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
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
            };
            FcpSession session = new FcpSession(cfg, listener);

            // 单线程泵：接收 + tick + 用户动作全部串行（单写者契约）。
            final BlockingQueue<Runnable> actions = new LinkedBlockingQueue<>();
            Thread driver = new Thread(() -> {
                byte[] buf = new byte[65536];
                DatagramPacket pkt = new DatagramPacket(buf, buf.length);
                while (!session.isClosed() && closeReason.get() == null) {
                    try {
                        Runnable action = actions.poll();
                        if (action != null) action.run();
                        try {
                            udp.setSoTimeout(1);
                            udp.receive(pkt);
                            byte[] copy = java.util.Arrays.copyOfRange(buf, 0, pkt.getLength());
                            session.onWire(copy, System.currentTimeMillis());
                        } catch (java.net.SocketTimeoutException ignore) {
                            // 无包
                        }
                        session.onTick(System.currentTimeMillis());
                        Thread.sleep(1);
                    } catch (InterruptedException e) {
                        break;
                    } catch (Exception e) {
                        break;
                    }
                }
            });
            driver.setDaemon(true);
            driver.start();

            session.start(System.currentTimeMillis());
            assertTrue("握手应在 10s 内建立（重试 9 次）",
                    establishedAwait(session, 10000));

            long deadline = System.currentTimeMillis() + 5000;
            while (!session.isMuxActive() && System.currentTimeMillis() < deadline) {
                Thread.sleep(20);
            }
            assertTrue("M1 mux 应协商成功（fcp-node 服务端提供 TLV 5）", session.isMuxActive());

            // ---- 用例 1：FCP OPEN + 64KiB echo 往返 ----
            final int payloadSize = 64 * 1024;
            final byte[] payload = new byte[payloadSize];
            rnd.nextBytes(payload);

            final CountDownLatch opened = new CountDownLatch(1);
            final AtomicBoolean openOk = new AtomicBoolean(false);
            final ByteArrayOutputStream received = new ByteArrayOutputStream();
            final CountDownLatch allReceived = new CountDownLatch(1);

            final Stream sid = openStreamOnDriver(session, actions, received, openOk, opened, allReceived);
            assertTrue("mux 已协商，openStream(1) 应成功", sid != null);

            // FCP OPEN：FCPO | ver=1 | atyp=1(IPv4) | len=4 | 127.0.0.1 | port(BE)
            final byte[] open = new byte[4 + 1 + 1 + 1 + 4 + 2];
            System.arraycopy("FCPO".getBytes(StandardCharsets.US_ASCII), 0, open, 0, 4);
            open[4] = 1;
            open[5] = OpenTarget.ATYP_IPV4;
            open[6] = 4;
            open[7] = 127;
            open[8] = 0;
            open[9] = 0;
            open[10] = 1;
            Wire.putBe16(echoPort, open, 11);
            actions.put(() -> sid.write(open, 0, open.length, System.currentTimeMillis()));

            assertTrue("OPEN_OK 应在 10s 内到达", opened.await(10, TimeUnit.SECONDS));
            assertTrue(openOk.get());

            int off = 0;
            while (off < payloadSize) {
                final int fOff = off;
                final int fTake = Math.min(16384, payloadSize - off);
                actions.put(() -> sid.write(payload, fOff, fTake, System.currentTimeMillis()));
                off += fTake;
                Thread.sleep(2);
            }

            assertTrue("64KiB echo 应在 30s 内完整返回",
                    allReceived.await(30, TimeUnit.SECONDS));
            byte[] all = received.toByteArray();
            byte[] echoed = java.util.Arrays.copyOfRange(all, 8, 8 + payloadSize);
            assertArrayEquals("echo 数据必须逐字节一致", payload, echoed);

            // ---- 用例 2：底层网络切换（Wi-Fi → 蜂窝）----
            // 客户端不重建 socket：发一次认证保活让服务端跟随新源地址，把 PMTU 打回
            // 起点重测（新路径的 MTU 可能更小），PMTU 探测的 ACK 同时就是"新路径通
            // 不通"的回音。会话必须保持可用，数据必须继续往返。
            long pmtuDeadline = System.currentTimeMillis() + 20000;
            while (session.currentMtu() < 1500 && System.currentTimeMillis() < pmtuDeadline) {
                Thread.sleep(50);
            }
            assertEquals("前置：PMTU 应已爬到上限 1500", 1500, session.currentMtu());

            actions.put(() -> session.onPathChanged(System.currentTimeMillis(), true));
            Thread.sleep(200);
            assertNull("换路径不应关闭会话", closeReason.get());
            assertTrue("PMTU 应被打回起点重测，实际 " + session.currentMtu(),
                    session.currentMtu() <= 1140);

            final int extra = 8192;
            final byte[] extraPayload = new byte[extra];
            rnd.nextBytes(extraPayload);
            final int base = received.size();
            for (int off2 = 0; off2 < extra; off2 += 4096) {
                final int fOff = off2;
                final int fTake = Math.min(4096, extra - off2);
                actions.put(() -> sid.write(extraPayload, fOff, fTake, System.currentTimeMillis()));
                Thread.sleep(2);
            }
            long echoDeadline = System.currentTimeMillis() + 15000;
            while (received.size() < base + extra && System.currentTimeMillis() < echoDeadline) {
                Thread.sleep(20);
            }
            byte[] afterPath = received.toByteArray();
            assertEquals("换路径后 echo 应完整返回", base + extra, afterPath.length);
            assertArrayEquals("换路径后的数据必须逐字节一致", extraPayload,
                    java.util.Arrays.copyOfRange(afterPath, base, base + extra));

            pmtuDeadline = System.currentTimeMillis() + 20000;
            while (session.currentMtu() < 1500 && System.currentTimeMillis() < pmtuDeadline) {
                Thread.sleep(50);
            }
            assertEquals("新路径的 PMTU 应重新爬到上限（回音窗口已被 ACK 解除）",
                    1500, session.currentMtu());
            assertNull("换路径全过程不应关闭会话", closeReason.get());

            // ---- 用例 3：FIN 半关闭 ----
            actions.put(() -> sid.closeWrite(System.currentTimeMillis()));
            Thread.sleep(300);
            assertEquals("FIN 后会话不应被 RST", null, closeReason.get());

            actions.put(() -> session.closeWrite());
            Thread.sleep(200);
        } finally {
            server.destroy();
        }
    }

    /** 在驱动线程上执行 openStream；read 回调在驱动线程上累加到 received 并推进 latch。 */
    private static Stream openStreamOnDriver(final FcpSession session,
                                             final BlockingQueue<Runnable> actions,
                                             final ByteArrayOutputStream received,
                                             final AtomicBoolean openOk,
                                             final CountDownLatch opened,
                                             final CountDownLatch allReceived)
            throws InterruptedException {
        final AtomicReference<Stream> out = new AtomicReference<>();
        final CountDownLatch done = new CountDownLatch(1);
        actions.put(() -> {
            out.set(session.openStream(1, new StreamCallbacks() {
                @Override
                public void send(byte[] seg) {
                }

                @Override
                public void read(byte[] bytes) {
                    received.write(bytes, 0, bytes.length);
                    if (!openOk.get() && received.size() >= 8) {
                        byte[] head = received.toByteArray();
                        if (head[0] == 'F' && head[1] == 'C' && head[2] == 'P' && head[3] == 'O'
                                && head[4] == 1 && head[5] == 1) {
                            openOk.set(true);
                            opened.countDown();
                        }
                    }
                    if (received.size() >= 8 + 64 * 1024) {
                        allReceived.countDown();
                    }
                }

                @Override
                public void closed(String reason) {
                }
            }));
            done.countDown();
        });
        done.await(5, TimeUnit.SECONDS);
        return out.get();
    }

    private static boolean establishedAwait(FcpSession session, long timeoutMs) throws InterruptedException {
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < deadline) {
            if (session.isEstablished()) return true;
            if (session.isClosed()) return false;
            Thread.sleep(20);
        }
        return session.isEstablished();
    }

    private static boolean nodeAvailable() {
        return FcpServerProcess.nodeAvailable();
    }
}
