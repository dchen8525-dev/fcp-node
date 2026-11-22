package com.dchen.fcpvpn.core.interop;

import com.dchen.fcpvpn.core.session.FcpSession;

import org.junit.Test;

import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.SecureRandom;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * 协议内 DNS（oob FCP_DNS1）验收：Java 客户端 ↔ 真实 fcp-node 服务端。
 *
 * 断言服务端用自己的 resolver 解析并原样回包——这正是 TUN 模式（IP 层、
 * 域名已丢失）下客户端解析域名的唯一正确来源，且不需要额外端口或流。
 *
 * 线程模型：queryDns 在测试线程上阻塞等待，发送动作经 actions 队列交给
 * 驱动线程执行（FcpSession 单写者），驱动线程继续接收应答 → 无死锁。
 */
public class FcpDnsInteropTest {

    private static final int SERVER_PORT = 44612;

    private static String hex32(byte[] psk) {
        StringBuilder sb = new StringBuilder(32);
        for (byte b : psk) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    /** 起服务端：仓库根自动探测（见 FcpServerProcess），不依赖本机绝对路径。 */
    private Process startServer(String keyHex) throws Exception {
        return FcpServerProcess.start(SERVER_PORT, keyHex);
    }

    /** 手搓一个 A 查询（DNS wire format）。 */
    private static byte[] buildQueryA(int id, String name) {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        out.write((id >>> 8) & 0xff);
        out.write(id & 0xff);
        out.write(0x01); // RD
        out.write(0x00);
        out.write(0); out.write(1); // qdcount
        out.write(0); out.write(0);
        out.write(0); out.write(0);
        out.write(0); out.write(0);
        for (String label : name.split("\\.")) {
            byte[] b = label.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            out.write(b.length);
            out.write(b, 0, b.length);
        }
        out.write(0);
        out.write(0); out.write(1); // type A
        out.write(0); out.write(1); // class IN
        return out.toByteArray();
    }

    @Test
    public void dnsOverOobResolvesThroughRealServer() throws Exception {
        org.junit.Assume.assumeTrue("node 不可用则跳过", nodeAvailable());
        SecureRandom rnd = new SecureRandom();
        byte[] psk = new byte[16];
        rnd.nextBytes(psk);
        byte[] salt = new byte[8];
        rnd.nextBytes(salt);

        Process server = startServer(hex32(psk));
        DatagramSocket udp = new DatagramSocket(0, InetAddress.getByName("127.0.0.1"));
        udp.setReceiveBufferSize(1 << 20);
        try {
            FcpSession.Config cfg = new FcpSession.Config();
            cfg.psk = psk;
            cfg.salt = salt;
            cfg.d = 10;
            cfg.p = 6;
            cfg.mtu = 1040;

            final AtomicReference<String> closeReason = new AtomicReference<>();
            FcpSession session = new FcpSession(cfg, new FcpSession.Listener() {
                @Override
                public void sendWire(byte[] wire, int symbolType) {
                    try {
                        udp.send(new DatagramPacket(wire, wire.length,
                                InetAddress.getByName("127.0.0.1"), SERVER_PORT));
                    } catch (Exception ignored) {
                    }
                }

                @Override
                public void read(byte[] bytes) {
                }

                @Override
                public void closed(String reason) {
                    closeReason.set(reason);
                }
            });

            // 驱动线程：接收 + tick（queryDns 的发送动作也排在这条线程上）
            final BlockingQueue<Runnable> actions = new LinkedBlockingQueue<>();
            Thread driver = new Thread(() -> {
                byte[] buf = new byte[65536];
                DatagramPacket pkt = new DatagramPacket(buf, buf.length);
                while (!session.isClosed() && closeReason.get() == null) {
                    try {
                        Runnable a = actions.poll();
                        if (a != null) a.run();
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
            long deadline = System.currentTimeMillis() + 12000;
            while (!session.isEstablished() && System.currentTimeMillis() < deadline) {
                Thread.sleep(20);
            }
            assertTrue("握手应在 12s 内建立", session.isEstablished());

            // ---- 协议内 DNS 解析 ----
            byte[] query = buildQueryA(0x4242, "www.baidu.com");
            byte[] answer = session.queryDns(query, 8000, actions::add);
            assertNotNull("服务端应在 8s 内返回 DNS 应答", answer);
            assertTrue("应答长度应大于头", answer.length > 12);
            // 事务 ID 必须原样回显
            assertEquals(0x42, answer[0] & 0xff);
            assertEquals(0x42, answer[1] & 0xff);
            // qr=1, rcode=0
            assertTrue("QR 位应为 1", (answer[2] & 0x80) != 0);
            assertEquals("rcode 应为 0（NOERROR）", 0, answer[3] & 0x0f);
            int ancount = ((answer[6] & 0xff) << 8) | (answer[7] & 0xff);
            assertTrue("应至少有一条答案记录，实际 " + ancount, ancount >= 1);

            // ---- 未知名应返回 NXDOMAIN（0 答案或 rcode=3），而不是超时 ----
            byte[] badQuery = buildQueryA(0x4343, "no-such-host-fcp-test.invalid");
            byte[] badAnswer = session.queryDns(badQuery, 8000, actions::add);
            assertNotNull("未知域名也应返回应答（而非超时）", badAnswer);
            int badAncount = ((badAnswer[6] & 0xff) << 8) | (badAnswer[7] & 0xff);
            int badRcode = badAnswer[3] & 0x0f;
            assertTrue("未知域名应为 NXDOMAIN/无答案：rcode=" + badRcode + " ancount=" + badAncount,
                    badRcode == 3 || badAncount == 0);
        } finally {
            udp.close();
            server.destroy();
        }
    }

    private static boolean nodeAvailable() {
        return FcpServerProcess.nodeAvailable();
    }
}
