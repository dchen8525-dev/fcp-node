package com.dchen.fcpvpn.core.interop;

import com.dchen.fcpvpn.core.proxy.MixedProxyListener;
import com.dchen.fcpvpn.core.session.EngineConfig;
import com.dchen.fcpvpn.core.session.FcpTunnelEngine;
import com.dchen.fcpvpn.core.session.SocketProtector;

import org.junit.Test;

import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;

/**
 * M5/M6 级验收：FcpTunnelEngine（4 会话池 + 单线程泵）+ MixedProxyListener
 * （三合一入口）↔ 真实 fcp-node 服务端。对拍桌面端完整使用路径：
 * SOCKS5 CONNECT、HTTP CONNECT、absolute-form 正向代理三种入口，经真实 UDP
 * 隧道到回环 echo 目标的字节级往返。
 */
public class FcpEngineProxyInteropTest {

    private static final int SERVER_PORT = 44611;
    private static final int PROXY_PORT = 44590;

    private static String hex32(byte[] psk) {
        StringBuilder sb = new StringBuilder(32);
        for (byte b : psk) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    /** 起服务端：仓库根自动探测（见 FcpServerProcess），不依赖本机绝对路径。 */
    private Process startServer(String keyHex) throws Exception {
        return FcpServerProcess.start(SERVER_PORT, keyHex);
    }

    /** 回环 echo 目标：收多少回多少。 */
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

    private static byte[] readN(InputStream in, int n, long timeoutMs) throws Exception {
        byte[] out = new byte[n];
        long deadline = System.currentTimeMillis() + timeoutMs;
        int off = 0;
        while (off < n) {
            long remain = deadline - System.currentTimeMillis();
            if (remain <= 0) break;
            int r = in.read(out, off, n - off);
            if (r < 0) break;
            off += r;
        }
        if (off != n) throw new AssertionError("期望读 " + n + " 字节，只读到 " + off);
        return out;
    }

    private static void awaitTrue(AtomicBooleanLike flag, long timeoutMs, String msg)
            throws InterruptedException {
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (!flag.get()) {
            if (System.currentTimeMillis() > deadline) {
                throw new AssertionError(msg);
            }
            Thread.sleep(20);
        }
    }

    /** 极简可轮询布尔（org.junit 之外不引入依赖）。 */
    private static final class AtomicBooleanLike {
        private volatile boolean v;

        void set(boolean b) {
            v = b;
        }

        boolean get() {
            return v;
        }
    }

    @Test
    public void engineAndMixedProxyInteropWithRealServer() throws Exception {
        org.junit.Assume.assumeTrue("node 不可用则跳过", nodeAvailable());
        SecureRandom rnd = new SecureRandom();
        byte[] psk = new byte[16];
        rnd.nextBytes(psk);

        int echoPort = startEchoServer();
        Process server = startServer(hex32(psk));
        SocketProtector nullProtector = new SocketProtector() {
            @Override
            public boolean protect(java.net.DatagramSocket socket) { return true; }

            @Override
            public boolean protect(Socket socket) { return true; }

            @Override
            public boolean protect(int fd) { return true; }
        };

        FcpTunnelEngine engine = new FcpTunnelEngine();
        EngineConfig cfg = new EngineConfig("127.0.0.1", SERVER_PORT, hex32(psk),
                10, 6, 1040, 600, "warn");
        cfg.proxyPort = 0; // 引擎自身的监听关闭；测试里手动起 MixedProxyListener

        final AtomicBooleanLike established = new AtomicBooleanLike();
        engine.start(cfg, nullProtector, new TunnelEngineListenerAdapter(established));
        try {
            awaitTrue(established, 15000, "引擎握手应在 15s 内建立");

            // 启动混合代理（指向引擎）
            MixedProxyListener proxy = new MixedProxyListener(PROXY_PORT,
                    engine::open, Runnable::run, null);
            proxy.start();
            try {
                // ---- 入口 1：SOCKS5 CONNECT + 64KiB echo ----
                byte[] payload = new byte[64 * 1024];
                rnd.nextBytes(payload);
                byte[] echoed = socks5RoundTrip(echoPort, payload);
                assertArrayEquals("SOCKS5: echo 必须逐字节一致", payload, echoed);

                // ---- 入口 2：HTTP CONNECT ----
                byte[] msg = "hello-over-connect".getBytes(StandardCharsets.US_ASCII);
                byte[] got = httpConnectRoundTrip(echoPort, msg);
                assertArrayEquals("HTTP CONNECT: echo 必须逐字节一致", msg, got);

                // ---- 入口 3：absolute-form 正向代理（校验 origin-form 改写） ----
                byte[] resp = forwardProxyRoundTrip(echoPort);
                String respText = new String(resp, StandardCharsets.US_ASCII);
                assertTrue("absolute-form 应改写为 origin-form：" + respText,
                        respText.startsWith("GET /path?a=1 HTTP/1.1"));
                assertTrue("逐跳头应被剥离：" + respText,
                        !respText.contains("Connection: keep-alive"));
                assertTrue("Host 头应重建为 authority：" + respText,
                        respText.contains("Host: 127.0.0.1:" + echoPort));
                assertTrue("应追加 Connection: close：" + respText,
                        respText.contains("Connection: close"));
            } finally {
                proxy.stop();
            }
        } finally {
            engine.stop();
            server.destroy();
        }
    }

    private static final class TunnelEngineListenerAdapter
            implements com.dchen.fcpvpn.core.session.TunnelEngine.EngineListener {
        private final AtomicBooleanLike established;

        TunnelEngineListenerAdapter(AtomicBooleanLike established) {
            this.established = established;
        }

        @Override
        public void onEstablished(String salt) {
            established.set(true);
        }

        @Override
        public void onDown(String reason) {
        }

        @Override
        public void onStatsLine(String line) {
        }
    }

    private byte[] socks5RoundTrip(int echoPort, byte[] payload) throws Exception {
        try (Socket s = new Socket("127.0.0.1", PROXY_PORT)) {
            s.setSoTimeout(30000);
            InputStream in = s.getInputStream();
            OutputStream out = s.getOutputStream();
            // greeting: ver=5, 1 method, no-auth
            out.write(new byte[]{5, 1, 0});
            out.flush();
            byte[] greetReply = readN(in, 2, 10000);
            assertTrue("SOCKS5 greeting 应选择 no-auth",
                    greetReply[0] == 5 && greetReply[1] == 0);
            // CONNECT 127.0.0.1:echoPort
            byte[] req = new byte[]{5, 1, 0, 1, 127, 0, 0, 1,
                    (byte) (echoPort >> 8), (byte) echoPort};
            out.write(req);
            out.flush();
            byte[] rep = readN(in, 10, 15000);
            assertTrue("SOCKS5 reply 应为 Succeeded(0)，实际 rep=" + rep[1],
                    rep[0] == 5 && rep[1] == 0);
            // payload 往返
            out.write(payload);
            out.flush();
            byte[] echoed = readN(in, payload.length, 30000);
            // FIN 本端 → 对端排空（echo 服务端关闭）——测试在数据完整后直接关闭。
            return echoed;
        }
    }

    private byte[] httpConnectRoundTrip(int echoPort, byte[] payload) throws Exception {
        try (Socket s = new Socket("127.0.0.1", PROXY_PORT)) {
            s.setSoTimeout(30000);
            InputStream in = s.getInputStream();
            OutputStream out = s.getOutputStream();
            out.write(("CONNECT 127.0.0.1:" + echoPort + " HTTP/1.1\r\n\r\n")
                    .getBytes(StandardCharsets.US_ASCII));
            out.flush();
            byte[] head = readN(in, "HTTP/1.1 200 Connection Established\r\n\r\n".length(), 15000);
            String headText = new String(head, StandardCharsets.US_ASCII);
            assertTrue("应收到 200 Connection Established：" + headText,
                    headText.startsWith("HTTP/1.1 200"));
            out.write(payload);
            out.flush();
            return readN(in, payload.length, 30000);
        }
    }

    private byte[] forwardProxyRoundTrip(int echoPort) throws Exception {
        try (Socket s = new Socket("127.0.0.1", PROXY_PORT)) {
            s.setSoTimeout(30000);
            InputStream in = s.getInputStream();
            OutputStream out = s.getOutputStream();
            out.write(("GET http://127.0.0.1:" + echoPort + "/path?a=1 HTTP/1.1\r\n"
                    + "Host: 127.0.0.1:" + echoPort + "\r\n"
                    + "Connection: keep-alive\r\n"
                    + "X-Drop-Me: hop\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
            out.flush();
            // echo 把改写后的请求原样回显；读到含 Host 行的完整响应即可。
            byte[] buf = new byte[8192];
            StringBuilder sb = new StringBuilder();
            long deadline = System.currentTimeMillis() + 15000;
            int n;
            while (System.currentTimeMillis() < deadline && (n = in.read(buf)) != -1) {
                sb.append(new String(buf, 0, n, StandardCharsets.US_ASCII));
                if (sb.toString().contains("\r\n\r\n")) break;
            }
            return sb.toString().getBytes(StandardCharsets.US_ASCII);
        }
    }

    private static boolean nodeAvailable() {
        return FcpServerProcess.nodeAvailable();
    }
}
