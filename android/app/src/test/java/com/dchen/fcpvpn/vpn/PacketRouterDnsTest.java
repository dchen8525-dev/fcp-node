package com.dchen.fcpvpn.vpn;

import com.dchen.fcpvpn.core.proxy.DnsWire;
import com.dchen.fcpvpn.core.session.EngineConfig;
import com.dchen.fcpvpn.core.session.OpenCallback;
import com.dchen.fcpvpn.core.session.OpenTarget;
import com.dchen.fcpvpn.core.session.SocketProtector;
import com.dchen.fcpvpn.core.session.TunnelEngine;

import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.net.DatagramSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * PacketRouter 的 DNS 中继：AAAA 查询必须就地空应答，不能把 IPv6 地址交给应用。
 *
 * <p>本客户端只提供 IPv4 隧道，而 Android 的 per-UID VPN 规则只把 IPv4 收进
 * TUN——应用一旦拿到 AAAA 就会优先走 IPv6，那部分流量从物理网卡直出、绕过隧道，
 * 真机上的表现正是"按应用代理好像没生效"。</p>
 */
public class PacketRouterDnsTest {

    /** 构造一个 AAAA 查询的 DNS 报文。 */
    private static byte[] buildAaaaQuery(int id, String name) {
        return buildQuery(id, name, DnsWire.TYPE_AAAA);
    }

    /** 构造一个单 question 的 DNS 查询报文。 */
    private static byte[] buildQuery(int id, String name, int qtype) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write((id >>> 8) & 0xff);
        out.write(id & 0xff);
        out.write(0x01); // RD
        out.write(0x00);
        out.write(0); out.write(1); // qdcount=1
        out.write(0); out.write(0);
        out.write(0); out.write(0);
        out.write(0); out.write(0);
        for (String label : name.split("\\.")) {
            byte[] b = label.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            out.write(b.length);
            out.write(b, 0, b.length);
        }
        out.write(0);
        out.write((qtype >>> 8) & 0xff); out.write(qtype & 0xff);
        out.write(0); out.write(1); // IN
        return out.toByteArray();
    }

    /** 构造一个 IPv4 + UDP 报文（应用 → DNS 服务器）。 */
    private static byte[] buildUdpPacket(byte[] srcAddr, int srcPort,
                                         byte[] dstAddr, int dstPort, byte[] payload) {
        int udpLen = 8 + payload.length;
        int totalLen = 20 + udpLen;
        byte[] packet = new byte[totalLen];
        ByteBuffer buf = ByteBuffer.wrap(packet).order(ByteOrder.BIG_ENDIAN);
        buf.put((byte) 0x45);      // version 4, IHL 5
        buf.put((byte) 0);         // TOS
        buf.putShort((short) totalLen);
        buf.putShort((short) 0);   // id
        buf.putShort((short) 0x4000); // DF
        buf.put((byte) 64);        // TTL
        buf.put((byte) 17);        // UDP
        buf.putShort((short) 0);   // checksum（路由器不校验）
        buf.put(srcAddr);
        buf.put(dstAddr);
        buf.putShort((short) srcPort);
        buf.putShort((short) dstPort);
        buf.putShort((short) udpLen);
        buf.putShort((short) 0);   // UDP checksum
        buf.put(payload);
        return packet;
    }

    /** 取出应答报文里的 UDP 负载（IPv4 头 20 字节 + UDP 头 8 字节）。 */
    private static byte[] udpPayload(byte[] packet) {
        byte[] out = new byte[packet.length - 28];
        System.arraycopy(packet, 28, out, 0, out.length);
        return out;
    }

    private static Object getField(Object target, String name) throws ReflectiveOperationException {
        Field field = target.getClass().getDeclaredField(name);
        field.setAccessible(true);
        return field.get(target);
    }

    @Test
    public void aaaaQueryGetsEmptyNoerrorAnswerWithoutNetwork() throws Exception {
        PacketRouter router = new PacketRouter(null);
        router.start();
        try {
            byte[] query = buildAaaaQuery(0x1234, "v6.example.com");
            byte[] packet = buildUdpPacket(
                    new byte[]{10, 0, 0, 2}, 40000,
                    new byte[]{1, 1, 1, 1}, 53,
                    query);

            CountDownLatch latch = new CountDownLatch(1);
            AtomicReference<byte[]> written = new AtomicReference<>();
            router.handleOutboundPacket(packet, p -> {
                written.set(p);
                latch.countDown();
            });

            // 不出网就地应答：不能等上游解析器（那会走网络，测试就变成网络依赖）
            assertTrue("AAAA 查询没有就地应答", latch.await(2, TimeUnit.SECONDS));

            byte[] resp = udpPayload(written.get());
            assertNotNull(resp);
            // 事务 ID 原样回填
            assertEquals(0x12, resp[0] & 0xff);
            assertEquals(0x34, resp[1] & 0xff);
            // QR=1、rcode=0（NOERROR）
            assertEquals(0x81, resp[2] & 0xff);
            assertEquals(0x80, resp[3] & 0xff);
            // ancount=0：该类型没有记录（应用于是立刻改用 A）
            assertEquals(0, ((resp[6] & 0xff) << 8) | (resp[7] & 0xff));
            // question 区原样回填（应答本身 QR=1，不能再用 parseQuery 解析）
            assertEquals(query.length, resp.length);
            assertArrayEquals(Arrays.copyOfRange(query, 12, query.length),
                    Arrays.copyOfRange(resp, 12, resp.length));
        } finally {
            router.stop();
        }
    }

    @Test
    public void responseMatchesQueryAcceptsMatchingResponse() {
        byte[] query = buildQuery(0x1234, "www.example.com", DnsWire.TYPE_A);
        byte[] response = DnsWire.buildResponse(DnsWire.parseQuery(query),
                Arrays.asList(new byte[]{1, 2, 3, 4}), 0);

        assertTrue(DnsWire.responseMatchesQuery(response, query));
        assertFalse(DnsWire.responseMatchesQuery(null, query));
        assertFalse(DnsWire.responseMatchesQuery(response, null));
    }

    @Test
    public void responseMatchesQueryRejectsWrongFlagsIdCountAndQuestion() {
        byte[] query = buildQuery(0x1234, "www.example.com", DnsWire.TYPE_A);
        byte[] response = DnsWire.buildResponse(DnsWire.parseQuery(query),
                new ArrayList<byte[]>(), 0);

        byte[] notResponse = response.clone();
        notResponse[2] &= 0x7F;
        assertFalse(DnsWire.responseMatchesQuery(notResponse, query));

        byte[] wrongId = response.clone();
        wrongId[1] ^= 1;
        assertFalse(DnsWire.responseMatchesQuery(wrongId, query));

        byte[] noQuestion = response.clone();
        noQuestion[4] = 0;
        noQuestion[5] = 0;
        assertFalse(DnsWire.responseMatchesQuery(noQuestion, query));

        byte[] twoQuestions = response.clone();
        twoQuestions[5] = 2;
        assertFalse(DnsWire.responseMatchesQuery(twoQuestions, query));

        byte[] wrongName = response.clone();
        wrongName[13] = 'x';
        assertFalse(DnsWire.responseMatchesQuery(wrongName, query));

        DnsWire.Query parsed = DnsWire.parseQuery(query);
        int questionEnd = 12 + parsed.questionSection.length;
        byte[] wrongType = response.clone();
        wrongType[questionEnd - 4] = 0;
        wrongType[questionEnd - 3] = DnsWire.TYPE_AAAA;
        assertFalse(DnsWire.responseMatchesQuery(wrongType, query));

        byte[] wrongClass = response.clone();
        wrongClass[questionEnd - 1] = 3;
        assertFalse(DnsWire.responseMatchesQuery(wrongClass, query));

        byte[] truncated = Arrays.copyOf(response, questionEnd - 1);
        assertFalse(DnsWire.responseMatchesQuery(truncated, query));
    }

    @Test
    public void tunneledDnsResponseIsValidatedBeforeWriteAndCache() throws Exception {
        byte[] query = buildQuery(0x1111, "tunnel.example.com", DnsWire.TYPE_A);
        byte[] matching = DnsWire.buildResponse(DnsWire.parseQuery(query),
                Arrays.asList(new byte[]{1, 2, 3, 4}), 0);
        AtomicReference<byte[]> tunneledResponse = new AtomicReference<>(matching);
        TunnelManager manager = tunnelManagerReturning(tunneledResponse);
        PacketRouter router = new PacketRouter(manager);
        CountDownLatch firstWrite = new CountDownLatch(1);
        CountDownLatch fallbackAttempted = new CountDownLatch(1);
        AtomicInteger writes = new AtomicInteger();
        AtomicBoolean fallbackSocketRegistered = new AtomicBoolean();
        router.setSocketProtector(new SocketProtector() {
            @Override
            public boolean protect(DatagramSocket socket) {
                fallbackSocketRegistered.set(inFlightSockets(router).contains(socket));
                fallbackAttempted.countDown();
                return false;
            }

            @Override
            public boolean protect(Socket socket) {
                return false;
            }

            @Override
            public boolean protect(int fd) {
                return false;
            }
        });
        router.start();
        try {
            byte[] packet = buildUdpPacket(
                    new byte[]{10, 0, 0, 2}, 40000,
                    new byte[]{1, 1, 1, 1}, 53, query);
            router.handleOutboundPacket(packet, p -> {
                writes.incrementAndGet();
                firstWrite.countDown();
            });
            assertTrue("valid tunneled DNS response was not written", firstWrite.await(2, TimeUnit.SECONDS));
            @SuppressWarnings("unchecked")
            Map<String, Object> cache = (Map<String, Object>) getField(router, "dnsCache");
            assertTrue(cache.containsKey("tunnel.example.com|1"));

            byte[] wrongQuery = buildQuery(0x2222, "reject.example.com", DnsWire.TYPE_A);
            router.handleOutboundPacket(buildUdpPacket(
                    new byte[]{10, 0, 0, 2}, 40001,
                    new byte[]{1, 1, 1, 1}, 53, wrongQuery), p -> writes.incrementAndGet());
            assertTrue("mismatched response did not exercise local fallback",
                    fallbackAttempted.await(2, TimeUnit.SECONDS));
            assertTrue("fallback socket was not registered while in flight", fallbackSocketRegistered.get());
            assertEquals("mismatched tunneled response reached TUN", 1, writes.get());
            assertFalse(cache.containsKey("reject.example.com|1"));
        } finally {
            router.stop();
        }
    }

    @Test
    public void stopClosesBlockedFallbackSocketWithoutWaitingForTimeout() throws Exception {
        PacketRouter router = new PacketRouter(null);
        CountDownLatch protectorEntered = new CountDownLatch(1);
        CountDownLatch releaseProtector = new CountDownLatch(1);
        AtomicReference<DatagramSocket> captured = new AtomicReference<>();
        router.setSocketProtector(new SocketProtector() {
            @Override
            public boolean protect(DatagramSocket socket) {
                captured.set(socket);
                protectorEntered.countDown();
                try {
                    releaseProtector.await();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                return true;
            }

            @Override
            public boolean protect(Socket socket) {
                return true;
            }

            @Override
            public boolean protect(int fd) {
                return true;
            }
        });
        router.start();
        ThreadPoolExecutor relay = (ThreadPoolExecutor) getField(router, "dnsRelayExecutor");
        try {
            byte[] query = buildQuery(0x3333, "fallback.example.com", DnsWire.TYPE_A);
            router.handleOutboundPacket(buildUdpPacket(
                    new byte[]{10, 0, 0, 2}, 40000,
                    new byte[]{1, 1, 1, 1}, 53, query), p -> { });
            assertTrue(protectorEntered.await(2, TimeUnit.SECONDS));
            assertTrue(inFlightSockets(router).contains(captured.get()));

            long started = System.nanoTime();
            router.stop();
            long elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started);
            assertTrue("stop waited for DNS receive timeout: " + elapsedMs + "ms", elapsedMs < 1000);
            assertTrue(captured.get().isClosed());
            releaseProtector.countDown();
            assertTrue("DNS worker remained blocked after socket close", relay.awaitTermination(2, TimeUnit.SECONDS));
        } finally {
            releaseProtector.countDown();
            router.stop();
        }
    }

    @SuppressWarnings("unchecked")
    private static Set<DatagramSocket> inFlightSockets(PacketRouter router) {
        try {
            return (Set<DatagramSocket>) getField(router, "inFlightDnsSockets");
        } catch (ReflectiveOperationException e) {
            throw new AssertionError(e);
        }
    }

    private static TunnelManager tunnelManagerReturning(AtomicReference<byte[]> response) throws Exception {
        Class<?> contextType = Class.forName("android.content.Context");
        Constructor<TunnelManager> constructor = TunnelManager.class.getDeclaredConstructor(contextType);
        constructor.setAccessible(true);
        TunnelManager manager = constructor.newInstance((Object) null);
        Field engineField = TunnelManager.class.getDeclaredField("engine");
        engineField.setAccessible(true);
        engineField.set(manager, new FakeDnsEngine(response));
        return manager;
    }

    @Test
    public void dnsRelayQueueIsBoundedAndRejectsWithoutBlocking() throws Exception {
        PacketRouter router = new PacketRouter(null);
        router.start();
        ThreadPoolExecutor relay = (ThreadPoolExecutor) getField(router, "dnsRelayExecutor");
        CountDownLatch workersStarted = new CountDownLatch(4);
        CountDownLatch releaseWorkers = new CountDownLatch(1);
        try {
            // 占满 4 个 worker，使后续查询只能进入队列，不会访问网络。
            for (int i = 0; i < 4; i++) {
                relay.execute(() -> {
                    workersStarted.countDown();
                    try {
                        releaseWorkers.await();
                    } catch (InterruptedException ignored) {
                        Thread.currentThread().interrupt();
                    }
                });
            }
            assertTrue("DNS workers did not start", workersStarted.await(2, TimeUnit.SECONDS));

            byte[] query = buildAaaaQuery(0x4321, "queue.example.com");
            int capacity = relay.getQueue().remainingCapacity();
            assertTrue("DNS relay queue must be bounded", capacity > 0 && capacity < 1024);
            for (int i = 0; i < capacity; i++) {
                byte[] packet = buildUdpPacket(
                        new byte[]{10, 0, 0, 2}, 40000 + i,
                        new byte[]{1, 1, 1, 1}, 53, query);
                router.handleOutboundPacket(packet, p -> { });
            }
            assertEquals(capacity, relay.getQueue().size());

            byte[] overflow = buildUdpPacket(
                    new byte[]{10, 0, 0, 2}, 50000,
                    new byte[]{1, 1, 1, 1}, 53, query);
            long startedNs = System.nanoTime();
            router.handleOutboundPacket(overflow, p -> { });
            long elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startedNs);
            assertTrue("TUN thread blocked on a full DNS queue: " + elapsedMs + "ms",
                    elapsedMs < 1000);
            assertEquals(1L, ((AtomicLong) getField(router, "dnsRelayRejections")).get());

            // 关闭必须中断 worker、丢弃排队任务，并拒绝后续提交。
            router.stop();
            assertTrue(relay.isShutdown());
            assertEquals(0, relay.getQueue().size());
        } finally {
            releaseWorkers.countDown();
            router.stop();
        }
    }

    private static final class FakeDnsEngine implements TunnelEngine {
        private final AtomicReference<byte[]> response;

        FakeDnsEngine(AtomicReference<byte[]> response) {
            this.response = response;
        }

        @Override
        public void start(EngineConfig config, SocketProtector protector, EngineListener listener) { }

        @Override
        public void stop() { }

        @Override
        public void open(OpenTarget target, OpenCallback callback) { }

        @Override
        public DatagramSocket socket() {
            return null;
        }

        @Override
        public byte[] queryDns(byte[] dnsQuery, int timeoutMs) {
            return response.get();
        }

        @Override
        public boolean isEstablished() {
            return true;
        }
    }
}
