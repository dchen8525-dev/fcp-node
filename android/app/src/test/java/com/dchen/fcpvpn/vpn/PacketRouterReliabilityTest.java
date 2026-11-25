package com.dchen.fcpvpn.vpn;

import com.dchen.fcpvpn.core.session.StreamHandle;

import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PipedInputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/** PacketRouter 的 TCP 回绕与连接回收回归测试。 */
public class PacketRouterReliabilityTest {
    private static final byte[] SRC = {10, 0, 0, 2};
    private static final byte[] TUNNEL_DST = {1, 1, 1, 1};
    private static final byte[] LAN_DST = {127, 0, 0, 1};
    private static final int SERVER_SEQ = 0x1001;

    @Test
    public void sequenceComparisonsHonorWrapBoundary() {
        assertTrue(PacketRouter.seqAfterOrEqual(0, 0xFFFFFFFF));
        assertTrue(PacketRouter.seqAfterOrEqual(0x80000000, 0x7FFFFFFF));
        assertFalse(PacketRouter.seqAfterOrEqual(0x7FFFFFFF, 0x80000000));
        assertTrue(PacketRouter.seqBefore(0x7FFFFFFF, 0x80000000));
        assertFalse(PacketRouter.seqBefore(0x80000000, 0x7FFFFFFF));
        assertTrue(PacketRouter.seqAfterOrEqual(0x80000000, 0x80000000));
        assertFalse(PacketRouter.seqBefore(0x80000000, 0x80000000));
    }

    @Test
    public void duplicatePayloadBeforeWrappedSequenceStillGetsAck() throws Exception {
        List<byte[]> written = new ArrayList<>();
        PacketRouter router = new PacketRouter(null);
        router.start();
        try {
            insertConnection(router, 40000, 0x80000000, written);
            router.handleOutboundPacket(buildTcpPacket(
                    40000, 443, 0x7FFFFFFF, SERVER_SEQ, 0x18, new byte[]{1}), written::add);

            assertEquals("duplicate payload must still receive an ACK", 1, written.size());
            assertEquals(0x80000000, ackOf(written.get(0)));
        } finally {
            router.stop();
        }
    }

    @Test
    public void partialOverlapAcrossWrapForwardsOnlyNewSuffix() throws Exception {
        List<byte[]> written = new ArrayList<>();
        PacketRouter router = new PacketRouter(null);
        router.start();
        try {
            Object conn = insertConnection(router, 40000, 0xFFFFFFFF, written);
            router.handleOutboundPacket(buildTcpPacket(
                    40000, 443, 0xFFFFFFFE, SERVER_SEQ, 0x18, new byte[]{1, 2, 3}), written::add);

            @SuppressWarnings("unchecked")
            Deque<byte[]> outbound = (Deque<byte[]>) getField(conn, "outboundBuffer");
            assertEquals(1, outbound.size());
            assertArrayEquals(new byte[]{2, 3}, outbound.removeFirst());
            assertEquals(0x00000001, getField(conn, "clientNextSeq"));
            assertEquals(1, written.size());
            assertEquals(0x00000001, ackOf(written.get(0)));
        } finally {
            router.stop();
        }
    }

    @Test
    public void outOfOrderPayloadAcksCurrentNextWithoutBuffering() throws Exception {
        List<byte[]> written = new ArrayList<>();
        PacketRouter router = new PacketRouter(null);
        router.start();
        try {
            Object conn = insertConnection(router, 40000, 0x80000010, written);
            router.handleOutboundPacket(buildTcpPacket(
                    40000, 443, 0x80000014, SERVER_SEQ, 0x18, new byte[]{9}), written::add);

            @SuppressWarnings("unchecked")
            Deque<byte[]> outbound = (Deque<byte[]>) getField(conn, "outboundBuffer");
            assertTrue(outbound.isEmpty());
            assertEquals(0x80000010, getField(conn, "clientNextSeq"));
            assertEquals(1, written.size());
            assertEquals(0x80000010, ackOf(written.get(0)));
        } finally {
            router.stop();
        }
    }

    @Test
    public void finWithGapDoesNotAdvanceOrCloseOutbound() throws Exception {
        List<byte[]> written = new ArrayList<>();
        PacketRouter router = new PacketRouter(null);
        router.start();
        try {
            Object conn = insertConnection(router, 40000, 0x80000010, written);
            router.handleOutboundPacket(buildTcpPacket(
                    40000, 443, 0x8000000E, SERVER_SEQ, 0x11, new byte[0]), written::add);

            assertEquals(0x80000010, getField(conn, "clientNextSeq"));
            assertEquals(false, getField(conn, "clientFinSeen"));
            assertEquals(false, getField(conn, "pendingCloseWrite"));
            assertEquals(1, written.size());
            assertEquals(0x80000010, ackOf(written.get(0)));
        } finally {
            router.stop();
        }
    }

    @Test
    public void duplicateFinDoesNotAdvanceOrCloseOutboundTwice() throws Exception {
        List<byte[]> written = new ArrayList<>();
        PacketRouter router = new PacketRouter(null);
        router.start();
        try {
            Object conn = insertConnection(router, 40000, 0x80000010, written);
            CountingStream stream = new CountingStream();
            setField(conn, "tunnelStream", stream);
            invoke(router, "attachTunnelStream",
                    new Class<?>[]{conn.getClass(), StreamHandle.class}, conn, stream);

            router.handleOutboundPacket(buildTcpPacket(
                    40000, 443, 0x80000010, SERVER_SEQ, 0x11, new byte[0]), written::add);
            router.handleOutboundPacket(buildTcpPacket(
                    40000, 443, 0x8000000F, SERVER_SEQ, 0x11, new byte[0]), written::add);

            assertEquals(0x80000011, getField(conn, "clientNextSeq"));
            assertEquals(1, stream.closeWriteCalls.get());
            assertEquals(2, written.size());
            assertEquals(0x80000011, ackOf(written.get(0)));
            assertEquals(0x80000011, ackOf(written.get(1)));
        } finally {
            router.stop();
        }
    }

    @Test
    public void serverFinWaitsForPendingThenFlushesDataBeforeFin() throws Exception {
        List<byte[]> written = new ArrayList<>();
        PacketRouter router = new PacketRouter(null);
        router.start();
        try {
            Object conn = insertConnection(router, 40000, 0x80000010, written);
            setField(conn, "appWindowAck", SERVER_SEQ);
            setField(conn, "appWindow", 0);
            invoke(router, "ingestServerData",
                    new Class<?>[]{conn.getClass(), byte[].class, int.class, int.class},
                    conn, new byte[]{1, 2, 3}, 0, 3);
            invoke(router, "sendFinToApp", new Class<?>[]{conn.getClass()}, conn);

            assertTrue("FIN crossed unsent pending data", written.isEmpty());
            assertEquals(true, getField(conn, "serverFinPending"));
            assertEquals(false, getField(conn, "serverFinSeen"));
            assertEquals(1, router.getActiveConnectionCount());

            router.handleOutboundPacket(buildTcpPacket(
                    40000, 443, 0x80000010, SERVER_SEQ, 0x10, new byte[0]), written::add);
            // 上面 builder 的窗口固定为 65535，窗口打开后必须先发数据再发 FIN。
            assertEquals(2, written.size());
            assertEquals(0x18, flagsOf(written.get(0)));
            assertEquals(SERVER_SEQ, seqOf(written.get(0)));
            assertArrayEquals(new byte[]{1, 2, 3}, payloadOf(written.get(0)));
            assertEquals(0x11, flagsOf(written.get(1)));
            assertEquals(SERVER_SEQ + 3, seqOf(written.get(1)));
            assertEquals(false, getField(conn, "serverFinPending"));
            assertEquals(true, getField(conn, "serverFinSeen"));
        } finally {
            router.stop();
        }
    }

    @Test
    public void appFinBeforeServerFinKeepsConnectionUntilPendingFlushes() throws Exception {
        List<byte[]> written = new ArrayList<>();
        PacketRouter router = new PacketRouter(null);
        router.start();
        try {
            Object conn = insertConnection(router, 40000, 0x80000010, written);
            setField(conn, "clientFinSeen", true);
            setField(conn, "appWindowAck", SERVER_SEQ);
            setField(conn, "appWindow", 0);
            invoke(router, "ingestServerData",
                    new Class<?>[]{conn.getClass(), byte[].class, int.class, int.class},
                    conn, new byte[]{4, 5}, 0, 2);
            invoke(router, "sendFinToApp", new Class<?>[]{conn.getClass()}, conn);
            assertEquals(1, router.getActiveConnectionCount());
            assertTrue(written.isEmpty());

            router.handleOutboundPacket(buildTcpPacket(
                    40000, 443, 0x80000010, SERVER_SEQ, 0x10, new byte[0]), written::add);
            assertEquals(2, written.size());
            assertEquals(0x18, flagsOf(written.get(0)));
            assertEquals(0x11, flagsOf(written.get(1)));
            assertEquals(0, router.getActiveConnectionCount());
        } finally {
            router.stop();
        }
    }

    @Test
    public void serverFinBeforeAppFinRemovesConnectionOnlyAfterBoth() throws Exception {
        List<byte[]> written = new ArrayList<>();
        PacketRouter router = new PacketRouter(null);
        router.start();
        try {
            insertConnection(router, 40000, 0x80000010, written);
            Object conn = onlyConnection(router);
            invoke(router, "sendFinToApp", new Class<?>[]{conn.getClass()}, conn);
            assertEquals(1, router.getActiveConnectionCount());

            router.handleOutboundPacket(buildTcpPacket(
                    40000, 443, 0x80000010, SERVER_SEQ, 0x11, new byte[0]), written::add);
            assertEquals(0, router.getActiveConnectionCount());
        } finally {
            router.stop();
        }
    }

    @Test
    public void stopDoesNotJoinBlockedCleanupWriter() throws Exception {
        PacketRouter router = new PacketRouter(null);
        router.start();
        CountDownLatch cleanupWriting = new CountDownLatch(1);
        CountDownLatch releaseWriter = new CountDownLatch(1);
        List<byte[]> written = new ArrayList<>();
        Thread sweeper = (Thread) getField(router, "cleanupThread");
        try {
            Object conn = newConnection(40000, 0x80000010, packet -> {
                if (Thread.currentThread() == sweeper) {
                    cleanupWriting.countDown();
                    boolean interrupted = false;
                    while (true) {
                        try {
                            releaseWriter.await();
                            break;
                        } catch (InterruptedException e) {
                            interrupted = true;
                        }
                    }
                    if (interrupted) {
                        Thread.currentThread().interrupt();
                    }
                } else {
                    written.add(packet);
                }
            });
            setField(conn, "serverNextSeq", SERVER_SEQ);
            setField(conn, "appWindowAck", SERVER_SEQ);
            setField(conn, "appWindow", 65535);
            insertConnection(router, conn);
            invoke(router, "ingestServerData",
                    new Class<?>[]{conn.getClass(), byte[].class, int.class, int.class},
                    conn, new byte[]{7}, 0, 1);
            setField(conn, "lastAckProgressMs", 0L);
            setField(conn, "lastRetransmitMs", 0L);
            assertTrue("cleanup did not reach TUN write", cleanupWriting.await(4, TimeUnit.SECONDS));

            long started = System.nanoTime();
            router.stop();
            long elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started);
            assertTrue("stop waited for cleanup TUN write: " + elapsedMs + "ms", elapsedMs < 1000);
            assertEquals(0, router.getActiveConnectionCount());
            assertNull(getField(router, "cleanupThread"));
        } finally {
            releaseWriter.countDown();
            sweeper.join(2000);
            router.stop();
        }
    }

    @Test
    public void stopClosesDnsSocketsAndLifecycleIsRepeatable() throws Exception {
        PacketRouter router = new PacketRouter(null);
        router.stop();
        router.stop();
        router.start();
        Thread firstSweeper = (Thread) getField(router, "cleanupThread");
        ThreadPoolExecutor firstRelay = (ThreadPoolExecutor) getField(router, "dnsRelayExecutor");
        router.start();
        assertSame(firstSweeper, getField(router, "cleanupThread"));
        assertSame(firstRelay, getField(router, "dnsRelayExecutor"));

        @SuppressWarnings("unchecked")
        Set<DatagramSocket> sockets = (Set<DatagramSocket>) getField(router, "inFlightDnsSockets");
        DatagramSocket socket = new DatagramSocket();
        sockets.add(socket);
        router.stop();
        router.stop();
        assertTrue(socket.isClosed());
        assertTrue(firstRelay.isShutdown());
        assertNull(getField(router, "cleanupThread"));
        firstSweeper.join(2000);
        assertFalse(firstSweeper.isAlive());

        router.start();
        assertNotSame(firstRelay, getField(router, "dnsRelayExecutor"));
        assertNotSame(firstSweeper, getField(router, "cleanupThread"));
        router.stop();
    }

    @Test
    public void malformedIpv4HeadersAreRejected() throws Exception {
        List<byte[]> written = new ArrayList<>();
        PacketRouter router = new PacketRouter(null);
        router.start();
        try {
            byte[] shortIhl = buildTcpPacket(40000, 443, 0x2000, 0, 0x02, new byte[0]);
            shortIhl[0] = 0x44;
            router.handleOutboundPacket(shortIhl, written::add);
            assertTrue(written.isEmpty());
            assertEquals(0, router.getActiveConnectionCount());

            byte[] shortTotalLen = buildTcpPacket(40001, 443, 0x2000, 0, 0x02, new byte[0]);
            ByteBuffer.wrap(shortTotalLen).order(ByteOrder.BIG_ENDIAN).putShort(2, (short) 19);
            router.handleOutboundPacket(shortTotalLen, written::add);
            assertTrue(written.isEmpty());
            assertEquals(0, router.getActiveConnectionCount());
        } finally {
            router.stop();
        }
    }

    @Test
    public void finAtWrapBoundaryAdvancesClientSequence() throws Exception {
        List<byte[]> written = new ArrayList<>();
        PacketRouter router = new PacketRouter(null);
        router.start();
        try {
            insertConnection(router, 40000, 0x7FFFFFFF, written);
            router.handleOutboundPacket(buildTcpPacket(
                    40000, 443, 0x7FFFFFFF, SERVER_SEQ, 0x11, new byte[0]), written::add);

            assertEquals(1, written.size());
            assertEquals(0x80000000, ackOf(written.get(0)));
        } finally {
            router.stop();
        }
    }

    @Test
    public void retransmittedFinBeforeWrapDoesNotMoveAckBackwards() throws Exception {
        List<byte[]> written = new ArrayList<>();
        PacketRouter router = new PacketRouter(null);
        router.start();
        try {
            insertConnection(router, 40000, 0x80000005, written);
            router.handleOutboundPacket(buildTcpPacket(
                    40000, 443, 0x7FFFFFFD, SERVER_SEQ, 0x11, new byte[0]), written::add);

            assertEquals(1, written.size());
            assertEquals(0x80000005, ackOf(written.get(0)));
        } finally {
            router.stop();
        }
    }

    @Test
    public void removeConnectionCleanupIsCompleteAndIdempotent() throws Exception {
        PacketRouter router = new PacketRouter(null);
        router.start();
        TrackingSocket socket = new TrackingSocket();
        CountingStream stream = new CountingStream();
        Thread reader = new Thread(() -> {
            try {
                socket.getInputStream().read();
            } catch (IOException ignored) {
                // close 会唤醒阻塞读取
            }
        }, "PacketRouterReliabilityTest-Reader");
        reader.start();
        assertTrue("LAN reader did not enter read", socket.readStarted.await(2, TimeUnit.SECONDS));
        try {
            Object conn = newConnection(40000, 0x80000000, p -> { });
            setField(conn, "tunnelStream", stream);
            setField(conn, "lanSocket", socket);
            setField(conn, "lanPump", reader);
            insertConnection(router, conn);

            Method attachSink = conn.getClass().getDeclaredMethod("attachLanSink", Socket.class);
            attachSink.setAccessible(true);
            assertTrue((Boolean) attachSink.invoke(conn, socket));
            Method closeOutbound = PacketRouter.class.getDeclaredMethod(
                    "sendCloseToOutbound", conn.getClass(), boolean.class);
            closeOutbound.setAccessible(true);
            closeOutbound.invoke(router, conn, true);

            removeConnection(router, conn);
            removeConnection(router, conn);

            assertEquals(1, socket.closeCalls.get());
            assertEquals(1, stream.abortCalls.get());
            assertNull(getField(conn, "tunnelStream"));
            assertNull(getField(conn, "sink"));
            assertNull(getField(conn, "lanSocket"));
            assertNull(getField(conn, "lanPump"));
            assertEquals(0, router.getActiveConnectionCount());
            reader.join(2000);
            assertFalse("LAN reader still alive after connection removal", reader.isAlive());
        } finally {
            router.stop();
            socket.close();
            reader.join(2000);
        }
    }

    @Test
    public void removeConnectionDuringLanConnectClosesSocketAndConnector() throws Exception {
        PacketRouter router = new PacketRouter(null);
        router.start();
        TrackingSocket socket = new TrackingSocket();
        CountDownLatch releaseConnector = new CountDownLatch(1);
        Thread connector = new Thread(() -> {
            try {
                releaseConnector.await();
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
            }
        }, "PacketRouterReliabilityTest-Connector");
        connector.start();
        try {
            Object conn = newConnection(40000, 0x80000000, p -> { });
            setField(conn, "lanSocket", socket);
            setField(conn, "lanConnector", connector);
            insertConnection(router, conn);

            removeConnection(router, conn);
            removeConnection(router, conn);

            assertEquals(1, socket.closeCalls.get());
            assertNull(getField(conn, "lanSocket"));
            assertNull(getField(conn, "lanConnector"));
            connector.join(2000);
            assertFalse("LAN connector still alive after connection removal", connector.isAlive());
        } finally {
            releaseConnector.countDown();
            router.stop();
            socket.close();
            connector.join(2000);
        }
    }

    @Test
    public void stopClosesEstablishedLanSocketAndReader() throws Exception {
        PacketRouter router = new PacketRouter(null);
        ServerSocket server = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"));
        Socket peer = null;
        try {
            server.setSoTimeout(3000);
            router.start();
            List<byte[]> written = new ArrayList<>();
            router.handleOutboundPacket(buildTcpPacket(
                    40000, server.getLocalPort(), 0x2000, 0, 0x02, new byte[0],
                    SRC, LAN_DST), written::add);
            assertFalse("LAN SYN did not produce SYN-ACK", written.isEmpty());

            peer = server.accept();
            peer.setSoTimeout(3000);
            Object conn = onlyConnection(router);
            Thread pump = awaitLiveThreadField(conn, "lanPump", 3000);
            assertNotNull(pump);

            router.stop();
            pump.join(3000);
            assertFalse("LAN pump still alive after router.stop", pump.isAlive());
            assertEquals(0, router.getActiveConnectionCount());
            try {
                assertEquals(-1, peer.getInputStream().read());
            } catch (SocketException expected) {
                // 关闭尚未排空数据的 TCP 连接时，对端观察到 RST 也属于已关闭。
            }
        } finally {
            router.stop();
            if (peer != null) {
                peer.close();
            }
            server.close();
        }
    }

    private static Object insertConnection(PacketRouter router, int srcPort, int clientNextSeq,
                                         List<byte[]> written) throws Exception {
        Object conn = newConnection(srcPort, clientNextSeq, written::add);
        setField(conn, "serverNextSeq", SERVER_SEQ);
        setField(conn, "synAckSent", true);
        insertConnection(router, conn);
        return conn;
    }

    private static Object newConnection(int srcPort, int clientNextSeq,
                                        PacketRouter.WritePacketCallback callback) throws Exception {
        Class<?> type = Class.forName("com.dchen.fcpvpn.vpn.PacketRouter$TcpConnection");
        Constructor<?> constructor = type.getDeclaredConstructor(
                long.class, String.class, byte[].class, int.class, byte[].class, int.class,
                int.class, PacketRouter.WritePacketCallback.class);
        constructor.setAccessible(true);
        String key = "10.0.0.2:" + srcPort + "->1.1.1.1:443";
        Object conn = constructor.newInstance(
                42L, key, SRC, srcPort, TUNNEL_DST, 443, 0x1000, callback);
        setField(conn, "clientNextSeq", clientNextSeq);
        return conn;
    }

    @SuppressWarnings("unchecked")
    private static void insertConnection(PacketRouter router, Object conn) throws Exception {
        Map<String, Object> byKey = (Map<String, Object>) getField(router, "connectionsByKey");
        Map<Long, Object> byId = (Map<Long, Object>) getField(router, "connectionsById");
        byKey.put((String) getField(conn, "key"), conn);
        byId.put((Long) getField(conn, "connectionId"), conn);
    }

    @SuppressWarnings("unchecked")
    private static Object onlyConnection(PacketRouter router) throws Exception {
        Map<Long, Object> byId = (Map<Long, Object>) getField(router, "connectionsById");
        assertEquals(1, byId.size());
        return byId.values().iterator().next();
    }

    private static void removeConnection(PacketRouter router, Object conn) throws Exception {
        Method method = PacketRouter.class.getDeclaredMethod("removeConnection", conn.getClass());
        method.setAccessible(true);
        method.invoke(router, conn);
    }

    private static Object invoke(Object target, String name, Class<?>[] parameterTypes,
                                 Object... args) throws Exception {
        Method method = target.getClass().getDeclaredMethod(name, parameterTypes);
        method.setAccessible(true);
        return method.invoke(target, args);
    }

    private static Thread awaitLiveThreadField(Object target, String name, long timeoutMs)
            throws Exception {
        long deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMs);
        while (System.nanoTime() < deadline) {
            Object value = getField(target, name);
            if (value instanceof Thread && ((Thread) value).isAlive()) {
                return (Thread) value;
            }
            Thread.sleep(10);
        }
        fail("timed out waiting for " + name);
        return null;
    }

    private static Object getField(Object target, String name) throws Exception {
        Field field = target.getClass().getDeclaredField(name);
        field.setAccessible(true);
        return field.get(target);
    }

    private static void setField(Object target, String name, Object value) throws Exception {
        Field field = target.getClass().getDeclaredField(name);
        field.setAccessible(true);
        field.set(target, value);
    }

    private static int ackOf(byte[] packet) {
        return ByteBuffer.wrap(packet).order(ByteOrder.BIG_ENDIAN).getInt(28);
    }

    private static int seqOf(byte[] packet) {
        return ByteBuffer.wrap(packet).order(ByteOrder.BIG_ENDIAN).getInt(24);
    }

    private static int flagsOf(byte[] packet) {
        return packet[33] & 0xFF;
    }

    private static byte[] payloadOf(byte[] packet) {
        return Arrays.copyOfRange(packet, 40, packet.length);
    }

    private static byte[] buildTcpPacket(int srcPort, int dstPort, int seq, int ack,
                                         int flags, byte[] payload) {
        return buildTcpPacket(srcPort, dstPort, seq, ack, flags, payload, SRC, TUNNEL_DST);
    }

    private static byte[] buildTcpPacket(int srcPort, int dstPort, int seq, int ack,
                                         int flags, byte[] payload, byte[] src, byte[] dst) {
        int totalLen = 40 + payload.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream(totalLen);
        ByteBuffer buf = ByteBuffer.allocate(totalLen).order(ByteOrder.BIG_ENDIAN);
        buf.put((byte) 0x45);
        buf.put((byte) 0);
        buf.putShort((short) totalLen);
        buf.putShort((short) 0);
        buf.putShort((short) 0x4000);
        buf.put((byte) 64);
        buf.put((byte) 6);
        buf.putShort((short) 0);
        buf.put(src);
        buf.put(dst);
        buf.putShort((short) srcPort);
        buf.putShort((short) dstPort);
        buf.putInt(seq);
        buf.putInt(ack);
        buf.put((byte) 0x50);
        buf.put((byte) flags);
        buf.putShort((short) 65535);
        buf.putShort((short) 0);
        buf.putShort((short) 0);
        buf.put(payload);
        out.write(buf.array(), 0, buf.array().length);
        return out.toByteArray();
    }

    private static final class CountingStream implements StreamHandle {
        private final AtomicInteger abortCalls = new AtomicInteger();
        private final AtomicInteger closeWriteCalls = new AtomicInteger();

        @Override
        public void setListener(Listener listener) { }

        @Override
        public void write(byte[] data, int offset, int len) { }

        @Override
        public void closeWrite() {
            closeWriteCalls.incrementAndGet();
        }

        @Override
        public void abort() {
            abortCalls.incrementAndGet();
        }

        @Override
        public void consumed(int n) { }
    }

    private static final class TrackingSocket extends Socket {
        private final AtomicInteger closeCalls = new AtomicInteger();
        private final CountDownLatch readStarted = new CountDownLatch(1);
        private final PipedInputStream input = new PipedInputStream() {
            @Override
            public synchronized int read() throws IOException {
                readStarted.countDown();
                return super.read();
            }
        };

        @Override
        public InputStream getInputStream() {
            return input;
        }

        @Override
        public synchronized void close() throws IOException {
            closeCalls.incrementAndGet();
            try {
                input.close();
            } finally {
                super.close();
            }
        }
    }
}
