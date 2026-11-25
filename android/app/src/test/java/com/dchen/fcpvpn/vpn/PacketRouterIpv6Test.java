package com.dchen.fcpvpn.vpn;

import org.junit.Test;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * PacketRouter 的 IPv6 处理：必须把 IPv6 收进 TUN 再快速拒绝。
 *
 * <p>Android 的 per-UID VPN 规则只把本接口通告过的地址族收进 TUN。接口不通告
 * ::/0 的话，应用的 IPv6 流量根本不会进 TUN，而是绕过隧道从物理网卡直出——
 * "按应用代理"看上去就完全没生效。收进 TUN 后回 ICMPv6 unreachable，应用才会
 * 立刻回退到 IPv4。</p>
 */
public class PacketRouterIpv6Test {

    /** 应用的源地址（这里用 link-local，真实场景下通常是 TUN 的 fd00::2）。 */
    private static final byte[] SRC_V6 = {
            (byte) 0xfe, (byte) 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};
    private static final byte[] DST_V6 = {
            (byte) 0x20, 0x01, (byte) 0x0d, (byte) 0xb8, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0x01};
    /** TUN 的本地 IPv6 地址（ICMPv6 拒绝报文的源地址）。 */
    private static final byte[] TUN_V6 = {
            (byte) 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02};

    /** 构造一个 IPv6 + TCP(SYN) 报文。 */
    private static byte[] buildIpv6TcpPacket(byte[] src, byte[] dst, int srcPort, int dstPort) {
        int tcpLen = 20;
        byte[] packet = new byte[40 + tcpLen];
        ByteBuffer buf = ByteBuffer.wrap(packet).order(ByteOrder.BIG_ENDIAN);
        buf.putInt(0x60000000);        // version 6
        buf.putShort((short) tcpLen);  // payload length
        buf.put((byte) 6);             // next header = TCP
        buf.put((byte) 64);            // hop limit
        buf.put(src);
        buf.put(dst);
        // TCP 头
        buf.putShort((short) srcPort);
        buf.putShort((short) dstPort);
        buf.putInt(0x1000);            // seq
        buf.putInt(0);                 // ack
        buf.put((byte) 0x50);          // data offset = 5
        buf.put((byte) 0x02);          // flags = SYN
        buf.putShort((short) 65535);   // window
        buf.putShort((short) 0);       // checksum
        buf.putShort((short) 0);       // urgent
        return packet;
    }

    /** 与 PacketRouter 里同款的 Internet checksum。 */
    private static int checksum(byte[] data, int offset, int len) {
        long sum = 0;
        int i = offset;
        while (len > 1) {
            sum += ((data[i] & 0xFF) << 8) | (data[i + 1] & 0xFF);
            i += 2;
            len -= 2;
        }
        if (len > 0) {
            sum += (data[i] & 0xFF) << 8;
        }
        while ((sum >> 16) != 0) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        return (int) (~sum) & 0xFFFF;
    }

    @Test
    public void ipv6PacketGetsIcmpv6Unreachable() throws Exception {
        PacketRouter router = new PacketRouter(null);
        router.start();
        try {
            byte[] packet = buildIpv6TcpPacket(SRC_V6, DST_V6, 40000, 443);

            CountDownLatch latch = new CountDownLatch(1);
            AtomicReference<byte[]> written = new AtomicReference<>();
            router.handleOutboundPacket(packet, p -> {
                written.set(p);
                latch.countDown();
            });

            assertTrue("IPv6 报文没有被拒绝", latch.await(2, TimeUnit.SECONDS));
            byte[] resp = written.get();
            assertNotNull(resp);

            // IPv6 头：next header = 58 (ICMPv6)
            assertEquals(0x60, (resp[0] & 0xF0));
            assertEquals(58, resp[6] & 0xFF);
            // 源 = TUN 的本地 IPv6 地址，目的 = 原包的源地址
            for (int i = 0; i < 16; i++) {
                assertEquals(TUN_V6[i], resp[8 + i]);
                assertEquals(SRC_V6[i], resp[24 + i]);
            }
            // ICMPv6：type = 1 (Destination Unreachable)，code = 0
            assertEquals(1, resp[40] & 0xFF);
            assertEquals(0, resp[41] & 0xFF);

            // 校验和必须正确（用伪首部重算，结果应为 0）
            int icmpLen = resp.length - 40;
            byte[] pseudo = new byte[40 + icmpLen];
            System.arraycopy(resp, 8, pseudo, 0, 16);
            System.arraycopy(resp, 24, pseudo, 16, 16);
            pseudo[32] = (byte) ((icmpLen >> 24) & 0xFF);
            pseudo[33] = (byte) ((icmpLen >> 16) & 0xFF);
            pseudo[34] = (byte) ((icmpLen >> 8) & 0xFF);
            pseudo[35] = (byte) (icmpLen & 0xFF);
            pseudo[39] = 58;
            System.arraycopy(resp, 40, pseudo, 40, icmpLen);
            assertEquals("ICMPv6 校验和不对", 0, checksum(pseudo, 0, pseudo.length));

            // 带上原报文，内核才能把错误匹配回对应的 socket
            assertEquals(packet.length, resp.length - 48);
            for (int i = 0; i < packet.length; i++) {
                assertEquals(packet[i], resp[48 + i]);
            }
        } finally {
            router.stop();
        }
    }

    @Test
    public void extensionHeaderPacketIsAlsoRejected() throws Exception {
        // 带分片扩展头（next header = 44）的 IPv6 报文同样要快速失败：
        // 拒绝逻辑不能排在扩展头检查之后，否则这类报文只能干等超时。
        byte[] packet = buildIpv6TcpPacket(SRC_V6, DST_V6, 40000, 443);
        packet[6] = 44; // next header = Fragment

        PacketRouter router = new PacketRouter(null);
        router.start();
        try {
            CountDownLatch latch = new CountDownLatch(1);
            AtomicReference<byte[]> written = new AtomicReference<>();
            router.handleOutboundPacket(packet, p -> {
                written.set(p);
                latch.countDown();
            });
            assertTrue("带扩展头的 IPv6 报文没有被拒绝", latch.await(2, TimeUnit.SECONDS));
            assertEquals(58, written.get()[6] & 0xFF);
            assertEquals(1, written.get()[40] & 0xFF);
        } finally {
            router.stop();
        }
    }

    @Test
    public void multicastIpv6IsDroppedWithoutIcmpError() throws Exception {
        // RFC 4443：不能对目的为组播的报文回 ICMPv6 错误（mDNS ff02::fb 之类）。
        byte[] mcast = {
                (byte) 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 0xfb};
        byte[] packet = buildIpv6TcpPacket(SRC_V6, mcast, 40000, 5353);

        PacketRouter router = new PacketRouter(null);
        router.start();
        try {
            CountDownLatch latch = new CountDownLatch(1);
            router.handleOutboundPacket(packet, p -> latch.countDown());
            assertFalse("组播报文不应回 ICMPv6 错误", latch.await(200, TimeUnit.MILLISECONDS));
        } finally {
            router.stop();
        }
    }
}
