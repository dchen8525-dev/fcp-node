package com.dchen.fcpvpn.vpn;

import com.dchen.fcpvpn.core.proxy.DnsWire;
import com.dchen.fcpvpn.core.session.OpenCallback;
import com.dchen.fcpvpn.core.session.SocketProtector;
import com.dchen.fcpvpn.core.session.OpenTarget;
import com.dchen.fcpvpn.core.session.StreamHandle;
import com.dchen.fcpvpn.log.LogConfig;
import com.dchen.fcpvpn.log.Logger;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 数据包路由器 —— TUN 读出的 IP 包 → 虚拟 TCP 连接管理（按目标四元组）→
 * {@link TunnelManager#open} 建隧道流 → {@link StreamHandle} 与 TUN 双向搬运。
 *
 * <p>与 kcp 版的差异：kcp 把流量写成 SOCKS5-over-KCP 帧；本类改为调用
 * {@code TunnelEngine.open(OpenTarget, OpenCallback)}（FCP OPEN 的编解码在
 * 引擎内部完成），路由器只负责字节搬运、虚拟 TCP 状态机与连接表。</p>
 *
 * <p>豁免策略（照搬 kcp 的 Builder/router 配套策略）：</p>
 * <ul>
 *   <li>DNS（UDP 53）：不经隧道，本地用受保护 socket 直接向上游解析器中继；</li>
 *   <li>其余 UDP：丢弃（kcp 同策略）；</li>
 *   <li>局域网 TCP：豁免直连——用受保护 socket 直接连目标并在两侧搬运
 *       （VPN 开启后局域网设备仍可达：路由器/NAS/打印机等）；</li>
 *   <li>局域网 UDP：丢弃。</li>
 * </ul>
 */
public class PacketRouter {
    private static final String TAG_MODULE = LogConfig.MODULE_VPN;

    private static final long ESTABLISHED_IDLE_TIMEOUT_MS = 3 * 60 * 1000L;
    // 半关闭排空上限：给对端在途数据留出足够的接收时间，再回收连接。
    private static final long CLOSING_IDLE_TIMEOUT_MS = 150 * 1000L;
    // server→app 方向的在途段重传。TUN 写丢失的段没有别的恢复途径（内核 TCP
    // 栈不会替我们重传我们发出的段）：应用对序号空洞回 dup-ACK，累计到阈值就
    // 快速重传最早的未确认段；尾部段丢失收不到 dup-ACK，由清理线程按停滞超时
    // 兜底重传。两者都依赖保留在途段负载。
    private static final int DUP_ACK_RETRANSMIT_THRESHOLD = 3;
    private static final long RETRANSMIT_STALL_MS = 3000;
    // 连续多次兜底重传仍无任何 ACK 进展：连接不可恢复（对端内核彻底静默），
    // 放弃重传并回 RST，避免每 3s 无限重发。
    private static final int MAX_STALL_RETRANSMITS = 10;
    // 单连接滞留的未确认负载上限：应用长时间不 ACK（接收缓冲不再 drain 或进程
    // 已死）时，超过即判定连接不可恢复，回 RST 明确失败，而不是无界吃内存。
    private static final int MAX_UNACKED_RETAINED_BYTES = 256 * 1024;
    // 隧道流/LAN 连接尚未就绪时，应用方向数据的缓冲上限；超过即 RST 失败。
    private static final int MAX_OUTBOUND_BUFFERED_BYTES = 256 * 1024;
    private static final int TCP_IPV4_HEADER_LEN = 40;
    private static final int IPV4_HEADER_LEN = 20;
    private static final int IPV6_HEADER_LEN = 40;
    private static final int IPV6_ADDR_LEN = 16;
    private static final int TCP_HEADER_LEN = 20;
    private static final int UDP_TRACE_SAMPLE_RATE = 64;
    private static final int LAN_CONNECT_TIMEOUT_MS = 5000;
    private static final int DNS_RELAY_TIMEOUT_MS = 5000;
    // 隧道内 TCP DNS：服务端监听 53/tcp 做 UDP->DNS 转发（受限网络里本地公共解析器不通时的回退）。
    private static final int DNS_TUNNEL_PORT = 53;
    private static final int DNS_TUNNEL_TIMEOUT_MS = 6000;
    private static final int DNS_RELAY_THREADS = 4;
    private static final int DNS_RELAY_QUEUE_CAPACITY = 64;

    private final TunnelManager tunnelManager;
    private final int tunMtu;

    private final Map<String, TcpConnection> connectionsByKey = new ConcurrentHashMap<>();
    private final Map<Long, TcpConnection> connectionsById = new ConcurrentHashMap<>();
    private final AtomicLong nextConnectionId = new AtomicLong(System.currentTimeMillis());
    private final AtomicLong nextTcpSequence = new AtomicLong(System.nanoTime());
    private final AtomicLong udpTraceCounter = new AtomicLong(0);
    private volatile boolean running;
    // 连接注册与 stop 清表必须互斥：否则 running 检查后仍可能把新连接插回已停表。
    private final Object lifecycleLock = new Object();
    private volatile SocketProtector socketProtector;
    // DNS 中继线程池：固定小池 + 有界队列。队列满时丢弃最新查询，绝不在 TUN
    // 读取线程里等待 DNS；shutdownNow 会清空排队任务并中断正在执行的任务。
    private volatile ExecutorService dnsRelayExecutor;
    private final AtomicLong dnsRelayRejections = new AtomicLong();
    // 本地 UDP fallback 的在途 socket：stop 不能只靠 shutdownNow，receive 还需要显式关闭。
    private final java.util.Set<DatagramSocket> inFlightDnsSockets = ConcurrentHashMap.newKeySet();
    // DNS 应答缓存：key = "name|qtype"（小写），TTL 取自应答报文并钳位。
    private final java.util.concurrent.ConcurrentHashMap<String, DnsCacheEntry> dnsCache =
            new java.util.concurrent.ConcurrentHashMap<>();
    private static final int DNS_CACHE_MAX_ENTRIES = 512;
    private static final int DNS_CACHE_MIN_TTL_S = 30;     // 太短的 TTL 不值得缓存
    private static final int DNS_CACHE_MAX_TTL_S = 3600;   // 上限 1 小时
    private static final int DNS_CACHE_NEGATIVE_TTL_S = 15; // 负应答（无记录/错误）短缓存
    // 已告警过的 UDP 目的端口：非 DNS 的 UDP 一律丢弃，每个端口只告警一次。
    private final java.util.Set<Integer> warnedUdpPorts = ConcurrentHashMap.newKeySet();
    // 已被就地空应答过的 AAAA 域名：只为前 64 个域名打日志，避免刷屏。
    private final java.util.Set<String> loggedAaaaNames = ConcurrentHashMap.newKeySet();
    // IPv6 拒绝：限流 + 已告警过的目的地址（每个地址只告警一次，且设上限）。
    // 上限取得够宽：一个页面同时开几十条 IPv6 连接是常态，限得太死会让后一半
    // 连接拿不到 ICMPv6、退化成干等超时。
    private static final int IPV6_REJECT_MAX_PER_SEC = 200;
    /** TUN 的本地 IPv6 地址：ICMPv6 拒绝报文按 RFC 4443 用它做源地址。 */
    private static final byte[] TUN_ADDR_V6 = parseIpv6Literal(VpnConfig.VPN_ADDRESS_V6);
    private final java.util.Set<String> warnedIpv6Targets = ConcurrentHashMap.newKeySet();
    private final AtomicLong ipv6RejectSecond = new AtomicLong(0);
    private final java.util.concurrent.atomic.AtomicInteger ipv6RejectCount =
            new java.util.concurrent.atomic.AtomicInteger(0);

    /** 解析 IPv6 字面量（只用于本地常量，不会走 DNS）。 */
    private static byte[] parseIpv6Literal(String literal) {
        try {
            return java.net.InetAddress.getByName(literal).getAddress();
        } catch (java.net.UnknownHostException e) {
            return new byte[IPV6_ADDR_LEN];
        }
    }
    private volatile Thread cleanupThread;

    public PacketRouter(TunnelManager tunnelManager) {
        this(tunnelManager, VpnConfig.VPN_MTU);
    }

    public PacketRouter(TunnelManager tunnelManager, int tunMtu) {
        this.tunnelManager = tunnelManager;
        this.tunMtu = tunMtu;
    }

    public void setSocketProtector(SocketProtector protector) {
        this.socketProtector = protector;
    }

    public void start() {
        synchronized (lifecycleLock) {
            if (running) {
                return;
            }
            running = true;
            dnsRelayExecutor = new ThreadPoolExecutor(
                    DNS_RELAY_THREADS, DNS_RELAY_THREADS, 0L, TimeUnit.MILLISECONDS,
                    new ArrayBlockingQueue<>(DNS_RELAY_QUEUE_CAPACITY),
                    r -> {
                        Thread t = new Thread(r, "Fcp-DNS-Relay");
                        t.setDaemon(true);
                        return t;
                    },
                    (task, executor) -> {
                        // 有界队列的明确丢弃策略：不让 execute() 阻塞 TUN 读取线程。
                        // 限流日志，避免恶意 DNS 洪泛把 logcat 也打满。
                        long rejected = dnsRelayRejections.incrementAndGet();
                        if (rejected == 1 || rejected % 64 == 0) {
                            Logger.warning(TAG_MODULE, "DNS relay queue full; dropped query #"
                                    + rejected + ", capacity=" + DNS_RELAY_QUEUE_CAPACITY);
                        }
                    });
            startCleanupThread();
        }
        Logger.info(TAG_MODULE, "PacketRouter started tunMtu=" + tunMtu
                + ", socketProtectorSet=" + (socketProtector != null));
    }

    /**
     * 幂等停止。这里绝不能 join 清理线程：TUN 写入需要 FcpVpnService 的同一把锁，
     * 而 closeVpn 持锁调用 stop，等待清理线程完成写入会形成 ANR。
     */
    public void stop() {
        synchronized (lifecycleLock) {
            if (!running) {
                return;
            }
            running = false;
            Thread sweeper = cleanupThread;
            cleanupThread = null;
            if (sweeper != null) {
                sweeper.interrupt();
            }

            dnsCache.clear();
            ExecutorService relay = dnsRelayExecutor;
            dnsRelayExecutor = null;
            if (relay != null) {
                relay.shutdownNow();
            }
            for (DatagramSocket socket : inFlightDnsSockets) {
                socket.close();
            }
            inFlightDnsSockets.clear();

            for (TcpConnection conn : connectionsById.values()) {
                conn.close();
            }
            connectionsByKey.clear();
            connectionsById.clear();
        }
        Logger.info(TAG_MODULE, "PacketRouter stopped");
    }

    /** 当前活跃的虚拟 TCP 连接数（供通知/主页的"会话"统计）。 */
    public int getActiveConnectionCount() {
        return connectionsById.size();
    }

    // ================================================================ 出站

    /**
     * 处理 TUN 读出的一个出站 IP 包。onWritePacket 用于把合成的响应包
     * （SYN-ACK/ACK/RST/FIN/数据）写回 TUN。
     */
    public void handleOutboundPacket(byte[] packet, WritePacketCallback writePacketCallback) {
        if (!running || packet == null || packet.length < 20) {
            return;
        }

        try {
            ByteBuffer buf = ByteBuffer.wrap(packet).order(ByteOrder.BIG_ENDIAN);
            int version = (buf.get(0) >> 4) & 0x0F;

            int ipHeaderLen;
            int totalLen;
            int protocol;
            byte[] srcAddr;
            byte[] dstAddr;

            if (version == 4) {
                ipHeaderLen = (buf.get(0) & 0x0F) * 4;
                if (ipHeaderLen < IPV4_HEADER_LEN || packet.length < ipHeaderLen + 8) {
                    return;
                }

                totalLen = buf.getShort(2) & 0xFFFF;
                if (totalLen < ipHeaderLen) {
                    return;
                }
                if (totalLen > packet.length) {
                    totalLen = packet.length;
                }

                int flagsAndFragment = buf.getShort(6) & 0xFFFF;
                if ((flagsAndFragment & 0x2000) != 0 || ((flagsAndFragment & 0x1FFF) << 3) != 0) {
                    Logger.debug(TAG_MODULE, "Ignoring fragmented IP packet");
                    return;
                }

                srcAddr = Arrays.copyOfRange(packet, 12, 16);
                dstAddr = Arrays.copyOfRange(packet, 16, 20);
                protocol = buf.get(9) & 0xFF;
            } else if (version == 6) {
                if (packet.length < IPV6_HEADER_LEN + 8) {
                    return;
                }

                // 本隧道只有 IPv4 通路：所有 IPv6 出站一律就地快速失败。
                // 必须把 IPv6 收进 TUN 才能拒——不通告 ::/0 的话，应用的 IPv6
                // 流量会绕过隧道从物理网卡直出（见 rejectIpv6 的说明）。
                // 拒绝放在扩展头检查之前：带扩展头（分片头等）的报文同样要回
                // ICMPv6，否则应用只能干等超时——而那正是这次改动要消除的现象。
                int payloadLength = buf.getShort(4) & 0xFFFF;
                int totalLen6 = payloadLength + IPV6_HEADER_LEN;
                if (totalLen6 > packet.length) {
                    totalLen6 = packet.length;
                }
                rejectIpv6(packet,
                        Arrays.copyOfRange(packet, 8, 24),
                        Arrays.copyOfRange(packet, 24, 40),
                        totalLen6, writePacketCallback);
                return;
            } else {
                return;
            }

            Logger.debug(TAG_MODULE, "PacketRouter parse protocol=" + protocol
                    + " src=" + addressToString(srcAddr)
                    + " dst=" + addressToString(dstAddr)
                    + " len=" + totalLen);
            if (protocol == 6) {
                handleOutboundTcp(packet, buf, ipHeaderLen, totalLen, srcAddr, dstAddr,
                        writePacketCallback);
            } else if (protocol == 17) {
                handleOutboundUdp(packet, buf, ipHeaderLen, totalLen, srcAddr, dstAddr,
                        writePacketCallback);
            } else {
                Logger.debug(TAG_MODULE, "Ignoring non-TCP/UDP packet: protocol=" + protocol);
            }
        } catch (Exception e) {
            Logger.error(TAG_MODULE, "Handle outbound error: " + e.getMessage());
        }
    }

    private void handleOutboundTcp(byte[] packet, ByteBuffer buf, int ipHeaderLen, int totalLen,
                                   byte[] srcAddr, byte[] dstAddr,
                                   WritePacketCallback writePacketCallback) {
        int tcpOffset = ipHeaderLen;
        if (totalLen < tcpOffset + 20) {
            return;
        }

        int srcPort = buf.getShort(tcpOffset) & 0xFFFF;
        int dstPort = buf.getShort(tcpOffset + 2) & 0xFFFF;
        int clientSeq = buf.getInt(tcpOffset + 4);
        int clientAck = buf.getInt(tcpOffset + 8);
        int tcpHeaderLen = ((buf.get(tcpOffset + 12) >> 4) & 0x0F) * 4;
        int flags = buf.get(tcpOffset + 13) & 0xFF;
        // 应用通告的接收窗口（相对其 ack）：这是我们对应用方向的唯一流控信号。
        // 窗口耗尽即暂停转发（见 acceptOutboundSegment）。
        int peerWindow = buf.getShort(tcpOffset + 14) & 0xFFFF;
        int payloadOffset = tcpOffset + tcpHeaderLen;
        int payloadLen = totalLen - payloadOffset;
        if (tcpHeaderLen < 20 || payloadLen < 0) {
            return;
        }

        boolean isSyn = (flags & 0x02) != 0;
        boolean isAck = (flags & 0x10) != 0;
        boolean isRst = (flags & 0x04) != 0;
        boolean isFin = (flags & 0x01) != 0;

        logTcpIn(srcAddr, srcPort, dstAddr, dstPort, flags, clientSeq, clientAck, payloadLen);

        String key = connectionKey(srcAddr, srcPort, dstAddr, dstPort);
        TcpConnection conn = connectionsByKey.get(key);
        if (conn == null) {
            if (!isSyn || isAck) {
                Logger.info(TAG_MODULE, "drop unknown non-SYN packet: src="
                        + addressToString(srcAddr) + ":" + srcPort
                        + ", dst=" + addressToString(dstAddr) + ":" + dstPort
                        + ", flags=" + flags + ", payloadLength=" + payloadLen);
                return;
            }
            conn = createConnection(key, srcAddr, srcPort, dstAddr, dstPort, clientSeq,
                    writePacketCallback);
            if (conn == null) {
                return;
            }
        }

        if (!running || conn.closed) {
            return;
        }

        if (isSyn && !isAck) {
            synchronized (conn) {
                conn.clientNextSeq = clientSeq + 1;
                // 窗口基准必须锚在我们自己的序列空间：应用期望我们的第一个数据
                // 字节落在 serverInitialSeq+1。锚到 clientSeq+1（对端 ISN+1，另一个
                // 方向的序列空间）时，错误基准会毒化窗口数学（kcp 版踩过的坑）。
                conn.setSendWindow(conn.serverInitialSeq + 1, peerWindow);
                byte[] synAck = buildTcpPacket(conn, new byte[0], (byte) 0x12,
                        conn.serverInitialSeq, conn.clientNextSeq);
                writePacketCallback.onWritePacket(synAck);
                logTcpOut(conn, 0x12, conn.serverInitialSeq, conn.clientNextSeq, 0);
                if (!conn.synAckSent) {
                    conn.serverNextSeq = conn.serverInitialSeq + 1;
                    conn.synAckSent = true;
                }
                conn.state = TcpState.SYN_RECEIVED;
                conn.touch();
            }
            Logger.debug(TAG_MODULE, "TCP SYN-ACK: connectionId=" + conn.connectionId
                    + ", src=" + conn.dstHost + ":" + conn.dstPort
                    + ", dst=" + conn.srcHost + ":" + conn.srcPort + ", payloadLength=0");
            return;
        }

        if (isAck) {
            UnackedSegment retransmit = null;
            boolean sendPendingFin = false;
            synchronized (conn) {
                conn.lastAckFromClient = clientAck;
                // 窗口随每个应用报文按 RFC 793 规则刷新；窗口重新打开时要先
                // 冲刷滞留段，dup-ACK/快速重传逻辑才能看到完整的在途队列。
                conn.updateSendWindow(clientAck, peerWindow);
                if (conn.state == TcpState.SYN_RECEIVED) {
                    conn.state = TcpState.ESTABLISHED;
                }
                int removed = conn.removeAckedServerSegments(clientAck);
                flushPendingSegments(conn, writePacketCallback);
                if (conn.serverFinPending && !conn.hasPendingSegments()) {
                    sendPendingFin = true;
                }
                if (removed > 0 || !conn.hasUnackedServerData()) {
                    conn.resetDupAcks();
                } else if (conn.tickDupAck()) {
                    UnackedSegment first = conn.peekFirstUnacked();
                    // 段已超出应用当前窗口时不白白重发（内核仍会丢弃）。
                    if (first != null && conn.fitsInSendWindow(first.seq, first.length)) {
                        retransmit = first;
                        conn.markRetransmitted();
                    }
                }
                conn.touch();
            }
            if (retransmit != null) {
                byte[] retransmitPacket;
                int ack;
                synchronized (conn) {
                    ack = conn.clientNextSeq;
                    retransmitPacket = buildTcpPacket(conn, retransmit.payload, (byte) 0x18,
                            retransmit.seq, ack);
                }
                writePacketCallback.onWritePacket(retransmitPacket);
                logTcpOut(conn, 0x18, retransmit.seq, ack, retransmit.length);
                Logger.info(TAG_MODULE, "Fast retransmit: connectionId=" + conn.connectionId
                        + ", seq=" + (retransmit.seq & 0xFFFFFFFFL)
                        + ", len=" + retransmit.length);
            }
            if (sendPendingFin) {
                sendFinToApp(conn);
            }
        }

        if (isRst) {
            sendCloseToOutbound(conn, true);
            byte[] rstPacket = buildTcpPacket(conn, new byte[0], (byte) 0x14,
                    conn.serverNextSeq, clientSeq + 1);
            writePacketCallback.onWritePacket(rstPacket);
            logTcpOut(conn, 0x14, conn.serverNextSeq, clientSeq + 1, 0);
            removeConnection(conn);
            Logger.info(TAG_MODULE, "RESET frame: connectionId=" + conn.connectionId
                    + ", src=" + conn.srcHost + ":" + conn.srcPort
                    + ", dst=" + conn.dstHost + ":" + conn.dstPort + ", payloadLength=0");
            return;
        }

        if (payloadLen > 0) {
            byte[] payload = new byte[payloadLen];
            System.arraycopy(packet, payloadOffset, payload, 0, payloadLen);
            byte[] newPayload = null;
            synchronized (conn) {
                if (seqBefore(clientSeq, conn.clientNextSeq)) {
                    // 只丢已确认前缀；部分重叠的新后缀仍必须转发。int 减法保留
                    // 低 32 位，因此跨 wrap 的重传前缀长度同样正确。
                    int duplicateBytes = conn.clientNextSeq - clientSeq;
                    if (duplicateBytes < payloadLen) {
                        newPayload = Arrays.copyOfRange(payload, duplicateBytes, payloadLen);
                        conn.clientNextSeq += newPayload.length;
                        conn.touch();
                    } else {
                        Logger.debug(TAG_MODULE, "Ignoring duplicate TCP payload: connectionId="
                                + conn.connectionId + ", seq=" + clientSeq
                                + ", expected=" + conn.clientNextSeq);
                    }
                } else if (clientSeq != conn.clientNextSeq) {
                    Logger.warning(TAG_MODULE, "Dropping out-of-order TCP payload: connectionId="
                            + conn.connectionId + ", seq=" + clientSeq
                            + ", expected=" + conn.clientNextSeq + ", payloadLength=" + payloadLen);
                } else {
                    newPayload = payload;
                    conn.clientNextSeq += payloadLen;
                    conn.touch();
                }
            }

            if (newPayload != null) {
                sendOutboundTcpData(conn, newPayload);
            }
            int dataAckSeq;
            int dataAck;
            synchronized (conn) {
                dataAckSeq = conn.serverNextSeq;
                dataAck = conn.clientNextSeq;
            }
            // 重传与乱序包都回当前 next，促使对端重传缺口并推进窗口。
            byte[] ackPacket = buildTcpPacket(conn, new byte[0], (byte) 0x10,
                    dataAckSeq, dataAck);
            writePacketCallback.onWritePacket(ackPacket);
            logTcpOut(conn, 0x10, dataAckSeq, dataAck, 0);
            Logger.debug(TAG_MODULE, "DATA frame: connectionId=" + conn.connectionId
                    + ", src=" + conn.srcHost + ":" + conn.srcPort
                    + ", dst=" + conn.dstHost + ":" + conn.dstPort
                    + ", payloadLength=" + (newPayload == null ? 0 : newPayload.length));
        }

        if (isFin) {
            boolean firstFin = false;
            boolean finAccepted = false;
            synchronized (conn) {
                // FIN 只有落在当前 next 才能消费；有缺口或重复 FIN 都不能推进序号。
                int finSeq = clientSeq + payloadLen;
                if (finSeq == conn.clientNextSeq) {
                    finAccepted = true;
                    firstFin = !conn.clientFinSeen;
                    conn.clientFinSeen = true;
                    conn.clientNextSeq = finSeq + 1;
                    conn.state = TcpState.CLOSING;
                    conn.touch();
                }
            }
            if (finAccepted && firstFin) {
                // 应用半关闭：隧道侧 closeWrite（发完已排队数据后发 FIN），保留
                // 连接继续接收对端在途数据（StreamHandle 半关闭语义）。
                sendCloseToOutbound(conn, false);
                Logger.info(TAG_MODULE, "CLOSE frame: connectionId=" + conn.connectionId
                        + ", src=" + conn.srcHost + ":" + conn.srcPort
                        + ", dst=" + conn.dstHost + ":" + conn.dstPort + ", payloadLength=0");
            }
            // 本地 FIN（含缺口/重复 FIN）只回当前 ACK，不越过空洞。
            int finAckSeq;
            int finAckAck;
            synchronized (conn) {
                finAckSeq = conn.serverNextSeq;
                finAckAck = conn.clientNextSeq;
            }
            byte[] ackPacket = buildTcpPacket(conn, new byte[0], (byte) 0x10, finAckSeq, finAckAck);
            writePacketCallback.onWritePacket(ackPacket);
            logTcpOut(conn, 0x10, finAckSeq, finAckAck, 0);
            if (finAccepted && conn.serverFinSeen) {
                removeConnection(conn);
            }
        }
    }

    private TcpConnection createConnection(String key, byte[] srcAddr, int srcPort,
                                           byte[] dstAddr, int dstPort, int clientSeq,
                                           WritePacketCallback writePacketCallback) {
        TcpConnection conn = new TcpConnection(nextConnectionId.incrementAndGet(), key, srcAddr,
                srcPort, dstAddr, dstPort, (int) nextTcpSequence.addAndGet(0x10000L),
                writePacketCallback);
        conn.clientNextSeq = clientSeq + 1;
        synchronized (lifecycleLock) {
            if (!running) {
                return null;
            }
            connectionsByKey.put(key, conn);
            connectionsById.put(conn.connectionId, conn);
            if (dstAddr.length == 4 && isLanAddress(dstAddr)) {
                // 局域网豁免：不经隧道，用受保护 socket 直连目标并双向搬运。
                Logger.info(TAG_MODULE, "TCP SYN connectionId=" + conn.connectionId
                        + " mode=LAN_DIRECT dst=" + conn.dstHost + ":" + conn.dstPort);
                startLanRelay(conn);
            } else {
                Logger.info(TAG_MODULE, "TCP SYN connectionId=" + conn.connectionId
                        + " mode=TUNNEL dst=" + conn.dstHost + ":" + conn.dstPort);
                startTunnelOpen(conn);
            }
        }
        return conn;
    }

    /** 通过 TunnelEngine.open 建立隧道流（FCP OPEN 的编解码在引擎内部完成）。 */
    private void startTunnelOpen(TcpConnection conn) {
        byte[] addr4 = conn.dstAddr.length == 4 ? conn.dstAddr : fallbackIpv4();
        tunnelManager.open(OpenTarget.ipv4(addr4, conn.dstPort), new OpenCallback() {
            @Override
            public void onOpened(StreamHandle stream) {
                attachTunnelStream(conn, stream);
            }

            @Override
            public void onFailed(int code, String message) {
                Logger.warning(TAG_MODULE, "OPEN failed connectionId=" + conn.connectionId
                        + " code=" + code + " msg=" + message);
                if (conn.closed) {
                    return;
                }
                abortConnection(conn, "open_failed_" + code);
            }
        });
    }

    /** IPv6 目标当前不建隧道（Builder 未通告 ::/0），理论上到不了这里；兜底 0.0.0.0。 */
    private static byte[] fallbackIpv4() {
        return new byte[]{0, 0, 0, 0};
    }

    /** 引擎流就绪：挂 listener，把建流期间缓冲的应用数据灌入隧道。 */
    private void attachTunnelStream(TcpConnection conn, StreamHandle stream) {
        boolean attached;
        synchronized (conn) {
            attached = !conn.closed;
            if (attached) {
                conn.tunnelStream = stream;
                conn.sink = new TunnelSink(stream, conn);
            }
        }
        if (!attached) {
            stream.abort();
            return;
        }
        stream.setListener(new StreamHandle.Listener() {
            @Override
            public void onData(byte[] data, int offset, int len) {
                try {
                    ingestServerData(conn, data, offset, len);
                } finally {
                    // 已处理完本批数据，推进对端发送窗口（背压契约）。
                    stream.consumed(len);
                }
            }

            @Override
            public void onFin() {
                sendFinToApp(conn);
            }

            @Override
            public void onReset(int code) {
                Logger.info(TAG_MODULE, "Stream reset connectionId=" + conn.connectionId
                        + " code=" + code);
                sendRstToApp(conn);
                removeConnection(conn);
            }
        });

        byte[][] buffered;
        boolean doCloseWrite;
        boolean doAbort;
        synchronized (conn) {
            if (conn.closed) {
                return;
            }
            buffered = conn.drainOutboundBuffer();
            doCloseWrite = conn.pendingCloseWrite;
            conn.pendingCloseWrite = false;
            doAbort = conn.pendingAbort;
            conn.pendingAbort = false;
            if (doCloseWrite) {
                conn.state = TcpState.CLOSING;
            }
            conn.touch();
        }
        if (doAbort) {
            // 建流期间应用已 RST：立即中止刚建立的流。
            conn.abortTunnelStream();
            sendRstToApp(conn);
            return;
        }
        for (byte[] chunk : buffered) {
            stream.write(chunk, 0, chunk.length);
        }
        if (doCloseWrite) {
            stream.closeWrite();
        }
        Logger.info(TAG_MODULE, "Stream opened connectionId=" + conn.connectionId
                + " dst=" + conn.dstHost + ":" + conn.dstPort
                + " flushed=" + buffered.length + " chunks");
    }

    // ================================================================ LAN 直连

    /**
     * 局域网 TCP 豁免直连：受保护 socket 连目标，泵线程把 socket→应用方向搬运；
     * 应用→socket 方向走 LanSink。连接失败向应用回 RST。
     */
    private void startLanRelay(TcpConnection conn) {
        Thread connector = new Thread(() -> {
            Socket socket = new Socket();
            try {
                // 在 connect 前登记，stop/removeConnection 才能关闭正在连接的 socket。
                if (!conn.registerLanSocket(socket)) {
                    closeQuietly(socket);
                    return;
                }
                SocketProtector protector = socketProtector;
                if (protector != null) {
                    // 先 protect 再 connect：VPN 进程内新建的 socket 默认走 TUN。
                    protector.protect(socket);
                    try {
                        protector.bindToNetwork(socket);
                    } catch (IOException e) {
                        Logger.warning(TAG_MODULE, "LAN bindToNetwork failed: " + e.getMessage());
                    }
                }
                socket.connect(new InetSocketAddress(
                        InetAddress.getByAddress(conn.dstAddr), conn.dstPort),
                        LAN_CONNECT_TIMEOUT_MS);
                socket.setTcpNoDelay(true);
                if (conn.closed || !conn.attachLanSink(socket)) {
                    return;
                }
                Logger.info(TAG_MODULE, "LAN relay connected connectionId=" + conn.connectionId
                        + " dst=" + conn.dstHost + ":" + conn.dstPort);

                byte[][] buffered;
                boolean doCloseWrite;
                boolean doAbort;
                synchronized (conn) {
                    if (conn.closed) {
                        return;
                    }
                    buffered = conn.drainOutboundBuffer();
                    doCloseWrite = conn.pendingCloseWrite;
                    conn.pendingCloseWrite = false;
                    doAbort = conn.pendingAbort;
                    conn.pendingAbort = false;
                    if (doCloseWrite) {
                        conn.state = TcpState.CLOSING;
                    }
                    conn.touch();
                }
                if (doAbort) {
                    // 建连期间应用已 RST：sendRstToApp 会经 removeConnection 统一关 socket。
                    sendRstToApp(conn);
                    return;
                }
                OutputStream out = socket.getOutputStream();
                for (byte[] chunk : buffered) {
                    out.write(chunk);
                }
                out.flush();
                if (doCloseWrite) {
                    try {
                        socket.shutdownOutput();
                    } catch (IOException ignored) {
                        // socket 已异常关闭
                    }
                }
                pumpLanToApp(conn, socket);
            } catch (Exception e) {
                Logger.warning(TAG_MODULE, "LAN relay failed connectionId=" + conn.connectionId
                        + " dst=" + conn.dstHost + ":" + conn.dstPort + " error=" + e.getMessage());
                if (!conn.closed) {
                    abortConnection(conn, "lan_connect_failed");
                }
            } finally {
                conn.finishLanConnector(Thread.currentThread());
            }
        }, "Fcp-Lan-Connect-" + conn.connectionId);
        connector.setDaemon(true);
        if (conn.registerLanConnector(connector)) {
            connector.start();
        }
    }

    /** socket→应用方向的常驻泵：读到 EOF 视为对端 FIN，异常视为 RST。 */
    private void pumpLanToApp(TcpConnection conn, Socket socket) {
        Thread pump = new Thread(() -> {
            byte[] buf = new byte[Math.max(tunMtu, 2048)];
            try {
                InputStream in = socket.getInputStream();
                while (running && !conn.closed) {
                    int n = in.read(buf);
                    if (n < 0) {
                        sendFinToApp(conn);
                        return;
                    }
                    if (n > 0) {
                        ingestServerData(conn, buf, 0, n);
                    }
                }
            } catch (IOException e) {
                if (running && !conn.closed) {
                    Logger.info(TAG_MODULE, "LAN relay read error connectionId="
                            + conn.connectionId + ": " + e.getMessage());
                    sendRstToApp(conn);
                }
            } finally {
                // socket 由 TcpConnection.close 统一关闭；这里只释放线程引用。
                conn.finishLanPump(Thread.currentThread());
            }
        }, "Fcp-Lan-Pump-" + conn.connectionId);
        pump.setDaemon(true);
        if (conn.registerLanPump(pump)) {
            pump.start();
        }
    }

    // ================================================================ 出站数据通路

    /** 应用方向数据：sink 就绪直接写，否则缓冲（建流/建连进行中）。 */
    private void sendOutboundTcpData(TcpConnection conn, byte[] payload) {
        OutboundSink sink = conn.sink;
        if (sink != null) {
            try {
                sink.write(payload, 0, payload.length);
            } catch (IOException e) {
                Logger.warning(TAG_MODULE, "sink write failed connectionId="
                        + conn.connectionId + ": " + e.getMessage());
                sendRstToApp(conn);
                removeConnection(conn);
            }
            return;
        }
        if (!conn.bufferOutbound(payload)) {
            // 建流迟迟不完成且缓冲爆掉：明确失败而不是无限积压。
            abortConnection(conn, "outbound_buffer_overflow");
        }
    }

    /** 隧道/LAN 侧的关闭语义：reset=true 走 RST（abort），否则半关闭（FIN）。 */
    private void sendCloseToOutbound(TcpConnection conn, boolean reset) {
        OutboundSink sink = conn.sink;
        if (sink != null) {
            try {
                if (reset) {
                    sink.abort();
                } else {
                    sink.closeWrite();
                }
            } catch (IOException e) {
                Logger.warning(TAG_MODULE, "sink close failed connectionId="
                        + conn.connectionId + ": " + e.getMessage());
            }
            return;
        }
        synchronized (conn) {
            if (reset) {
                conn.pendingAbort = true;
            } else {
                conn.pendingCloseWrite = true;
            }
        }
    }

    /**
     * 把隧道/LAN 侧数据写入 TUN（server→app）：按 MTU 切段、窗口装不下滞留
     * pending、滞留超限回 RST（kcp handleInboundFrame TYPE_DATA 的同款逻辑）。
     */
    private void ingestServerData(TcpConnection conn, byte[] data, int offset, int len) {
        if (!running || conn.closed || len <= 0) {
            return;
        }
        WritePacketCallback writePacketCallback = conn.writePacketCallback;
        try {
            boolean unackedOverflow = false;
            synchronized (conn) {
                int pos = offset;
                int remaining = len;
                while (remaining > 0) {
                    int segmentLen = Math.min(maxTcpPayload(conn), remaining);
                    byte[] segment = Arrays.copyOfRange(data, pos, pos + segmentLen);
                    int seq = conn.serverNextSeq;
                    // 窗口内 → 立即写 TUN；窗口耗尽 → 滞留 pending 等待窗口
                    // 重新打开（由应用报文触发的 flushPendingSegments 送出）。
                    SegmentOutcome outcome = conn.acceptOutboundSegment(seq, segment);
                    if (outcome == SegmentOutcome.OVERFLOW) {
                        unackedOverflow = true;
                        break;
                    }
                    if (outcome == SegmentOutcome.SEND_NOW) {
                        byte[] ipPacket = buildTcpPacket(conn, segment, (byte) 0x18,
                                seq, conn.clientNextSeq);
                        writePacketCallback.onWritePacket(ipPacket);
                        logTcpOut(conn, 0x18, seq, conn.clientNextSeq, segmentLen);
                    }
                    conn.serverNextSeq += segmentLen;
                    pos += segmentLen;
                    remaining -= segmentLen;
                }
                if (!unackedOverflow) {
                    conn.touch();
                }
            }
            if (unackedOverflow) {
                // 应用长时间不 ACK：继续转发只会无界吃内存。明确失败（回 RST），
                // 而不是丢段造成应用侧静默的流损坏。
                abortConnection(conn, "unacked_overflow");
            }
        } catch (Exception e) {
            Logger.error(TAG_MODULE, "TUN_WRITE_FAILED connectionId="
                    + conn.connectionId + " error=" + e.getMessage());
        }
    }

    /** 对端半关闭（收到 FIN / LAN 读到 EOF）：向应用回 FIN，保留连接等应用收尾。 */
    private void sendFinToApp(TcpConnection conn) {
        if (conn.closed || !running) {
            return;
        }
        WritePacketCallback writePacketCallback = conn.writePacketCallback;
        byte[] finPacket;
        int seq;
        int ack;
        boolean bothDone;
        synchronized (conn) {
            if (conn.serverFinSeen) {
                return;
            }
            // 先冲刷窗口允许的 pending；仍有空洞时只记住远端 FIN，等 ACK/窗口
            // 或清理线程的超时重传继续推进，绝不能直接用 serverNextSeq 越过数据。
            conn.serverFinPending = true;
            flushPendingSegments(conn, writePacketCallback);
            if (conn.hasPendingSegments()) {
                return;
            }
            seq = conn.serverNextSeq;
            ack = conn.clientNextSeq;
            finPacket = buildTcpPacket(conn, new byte[0], (byte) 0x11, seq, ack);
            conn.serverNextSeq += 1;
            conn.serverFinSeen = true;
            conn.serverFinPending = false;
            conn.state = TcpState.CLOSING;
            conn.touch();
            bothDone = conn.clientFinSeen;
        }
        if (!running || conn.closed) {
            return;
        }
        try {
            writePacketCallback.onWritePacket(finPacket);
            logTcpOut(conn, 0x11, seq, ack, 0);
        } catch (Exception e) {
            Logger.error(TAG_MODULE, "FIN write failed connectionId="
                    + conn.connectionId + ": " + e.getMessage());
        }
        if (bothDone) {
            removeConnection(conn);
        }
    }

    /** 对端/本端异常中止：向应用回 RST 并摘除连接。 */
    private void sendRstToApp(TcpConnection conn) {
        if (!running || conn.closed) {
            return;
        }
        WritePacketCallback writePacketCallback = conn.writePacketCallback;
        byte[] rst;
        synchronized (conn) {
            rst = buildTcpPacket(conn, new byte[0], (byte) 0x14,
                    conn.serverNextSeq, conn.clientNextSeq);
        }
        try {
            writePacketCallback.onWritePacket(rst);
            logTcpOut(conn, 0x14, conn.serverNextSeq, conn.clientNextSeq, 0);
        } catch (Exception e) {
            Logger.error(TAG_MODULE, "RST write failed connectionId="
                    + conn.connectionId + ": " + e.getMessage());
        }
        removeConnection(conn);
    }

    /**
     * 不可恢复时强制拆链：关隧道/LAN 侧、向应用回 RST、摘除本地映射。
     * 应用看到的是明确的连接重置（可以立即重试），而不是静默丢段导致的挂死。
     */
    private void abortConnection(TcpConnection conn, String reason) {
        if (!running || conn.closed) {
            return;
        }
        sendCloseToOutbound(conn, true);
        sendRstToApp(conn);
        Logger.info(TAG_MODULE, "ABORT connectionId=" + conn.connectionId + " reason=" + reason);
    }

    /**
     * 把滞留在 pending 的段按序送出：只要窗口装得下就从队首逐段转为在途并写
     * TUN。触发点是每个应用报文——窗口重新打开往往伴随一个不含新确认的
     * dup-ACK，所以必须在 dup-ACK 判定之前冲刷。
     */
    private void flushPendingSegments(TcpConnection conn, WritePacketCallback writePacketCallback) {
        while (running && !conn.closed && conn.hasPendingSegments()) {
            UnackedSegment seg = conn.peekFirstPending();
            if (!conn.fitsInSendWindow(seg.seq, seg.length)) {
                return;
            }
            conn.promoteFirstPending();
            byte[] packet = buildTcpPacket(conn, seg.payload, (byte) 0x18,
                    seg.seq, conn.clientNextSeq);
            writePacketCallback.onWritePacket(packet);
            logTcpOut(conn, 0x18, seg.seq, conn.clientNextSeq, seg.length);
        }
    }

    private void removeConnection(TcpConnection conn) {
        conn.close();
        // 旧连接的回调不能误删 stop/start 后同四元组的新连接。
        connectionsByKey.remove(conn.key, conn);
        connectionsById.remove(conn.connectionId, conn);
    }

    /** 该连接的 IP 族对应的单包最大 TCP 负载（保证 头 + TCP头 + 负载 ≤ MTU）。 */
    private int maxTcpPayload(TcpConnection conn) {
        return conn.dstAddr.length == IPV6_ADDR_LEN
                ? tunMtu - IPV6_HEADER_LEN - TCP_HEADER_LEN
                : tunMtu - TCP_IPV4_HEADER_LEN;
    }

    // ================================================================ IPv6 拒绝

    /**
     * 拒绝 IPv6 出站流量（本隧道只有 IPv4 通路）。
     *
     * <p>为什么非拒不可：Android 的 per-UID VPN 规则只把本接口通告过的地址族收进
     * TUN。如果接口只通告 0.0.0.0/0，应用的 IPv6 流量根本不会进 TUN，而是绕过
     * 隧道从物理网卡直出——这正是"按应用代理看起来没生效"的直接原因：应用拿到
     * AAAA（或走 DoH/DoT 拿到）就优先走 IPv6，那部分流量根本没进隧道。</p>
     *
     * <p>回 ICMPv6 Destination Unreachable 而不是静默丢弃：应用会立刻拿到
     * "连接失败"并回退到 IPv4（Happy Eyeballs），而不是干等 IPv6 超时。</p>
     */
    private void rejectIpv6(byte[] packet, byte[] srcAddr, byte[] dstAddr, int totalLen,
                            WritePacketCallback writePacketCallback) {
        // 组播（ff00::/8，mDNS/ND 之类）不回 ICMPv6 错误：RFC 4443 明确禁止，
        // 回了内核也只会丢掉。这类报文静默失败即可。
        if ((dstAddr[0] & 0xFF) == 0xFF) {
            return;
        }
        if (!allowIpv6Reject()) {
            return; // 限流：别被 IPv6 洪泛打爆
        }
        String dst = addressToString(dstAddr);
        // 只记前 64 个地址：IPv6 目的地址是无限的，不设上限就是个慢性内存泄漏。
        if (warnedIpv6Targets.size() < 64 && warnedIpv6Targets.add(dst)) {
            Logger.info(LogConfig.MODULE_VPN, "IPv6 rejected dst=" + dst
                    + "（本隧道只支持 IPv4，已回 ICMPv6 unreachable，应用会回退 IPv4）");
        }
        byte[] icmp = buildIcmpv6Unreachable(srcAddr, packet, totalLen);
        writePacketCallback.onWritePacket(icmp);
    }

    /** 每秒最多回多少个 ICMPv6 拒绝（避免 IPv6 洪泛把写队列打爆）。 */
    private boolean allowIpv6Reject() {
        long sec = System.currentTimeMillis() / 1000;
        if (ipv6RejectSecond.get() != sec) {
            ipv6RejectSecond.set(sec);
            ipv6RejectCount.set(0);
        }
        return ipv6RejectCount.incrementAndGet() <= IPV6_REJECT_MAX_PER_SEC;
    }

    /**
     * 构造 ICMPv6 Destination Unreachable（type=1, code=0），并带上被触发的
     * 原报文（内核靠它把错误匹配回对应的 socket）。
     *
     * <p>源地址用 TUN 自己的 IPv6 地址（RFC 4443：ICMPv6 错误的源必须是本机
     * 某个接口上的地址），目的地址是原包的源地址。</p>
     */
    private byte[] buildIcmpv6Unreachable(byte[] srcAddr, byte[] originalPacket, int originalLen) {
        // 尽量带上原报文，但别超过 MTU；至少要含 IPv6 头 + 8 字节传输层头。
        int include = Math.min(originalLen, tunMtu - IPV6_HEADER_LEN - 8);
        if (include < IPV6_HEADER_LEN + 8) {
            include = Math.min(originalLen, IPV6_HEADER_LEN + 8);
        }
        int icmpLen = 8 + include;
        byte[] packet = new byte[IPV6_HEADER_LEN + icmpLen];
        ByteBuffer buf = ByteBuffer.wrap(packet).order(ByteOrder.BIG_ENDIAN);
        // IPv6 头
        buf.putInt(0x60000000);            // version 6
        buf.putShort((short) icmpLen);     // payload length
        buf.put((byte) 58);                // next header = ICMPv6
        buf.put((byte) 64);                // hop limit
        buf.put(TUN_ADDR_V6);              // 源地址 = TUN 的本地 IPv6 地址
        buf.put(srcAddr);                  // 目的地址 = 原包的源地址
        // ICMPv6 头
        buf.put((byte) 1);                 // type = Destination Unreachable
        buf.put((byte) 0);                 // code = 0 (no route to destination)
        buf.putShort((short) 0);           // checksum（稍后回填）
        buf.putInt(0);                     // unused
        System.arraycopy(originalPacket, 0, packet, IPV6_HEADER_LEN + 8, include);
        // 校验和：IPv6 伪首部（源=TUN 地址，目的=原包源地址）+ ICMPv6 报文。
        // 注意 ICMPv6 没有 UDP 那条"算出 0 就写 0xFFFF"的规则，值 0 必须原样写出。
        int sum = protocolChecksum(packet, IPV6_HEADER_LEN, icmpLen, TUN_ADDR_V6, srcAddr, 58);
        putChecksum(packet, IPV6_HEADER_LEN + 2, sum);
        return packet;
    }

    // ================================================================ UDP
    private void handleOutboundUdp(byte[] packet, ByteBuffer buf, int ipHeaderLen, int totalLen,
                                   byte[] srcAddr, byte[] dstAddr,
                                   WritePacketCallback writePacketCallback) {
        int udpOffset = ipHeaderLen;
        if (totalLen < udpOffset + 8) {
            return;
        }
        // UDP 只处理 IPv4 的 DNS（53）：本地解析、不经隧道。其余 UDP（QUIC/mDNS）
        // 一律丢弃——与 kcp 的"仅中继 DNS"策略一致。DNS 不受影响：
        // Builder 里通告的解析器是 IPv4 的 1.1.1.1 / 8.8.8.8。
        // （IPv6 根本走不到这里：出站 IPv6 在解析阶段就被 rejectIpv6 拒掉了。）
        if (srcAddr.length != 4 || dstAddr.length != 4) {
            Logger.debug(TAG_MODULE, "Ignoring IPv6 UDP dst="
                    + addressToString(dstAddr) + ":" + (buf.getShort(udpOffset + 2) & 0xFFFF));
            return;
        }
        int srcPort = buf.getShort(udpOffset) & 0xFFFF;
        int dstPort = buf.getShort(udpOffset + 2) & 0xFFFF;
        int udpLen = buf.getShort(udpOffset + 4) & 0xFFFF;
        int payloadLen = udpLen - 8;
        if (payloadLen <= 0 || udpOffset + 8 + payloadLen > totalLen) {
            return;
        }
        logUdpTrace(() -> "UDP IN src=" + addressToString(srcAddr) + ":" + srcPort
                + " dst=" + addressToString(dstAddr) + ":" + dstPort
                + " len=" + payloadLen, srcPort, dstPort);
        byte[] udpPayload = new byte[payloadLen];
        System.arraycopy(packet, udpOffset + 8, udpPayload, 0, payloadLen);
        if (dstPort == 53) {
            // 本地解析 DNS（豁免）：受保护 socket 直连上游解析器，应答写回 TUN。
            relayDnsLocally(srcAddr, srcPort, dstAddr, dstPort, udpPayload, writePacketCallback);
        } else {
            // 非 DNS 的 UDP（含 QUIC/HTTP3 的 UDP 443）一律丢弃：每个端口只告警
            // 一次，避免刷屏——之前这里只打 DEBUG，release 包里完全看不到，
            // 用户只会觉得"应用没走代理"。
            if (warnedUdpPorts.add(dstPort)) {
                Logger.warning(TAG_MODULE, "Ignoring non-DNS UDP dst="
                        + addressToString(dstAddr) + ":" + dstPort
                        + "（QUIC/HTTP3 走不通，应用应回退到 TCP；本通道只支持 TCP）");
            }
            Logger.debug(TAG_MODULE, "Ignoring non-DNS UDP dst="
                    + addressToString(dstAddr) + ":" + dstPort + " len=" + payloadLen);
        }
    }

    /**
     * 本地 DNS 中继：优先查缓存，其次走隧道内的协议内 DNS（oob FCP_DNS1，
     * 由服务端用自己的 resolver 解析），最后本地 UDP 直连解析器。
     * 应答写回 TUN；成功解析的应答按报文 TTL 缓存（带上下限）。
     */
    private void relayDnsLocally(byte[] srcAddr, int srcPort, byte[] dstAddr, int dstPort,
                                 byte[] payload, WritePacketCallback writePacketCallback) {
        ExecutorService relay = dnsRelayExecutor;
        if (relay == null || relay.isShutdown() || !running) {
            return; // 路由器已停止
        }
        relay.execute(() -> {
            if (!running || relay.isShutdown()) {
                return;
            }
            // 0. AAAA 查询就地过滤（不进缓存、不出网）：本客户端只提供 IPv4 隧道。
            //    Android 的 per-UID VPN 规则只把 IPv4 收进 TUN——AAAA 一旦交给
            //    应用，应用就会优先走 IPv6，那部分流量从物理网卡直出、绕过隧道，
            //    真机上的表现正是"选了应用但流量没走代理"。这里用空应答
            //    （NOERROR + 0 条记录）告诉应用"该类型没有记录"，应用会立刻
            //    改用 A，而不是干等 IPv6 超时。
            DnsWire.Query query = DnsWire.parseQuery(payload);
            if (DnsWire.isIpv6Query(query)) {
                if (!running || relay.isShutdown()) {
                    return;
                }
                // 不写缓存：过滤在 dnsCacheLookup 之前，存进去的条目永远读不到，
                // 只会占满 512 条上限并把有用的 A 记录一起冲掉。
                byte[] nodata = DnsWire.buildNoData(query);
                byte[] udpPacketAaaa = buildUdpPacket(nodata, dstAddr, dstPort, srcAddr, srcPort);
                writePacketCallback.onWritePacket(udpPacketAaaa);
                if (loggedAaaaNames.size() < 64 && loggedAaaaNames.add(query.name)) {
                    Logger.info(TAG_MODULE, "DNS AAAA filtered name=" + query.name
                            + "（只提供 IPv4 隧道，AAAA 一律就地空应答）");
                }
                logUdpTrace(() -> "UDP OUT (DNS AAAA filtered) src="
                        + addressToString(dstAddr) + ":" + dstPort
                        + " len=" + nodata.length, dstPort, srcPort);
                return;
            }

            // 1. 缓存命中：直接回写，不产生任何网络往返。
            byte[] hit = dnsCacheLookup(payload);
            if (hit != null) {
                if (!running || relay.isShutdown()) {
                    return;
                }
                byte[] pkt = buildUdpPacket(hit, dstAddr, dstPort, srcAddr, srcPort);
                writePacketCallback.onWritePacket(pkt);
                logUdpTrace(() -> "UDP OUT (DNS cache hit) src="
                        + addressToString(dstAddr) + ":" + dstPort
                        + " len=" + hit.length, dstPort, srcPort);
                return;
            }

            // 2. 优先走协议内 DNS：oob FCP_DNS1 随隧道本身走，不占流、不开新端口，
            //    且由服务端解析——结果与 OPEN(domain) 路径完全一致。移动网络 /
            //    模拟器里本地公共解析器常被阻断，这条路径始终可用。
            TunnelManager tm = tunnelManager;
            byte[] tunneled = tm != null
                    ? tm.queryDns(payload, DNS_TUNNEL_TIMEOUT_MS) : null;
            if (!running || relay.isShutdown()) {
                return;
            }
            if (tunneled != null && !DnsWire.responseMatchesQuery(tunneled, payload)) {
                Logger.warning(TAG_MODULE, "DNS tunneled response did not match query; falling back");
                tunneled = null;
            }
            if (tunneled != null) {
                final byte[] response = tunneled;
                dnsCacheStore(payload, response);
                if (!running || relay.isShutdown()) {
                    return;
                }
                byte[] udpPacket0 = buildUdpPacket(response, dstAddr, dstPort, srcAddr, srcPort);
                writePacketCallback.onWritePacket(udpPacket0);
                logUdpTrace(() -> "UDP OUT (DNS relay via tunnel oob) src="
                        + addressToString(dstAddr) + ":" + dstPort
                        + " len=" + response.length, dstPort, srcPort);
                return;
            }

            // 回退路径：本地 UDP 直连公共解析器。
            String[] upstreams = {"1.1.1.1", "8.8.8.8"};
            for (String upstream : upstreams) {
                if (!running || relay.isShutdown()) {
                    return;
                }
                DatagramSocket socket = null;
                try {
                    socket = new DatagramSocket();
                    inFlightDnsSockets.add(socket);
                    if (!running || relay.isShutdown()) {
                        return;
                    }
                    boolean protectedOk = socketProtector == null || socketProtector.protect(socket);
                    if (!protectedOk) {
                        Logger.error(TAG_MODULE, "DNS_FAILED reason=protect_failed");
                        return;
                    }
                    InetAddress server = InetAddress.getByName(upstream);
                    socket.connect(server, 53);
                    socket.setSoTimeout(DNS_RELAY_TIMEOUT_MS);
                    socket.send(new DatagramPacket(payload, payload.length, server, 53));
                    byte[] buf = new byte[1500];
                    DatagramPacket response = new DatagramPacket(buf, buf.length);
                    socket.receive(response);
                    byte[] dnsPayload = Arrays.copyOfRange(response.getData(), response.getOffset(),
                            response.getOffset() + response.getLength());
                    if (!running || relay.isShutdown()) {
                        return;
                    }
                    if (!DnsWire.responseMatchesQuery(dnsPayload, payload)) {
                        Logger.warning(TAG_MODULE, "DNS UDP response did not match query via "
                                + upstream + ", trying next upstream");
                        continue;
                    }
                    dnsCacheStore(payload, dnsPayload);
                    if (!running || relay.isShutdown()) {
                        return;
                    }
                    byte[] udpPacket = buildUdpPacket(dnsPayload, dstAddr, dstPort, srcAddr, srcPort);
                    writePacketCallback.onWritePacket(udpPacket);
                    logUdpTrace(() -> "UDP OUT (DNS relay via " + upstream + ") src="
                            + addressToString(dstAddr) + ":" + dstPort
                            + " dst=" + addressToString(srcAddr) + ":" + srcPort
                            + " len=" + dnsPayload.length, dstPort, srcPort);
                    return;
                } catch (SocketTimeoutException e) {
                    Logger.warning(TAG_MODULE, "DNS relay timeout via " + upstream
                            + ", trying next upstream");
                } catch (Exception e) {
                    Logger.error(TAG_MODULE, "DNS_FAILED error=" + e.getMessage());
                    return;
                } finally {
                    if (socket != null) {
                        inFlightDnsSockets.remove(socket);
                        socket.close();
                    }
                }
            }
            Logger.error(TAG_MODULE, "DNS_FAILED reason=all_upstreams_timeout");
        });
    }

    /**
     * 查缓存。命中且未过期时返回「已适配本次查询」的应答（替换事务 ID、
     * 递减 TTL）；未命中或已过期返回 null。
     */
    private byte[] dnsCacheLookup(byte[] query) {
        DnsWire.Query q = DnsWire.parseQuery(query);
        if (q == null) return null;
        String key = dnsCacheKey(q.name, q.qtype);
        DnsCacheEntry e = dnsCache.get(key);
        if (e == null) return null;
        long now = System.currentTimeMillis();
        if (now >= e.expiresAtMs) {
            dnsCache.remove(key, e);
            return null;
        }
        long elapsedSec = Math.max(0, (now - e.insertedAtMs) / 1000);
        return DnsWire.adaptCached(e.response, q.id, elapsedSec);
    }

    /** 按应答报文的 TTL 存入缓存（钳位到上下限；负应答用短 TTL；畸形报文不缓存）。 */
    private void dnsCacheStore(byte[] query, byte[] response) {
        DnsWire.Query q = DnsWire.parseQuery(query);
        if (q == null || response == null || response.length < 12) return;
        if (!DnsWire.responseMatchesQuery(response, query)) return;
        int rcode = response[3] & 0x0f;
        int ancount = ((response[6] & 0xff) << 8) | (response[7] & 0xff);
        int ttlSec;
        if (rcode != 0 || ancount == 0) {
            ttlSec = DNS_CACHE_NEGATIVE_TTL_S;
        } else {
            int minTtl = DnsWire.minTtl(response, response.length);
            if (minTtl < 0) return; // 解析不了就不缓存
            ttlSec = Math.max(DNS_CACHE_MIN_TTL_S, Math.min(DNS_CACHE_MAX_TTL_S, minTtl));
        }
        // 简单容量控制：超限先清过期项，仍超限就整体清空（缓存可重建，
        // 不做 LRU 以免为几百项引入额外结构）。
        if (dnsCache.size() >= DNS_CACHE_MAX_ENTRIES) {
            long cutoff = System.currentTimeMillis();
            dnsCache.entrySet().removeIf(en -> cutoff >= en.getValue().expiresAtMs);
            if (dnsCache.size() >= DNS_CACHE_MAX_ENTRIES) dnsCache.clear();
        }
        long now = System.currentTimeMillis();
        dnsCache.put(dnsCacheKey(q.name, q.qtype),
                new DnsCacheEntry(response.clone(), now, now + ttlSec * 1000L));
    }

    private static String dnsCacheKey(String name, int qtype) {
        return name.toLowerCase(java.util.Locale.US) + '|' + qtype;
    }

    /** 一条缓存应答：报文副本 + 插入时刻 + 过期时刻。 */
    private static final class DnsCacheEntry {
        final byte[] response;
        final long insertedAtMs;
        final long expiresAtMs;

        DnsCacheEntry(byte[] response, long insertedAtMs, long expiresAtMs) {
            this.response = response;
            this.insertedAtMs = insertedAtMs;
            this.expiresAtMs = expiresAtMs;
        }
    }

    // ================================================================ 清理线程

    private void startCleanupThread() {
        cleanupThread = new Thread(() -> {
            while (running && Thread.currentThread() == cleanupThread) {
                try {
                    Thread.sleep(1000);
                    if (!running || Thread.currentThread() != cleanupThread) {
                        break;
                    }
                    long now = System.currentTimeMillis();
                    for (TcpConnection conn : connectionsById.values()) {
                        if (!running || Thread.currentThread() != cleanupThread) {
                            return;
                        }
                        // 兜底重传先于回收判定：有未确认在途段时连接是"停滞"而非
                        // "陈旧"。尾部段丢失收不到 dup-ACK，只有这里能把流救回来。
                        List<UnackedSegment> stalledBatch =
                                conn.collectStalledRetransmits(now, RETRANSMIT_STALL_MS);
                        if (!stalledBatch.isEmpty()) {
                            // 与 TCP RTO 的整窗重传同形：一次探测把窗口允许范围内
                            // 的全部未确认段一并重发。
                            for (UnackedSegment stalled : stalledBatch) {
                                if (!running || Thread.currentThread() != cleanupThread) {
                                    return;
                                }
                                byte[] packet;
                                int ack;
                                synchronized (conn) {
                                    ack = conn.clientNextSeq;
                                    packet = buildTcpPacket(conn, stalled.payload, (byte) 0x18,
                                            stalled.seq, ack);
                                }
                                try {
                                    conn.writePacketCallback.onWritePacket(packet);
                                    logTcpOut(conn, 0x18, stalled.seq, ack, stalled.length);
                                } catch (Exception e) {
                                    Logger.error(TAG_MODULE,
                                            "Stall retransmit write failed: " + e.getMessage());
                                }
                            }
                            Logger.info(TAG_MODULE, "Stall retransmit: connectionId="
                                    + conn.connectionId
                                    + ", segments=" + stalledBatch.size()
                                    + ", attempt=" + conn.stalledRetransmitCount());
                            if (!running || Thread.currentThread() != cleanupThread) {
                                return;
                            }
                            if (conn.stalledRetransmitCount() > MAX_STALL_RETRANSMITS) {
                                abortConnection(conn, "stall_retransmit_exhausted");
                            }
                            boolean finishFin;
                            synchronized (conn) {
                                finishFin = conn.serverFinPending && !conn.hasPendingSegments();
                            }
                            if (finishFin) {
                                sendFinToApp(conn);
                            }
                            continue;
                        }
                        long age = now - conn.lastActivityTime;
                        if (conn.state == TcpState.ESTABLISHED) {
                            if (age <= ESTABLISHED_IDLE_TIMEOUT_MS) {
                                continue;
                            }
                            // 隧道侧仍是建立的 → 这是"长时间没数据"，不是死连接。
                            // 远端存活性由引擎保活（keepalive 45s / 静默 135s）负责，
                            // 真死时会经 onReset 走 RST 路径。
                            if (isTunnelAlive()) {
                                continue;
                            }
                        } else if (age <= CLOSING_IDLE_TIMEOUT_MS) {
                            continue;
                        }
                        Logger.info(TAG_MODULE, "Stale connection cleanup: connectionId="
                                + conn.connectionId + ", state=" + conn.state
                                + ", idleMs=" + age);
                        if (!running || Thread.currentThread() != cleanupThread) {
                            return;
                        }
                        sendCloseToOutbound(conn, conn.state != TcpState.ESTABLISHED);
                        // 回收时必须向应用回 RST：远端已消失，缺了这个包应用只会
                        // 看到连接静默挂死，直到自己的超时才放弃。
                        byte[] rst;
                        synchronized (conn) {
                            rst = buildTcpPacket(conn, new byte[0], (byte) 0x14,
                                    conn.serverNextSeq, conn.clientNextSeq);
                        }
                        try {
                            if (!running || Thread.currentThread() != cleanupThread) {
                                return;
                            }
                            conn.writePacketCallback.onWritePacket(rst);
                        } catch (Exception e) {
                            Logger.error(TAG_MODULE, "Cleanup RST write failed: " + e.getMessage());
                        }
                        removeConnection(conn);
                    }
                } catch (InterruptedException e) {
                    break;
                }
            }
        }, "PacketRouter-Cleanup");
        cleanupThread.start();
    }

    /** 隧道侧是否仍是建立的会话（用于区分"空闲但健康"和"远端已消失"）。 */
    private boolean isTunnelAlive() {
        return tunnelManager != null && tunnelManager.isEstablished();
    }

    // ================================================================ 局域网判定

    /**
     * RFC1918 / 链路本地 / 环回 / 组播 / 受限广播。命中即豁免：TCP 直连，
     * UDP 丢弃。只处理 IPv4（Builder 未通告 IPv6 路由，IPv6 出不了 TUN）。
     */
    static boolean isLanAddress(byte[] addr4) {
        if (addr4 == null || addr4.length != 4) {
            return false;
        }
        int b0 = addr4[0] & 0xFF;
        int b1 = addr4[1] & 0xFF;
        if (b0 == 10 || b0 == 127) {
            return true;                    // 10/8, 127/8
        }
        if (b0 == 172 && (b1 >= 16 && b1 <= 31)) {
            return true;                    // 172.16/12
        }
        if (b0 == 192 && b1 == 168) {
            return true;                    // 192.168/16
        }
        if (b0 == 169 && b1 == 254) {
            return true;                    // 169.254/16 链路本地
        }
        if ((b0 & 0xF0) == 0xE0) {
            return true;                    // 224/4 组播（含 mDNS 224.0.0.251）
        }
        return b0 == 255;                   // 受限广播
    }

    // ================================================================ TCP/UDP 合包

    private byte[] buildTcpPacket(TcpConnection conn, byte[] payload, byte tcpFlags, int seq, int ack) {
        boolean ipv6 = conn.dstAddr.length == IPV6_ADDR_LEN;
        int ipHeaderLen = ipv6 ? IPV6_HEADER_LEN : IPV4_HEADER_LEN;
        int tcpLen = TCP_HEADER_LEN + payload.length;
        int totalLen = ipHeaderLen + tcpLen;
        byte[] packet = new byte[totalLen];
        ByteBuffer buf = ByteBuffer.wrap(packet).order(ByteOrder.BIG_ENDIAN);
        if (ipv6) {
            buf.put((byte) 0x60);
            buf.put((byte) 0);
            buf.put((byte) 0);
            buf.put((byte) 0);
            buf.putShort((short) tcpLen);   // payload length：不含 40 字节头
            buf.put((byte) 6);              // next header = TCP
            buf.put((byte) 64);             // hop limit
            buf.put(conn.dstAddr);          // src = 远端目标
            buf.put(conn.srcAddr);          // dst = 本机
        } else {
            buf.put((byte) 0x45);
            buf.put((byte) 0);
            buf.putShort((short) totalLen);
            buf.putShort((short) 0);
            buf.putShort((short) 0x4000);
            buf.put((byte) 64);
            buf.put((byte) 6);
            buf.putShort((short) 0);
            buf.put(conn.dstAddr);
            buf.put(conn.srcAddr);
        }
        buf.putShort((short) conn.dstPort);
        buf.putShort((short) conn.srcPort);
        buf.putInt(seq);
        buf.putInt(ack);
        buf.put((byte) 0x50);
        buf.put(tcpFlags);
        buf.putShort((short) 65535);
        buf.putShort((short) 0);
        buf.putShort((short) 0);
        buf.put(payload);
        if (!ipv6) {
            putChecksum(packet, 10, checksum(packet, 0, IPV4_HEADER_LEN));
        }
        putChecksum(packet, ipHeaderLen + 16,
                tcpChecksum(packet, ipHeaderLen, tcpLen, conn.dstAddr, conn.srcAddr));
        return packet;
    }

    private byte[] buildUdpPacket(byte[] payload, byte[] srcAddr, int srcPort, byte[] dstAddr, int dstPort) {
        int udpLen = 8 + payload.length;
        int totalLen = 20 + udpLen;
        byte[] packet = new byte[totalLen];
        ByteBuffer buf = ByteBuffer.wrap(packet).order(ByteOrder.BIG_ENDIAN);
        buf.put((byte) 0x45);
        buf.put((byte) 0);
        buf.putShort((short) totalLen);
        buf.putShort((short) 0);
        buf.putShort((short) 0x4000);
        buf.put((byte) 64);
        buf.put((byte) 17);
        buf.putShort((short) 0);
        buf.put(srcAddr);
        buf.put(dstAddr);
        buf.putShort((short) srcPort);
        buf.putShort((short) dstPort);
        buf.putShort((short) udpLen);
        buf.putShort((short) 0);
        buf.put(payload);
        putChecksum(packet, 10, checksum(packet, 0, 20));
        int udpChecksum = udpChecksum(packet, 20, udpLen, srcAddr, dstAddr);
        putChecksum(packet, 26, udpChecksum == 0 ? 0xFFFF : udpChecksum);
        return packet;
    }

    private static int tcpChecksum(byte[] packet, int offset, int len, byte[] srcAddr, byte[] dstAddr) {
        return protocolChecksum(packet, offset, len, srcAddr, dstAddr, 6);
    }

    private static int udpChecksum(byte[] packet, int offset, int len, byte[] srcAddr, byte[] dstAddr) {
        return protocolChecksum(packet, offset, len, srcAddr, dstAddr, 17);
    }

    private static int protocolChecksum(byte[] packet, int offset, int len, byte[] srcAddr,
                                        byte[] dstAddr, int protocol) {
        boolean ipv6 = srcAddr.length == IPV6_ADDR_LEN;
        int pseudoLen = ipv6 ? 40 : 12;
        byte[] pseudo = new byte[pseudoLen + len];
        if (ipv6) {
            System.arraycopy(srcAddr, 0, pseudo, 0, IPV6_ADDR_LEN);
            System.arraycopy(dstAddr, 0, pseudo, IPV6_ADDR_LEN, IPV6_ADDR_LEN);
            pseudo[32] = (byte) ((len >> 24) & 0xFF);
            pseudo[33] = (byte) ((len >> 16) & 0xFF);
            pseudo[34] = (byte) ((len >> 8) & 0xFF);
            pseudo[35] = (byte) (len & 0xFF);
            pseudo[39] = (byte) protocol;   // pseudo[36..38] 保持 0
        } else {
            System.arraycopy(srcAddr, 0, pseudo, 0, 4);
            System.arraycopy(dstAddr, 0, pseudo, 4, 4);
            pseudo[8] = 0;
            pseudo[9] = (byte) protocol;
            pseudo[10] = (byte) ((len >> 8) & 0xFF);
            pseudo[11] = (byte) (len & 0xFF);
        }
        System.arraycopy(packet, offset, pseudo, pseudoLen, len);
        return checksum(pseudo, 0, pseudo.length);
    }

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

    private static void putChecksum(byte[] packet, int offset, int checksum) {
        packet[offset] = (byte) ((checksum >> 8) & 0xFF);
        packet[offset + 1] = (byte) (checksum & 0xFF);
    }

    /** u32 序列号的模 2^32 半窗比较；有符号 int 减法保留低 32 位环绕语义。 */
    static boolean seqAfterOrEqual(int a, int b) {
        return a == b || (a - b) > 0;
    }

    static boolean seqBefore(int a, int b) {
        return a != b && (a - b) < 0;
    }

    private static String connectionKey(byte[] srcAddr, int srcPort, byte[] dstAddr, int dstPort) {
        return addressToString(srcAddr) + ":" + srcPort + "->" + addressToString(dstAddr) + ":" + dstPort;
    }

    private static String addressToString(byte[] addr) {
        if (addr.length == IPV6_ADDR_LEN) {
            return formatIpv6(addr);
        }
        return (addr[0] & 0xFF) + "." + (addr[1] & 0xFF) + "."
                + (addr[2] & 0xFF) + "." + (addr[3] & 0xFF);
    }

    /**
     * IPv6 文本形式。交给 InetAddress 做 RFC 5952 的 :: 压缩——getByAddress 只解析
     * 字面量、不发 DNS 查询。同一段字节永远得到同一个字符串，所以连接表 key 稳定。
     */
    private static String formatIpv6(byte[] addr) {
        try {
            return InetAddress.getByAddress(addr).getHostAddress();
        } catch (java.net.UnknownHostException e) {
            // 长度已由调用方保证为 16，理论不可达
            return "<ipv6:" + addr.length + "B>";
        }
    }

    private static void logTcpIn(byte[] srcAddr, int srcPort, byte[] dstAddr, int dstPort,
                                 int flags, int seq, int ack, int len) {
        Logger.packetTrace(TAG_MODULE, () -> "TCP IN src=" + addressToString(srcAddr) + ":" + srcPort
                + " dst=" + addressToString(dstAddr) + ":" + dstPort
                + " flags=0x" + Integer.toHexString(flags)
                + " seq=" + (seq & 0xFFFFFFFFL)
                + " ack=" + (ack & 0xFFFFFFFFL)
                + " len=" + len);
    }

    private static void logTcpOut(TcpConnection conn, int flags, int seq, int ack, int len) {
        Logger.packetTrace(TAG_MODULE, () -> "TCP OUT src=" + conn.dstHost + ":" + conn.dstPort
                + " dst=" + conn.srcHost + ":" + conn.srcPort
                + " flags=0x" + Integer.toHexString(flags)
                + " seq=" + (seq & 0xFFFFFFFFL)
                + " ack=" + (ack & 0xFFFFFFFFL)
                + " len=" + len);
    }

    private void logUdpTrace(java.util.function.Supplier<String> message, int srcPort, int dstPort) {
        if (srcPort == 53 || dstPort == 53
                || udpTraceCounter.incrementAndGet() % UDP_TRACE_SAMPLE_RATE == 0) {
            Logger.packetTrace(TAG_MODULE, message);
        }
    }

    private static void closeQuietly(Socket socket) {
        try {
            socket.close();
        } catch (IOException ignored) {
            // 关闭失败无需处理
        }
    }

    // ================================================================ 回调接口

    /** 合成的响应包写回 TUN。 */
    public interface WritePacketCallback {
        void onWritePacket(byte[] packet);
    }

    // ================================================================ 出站汇

    /**
     * 出站字节汇的统一抽象：隧道流（StreamHandle）与局域网直连（socket 输出流）
     * 对上层路由逻辑暴露同一套 write / closeWrite(FIN) / abort(RST) 语义。
     */
    private interface OutboundSink {
        void write(byte[] data, int offset, int len) throws IOException;

        void closeWrite() throws IOException;

        void abort();
    }

    /** StreamHandle 适配：引擎内部负责缓冲/背压/FCP 分段。 */
    private static final class TunnelSink implements OutboundSink {
        private final StreamHandle stream;
        private final TcpConnection connection;

        TunnelSink(StreamHandle stream, TcpConnection connection) {
            this.stream = stream;
            this.connection = connection;
        }

        @Override
        public void write(byte[] data, int offset, int len) {
            stream.write(data, offset, len);
        }

        @Override
        public void closeWrite() {
            stream.closeWrite();
        }

        @Override
        public void abort() {
            connection.abortTunnelStream();
        }
    }

    /** 局域网直连 socket 适配：closeWrite = shutdownOutput，abort = close。 */
    private static final class LanSink implements OutboundSink {
        private final Socket socket;
        private final AtomicBoolean closed = new AtomicBoolean();

        LanSink(Socket socket) {
            this.socket = socket;
        }

        /** sink.abort 与连接回收共用同一次 close，避免重复关闭。 */
        void closeSocket() {
            if (closed.compareAndSet(false, true)) {
                closeQuietly(socket);
            }
        }

        @Override
        public void write(byte[] data, int offset, int len) throws IOException {
            OutputStream out = socket.getOutputStream();
            out.write(data, offset, len);
            out.flush();
        }

        @Override
        public void closeWrite() throws IOException {
            socket.shutdownOutput();
        }

        @Override
        public void abort() {
            closeSocket();
        }
    }

    // ================================================================ 连接对象

    private enum TcpState {
        SYN_RECEIVED,
        ESTABLISHED,
        CLOSING
    }

    /** acceptOutboundSegment 的结果。 */
    private enum SegmentOutcome {
        SEND_NOW,
        HELD,
        OVERFLOW
    }

    private static class TcpConnection {
        private final long connectionId;
        private final String key;
        private final byte[] srcAddr;
        private final byte[] dstAddr;
        private final int srcPort;
        private final int dstPort;
        private final String srcHost;
        private final String dstHost;
        private final int serverInitialSeq;
        private final WritePacketCallback writePacketCallback;
        private int clientNextSeq;
        private int serverNextSeq;
        private int lastAckFromClient;
        // server→app 方向的在途段登记（保留负载以备重传）。
        private final Deque<UnackedSegment> unackedServerData;
        private int unackedBytes;
        // 窗口耗尽时滞留的未发送段（应用报文刷新窗口后按序送出）。
        private final Deque<UnackedSegment> pendingQueue = new ArrayDeque<>();
        private int pendingBytes;
        // 应用最近通告的接收窗口及其基准 ack：段 [ack, ack+window) 之内才允许
        // 写 TUN（无符号回绕比较见 fitsInSendWindow）。
        private int appWindowAck;
        private int appWindow;
        // 连续无进展的 dup-ACK 计数；达到阈值触发快速重传并复位。
        private int dupAckCount;
        private long lastAckProgressMs;
        private long lastRetransmitMs;
        private int stalledRetransmitCount;
        private long lastActivityTime;
        private TcpState state;
        private boolean synAckSent;
        private boolean clientFinSeen;
        // 远端 FIN 已排到 pending 之后，可以进入 TUN 关闭流程。
        private boolean serverFinSeen;
        // 远端 FIN 已收到但 pending 尚未发完；窗口/ACK/超时重传后继续尝试发 FIN。
        private boolean serverFinPending;
        // 隧道/LAN 侧尚未就绪时缓冲的应用方向数据（有界）。
        private final Deque<byte[]> outboundBuffer = new ArrayDeque<>();
        private int outboundBufferedBytes;
        private boolean pendingCloseWrite;
        private boolean pendingAbort;
        // 隧道流句柄（close 时 abort 释放引擎侧 sid；sink 持有实际写入通道）。
        private volatile StreamHandle tunnelStream;
        private volatile OutboundSink sink;
        // LAN socket 从建连开始就登记，close 必须能中断 connect/read；线程只跟踪不 join，
        // 避免清理线程或 pump 自身调用 close 时发生自等待死锁。
        private volatile Socket lanSocket;
        private volatile Thread lanConnector;
        private volatile Thread lanPump;
        private volatile boolean closed;

        TcpConnection(long connectionId, String key, byte[] srcAddr, int srcPort, byte[] dstAddr,
                      int dstPort, int initialServerSeq, WritePacketCallback writePacketCallback) {
            this.connectionId = connectionId;
            this.key = key;
            this.srcAddr = Arrays.copyOf(srcAddr, srcAddr.length);
            this.dstAddr = Arrays.copyOf(dstAddr, dstAddr.length);
            this.srcPort = srcPort;
            this.dstPort = dstPort;
            this.srcHost = addressToString(srcAddr);
            this.dstHost = addressToString(dstAddr);
            this.serverInitialSeq = initialServerSeq;
            this.writePacketCallback = writePacketCallback;
            this.clientNextSeq = 0;
            this.serverNextSeq = initialServerSeq;
            this.lastAckFromClient = 0;
            this.unackedServerData = new ArrayDeque<>();
            this.lastAckProgressMs = System.currentTimeMillis();
            this.lastActivityTime = System.currentTimeMillis();
            this.state = TcpState.SYN_RECEIVED;
            this.synAckSent = false;
            this.closed = false;
        }

        void touch() {
            lastActivityTime = System.currentTimeMillis();
        }

        /** 记录应用最近通告的接收窗口（相对其 ack）。仅用于连接初始化。 */
        void setSendWindow(int ack, int window) {
            appWindowAck = ack;
            appWindow = window;
        }

        /**
         * RFC 793 式窗口更新：确认推进时无条件采纳；确认不动时只在窗口扩大时
         * 采纳（采纳同确认上的收缩值会让发送端被陈旧值自缚）。
         */
        void updateSendWindow(int ack, int window) {
            if (ack != appWindowAck
                    ? seqAfterOrEqual(ack, appWindowAck)
                    : window > appWindow) {
                appWindowAck = ack;
                appWindow = window;
            }
        }

        /** 段是否完整落在应用当前通告的窗口内。窗口为 0 时一律 false。 */
        boolean fitsInSendWindow(int seq, int len) {
            if (appWindow <= 0) {
                return false;
            }
            return seqAfterOrEqual(appWindowAck + appWindow, seq + len);
        }

        boolean hasUnackedServerData() {
            return !unackedServerData.isEmpty();
        }

        boolean hasPendingSegments() {
            return !pendingQueue.isEmpty();
        }

        UnackedSegment peekFirstPending() {
            return pendingQueue.peekFirst();
        }

        /** pending 队首转入在途（由调用方立刻写 TUN），保持与登记时相同的顺序。 */
        void promoteFirstPending() {
            UnackedSegment seg = pendingQueue.pollFirst();
            pendingBytes -= seg.length;
            unackedServerData.addLast(seg);
            unackedBytes += seg.length;
        }

        /**
         * 登记一个待发段。
         * @return SEND_NOW：已登记为在途，调用方须立即写 TUN；
         *         HELD：窗口耗尽，已滞留 pending，等窗口重新打开；
         *         OVERFLOW：滞留总量超过上限（应用长时间不确认），调用方应放弃连接。
         */
        SegmentOutcome acceptOutboundSegment(int seq, byte[] payload) {
            if (payload.length == 0) {
                return SegmentOutcome.SEND_NOW;
            }
            if (unackedBytes + pendingBytes + payload.length > MAX_UNACKED_RETAINED_BYTES) {
                return SegmentOutcome.OVERFLOW;
            }
            if (pendingQueue.isEmpty() && fitsInSendWindow(seq, payload.length)) {
                unackedServerData.addLast(new UnackedSegment(seq, payload));
                unackedBytes += payload.length;
                return SegmentOutcome.SEND_NOW;
            }
            pendingQueue.addLast(new UnackedSegment(seq, payload));
            pendingBytes += payload.length;
            return SegmentOutcome.HELD;
        }

        /** 移除被 ack 完全覆盖的段。返回移除数；任何进展都复位 dup-ACK 与兜底计数。 */
        int removeAckedServerSegments(int ack) {
            int removed = 0;
            while (!unackedServerData.isEmpty()) {
                UnackedSegment segment = unackedServerData.peekFirst();
                if (seqAfterOrEqual(ack, segment.endSeq())) {
                    unackedServerData.removeFirst();
                    unackedBytes -= segment.length;
                    removed++;
                } else {
                    break;
                }
            }
            if (removed > 0) {
                lastAckProgressMs = System.currentTimeMillis();
                dupAckCount = 0;
                stalledRetransmitCount = 0;
            }
            return removed;
        }

        /** 累计无进展 dup-ACK；达到阈值时复位计数并返回 true（触发快速重传）。 */
        boolean tickDupAck() {
            dupAckCount++;
            if (dupAckCount < DUP_ACK_RETRANSMIT_THRESHOLD) {
                return false;
            }
            dupAckCount = 0;
            return true;
        }

        void resetDupAcks() {
            dupAckCount = 0;
        }

        UnackedSegment peekFirstUnacked() {
            return unackedServerData.peekFirst();
        }

        void markRetransmitted() {
            lastRetransmitMs = System.currentTimeMillis();
        }

        int stalledRetransmitCount() {
            return stalledRetransmitCount;
        }

        /**
         * 清理线程的停滞兜底：没有任何 ACK 进展（典型是尾部段丢失，收不到
         * dup-ACK）超过 stallMs，就交回本连接需要重传的段——与 TCP RTO 的整窗
         * 重传同形：首个未确认段必含（兼作零窗口探测），其后窗口装得下的未确认
         * 段一并重发。返回空列表表示本轮无需重传。
         */
        List<UnackedSegment> collectStalledRetransmits(long now, long stallMs) {
            List<UnackedSegment> batch = new ArrayList<>();
            synchronized (this) {
                if (unackedServerData.isEmpty() && pendingQueue.isEmpty()) {
                    return batch;
                }
                long reference = Math.max(lastAckProgressMs, lastRetransmitMs);
                if (now - reference < stallMs) {
                    return batch;
                }
                lastRetransmitMs = now;
                stalledRetransmitCount++;
                if (unackedServerData.isEmpty()) {
                    // pending 首段从未发出：转登记为在途，随本批写出
                    UnackedSegment head = pendingQueue.pollFirst();
                    pendingBytes -= head.length;
                    unackedServerData.addLast(head);
                    unackedBytes += head.length;
                }
                boolean head = true;
                for (UnackedSegment seg : unackedServerData) {
                    // 首段无条件重发（零窗口探测）；其后只发窗口装得下的
                    if (head || fitsInSendWindow(seg.seq, seg.length)) {
                        batch.add(seg);
                        head = false;
                    } else {
                        break;
                    }
                }
            }
            return batch;
        }

        /** 建流期间缓冲应用数据。@return false 表示缓冲超限（调用方应放弃连接）。 */
        boolean bufferOutbound(byte[] payload) {
            synchronized (this) {
                if (outboundBufferedBytes + payload.length > MAX_OUTBOUND_BUFFERED_BYTES) {
                    return false;
                }
                outboundBuffer.addLast(payload);
                outboundBufferedBytes += payload.length;
                return true;
            }
        }

        /** 取走全部缓冲的应用数据（挂 sink 后由调用方灌入隧道）。 */
        byte[][] drainOutboundBuffer() {
            synchronized (this) {
                byte[][] chunks = outboundBuffer.toArray(new byte[0][]);
                outboundBuffer.clear();
                outboundBufferedBytes = 0;
                return chunks;
            }
        }

        boolean registerLanConnector(Thread thread) {
            synchronized (this) {
                if (closed) {
                    return false;
                }
                lanConnector = thread;
                return true;
            }
        }

        void finishLanConnector(Thread thread) {
            synchronized (this) {
                if (lanConnector == thread) {
                    lanConnector = null;
                }
            }
        }

        boolean registerLanSocket(Socket socket) {
            synchronized (this) {
                if (closed) {
                    return false;
                }
                lanSocket = socket;
                return true;
            }
        }

        boolean attachLanSink(Socket socket) {
            synchronized (this) {
                if (closed) {
                    return false;
                }
                lanSocket = socket;
                sink = new LanSink(socket);
                return true;
            }
        }

        boolean registerLanPump(Thread thread) {
            synchronized (this) {
                if (closed) {
                    return false;
                }
                lanPump = thread;
                return true;
            }
        }

        void finishLanPump(Thread thread) {
            synchronized (this) {
                if (lanPump == thread) {
                    lanPump = null;
                }
            }
        }

        /** 与 TunnelSink.abort/close 共用单次 detach，防止并发回调重复 abort。 */
        void abortTunnelStream() {
            StreamHandle stream;
            synchronized (this) {
                stream = tunnelStream;
                tunnelStream = null;
                if (sink instanceof TunnelSink) {
                    sink = null;
                }
            }
            if (stream != null) {
                try {
                    stream.abort();
                } catch (RuntimeException ignored) {
                    // 引擎侧清理失败不影响本地拆除
                }
            }
        }

        /** 完整、幂等回收；外部 close/abort 调用不持有连接锁，避免回调死锁。 */
        void close() {
            StreamHandle stream;
            Socket socket;
            OutboundSink outboundSink;
            Thread connector;
            Thread pump;
            synchronized (this) {
                if (closed) {
                    return;
                }
                closed = true;
                stream = tunnelStream;
                tunnelStream = null;
                outboundSink = sink;
                sink = null;
                socket = lanSocket;
                lanSocket = null;
                connector = lanConnector;
                lanConnector = null;
                pump = lanPump;
                lanPump = null;
                unackedServerData.clear();
                unackedBytes = 0;
                pendingQueue.clear();
                pendingBytes = 0;
                outboundBuffer.clear();
                outboundBufferedBytes = 0;
            }

            if (stream != null) {
                try {
                    stream.abort();
                } catch (RuntimeException ignored) {
                    // 引擎侧清理失败不影响本地拆除
                }
            }
            if (outboundSink instanceof LanSink) {
                ((LanSink) outboundSink).closeSocket();
            } else if (socket != null) {
                // 建连期间尚未挂 LanSink：由连接回收负责关闭已登记的 socket。
                closeQuietly(socket);
            }
            interruptUnlessCurrent(connector);
            interruptUnlessCurrent(pump);
        }

        private static void interruptUnlessCurrent(Thread thread) {
            if (thread != null && thread != Thread.currentThread()) {
                thread.interrupt();
            }
        }
    }

    private static class UnackedSegment {
        private final int seq;
        private final int length;
        private final byte[] payload;

        UnackedSegment(int seq, byte[] payload) {
            this.seq = seq;
            this.payload = payload;
            this.length = payload.length;
        }

        int endSeq() {
            return seq + length;
        }
    }
}
