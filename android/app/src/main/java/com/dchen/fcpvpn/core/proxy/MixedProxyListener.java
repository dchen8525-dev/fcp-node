package com.dchen.fcpvpn.core.proxy;

import com.dchen.fcpvpn.core.session.OpenCallback;
import com.dchen.fcpvpn.core.session.OpenTarget;
import com.dchen.fcpvpn.core.session.StreamHandle;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.Executor;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * 一个端口三种入口（SOCKS5 / HTTP CONNECT / absolute-form 正向代理），首字节分流
 * ——与桌面端 fcp-node 的本地代理行为逐字节一致（tunnel.ts 本地入口部分）。
 *
 * 连接生命周期：detectEntry → 协议解析（need_more 缓冲）→ 隧道 OPEN →
 * 协议级 OK 应答（OPEN_OK 之后）→ 双向搬运（FIN 半关闭语义对齐 StreamHandle）。
 *
 * 线程模型：accept 循环一根线程；每连接一根 reader 线程 + 一根 writer 线程；
 * 所有隧道操作经 {@code engineExecutor} 串行提交（满足 FcpSession 单写者契约）。
 * 背压：onData → writer 队列 → socket 写完后 consumed(n)，隧道流控自然节流。
 */
public final class MixedProxyListener {

    /** 隧道开启入口（由 FcpTunnelEngine 实现；open 回调在 engineExecutor 上触发）。 */
    public interface TunnelOpener {
        void open(OpenTarget target, OpenCallback callback);
    }

    public interface Logger {
        void log(String line);
    }

    private final int port;
    private final TunnelOpener opener;
    private final Executor engineExecutor;
    private final Logger logger;
    private ServerSocket serverSocket;
    private Thread acceptThread;
    private volatile boolean running = false;

    public MixedProxyListener(int port, TunnelOpener opener, Executor engineExecutor, Logger logger) {
        this.port = port;
        this.opener = opener;
        this.engineExecutor = engineExecutor;
        this.logger = logger;
    }

    public void start() throws IOException {
        serverSocket = new ServerSocket(port, 64, InetAddress.getByName("127.0.0.1"));
        running = true;
        acceptThread = new Thread(this::acceptLoop, "fcp-mixed-proxy-accept");
        acceptThread.setDaemon(true);
        acceptThread.start();
        log("mixed proxy listening on 127.0.0.1:" + port);
    }

    public void stop() {
        running = false;
        try {
            if (serverSocket != null) serverSocket.close();
        } catch (IOException ignored) {
        }
    }

    private void log(String line) {
        if (logger != null) logger.log(line);
    }

    private void acceptLoop() {
        while (running) {
            try {
                Socket socket = serverSocket.accept();
                socket.setTcpNoDelay(true);
                Thread t = new Thread(() -> handleConnection(socket), "fcp-proxy-conn");
                t.setDaemon(true);
                t.start();
            } catch (IOException e) {
                if (running) log("accept failed: " + e);
                break;
            }
        }
    }

    private void handleConnection(Socket socket) {
        try {
            InputStream in = socket.getInputStream();
            OutputStream out = socket.getOutputStream();
            // ---- 首字节分流 + 协议解析（need_more 缓冲） ----
            byte[] buf = new byte[ProxyCodec.HTTP_HEAD_MAX_BYTES];
            int filled = 0;
            int entry = -1;
            int consumed = 0;
            ProxyCodec.ProxyTarget target = null;
            byte[] rewrittenHead = null;
            boolean socksGreetNoAuth = false;
            int head = -1;
            while (filled < buf.length) {
                int n = in.read(buf, filled, buf.length - filled);
                if (n < 0) {
                    closeQuietly(socket);
                    return;
                }
                filled += n;
                if (entry < 0) {
                    entry = ProxyCodec.detectEntry(buf, filled);
                    if (entry == ProxyCodec.ENTRY_NEED_MORE) continue;
                    if (entry == ProxyCodec.ENTRY_UNKNOWN) {
                        out.write(ProxyCodec.HTTP_BAD_REQUEST);
                        out.flush();
                        closeQuietly(socket);
                        return;
                    }
                }
                if (entry == ProxyCodec.ENTRY_SOCKS5) {
                    // greeting
                    if (head < 0) {
                        ProxyCodec.ParseResult g = ProxyCodec.socks5ParseGreeting(buf, filled);
                        if (g.status == ProxyCodec.NEED_MORE) {
                            if (filled > ProxyCodec.SOCKS5_MAX_GREETING_BYTES) {
                                closeQuietly(socket);
                                return;
                            }
                            continue;
                        }
                        if (g.status != ProxyCodec.OK || !g.boolValue) {
                            out.write(ProxyCodec.socks5GreetingReply(false));
                            out.flush();
                            closeQuietly(socket);
                            return;
                        }
                        socksGreetNoAuth = true;
                        head = g.consumed;
                        out.write(ProxyCodec.socks5GreetingReply(true));
                        out.flush();
                        continue;
                    }
                    // request（greeting 之后）
                    ProxyCodec.ParseResult r = ProxyCodec.socks5ParseRequest(
                            java.util.Arrays.copyOfRange(buf, head, filled),
                            filled - head);
                    if (r.status == ProxyCodec.NEED_MORE) {
                        if (filled > ProxyCodec.SOCKS5_MAX_GREETING_BYTES + ProxyCodec.SOCKS5_MAX_REQUEST_BYTES) {
                            closeQuietly(socket);
                            return;
                        }
                        continue;
                    }
                    if (r.status == ProxyCodec.COMMAND_NOT_SUPPORTED) {
                        out.write(ProxyCodec.socks5Reply(ProxyCodec.REP_COMMAND_NOT_SUPPORTED));
                        out.flush();
                        closeQuietly(socket);
                        return;
                    }
                    if (r.status != ProxyCodec.OK) {
                        out.write(ProxyCodec.socks5Reply(ProxyCodec.REP_GENERAL_FAILURE));
                        out.flush();
                        closeQuietly(socket);
                        return;
                    }
                    consumed = head + r.consumed;
                    target = r.target;
                    break;
                }
                if (entry == ProxyCodec.ENTRY_CONNECT) {
                    ProxyCodec.ParseResult r = ProxyCodec.httpParseConnect(buf, filled);
                    if (r.status == ProxyCodec.NEED_MORE) continue;
                    if (r.status == ProxyCodec.HEAD_TOO_LARGE) {
                        out.write(ProxyCodec.HTTP_HEAD_TOO_LARGE);
                        out.flush();
                        closeQuietly(socket);
                        return;
                    }
                    if (r.status == ProxyCodec.METHOD_NOT_ALLOWED) {
                        out.write(ProxyCodec.HTTP_METHOD_NOT_ALLOWED);
                        out.flush();
                        closeQuietly(socket);
                        return;
                    }
                    if (r.status != ProxyCodec.OK) {
                        out.write(ProxyCodec.HTTP_BAD_REQUEST);
                        out.flush();
                        closeQuietly(socket);
                        return;
                    }
                    consumed = r.consumed;
                    target = r.target;
                    break;
                }
                // ENTRY_FORWARD
                ProxyCodec.ParseResult r = ProxyCodec.httpParseForward(buf, filled);
                if (r.status == ProxyCodec.NEED_MORE) continue;
                if (r.status == ProxyCodec.HEAD_TOO_LARGE) {
                    out.write(ProxyCodec.HTTP_HEAD_TOO_LARGE);
                    out.flush();
                    closeQuietly(socket);
                    return;
                }
                if (r.status == ProxyCodec.METHOD_NOT_ALLOWED) {
                    out.write(ProxyCodec.HTTP_FORWARD_METHOD_NOT_ALLOWED);
                    out.flush();
                    closeQuietly(socket);
                    return;
                }
                if (r.status != ProxyCodec.OK) {
                    out.write(ProxyCodec.HTTP_BAD_REQUEST);
                    out.flush();
                    closeQuietly(socket);
                    return;
                }
                consumed = r.consumed;
                target = r.target;
                rewrittenHead = r.rewrittenHead;
                break;
            }
            if (target == null) {
                closeQuietly(socket);
                return;
            }

            // ---- 隧道 OPEN（回调在 engineExecutor 上触发） ----
            final Socket sock = socket;
            final OutputStream sockOut = out;
            final byte[] initialExtra = filled > consumed
                    ? java.util.Arrays.copyOfRange(buf, consumed, filled) : null;
            final int fEntry = entry;
            final byte[] fRewritten = rewrittenHead;
            opener.open(toOpenTarget(target), new OpenCallback() {
                @Override
                public void onOpened(StreamHandle stream) {
                    pipe(sock, sockOut, in, stream, fEntry,
                            fEntry == ProxyCodec.ENTRY_FORWARD ? fRewritten : null,
                            initialExtra,
                            fEntry == ProxyCodec.ENTRY_SOCKS5);
                }

                @Override
                public void onFailed(int code, String message) {
                    try {
                        if (fEntry == ProxyCodec.ENTRY_SOCKS5) {
                            sockOut.write(ProxyCodec.socks5Reply(
                                    ProxyCodec.socks5RepForOpenError(code)));
                        } else if (fEntry == ProxyCodec.ENTRY_CONNECT) {
                            sockOut.write(ProxyCodec.HTTP_BAD_GATEWAY);
                        } else {
                            sockOut.write(ProxyCodec.HTTP_BAD_GATEWAY);
                        }
                        sockOut.flush();
                    } catch (IOException ignored) {
                    }
                    closeQuietly(sock);
                }
            });
        } catch (IOException e) {
            closeQuietly(socket);
        }
    }

    /**
     * 双向搬运。SOCKS5/CONNECT 在 OPEN_OK 后发协议级成功应答；forward 在 OPEN_OK
     * 后发改写后的请求头（+ 已随首包到达的 body 前缀）。FIN/RST 语义对齐
     * StreamHandle：对端 FIN → shutdownOutput；本端 socket EOF → closeWrite。
     */
    private void pipe(Socket sock, OutputStream sockOut, InputStream sockIn,
                      StreamHandle stream, int entry, byte[] rewrittenHead,
                      byte[] initialExtra, boolean isSocks5) {
        final LinkedBlockingQueue<byte[]> writerQueue = new LinkedBlockingQueue<>(1024);
        final AtomicFlag peerFinSeen = new AtomicFlag();
        final AtomicFlag localClosed = new AtomicFlag();
        final AtomicFlag readerDone = new AtomicFlag();

        // onData/onFin/onReset 在 engineExecutor 上触发 → 入队由 writer 线程落盘。
        stream.setListener(new StreamHandle.Listener() {
            @Override
            public void onData(byte[] data, int offset, int len) {
                byte[] copy = java.util.Arrays.copyOfRange(data, offset, offset + len);
                if (!writerQueue.offer(copy)) {
                    // 队列满：客户端停止读取，中止流（不无界占内存）。
                    localClosed.set(true);
                    writerQueue.clear();
                    writerQueue.offer(WAKE); // 唤醒阻塞在 take() 的 writer，否则线程泄漏
                    engineExecutor.execute(stream::abort);
                    closeQuietly(sock);
                }
            }

            @Override
            public void onFin() {
                peerFinSeen.set(true);
                writerQueue.offer(new byte[0]); // 哨兵：排空后 shutdownOutput
            }

            @Override
            public void onReset(int code) {
                localClosed.set(true);
                writerQueue.clear();
                writerQueue.offer(WAKE); // 同上：必须唤醒 writer
                closeQuietly(sock);
            }
        });

        // writer 线程：队列 → socket；写完才 consumed(n)（隧道流控背压）。
        Thread writer = new Thread(() -> {
            try {
                boolean finPending = false;
                while (true) {
                    byte[] chunk = writerQueue.take();
                    // WAKE 哨兵（空数组 + localClosed）表示本端已放弃：
                    // 直接退出，避免线程永远挂在 take() 上。
                    if (localClosed.get()) break;
                    if (chunk.length == 0) {
                        finPending = true;
                    } else {
                        sockOut.write(chunk, 0, chunk.length);
                        sockOut.flush();
                        final int n = chunk.length;
                        engineExecutor.execute(() -> stream.consumed(n));
                    }
                    if (finPending && writerQueue.isEmpty()) {
                        try {
                            sock.shutdownOutput();
                        } catch (IOException ignored) {
                        }
                        if (readerDone.get()) closeQuietly(sock);
                        break;
                    }
                    if (localClosed.get()) break;
                }
            } catch (InterruptedException e) {
                closeQuietly(sock);
            } catch (IOException e) {
                engineExecutor.execute(stream::abort);
                closeQuietly(sock);
            }
        }, "fcp-proxy-writer");
        writer.setDaemon(true);
        writer.start();

        // OPEN_OK（SOCKS5/CONNECT）应答给本地客户端；正向代理的改写请求头
        // 发往隧道（对端源服务器）——放错方向会把请求原样回显给本地客户端。
        try {
            if (isSocks5) {
                writerQueue.put(ProxyCodec.socks5Reply(ProxyCodec.REP_SUCCEEDED));
            } else if (rewrittenHead != null) {
                final byte[] head = rewrittenHead;
                engineExecutor.execute(() -> stream.write(head, 0, head.length));
            } else {
                writerQueue.put(ProxyCodec.HTTP_OK);
            }
            if (initialExtra != null && rewrittenHead == null) {
                // SOCKS5/CONNECT 下首包携带的协议后数据原样透传给对端；
                // forward 下 extra 属于请求 body，也发给对端（头已重写）。
                final byte[] extra = initialExtra;
                engineExecutor.execute(() -> stream.write(extra, 0, extra.length));
            }
        } catch (InterruptedException e) {
            closeQuietly(sock);
            return;
        }

        // reader 线程：socket → 隧道；EOF → closeWrite（FIN 半关闭）。
        Thread reader = new Thread(() -> {
            byte[] buf = new byte[16384];
            try {
                int n;
                while ((n = sockIn.read(buf)) != -1) {
                    if (n > 0 && !localClosed.get()) {
                        final byte[] copy = java.util.Arrays.copyOfRange(buf, 0, n);
                        engineExecutor.execute(() -> stream.write(copy, 0, copy.length));
                    }
                }
                // 本端 EOF：发 FIN，等待对端排空（FIN 半关闭）。
                readerDone.set(true);
                engineExecutor.execute(stream::closeWrite);
            } catch (IOException e) {
                readerDone.set(true);
                engineExecutor.execute(stream::abort);
            } finally {
                if (peerFinSeen.get()) closeQuietly(sock);
            }
        }, "fcp-proxy-reader");
        reader.setDaemon(true);
        reader.start();
    }

    private static OpenTarget toOpenTarget(ProxyCodec.ProxyTarget t) {
        if (t.atyp == ProxyCodec.ATYP_DOMAIN) {
            return OpenTarget.domain(new String(t.addr, java.nio.charset.StandardCharsets.US_ASCII),
                    t.port);
        }
        return new OpenTarget(t.atyp, t.addr, null, t.port);
    }

    /** 唤醒哨兵：空数组 + localClosed 让 writer 跳出 take()。 */
    private static final byte[] WAKE = new byte[0];

    private static void closeQuietly(Socket s) {
        try {
            s.close();
        } catch (IOException ignored) {
        }
    }

    /** 极简原子布尔（避免为每个连接建一套 AtomicXxx 链）。 */
    private static final class AtomicFlag {
        private volatile boolean value;

        void set(boolean v) {
            value = v;
        }

        boolean get() {
            return value;
        }
    }
}
