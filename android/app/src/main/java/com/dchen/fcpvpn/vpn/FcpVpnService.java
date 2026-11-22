package com.dchen.fcpvpn.vpn;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ServiceInfo;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.VpnService;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import androidx.localbroadcastmanager.content.LocalBroadcastManager;

import com.dchen.fcpvpn.R;
import com.dchen.fcpvpn.core.session.EngineConfig;
import com.dchen.fcpvpn.core.session.SocketProtector;
import com.dchen.fcpvpn.log.LogConfig;
import com.dchen.fcpvpn.log.Logger;
import com.dchen.fcpvpn.ui.ConfigStore;
import com.dchen.fcpvpn.ui.MainActivity;
import com.dchen.fcpvpn.util.SecretPrefs;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.net.DatagramSocket;
import java.net.Socket;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/**
 * FCP VPN 服务 —— Android VpnService 实现（参考 kcp 的 KcpVpnService 重写）。
 *
 * <p>数据流：TUN 读 IP 包 → PacketRouter（虚拟 TCP + LAN/DNS 豁免）→
 * TunnelManager（引擎生命周期 + 指数退避重连）→ TunnelEngine → FCP 隧道。</p>
 *
 * <p>TUN 配置照搬 kcp：仅通告 IPv4 0.0.0.0/0（Happy Eyeballs 正确回退，见下），
 * DNS 通告 1.1.1.1/8.8.8.8 由 PacketRouter 本地中继，排除本应用自身。</p>
 */
public class FcpVpnService extends VpnService {
    public static final String ACTION_STOP = "com.dchen.fcpvpn.action.STOP_VPN";

    // onStartCommand extras（ServiceUtil 负责打包，键名需与之一致）
    public static final String EXTRA_SERVER_HOST = "server_host";
    public static final String EXTRA_SERVER_PORT = "server_port";
    public static final String EXTRA_PSK = "psk";
    public static final String EXTRA_FEC_DATA = "fec_data";
    public static final String EXTRA_FEC_PARITY_MAX = "fec_parity_max";
    public static final String EXTRA_MTU_MIN = "mtu_min";
    public static final String EXTRA_PROBE_INTERVAL = "probe_interval";
    public static final String EXTRA_PROXY_PORT = "proxy_port";

    private static final String TAG = "FCPVPN_vpn";
    private static final String PREFS_NAME = "fcp_vpn_prefs";
    private static final String KEY_SERVER_HOST = "server_host";
    private static final String KEY_SERVER_PORT = "server_port";
    private static final String KEY_FEC_DATA = "fec_data";
    private static final String KEY_FEC_PARITY_MAX = "fec_parity_max";
    private static final String KEY_MTU_MIN = "mtu_min";
    private static final String KEY_PROBE_INTERVAL = "probe_interval";
    private static final String KEY_PROXY_PORT = "proxy_port";

    // 这些字段被 VPN-Read 线程读取，同时被 closeVpn() 置 null。volatile 保证置 null
    // 对其他线程立即可见，读线程再用局部变量取一次快照，避免 TOCTOU。
    private volatile ParcelFileDescriptor vpnInterface;
    private volatile FileInputStream vpnInputStream;
    private volatile FileOutputStream vpnOutputStream;
    private volatile FileChannel vpnInputChannel;
    private volatile FileChannel vpnOutputChannel;

    private volatile TunnelManager tunnelManager;
    private volatile PacketRouter packetRouter;

    private Thread vpnReadThread;
    // closeVpn 可被 onDestroy / onRevoke / stopVpn 三处并发调用，用它保证只真正执行一次。
    private boolean vpnClosed;
    // closeVpn 每次真正执行都自增。startVpn 用它检测"启动流程进行期间落入了 stop
    // 请求"（stopVpn 的 closeVpn 可能插在 startVpn 的两个装配步骤之间），启动完成
    // 后校验 epoch，变了就补一次完整清理，保证"用户要停就一定停干净"。
    private final AtomicInteger closeEpoch = new AtomicInteger(0);

    private final AtomicBoolean running = new AtomicBoolean(false);
    private volatile VpnConnectionState connectionState;

    // 配置参数
    private String serverHost;
    private int serverPort;
    private String psk;
    private int fecData;
    private int fecParityMax;
    private int mtuMin;
    private int probeIntervalSec;
    private int proxyPort;

    // 流量统计 —— AtomicLong 保证原子性（TUN 收发字节）
    private final AtomicLong uploadBytes = new AtomicLong(0);
    private final AtomicLong downloadBytes = new AtomicLong(0);
    private volatile long connectionStartTime;

    // 统计定时器：运行期间每秒检查一次，已连接时广播速率/时长/会话数。
    // 链式 postDelayed 期间状态可能从 CONNECTING 变为 CONNECTED，因此只要
    // 服务还在运行就持续续约，仅广播动作受状态限制。
    private final Handler statsHandler = new Handler(Looper.getMainLooper());
    private final Runnable statsTicker = new Runnable() {
        @Override
        public void run() {
            if (!running.get()) {
                return;
            }
            if (connectionState == VpnConnectionState.CONNECTED) {
                broadcastState();
            }
            statsHandler.postDelayed(this, 1000);
        }
    };

    // tun 写不进去时最多退让重试的次数（每次 1ms）。establish() 返回的 fd 是非阻塞
    // 的，队列满时 write 返回 0；此时直接丢弃等于让一个 TCP 段无声消失，所以短暂
    // 退让等队列排空，仍失败才上报。
    private static final int VPN_WRITE_MAX_STALLS = 10;

    @Override
    public void onCreate() {
        super.onCreate();
        // Logger 已在 FcpVpnApplication 中初始化
        Logger.info(LogConfig.MODULE_VPN, "FcpVpnService created");
        connectionState = VpnConnectionState.DISCONNECTED;
        uploadBytes.set(0);
        downloadBytes.set(0);
        // 恢复上次保存的参数（进程死亡后 START_STICKY 重启）
        restoreParams();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Logger.info(LogConfig.MODULE_VPN, "onStartCommand called");

        if (intent != null && ACTION_STOP.equals(intent.getAction())) {
            Logger.info(LogConfig.MODULE_VPN, "Stop action received");
            stopVpn();
            return START_NOT_STICKY;
        }

        if (intent != null) {
            serverHost = intent.getStringExtra(EXTRA_SERVER_HOST);
            serverPort = intent.getIntExtra(EXTRA_SERVER_PORT, 0);
            psk = intent.getStringExtra(EXTRA_PSK);
            fecData = intent.getIntExtra(EXTRA_FEC_DATA, VpnConfig.DEFAULT_FEC_DATA);
            fecParityMax = intent.getIntExtra(EXTRA_FEC_PARITY_MAX, VpnConfig.DEFAULT_FEC_PARITY_MAX);
            mtuMin = intent.getIntExtra(EXTRA_MTU_MIN, VpnConfig.DEFAULT_MTU_MIN);
            probeIntervalSec = intent.getIntExtra(EXTRA_PROBE_INTERVAL, VpnConfig.DEFAULT_PROBE_INTERVAL_SEC);
            proxyPort = intent.getIntExtra(EXTRA_PROXY_PORT, VpnConfig.DEFAULT_PROXY_PORT);
            // 持久化参数，供进程死亡后恢复
            saveParams();
            Logger.info(LogConfig.MODULE_VPN, "Parameters: host=" + serverHost
                    + ", port=" + serverPort + ", fec=" + fecData + "/" + fecParityMax
                    + ", mtuMin=" + mtuMin + ", probe=" + probeIntervalSec + "s");
        } else {
            Logger.info(LogConfig.MODULE_VPN, "onStartCommand intent is null, using saved params");
            // START_STICKY 重启：使用已保存的参数
            restoreParams();
            if (serverHost == null || psk == null) {
                Logger.error(LogConfig.MODULE_VPN, "No saved parameters, cannot restart VPN");
                stopSelf();
                return START_NOT_STICKY;
            }
        }

        if (!validateParams()) {
            connectionState = VpnConnectionState.DISCONNECTED;
            broadcastState();
            stopSelf();
            return START_NOT_STICKY;
        }

        // 立即启动前台服务（Android 11+ 要求 startForeground 在 5s 内完成）
        startForegroundService();
        Log.i(TAG, "Foreground started, starting VPN engine");

        if (running.compareAndSet(false, true)) {
            Logger.info(LogConfig.MODULE_VPN, "Starting VPN on background thread...");
            // 在后台线程执行网络 I/O，避免主线程 ANR
            Thread startThread = new Thread(this::startVpn, "VPN-Start");
            startThread.start();
        } else {
            // TODO(M4+): 已在运行时收到新配置应先拆旧再按新参数重启；
            // 目前沿用 kcp 行为（UI 层"先断开再连接"保证参数生效）。
            Logger.info(LogConfig.MODULE_VPN, "VPN already running");
        }

        return START_STICKY;
    }

    /** 参数健全性检查（UI 已校验过，这里兜底防 START_STICKY 恢复出坏值）。 */
    private boolean validateParams() {
        boolean ok = serverHost != null && !serverHost.trim().isEmpty()
                && serverPort > 0 && serverPort <= 65535
                && psk != null && psk.trim().matches("(?i)[0-9a-f]{32}");
        if (!ok) {
            Logger.error(LogConfig.MODULE_VPN, "Invalid VPN parameters, refusing to start");
        }
        return ok;
    }

    /**
     * 启动前台服务。foregroundServiceType=dataSync（manifest 已声明），
     * minSdk 30 恒可用三参 startForeground。
     */
    private void startForegroundService() {
        createNotificationChannel();

        Intent notificationIntent = new Intent(this, MainActivity.class);
        PendingIntent pendingIntent = PendingIntent.getActivity(
                this, 0, notificationIntent, PendingIntent.FLAG_IMMUTABLE);

        startForeground(VpnConfig.NOTIFICATION_ID,
                createNotification(pendingIntent),
                ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC);
        Logger.info(LogConfig.MODULE_VPN, "Foreground service started (dataSync)");
    }

    private void createNotificationChannel() {
        NotificationChannel channel = new NotificationChannel(
                VpnConfig.NOTIFICATION_CHANNEL_ID,
                VpnConfig.NOTIFICATION_CHANNEL_NAME,
                NotificationManager.IMPORTANCE_LOW);
        channel.setDescription("FCP VPN 服务状态");
        channel.setShowBadge(false);
        NotificationManager manager = getSystemService(NotificationManager.class);
        if (manager != null) {
            manager.createNotificationChannel(channel);
        }
    }

    private Notification createNotification(PendingIntent pendingIntent) {
        return baseNotificationBuilder(pendingIntent)
                .setContentText(connectionState.getDisplayText())
                .build();
    }

    private Notification.Builder baseNotificationBuilder(PendingIntent pendingIntent) {
        return new Notification.Builder(this, VpnConfig.NOTIFICATION_CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_vpn)
                .setContentTitle("FCP VPN")
                .setContentIntent(pendingIntent)
                .setOngoing(true);
    }

    private void updateNotification() {
        NotificationManager manager = getSystemService(NotificationManager.class);
        if (manager == null) {
            return;
        }
        Intent notificationIntent = new Intent(this, MainActivity.class);
        PendingIntent pendingIntent = PendingIntent.getActivity(
                this, 0, notificationIntent, PendingIntent.FLAG_IMMUTABLE);

        String content = connectionState.getDisplayText();
        if (connectionState == VpnConnectionState.CONNECTED) {
            content = "已连接 " + formatDuration(getConnectionDuration())
                    + " | ↑" + formatBytes(uploadBytes.get())
                    + " ↓" + formatBytes(downloadBytes.get());
        }
        Notification notification = baseNotificationBuilder(pendingIntent)
                .setContentText(content)
                .build();
        manager.notify(VpnConfig.NOTIFICATION_ID, notification);
    }

    /**
     * 启动 VPN：建 TUN → 引擎 → 路由器 → 读线程。
     */
    private void startVpn() {
        Logger.info(LogConfig.MODULE_VPN, "startVpn() begin");

        // 重置 closeVpn 的一次性标志。同步块保证：任何在此刻之前开始执行的
        // closeVpn 已经完整退出，不会与新启动的装配交错。
        synchronized (this) {
            vpnClosed = false;
        }
        final int startEpoch = closeEpoch.get();

        connectionState = VpnConnectionState.CONNECTING;
        broadcastState();
        updateNotification();

        try {
            vpnInterface = buildVpnInterface();
            if (vpnInterface == null) {
                Logger.error(LogConfig.MODULE_VPN, "VPN interface establish failed - null");
                finishStartFailure();
                return;
            }
            Logger.info(LogConfig.MODULE_VPN,
                    "VPN interface established, fd=" + vpnInterface.getFd());

            vpnInputStream = new FileInputStream(vpnInterface.getFileDescriptor());
            vpnOutputStream = new FileOutputStream(vpnInterface.getFileDescriptor());
            vpnInputChannel = vpnInputStream.getChannel();
            vpnOutputChannel = vpnOutputStream.getChannel();

            SocketProtector protector = createSocketProtector();

            // 引擎生命周期管理（含指数退避重连）。引擎实例同步创建，
            // start() 返回后 getEngine() 即非 null，路由器可立即使用。
            TunnelManager tm = TunnelManager.get(getApplicationContext());
            tunnelManager = tm;
            tm.setStateListener(state -> {
                connectionState = state;
                updateNotification();
            });
            // stats 行由 TunnelManager 直接经 LocalBroadcastManager 发给 UI，
            // 这里无需再注册 statsListener。
            EngineConfig engineCfg = new EngineConfig(serverHost, serverPort, psk,
                    fecData, fecParityMax, mtuMin, probeIntervalSec, logLevel());
            engineCfg.proxyPort = proxyPort; // 原样传入：0 表示不启动本机代理
            tm.start(engineCfg, protector);

            // 数据包路由器：TUN ↔ 隧道流搬运（含 LAN/DNS 豁免）
            PacketRouter pr = new PacketRouter(tm, mtuMin);
            packetRouter = pr;
            pr.setSocketProtector(protector);
            pr.start();

            startVpnReadThread(pr);

            connectionStartTime = System.currentTimeMillis();
            statsHandler.removeCallbacks(statsTicker);
            statsHandler.post(statsTicker);
            updateNotification();

            // 启动全程未持锁，stopVpn/onRevoke 的 closeVpn 可能插在任意两步之间。
            // epoch 变了说明有 stop 落在装配期间：补一次完整清理，确保停干净。
            if (closeEpoch.get() != startEpoch) {
                Logger.warning(LogConfig.MODULE_VPN,
                        "Stop request landed during VPN startup; completing teardown");
                synchronized (this) {
                    vpnClosed = false;
                }
                closeVpn();
                return;
            }

            Logger.info(LogConfig.MODULE_VPN, "LOCAL_VPN_STARTED VPN started successfully;"
                    + " awaiting engine onEstablished ( Stub 阶段将直接进入断开态)");
        } catch (Exception e) {
            Logger.error(LogConfig.MODULE_VPN, "Start VPN error: " + e.getMessage());
            Log.e(TAG, "startVpn failed", e);
            closeVpn();
            connectionState = VpnConnectionState.DISCONNECTED;
            broadcastState();
            updateNotification();
            stopSelf();
        }
    }

    /**
     * 建 TUN。路由与 DNS 豁免策略照搬 kcp：
     * 只通告 IPv4（0.0.0.0/0）——把 IPv6 也收进隧道会让所有 IPv6 目标在服务端
     * 连接失败，而本地合成的 SYN-ACK 又击穿应用的 Happy Eyeballs 回退。不通告
     * ::/0 后，应用的 IPv6 连接立即因无路由失败，Happy Eyeballs 正确回退到 IPv4。
     * DNS 通告 1.1.1.1/8.8.8.8，由 PacketRouter 本地中继（不经隧道）。
     */
    private ParcelFileDescriptor buildVpnInterface() throws IOException,
            android.content.pm.PackageManager.NameNotFoundException {
        Builder builder = new Builder();
        builder.setSession(VpnConfig.VPN_SESSION_NAME)
                .setMtu(mtuMin > 0 ? mtuMin : VpnConfig.VPN_MTU)
                .addAddress(VpnConfig.VPN_ADDRESS, VpnConfig.VPN_ADDRESS_PREFIX)
                .addRoute("0.0.0.0", 0)
                .addDnsServer("1.1.1.1")
                .addDnsServer("8.8.8.8");

        // 分应用代理：白名单非空时只有选中的应用走 VPN，其余直连。
        // addAllowedApplication 与 addDisallowedApplication 互斥，因此两种情形
        // 只能二选一；白名单里若出现自己会被 VPN 回环，这里跳过。
        java.util.Set<String> onlyApps = ConfigStore.getVpnApps(this);
        int applied = 0;
        int missing = 0;
        if (onlyApps.isEmpty()) {
            builder.addDisallowedApplication(getPackageName());
            Logger.info(LogConfig.MODULE_VPN, "VPN Builder route=0.0.0.0/0 (IPv4 only)"
                    + " dns=1.1.1.1,8.8.8.8 mode=all-apps excludedApp=" + getPackageName());
        } else {
            for (String pkg : onlyApps) {
                if (pkg == null || pkg.equals(getPackageName())) continue;
                try {
                    builder.addAllowedApplication(pkg);
                    ++applied;
                } catch (android.content.pm.PackageManager.NameNotFoundException e) {
                    // 应用已卸载：跳过，不让整条隧道建不起来
                    ++missing;
                }
            }
            if (applied == 0) {
                // 白名单里的应用全都没了：退回全部应用，总比建一个空隧道强
                builder.addDisallowedApplication(getPackageName());
                Logger.warning(LogConfig.MODULE_VPN,
                        "VPN 白名单里的应用都已卸载，退回全部应用模式");
            } else {
                Logger.info(LogConfig.MODULE_VPN, "VPN Builder route=0.0.0.0/0 (IPv4 only)"
                        + " dns=1.1.1.1,8.8.8.8 mode=whitelist apps=" + applied
                        + " missing=" + missing);
            }
        }
        return builder.establish();
    }

    /**
     * SocketProtector 实现（照搬 kcp）：protect DatagramSocket/Socket/fd +
     * bindToNetwork（绕过模拟器上 protect() 失效的问题）。
     */
    private SocketProtector createSocketProtector() {
        return new SocketProtector() {
            @Override
            public boolean protect(DatagramSocket socket) {
                boolean ok = FcpVpnService.this.protect(socket);
                Logger.info(LogConfig.MODULE_VPN, "Protected UDP socket: " + ok);
                return ok;
            }

            @Override
            public boolean protect(Socket socket) {
                boolean ok = FcpVpnService.this.protect(socket);
                Logger.info(LogConfig.MODULE_VPN, "Protected TCP socket: " + ok);
                return ok;
            }

            @Override
            public boolean protect(int fd) {
                boolean ok = FcpVpnService.this.protect(fd);
                Logger.info(LogConfig.MODULE_VPN, "Protected socket fd=" + fd + ": " + ok);
                return ok;
            }

            @Override
            public void bindToNetwork(Socket socket) throws IOException {
                ConnectivityManager cm =
                        (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
                if (cm == null) {
                    Logger.warning(LogConfig.MODULE_VPN,
                            "ConnectivityManager is null, cannot bind socket to network");
                    return;
                }
                Network[] networks = cm.getAllNetworks();
                for (Network network : networks) {
                    NetworkCapabilities caps = cm.getNetworkCapabilities(network);
                    if (caps != null
                            && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                            && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) {
                        network.bindSocket(socket);
                        Logger.info(LogConfig.MODULE_VPN,
                                "Socket bound to underlying network: " + network);
                        return;
                    }
                }
                Logger.warning(LogConfig.MODULE_VPN, "No underlying network found for socket binding");
            }
        };
    }

    private void startVpnReadThread(PacketRouter router) {
        vpnReadThread = new Thread(() -> {
            ByteBuffer buffer = ByteBuffer.allocate(mtuMin > 0 ? mtuMin + 64 : 1104);

            while (running.get()) {
                try {
                    // 取一次快照：closeVpn 会在另一个线程把这些字段置 null。
                    FileChannel in = vpnInputChannel;
                    if (in == null || router == null) {
                        break;
                    }

                    buffer.clear();
                    int len = in.read(buffer);

                    if (len > 0) {
                        buffer.flip();
                        byte[] packet = new byte[len];
                        buffer.get(packet);
                        uploadBytes.addAndGet(len);

                        // 处理出站数据包；路由器合成的响应包写回 TUN
                        router.handleOutboundPacket(packet, responsePacket -> {
                            try {
                                writeToVpn(responsePacket);
                                downloadBytes.addAndGet(responsePacket.length);
                            } catch (IOException e) {
                                Logger.error(LogConfig.MODULE_VPN,
                                        "VPN write-back error: " + e.getMessage());
                            }
                        });
                    } else if (len == 0) {
                        // establish() 返回的 fd 默认是非阻塞的，没有数据可读时立刻
                        // 返回 0。退让 1ms 把空转压成 1kHz 轮询（耗电/发热保护）。
                        Thread.sleep(1);
                    }
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    break;
                } catch (IOException e) {
                    if (running.get()) {
                        Logger.error(LogConfig.MODULE_VPN, "VPN read error: " + e.getMessage());
                    }
                    break;
                }
            }
        }, "VPN-Read");
        vpnReadThread.start();
    }

    private synchronized void writeToVpn(byte[] packet) throws IOException {
        // closeVpn 与本方法同锁，但调用方判空之后、进入本方法之前仍可能已被关闭。
        FileChannel out = vpnOutputChannel;
        if (out == null) {
            throw new IOException("VPN interface already closed");
        }
        ByteBuffer buffer = ByteBuffer.wrap(packet);
        int stalls = 0;
        while (buffer.hasRemaining()) {
            int written = out.write(buffer);
            if (written > 0) {
                stalls = 0;
                continue;
            }
            // write 返回 0：fd 是非阻塞的且 tun 队列已满。退让后重试。
            if (++stalls > VPN_WRITE_MAX_STALLS) {
                throw new IOException("VPN write stalled: " + buffer.remaining()
                        + " of " + packet.length + " bytes undelivered after "
                        + VPN_WRITE_MAX_STALLS + " retries");
            }
            try {
                Thread.sleep(1);
            } catch (InterruptedException ie) {
                Thread.currentThread().interrupt();
                throw new IOException("VPN write interrupted");
            }
        }
        Logger.debug(LogConfig.MODULE_VPN, "VPN WRITE len=" + packet.length);
    }

    private void finishStartFailure() {
        closeVpn();
        connectionState = VpnConnectionState.DISCONNECTED;
        broadcastState();
        updateNotification();
        stopSelf();
    }

    /**
     * 关闭 VPN。synchronized 必需：onDestroy / onRevoke / stopVpn 三条路径都会
     * 调用，且 writeToVpn 也锁 this；没有它两个 closeVpn 会交错地把字段置 null。
     */
    private synchronized void closeVpn() {
        if (vpnClosed) {
            return;
        }
        vpnClosed = true;
        closeEpoch.incrementAndGet();

        running.set(false);
        statsHandler.removeCallbacks(statsTicker);

        Logger.info(LogConfig.MODULE_VPN, "Closing VPN...");

        // 每个拆除步骤相互隔离：任一步抛异常都不能跳过其余步骤
        // （否则泄漏 socket/线程/TUN fd，"VPN closed" 也不会打出来）。
        TunnelManager tm = tunnelManager;
        tunnelManager = null;
        if (tm != null) {
            try {
                tm.setStateListener(null);
                tm.setStatsListener(null);
                tm.stop();
            } catch (RuntimeException e) {
                Logger.error(LogConfig.MODULE_VPN, "tunnel stop failed: " + e);
            }
        }

        PacketRouter pr = packetRouter;
        packetRouter = null;
        if (pr != null) {
            try {
                pr.stop();
            } catch (RuntimeException e) {
                Logger.error(LogConfig.MODULE_VPN, "PacketRouter stop failed: " + e);
            }
        }

        // 先关闭 VPN 接口，解除 vpnReadThread 的阻塞读
        try {
            if (vpnInterface != null) {
                vpnInterface.close();
            }
            if (vpnInputStream != null) {
                vpnInputStream.close();
            }
            if (vpnOutputStream != null) {
                vpnOutputStream.close();
            }
        } catch (IOException e) {
            Logger.error(LogConfig.MODULE_VPN, "Close VPN interface error: " + e.getMessage());
        }

        if (vpnReadThread != null) {
            vpnReadThread.interrupt();
            try {
                vpnReadThread.join(2000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            vpnReadThread = null;
        }

        vpnInputStream = null;
        vpnOutputStream = null;
        vpnInputChannel = null;
        vpnOutputChannel = null;
        vpnInterface = null;

        // 清除保存的参数（完整拆除意味着用户停止或授权被撤销，
        // START_STICKY 不应再用旧参数复活）
        clearSavedParams();

        Logger.info(LogConfig.MODULE_VPN, "VPN closed");
    }

    @Override
    public void onDestroy() {
        closeVpn();
        connectionState = VpnConnectionState.DISCONNECTED;
        broadcastState();
        stopForeground(true);
        super.onDestroy();
    }

    @Override
    public void onRevoke() {
        Logger.warning(LogConfig.MODULE_VPN, "VPN authorization revoked");
        closeVpn();
        connectionState = VpnConnectionState.DISCONNECTED;
        broadcastState();
        stopForeground(true);
        stopSelf();
    }

    /** 停止 VPN（ACTION_STOP 与外部调用）。 */
    public void stopVpn() {
        closeVpn();
        connectionState = VpnConnectionState.DISCONNECTED;
        broadcastState();
        stopForeground(true);
        stopSelf();
    }

    public VpnConnectionState getConnectionState() {
        return connectionState;
    }

    public long getConnectionDuration() {
        if (!running.get() || connectionStartTime == 0) {
            return 0;
        }
        return (System.currentTimeMillis() - connectionStartTime) / 1000;
    }

    private static String formatBytes(long bytes) {
        if (bytes < 1024) {
            return bytes + "B";
        } else if (bytes < 1024 * 1024) {
            return bytes / 1024 + "KB";
        } else {
            return bytes / (1024 * 1024) + "MB";
        }
    }

    private static String formatDuration(long seconds) {
        if (seconds < 60) {
            return seconds + "s";
        }
        return (seconds / 60) + "m" + (seconds % 60) + "s";
    }

    /** EngineConfig.logLevel 用构建配置里的日志级别。 */
    private static String logLevel() {
        return com.dchen.fcpvpn.BuildConfig.DEFAULT_LOG_LEVEL.toLowerCase();
    }

    // ------------------------------------------------------------ 参数持久化

    /**
     * 保存参数到 SharedPreferences。PSK 经 SecretPrefs 用 Keystore 包裹后落盘；
     * 其余非敏感参数明文存储。只服务于 START_STICKY 重启恢复。
     */
    private void saveParams() {
        SharedPreferences prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        SecretPrefs.save(prefs, psk);
        prefs.edit()
                .putString(KEY_SERVER_HOST, serverHost)
                .putInt(KEY_SERVER_PORT, serverPort)
                .putInt(KEY_FEC_DATA, fecData)
                .putInt(KEY_FEC_PARITY_MAX, fecParityMax)
                .putInt(KEY_MTU_MIN, mtuMin)
                .putInt(KEY_PROBE_INTERVAL, probeIntervalSec)
                .putInt(KEY_PROXY_PORT, proxyPort)
                .apply();
    }

    private void restoreParams() {
        SharedPreferences prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        serverHost = prefs.getString(KEY_SERVER_HOST, null);
        serverPort = prefs.getInt(KEY_SERVER_PORT, 0);
        psk = SecretPrefs.load(prefs);
        fecData = prefs.getInt(KEY_FEC_DATA, VpnConfig.DEFAULT_FEC_DATA);
        fecParityMax = prefs.getInt(KEY_FEC_PARITY_MAX, VpnConfig.DEFAULT_FEC_PARITY_MAX);
        mtuMin = prefs.getInt(KEY_MTU_MIN, VpnConfig.DEFAULT_MTU_MIN);
        probeIntervalSec = prefs.getInt(KEY_PROBE_INTERVAL, VpnConfig.DEFAULT_PROBE_INTERVAL_SEC);
        proxyPort = prefs.getInt(KEY_PROXY_PORT, VpnConfig.DEFAULT_PROXY_PORT);
    }

    private void clearSavedParams() {
        SharedPreferences prefs = getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        SecretPrefs.clear(prefs);
        prefs.edit().clear().apply();
        serverHost = null;
        serverPort = 0;
        psk = null;
    }

    // ------------------------------------------------------------ 状态广播

    private void broadcastState() {
        PacketRouter pr = packetRouter;
        int sessions = pr != null ? pr.getActiveConnectionCount() : -1;
        long duration = getConnectionDuration();
        Logger.info(LogConfig.MODULE_VPN, "Broadcasting state: " + connectionState.getDisplayText());

        Intent intent = new Intent(VpnStateBroadcast.ACTION_STATE_CHANGED);
        intent.putExtra(VpnStateBroadcast.EXTRA_STATE, connectionState.name());
        intent.putExtra(VpnStateBroadcast.EXTRA_UPLOAD_BYTES, uploadBytes.get());
        intent.putExtra(VpnStateBroadcast.EXTRA_DOWNLOAD_BYTES, downloadBytes.get());
        intent.putExtra(VpnStateBroadcast.EXTRA_DURATION, duration);
        intent.putExtra(VpnStateBroadcast.EXTRA_SESSIONS, sessions);
        TunnelManager tm = tunnelManager;
        if (tm != null) {
            String stats = tm.getLastStatsLine();
            if (stats != null) {
                intent.putExtra(VpnStateBroadcast.EXTRA_STATS_LINE, stats);
            }
        }
        LocalBroadcastManager.getInstance(this).sendBroadcast(intent);
    }
}
