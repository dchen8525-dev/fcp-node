package com.dchen.fcpvpn.core.interop;

import java.io.File;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * 互操作测试的服务端夹具：在测试进程里拉起仓库根目录下的
 * `src/app/server.ts`（Node ≥ 22.18 直接运行 TS）。
 *
 * 仓库根从工作目录向上探测（`src/app/server.ts` 存在即认定为根），因此
 * `android/` 作为 monorepo 子项目、或单独 checkout 时都能找到；也支持
 * {@code -DfcpNodeRoot=...} / {@code FCP_NODE_ROOT} 显式覆盖。
 */
final class FcpServerProcess {

    private FcpServerProcess() {}

    /** 定位仓库根；找不到返回 null（测试用 assumeTrue 跳过）。 */
    static File repoRoot() {
        String override = System.getProperty("fcpNodeRoot");
        if (override == null || override.isEmpty()) override = System.getenv("FCP_NODE_ROOT");
        if (override != null && !override.isEmpty()) {
            File f = new File(override).getAbsoluteFile();
            return new File(f, "src/app/server.ts").isFile() ? f : null;
        }
        File dir = new File(System.getProperty("user.dir")).getAbsoluteFile();
        for (int i = 0; i < 6 && dir != null; ++i) {
            if (new File(dir, "src/app/server.ts").isFile()) return dir;
            dir = dir.getParentFile();
        }
        return null;
    }

    static boolean nodeAvailable() {
        try {
            Process p = new ProcessBuilder("node", "--version").start();
            boolean ok = p.waitFor(5, TimeUnit.SECONDS);
            p.destroyForcibly();
            return ok;
        } catch (Exception e) {
            return false;
        }
    }

    /** 起服务端（UDP 端口由调用方指定）；返回的 Process 需在 finally 里 destroy。 */
    static Process start(int port, String keyHex, String... extraArgs) throws Exception {
        File root = repoRoot();
        if (root == null) throw new IllegalStateException("找不到 fcp-node 仓库根（src/app/server.ts）");
        List<String> cmd = new ArrayList<>();
        cmd.add("node");
        cmd.add(new File(root, "src/app/server.ts").getAbsolutePath());
        cmd.add("--key=" + keyHex);
        cmd.add("-b");
        cmd.add("127.0.0.1:" + port);
        cmd.add("--log-level=warn");
        for (String a : extraArgs) cmd.add(a);
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.directory(root);
        pb.redirectErrorStream(true);
        Process p = pb.start();
        // 必须持续消费 stdout，否则管道写满会阻塞服务端
        Thread drain = new Thread(() -> {
            try (InputStream in = p.getInputStream()) {
                byte[] buf = new byte[4096];
                while (in.read(buf) != -1) { /* discard */ }
            } catch (Exception ignored) {
                // 进程退出
            }
        });
        drain.setDaemon(true);
        drain.start();
        return p;
    }
}
