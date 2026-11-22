package com.dchen.fcpvpn.core.session;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.Socket;

/**
 * Socket 保护接口 - 用于 VPN 场景下保护 socket 不被 VPN 路由循环
 * （照搬 kcp-proxy-andriod 同名接口）。
 */
public interface SocketProtector {
    boolean protect(DatagramSocket socket);
    boolean protect(Socket socket);

    /**
     * 通过文件描述符保护 socket（绕过 Android VpnService.protect(Socket) 的兼容性问题）
     */
    boolean protect(int fd);

    /**
     * 将 socket 显式绑定到底层物理网络（绕过 emulator 中 protect() 无法正常工作的问题）
     */
    default void bindToNetwork(Socket socket) throws IOException {
        // 默认空实现，由 FcpVpnService 提供具体实现
    }
}
