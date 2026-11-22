package com.dchen.fcpvpn.core.session;

/**
 * 隧道内连接目标（对应 FCP OPEN 的 atyp/addr/port）。
 */
public final class OpenTarget {

    public static final int ATYP_IPV4 = 1;
    public static final int ATYP_DOMAIN = 3;
    public static final int ATYP_IPV6 = 4;

    /** atyp: 1=IPv4（address 为 4 字节）、3=域名（address 为 null，host 为域名）、4=IPv6（16 字节） */
    public final int atyp;
    /** IPv4/IPv6 的原始字节；域名时为 null。 */
    public final byte[] address;
    /** 域名（atyp=3 时）；IP 时为 null。 */
    public final String host;
    public final int port;

    public static OpenTarget ipv4(byte[] addr4, int port) {
        return new OpenTarget(ATYP_IPV4, addr4, null, port);
    }

    public static OpenTarget domain(String host, int port) {
        return new OpenTarget(ATYP_DOMAIN, null, host, port);
    }

    public OpenTarget(int atyp, byte[] address, String host, int port) {
        this.atyp = atyp;
        this.address = address;
        this.host = host;
        this.port = port;
    }
}
