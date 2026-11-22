package com.dchen.fcpvpn.core.proxy;

import com.dchen.fcpvpn.core.wire.Bytes;
import com.dchen.fcpvpn.core.wire.Wire;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * 本机代理入口编解码。移植自 fcp-node src/proxy/codec.ts
 * （对应 C++ src/proxy/proxy_proto.{h,cc}）。
 * 多字节代理字段一律网络序（大端）——与协议其余部分的小端相反。
 * FCP OPEN 是隧道流的首字节，不是独立帧。
 */
public final class ProxyCodec {

    private ProxyCodec() {}

    // ---- 常量（constants.ts Proxy 段）----
    public static final int ATYP_IPV4 = 0x01;
    public static final int ATYP_DOMAIN = 0x03;
    public static final int ATYP_IPV6 = 0x04;
    public static final int SOCKS5_VERSION = 0x05;
    public static final int SOCKS5_METHOD_NO_AUTH = 0x00;
    public static final int SOCKS5_METHOD_NONE = 0xff;
    public static final int SOCKS5_CMD_CONNECT = 0x01;
    public static final int SOCKS5_GREETING_REPLY_LEN = 2;
    public static final int SOCKS5_REPLY_LEN = 10;
    public static final int SOCKS5_MAX_DOMAIN_LEN = 255;
    public static final int SOCKS5_MAX_GREETING_BYTES = 257;
    public static final int SOCKS5_MAX_REQUEST_BYTES = 262;
    public static final int HTTP_HEAD_MAX_BYTES = 8192;
    public static final int HTTP_MAX_HOST_LEN = 255;
    public static final int HTTP_FORWARD_DEFAULT_PORT = 80;
    public static final byte[] OPEN_MAGIC = "FCPO".getBytes(StandardCharsets.US_ASCII);
    public static final int OPEN_VERSION = 1;
    public static final int OPEN_KIND_OK = 0x01;
    public static final int OPEN_KIND_ERR = 0xff;
    public static final int OPEN_MAX_ADDR_LEN = 255;
    public static final int OPEN_OK_LEN = 8;
    public static final int OPEN_ERR_LEN = 7;
    public static final int OPEN_MAX_BYTES = 264;

    /** OpenError（constants.ts:513-515）。 */
    public static final int OPEN_ERR_REFUSED = 1;
    public static final int OPEN_ERR_DNS = 2;
    public static final int OPEN_ERR_TARGET_TIMEOUT = 3;
    public static final int OPEN_ERR_NOT_SUPPORTED = 4;
    public static final int OPEN_ERR_TOO_MANY_SESSIONS = 5;

    // ---- 解析状态（ParseStatus）----
    public static final int NEED_MORE = 0;
    public static final int OK = 1;
    public static final int MALFORMED = 2;
    public static final int BAD_MAGIC = 3;
    public static final int BAD_VERSION = 4;
    public static final int BAD_ATYP = 5;
    public static final int BAD_ADDRESS = 6;
    public static final int COMMAND_NOT_SUPPORTED = 7;
    public static final int METHOD_NOT_ALLOWED = 8;
    public static final int BAD_REQUEST = 9;
    public static final int HEAD_TOO_LARGE = 10;

    /** 代理目标（ProxyTarget）。addr 为原始字节：IPv4 4 字节 / IPv6 16 字节 / 域名 latin1。 */
    public static final class ProxyTarget {
        public final int atyp;
        public final byte[] addr;
        public final int port;

        public ProxyTarget(int atyp, byte[] addr, int port) {
            this.atyp = atyp;
            this.addr = addr;
            this.port = port;
        }
    }

    /** 解析结果（ParseResult）。value/extra 按解析器语义填充。 */
    public static final class ParseResult {
        public final int status;
        public final int consumed;
        public final ProxyTarget target;
        public final byte[] extra;
        /** SOCKS5 greeting 的 noAuth / OPEN reply 的 ok+err 等附加载荷。 */
        public final boolean boolValue;
        public final int intValue;
        public final String[] requestLine;
        public final byte[] rewrittenHead;

        ParseResult(int status, int consumed, ProxyTarget target, byte[] extra,
                    boolean boolValue, int intValue, String[] requestLine, byte[] rewrittenHead) {
            this.status = status;
            this.consumed = consumed;
            this.target = target;
            this.extra = extra;
            this.boolValue = boolValue;
            this.intValue = intValue;
            this.requestLine = requestLine;
            this.rewrittenHead = rewrittenHead;
        }
    }

    private static ParseResult of(int status) {
        return new ParseResult(status, 0, null, null, false, 0, null, null);
    }

    public static boolean atypValid(int a) {
        return a == ATYP_IPV4 || a == ATYP_DOMAIN || a == ATYP_IPV6;
    }

    public static int atypAddrLen(int a) {
        return a == ATYP_IPV4 ? 4 : a == ATYP_IPV6 ? 16 : 0;
    }

    private static boolean hostCharOk(int c) {
        return (c >= 0x61 && c <= 0x7a) || (c >= 0x41 && c <= 0x5a)
                || (c >= 0x30 && c <= 0x39) || c == 0x2e || c == 0x2d || c == 0x5f;
    }

    private static boolean ipv6CharOk(int c) {
        return (c >= 0x30 && c <= 0x39) || (c >= 0x61 && c <= 0x66)
                || (c >= 0x41 && c <= 0x46) || c == 0x3a || c == 0x2e;
    }

    private static int parsePort(byte[] p, int n) {
        if (n == 0 || n > 5) return 0;
        int v = 0;
        for (int i = 0; i < n; ++i) {
            int c = p[i] & 0xff;
            if (c < 0x30 || c > 0x39) return 0;
            v = v * 10 + (c - 0x30);
        }
        return (v == 0 || v > 65535) ? 0 : v;
    }

    // ---- SOCKS5 ----

    /** greeting：ver | n | methods...，返回 noAuth。 */
    public static ParseResult socks5ParseGreeting(byte[] buf) {
        return socks5ParseGreeting(buf, buf.length);
    }

    public static ParseResult socks5ParseGreeting(byte[] buf, int len) {
        if (len == 0) return of(NEED_MORE);
        if ((buf[0] & 0xff) != SOCKS5_VERSION) return of(MALFORMED);
        if (len < 2) return of(NEED_MORE);
        int n = buf[1] & 0xff;
        if (n == 0) return of(MALFORMED);
        if (len < 2 + n) return of(NEED_MORE);
        boolean noAuth = false;
        for (int i = 0; i < n; ++i) {
            if ((buf[2 + i] & 0xff) == SOCKS5_METHOD_NO_AUTH) {
                noAuth = true;
                break;
            }
        }
        return new ParseResult(OK, 2 + n, null, null, noAuth, 0, null, null);
    }

    public static byte[] socks5GreetingReply(boolean accept) {
        return new byte[]{(byte) SOCKS5_VERSION,
                (byte) (accept ? SOCKS5_METHOD_NO_AUTH : SOCKS5_METHOD_NONE)};
    }

    /** Socks5Rep（codec.ts:67-71）。 */
    public static final int REP_SUCCEEDED = 0;
    public static final int REP_GENERAL_FAILURE = 1;
    public static final int REP_NOT_ALLOWED = 2;
    public static final int REP_NETWORK_UNREACHABLE = 3;
    public static final int REP_HOST_UNREACHABLE = 4;
    public static final int REP_CONNECTION_REFUSED = 5;
    public static final int REP_TTL_EXPIRED = 6;
    public static final int REP_COMMAND_NOT_SUPPORTED = 7;
    public static final int REP_ATYP_NOT_SUPPORTED = 8;

    public static ParseResult socks5ParseRequest(byte[] buf) {
        return socks5ParseRequest(buf, buf.length);
    }

    public static ParseResult socks5ParseRequest(byte[] buf, int len) {
        if (len == 0) return of(NEED_MORE);
        int win = Math.min(len, SOCKS5_MAX_REQUEST_BYTES);
        if ((buf[0] & 0xff) != SOCKS5_VERSION) return of(MALFORMED);
        if (win < 4) return of(NEED_MORE);
        if ((buf[1] & 0xff) != SOCKS5_CMD_CONNECT) return of(COMMAND_NOT_SUPPORTED);
        if (buf[2] != 0) return of(MALFORMED);
        int atyp = buf[3] & 0xff;
        if (!atypValid(atyp)) return of(BAD_ATYP);
        int addrLen = atypAddrLen(atyp);
        int header = 4;
        if (atyp == ATYP_DOMAIN) {
            if (win < 5) return of(NEED_MORE);
            addrLen = buf[4] & 0xff;
            header = 5;
            if (addrLen == 0) return of(MALFORMED);
        }
        int total = header + addrLen + 2;
        if (win < total) return of(NEED_MORE);
        if (atyp == ATYP_DOMAIN) {
            for (int i = 0; i < addrLen; ++i) {
                if (!hostCharOk(buf[header + i] & 0xff)) return of(MALFORMED);
            }
        }
        int port = Wire.getBe16(buf, header + addrLen);
        if (port == 0) return of(MALFORMED);
        return new ParseResult(OK, total,
                new ProxyTarget(atyp, Arrays.copyOfRange(buf, header, header + addrLen), port),
                null, false, 0, null, null);
    }

    public static byte[] socks5Reply(int rep) {
        byte[] out = new byte[SOCKS5_REPLY_LEN];
        out[0] = (byte) SOCKS5_VERSION;
        out[1] = (byte) rep;
        out[3] = (byte) ATYP_IPV4;
        return out;
    }

    public static int socks5RepForOpenError(int e) {
        switch (e) {
            case OPEN_ERR_REFUSED: return REP_CONNECTION_REFUSED;
            case OPEN_ERR_DNS: return REP_HOST_UNREACHABLE;
            case OPEN_ERR_TARGET_TIMEOUT: return REP_TTL_EXPIRED;
            case OPEN_ERR_NOT_SUPPORTED: return REP_ATYP_NOT_SUPPORTED;
            case OPEN_ERR_TOO_MANY_SESSIONS: return REP_NOT_ALLOWED;
            default: return REP_GENERAL_FAILURE;
        }
    }

    // ---- HTTP ----

    public static final byte[] HTTP_OK =
            "HTTP/1.1 200 Connection Established\r\n\r\n".getBytes(StandardCharsets.US_ASCII);
    public static final byte[] HTTP_BAD_REQUEST =
            "HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n".getBytes(StandardCharsets.US_ASCII);
    public static final byte[] HTTP_BAD_GATEWAY =
            "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n".getBytes(StandardCharsets.US_ASCII);
    public static final byte[] HTTP_METHOD_NOT_ALLOWED =
            "HTTP/1.1 405 Method Not Allowed\r\nAllow: CONNECT\r\nConnection: close\r\n\r\n"
                    .getBytes(StandardCharsets.US_ASCII);
    public static final byte[] HTTP_HEAD_TOO_LARGE =
            "HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\n\r\n"
                    .getBytes(StandardCharsets.US_ASCII);
    public static final byte[] HTTP_FORWARD_METHOD_NOT_ALLOWED =
            ("HTTP/1.1 405 Method Not Allowed\r\nAllow: CONNECT, GET, HEAD, POST, PUT, DELETE, "
                    + "OPTIONS, PATCH\r\nConnection: close\r\n\r\n").getBytes(StandardCharsets.US_ASCII);

    private static int findHeadEnd(byte[] b, int win) {
        for (int i = 0; i + 4 <= win; ++i) {
            if (b[i] == 13 && b[i + 1] == 10 && b[i + 2] == 13 && b[i + 3] == 10) return i;
        }
        return -1;
    }

    private static int findLineEnd(byte[] b, int win) {
        for (int i = 0; i + 2 <= win; ++i) {
            if (b[i] == 13 && b[i + 1] == 10) return i;
        }
        return -1;
    }

    private static String[] splitRequestLine(byte[] b, int lineLen) {
        String line = new String(b, 0, lineLen, StandardCharsets.US_ASCII).trim();
        return line.split("\\s+");
    }

    private static boolean httpVersionOk(String v) {
        return v.equals("HTTP/1.0") || v.equals("HTTP/1.1");
    }

    /**
     * 解析括号形式的 IPv6 字面量（"::1"、"2001:db8::1"、"::ffff:192.0.2.1"）为
     * 16 字节网络序；非法返回 null。Java 的 InetAddress 可作替代校验，但这里按
     * 源码自行展开（codec.ts:151-184）。
     */
    public static byte[] parseIpv6Literal(String text) {
        if (text == null || text.isEmpty() || text.length() > 45) return null;
        String body = text;
        int lastColon = text.lastIndexOf(':');
        if (lastColon >= 0 && text.substring(lastColon + 1).indexOf('.') >= 0) {
            String[] v4 = text.substring(lastColon + 1).split("\\.");
            if (v4.length != 4) return null;
            int[] parts = new int[4];
            for (int i = 0; i < 4; ++i) {
                if (!v4[i].matches("^\\d{1,3}$")) return null;
                parts[i] = Integer.parseInt(v4[i]);
                if (parts[i] > 255) return null;
            }
            String hi = Integer.toHexString((parts[0] << 8) | parts[1]);
            String lo = Integer.toHexString((parts[2] << 8) | parts[3]);
            body = text.substring(0, lastColon + 1) + hi + ":" + lo;
        }
        int dbl = body.indexOf("::");
        if (dbl >= 0 && body.indexOf("::", dbl + 2) >= 0) return null; // 两个 "::"
        String head = dbl >= 0 ? body.substring(0, dbl) : body;
        String rear = dbl >= 0 ? body.substring(dbl + 2) : "";
        int[] headParts = parseHextets(head);
        int[] rearParts = parseHextets(rear);
        if (headParts == null || rearParts == null) return null;
        // "::" 必须至少压缩一组；否则必须恰好 8 组。
        int zeros = dbl >= 0 ? 8 - headParts.length - rearParts.length : 0;
        if (dbl >= 0 ? zeros < 1 : headParts.length + rearParts.length != 8) return null;
        int[] words;
        if (dbl >= 0) {
            words = new int[headParts.length + zeros + rearParts.length];
            System.arraycopy(headParts, 0, words, 0, headParts.length);
            Arrays.fill(words, headParts.length, headParts.length + zeros, 0);
            System.arraycopy(rearParts, 0, words, headParts.length + zeros, rearParts.length);
        } else {
            words = headParts;
        }
        if (words.length != 8) return null;
        byte[] out = new byte[16];
        for (int i = 0; i < 8; ++i) {
            Wire.putBe16(words[i], out, i * 2);
        }
        return out;
    }

    private static int[] parseHextets(String s) {
        if (s.isEmpty()) return new int[0];
        String[] parts = s.split(":", -1);
        int[] out = new int[parts.length];
        for (int i = 0; i < parts.length; ++i) {
            if (!parts[i].matches("^[0-9a-fA-F]{1,4}$")) return null;
            out[i] = Integer.parseInt(parts[i], 16);
        }
        return out;
    }

    private static final class Authority {
        String host;
        int port;
        byte[] ipv6;
    }

    private static Authority parseAuthority(String text, int defaultPort) {
        if (text == null || text.isEmpty()) return null;
        for (int i = 0; i < text.length(); ++i) {
            int c = text.charAt(i);
            if (c == 0x40 || c < 0x21 || c > 0x7e) return null;
        }
        Authority a = new Authority();
        a.port = defaultPort;
        if (text.charAt(0) == '[') {
            int close = text.indexOf(']');
            if (close < 2) return null;
            a.host = text.substring(1, close);
            if (close + 1 < text.length()) {
                if (text.charAt(close + 1) != ':') return null;
                int p = parsePort(text.substring(close + 2).getBytes(StandardCharsets.US_ASCII),
                        text.length() - close - 2);
                if (p == 0) return null;
                a.port = p;
            }
            for (int i = 0; i < a.host.length(); ++i) {
                if (!ipv6CharOk(a.host.charAt(i))) return null;
            }
            a.ipv6 = parseIpv6Literal(a.host);
            if (a.ipv6 == null) return null;
            return a;
        }
        int colons = 0;
        for (int i = 0; i < text.length(); ++i) if (text.charAt(i) == ':') ++colons;
        if (colons > 1) return null;
        if (colons == 1) {
            int idx = text.indexOf(':');
            a.host = text.substring(0, idx);
            int p = parsePort(text.substring(idx + 1).getBytes(StandardCharsets.US_ASCII),
                    text.length() - idx - 1);
            if (p == 0) return null;
            a.port = p;
        } else {
            a.host = text;
        }
        for (int i = 0; i < a.host.length(); ++i) {
            if (!hostCharOk(a.host.charAt(i))) return null;
        }
        if (a.host.isEmpty() || a.host.length() > HTTP_MAX_HOST_LEN) return null;
        return a;
    }

    public static ParseResult httpParseConnect(byte[] buf) {
        return httpParseConnect(buf, buf.length);
    }

    public static ParseResult httpParseConnect(byte[] buf, int len) {
        boolean capped = len >= HTTP_HEAD_MAX_BYTES;
        int win = capped ? HTTP_HEAD_MAX_BYTES : len;
        int blank = findHeadEnd(buf, win);
        if (blank < 0) return of(capped ? HEAD_TOO_LARGE : NEED_MORE);
        int headLen = blank + 4;
        int lineEnd = findLineEnd(buf, headLen);
        if (lineEnd < 0 || lineEnd > blank) return of(BAD_REQUEST);
        String[] tok = splitRequestLine(buf, lineEnd);
        if (tok.length != 3 || !tok[0].toUpperCase().equals("CONNECT") || !httpVersionOk(tok[2])) {
            return of(METHOD_NOT_ALLOWED);
        }
        Authority auth = parseAuthority(tok[1], 0);
        if (auth == null || auth.port == 0) return of(BAD_REQUEST);
        if (auth.ipv6 != null) {
            return new ParseResult(OK, headLen,
                    new ProxyTarget(ATYP_IPV6, auth.ipv6, auth.port),
                    null, false, 0, tok, null);
        }
        byte[] addr = auth.host.getBytes(StandardCharsets.US_ASCII);
        if (addr.length == 0 || addr.length > SOCKS5_MAX_DOMAIN_LEN) return of(BAD_REQUEST);
        return new ParseResult(OK, headLen,
                new ProxyTarget(ATYP_DOMAIN, addr, auth.port), null, false, 0, tok, null);
    }

    private static final Set<String> FORWARD_METHODS = new HashSet<>(Arrays.asList(
            "GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"));

    private static boolean isTchar(int c) {
        return (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a)
                || c == 0x21 || c == 0x23 || c == 0x24 || c == 0x25 || c == 0x26 || c == 0x27
                || c == 0x2a || c == 0x2b || c == 0x2d || c == 0x2e || c == 0x5e || c == 0x5f
                || c == 0x60 || c == 0x7c || c == 0x7e;
    }

    private static boolean headerValueOk(String v) {
        for (int i = 0; i < v.length(); ++i) {
            int c = v.charAt(i);
            if (c != 0x09 && (c < 0x20 || c > 0x7e)) return false;
        }
        return true;
    }

    private static void collectHops(String value, Set<String> hops) {
        for (String raw : value.split(",")) {
            String name = raw.trim().toLowerCase();
            if (!name.isEmpty()) hops.add(name);
        }
    }

    /** 正向代理：absolute-form URL → origin-form 重写 + 逐跳头剥离。 */
    public static ParseResult httpParseForward(byte[] buf) {
        return httpParseForward(buf, buf.length);
    }

    public static ParseResult httpParseForward(byte[] buf, int len) {
        boolean capped = len >= HTTP_HEAD_MAX_BYTES;
        int win = capped ? HTTP_HEAD_MAX_BYTES : len;
        int blank = findHeadEnd(buf, win);
        if (blank < 0) return of(capped ? HEAD_TOO_LARGE : NEED_MORE);
        int headLen = blank + 4;
        int lineEnd = findLineEnd(buf, headLen);
        if (lineEnd < 0) return of(BAD_REQUEST);
        String[] tok = splitRequestLine(buf, lineEnd);
        if (tok.length != 3 || !FORWARD_METHODS.contains(tok[0]) || !httpVersionOk(tok[2])) {
            return of(METHOD_NOT_ALLOWED);
        }
        String url = tok[1];
        if (!url.startsWith("http://")) return of(BAD_REQUEST);
        String rest = url.substring(7);
        // authority 到第一个 '/'、'?' 或 '#' 为止；fragment 永不发往源服务器。
        int cut = rest.length();
        for (String ch : new String[]{"/", "?", "#"}) {
            int i = rest.indexOf(ch);
            if (i >= 0 && i < cut) cut = i;
        }
        String authority = rest.substring(0, cut);
        String path = rest.substring(cut);
        int hash = path.indexOf('#');
        if (hash >= 0) path = path.substring(0, hash);
        if (path.isEmpty()) path = "/";
        else if (path.charAt(0) == '?') path = "/" + path;
        for (int i = 0; i < path.length(); ++i) {
            int c = path.charAt(i);
            if (c < 0x21 || c > 0x7e) return of(BAD_REQUEST);
        }
        Authority auth = parseAuthority(authority, HTTP_FORWARD_DEFAULT_PORT);
        if (auth == null) return of(BAD_REQUEST);
        byte[] addr = auth.host.getBytes(StandardCharsets.US_ASCII);
        if (addr.length == 0 || addr.length > HTTP_MAX_HOST_LEN) return of(BAD_REQUEST);

        // 第一遍：收集头行与 Connection 列出的逐跳名。头可能出现在任意位置，
        // 丢弃名单必须全部行看完才算完整。
        String head = new String(buf, 0, headLen, StandardCharsets.US_ASCII);
        String[] lines = head.split("\r\n");
        Set<String> hops = new HashSet<>();
        List<String[]> kept = new ArrayList<>(); // [lowName, line]
        String hostValue = null;
        for (int i = 1; i < lines.length; ++i) {
            String line = lines[i];
            if (line.isEmpty()) continue;
            if (line.charAt(0) == ' ' || line.charAt(0) == '\t') return of(BAD_REQUEST); // obs-fold
            int colon = line.indexOf(':');
            if (colon <= 0) return of(BAD_REQUEST);
            String name = line.substring(0, colon);
            for (int k = 0; k < name.length(); ++k) {
                if (!isTchar(name.charAt(k))) return of(BAD_REQUEST);
            }
            String value = line.substring(colon + 1).trim();
            if (!headerValueOk(value)) return of(BAD_REQUEST);
            String low = name.toLowerCase();
            if (low.equals("host")) {
                if (hostValue != null) return of(BAD_REQUEST); // Host 歧义
                hostValue = value;
            } else if (low.equals("connection")) {
                collectHops(value, hops);
            }
            kept.add(new String[]{low, line});
        }

        // Host 与 absolute-form authority 不一致会放行请求走私——必须拒绝。
        // 缺 Host（HTTP/1.0）时从 URL 填充。发往源站的 Host 总是从 URL 重建。
        if (hostValue != null) {
            Authority h = parseAuthority(hostValue, 0);
            if (h == null || !h.host.toLowerCase().equals(auth.host.toLowerCase())
                    || (h.port != 0 && h.port != auth.port)) {
                return of(BAD_REQUEST);
            }
        }

        // 第二遍：改写为 origin-form 并剥离逐跳头。Transfer-Encoding/Content-Length
        // 即使被 Connection 点名也保留——本代理从不解码 body，丢任一个都会弄坏
        // chunked 上传。
        StringBuilder outBuf = new StringBuilder();
        outBuf.append(tok[0]).append(' ').append(path).append(' ').append(tok[2]);
        for (String[] l : kept) {
            String n = l[0];
            if (n.equals("connection") || n.equals("host") || n.equals("upgrade")
                    || n.equals("keep-alive") || n.equals("te") || n.equals("trailer")
                    || n.startsWith("proxy-")) {
                continue;
            }
            if (!n.equals("transfer-encoding") && !n.equals("content-length") && hops.contains(n)) {
                continue;
            }
            outBuf.append("\r\n").append(l[1]);
        }
        outBuf.append("\r\nHost: ").append(authority).append("\r\nConnection: close\r\n\r\n");
        ProxyTarget target = auth.ipv6 != null
                ? new ProxyTarget(ATYP_IPV6, auth.ipv6, auth.port)
                : new ProxyTarget(ATYP_DOMAIN, addr, auth.port);
        return new ParseResult(OK, headLen, target, null, false, 0, tok,
                outBuf.toString().getBytes(StandardCharsets.US_ASCII));
    }

    /** 首字节分流（codec.ts:383-391 detectEntry）。 */
    public static final int ENTRY_SOCKS5 = 0;
    public static final int ENTRY_CONNECT = 1;
    public static final int ENTRY_FORWARD = 2;
    public static final int ENTRY_NEED_MORE = 3;
    public static final int ENTRY_UNKNOWN = 4;

    public static int detectEntry(byte[] buf, int len) {
        if (len == 0) return ENTRY_NEED_MORE;
        if ((buf[0] & 0xff) == SOCKS5_VERSION) return ENTRY_SOCKS5;
        int n = Math.min(len, 16);
        String s = new String(buf, 0, n, StandardCharsets.US_ASCII);
        if (s.startsWith("CONNECT ")) return ENTRY_CONNECT;
        if (s.matches("^[A-Z]+ .*")) return ENTRY_FORWARD;
        if (len < 4) return ENTRY_NEED_MORE;
        return ENTRY_UNKNOWN;
    }

    // ---- FCP OPEN ----

    public static byte[] openWriteRequest(ProxyTarget t) {
        if (!atypValid(t.atyp) || t.port == 0) return null;
        int fixed = atypAddrLen(t.atyp);
        if (t.addr.length == 0 || t.addr.length > OPEN_MAX_ADDR_LEN) return null;
        if (fixed != 0 && t.addr.length != fixed) return null;
        byte[] out = new byte[7 + t.addr.length + 2];
        System.arraycopy(OPEN_MAGIC, 0, out, 0, OPEN_MAGIC.length);
        out[4] = (byte) OPEN_VERSION;
        out[5] = (byte) t.atyp;
        out[6] = (byte) t.addr.length;
        System.arraycopy(t.addr, 0, out, 7, t.addr.length);
        Wire.putBe16(t.port, out, 7 + t.addr.length);
        return out;
    }

    public static byte[] openWriteOk() {
        byte[] out = new byte[OPEN_OK_LEN];
        System.arraycopy(OPEN_MAGIC, 0, out, 0, OPEN_MAGIC.length);
        out[4] = (byte) OPEN_VERSION;
        out[5] = (byte) OPEN_KIND_OK;
        out[6] = 0;
        out[7] = 0;
        return out;
    }

    public static byte[] openWriteErr(int err) {
        byte[] out = new byte[OPEN_ERR_LEN];
        System.arraycopy(OPEN_MAGIC, 0, out, 0, OPEN_MAGIC.length);
        out[4] = (byte) OPEN_VERSION;
        out[5] = (byte) OPEN_KIND_ERR;
        out[6] = (byte) err;
        return out;
    }

    public static ParseResult openParseRequest(byte[] buf) {
        return openParseRequest(buf, buf.length);
    }

    public static ParseResult openParseRequest(byte[] buf, int len) {
        if (len == 0) return of(NEED_MORE);
        int win = Math.min(len, OPEN_MAX_BYTES);
        int magicLen = Math.min(win, 4);
        byte[] magic = Arrays.copyOf(OPEN_MAGIC, magicLen);
        if (!Bytes.bytesEqual(magic, buf, magicLen)) return of(BAD_MAGIC);
        if (win < 7) return of(NEED_MORE);
        if ((buf[4] & 0xff) != OPEN_VERSION) return of(BAD_VERSION);
        int atyp = buf[5] & 0xff;
        if (!atypValid(atyp)) return of(BAD_ATYP);
        int addrLen = buf[6] & 0xff;
        if (addrLen == 0) return of(BAD_ADDRESS);
        int fixed = atypAddrLen(atyp);
        if (fixed != 0 && addrLen != fixed) return of(BAD_ADDRESS);
        int total = 7 + addrLen + 2;
        if (win < total) return of(NEED_MORE);
        if (atyp == ATYP_DOMAIN) {
            for (int i = 0; i < addrLen; ++i) {
                if (!hostCharOk(buf[7 + i] & 0xff)) return of(BAD_ADDRESS);
            }
        }
        int port = Wire.getBe16(buf, 7 + addrLen);
        if (port == 0) return of(BAD_ADDRESS);
        return new ParseResult(OK, total,
                new ProxyTarget(atyp, Arrays.copyOfRange(buf, 7, 7 + addrLen), port),
                null, false, 0, null, null);
    }

    public static ParseResult openParseReply(byte[] buf) {
        return openParseReply(buf, buf.length);
    }

    public static ParseResult openParseReply(byte[] buf, int len) {
        if (len == 0) return of(NEED_MORE);
        int magicLen = Math.min(len, 4);
        byte[] magic = Arrays.copyOf(OPEN_MAGIC, magicLen);
        if (!Bytes.bytesEqual(magic, buf, magicLen)) return of(BAD_MAGIC);
        if (len < 7) return of(NEED_MORE);
        if ((buf[4] & 0xff) != OPEN_VERSION) return of(BAD_VERSION);
        int kind = buf[5] & 0xff;
        if (kind == OPEN_KIND_ERR) {
            return new ParseResult(OK, OPEN_ERR_LEN, null, null, false, buf[6] & 0xff, null, null);
        }
        if (kind != OPEN_KIND_OK) return of(MALFORMED);
        if (len < OPEN_OK_LEN) return of(NEED_MORE);
        if (buf[6] != 0 || buf[7] != 0) return of(MALFORMED);
        return new ParseResult(OK, OPEN_OK_LEN, null, null, true, 0, null, null);
    }
}
