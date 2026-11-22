package com.dchen.fcpvpn.core.crypto;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import com.dchen.fcpvpn.core.wire.Bytes;
import com.dchen.fcpvpn.core.wire.Wire;

/**
 * FCP v7 握手 —— 纯编解码 + 协商逻辑。移植自 fcp-node src/crypto/handshake.ts
 * （handshake.ts:1-175 的编解码部分与 341-360 的协商部分）；<b>不带定时重试与
 * 缓存状态机</b>——那是 session 层（session.ts）的职责。
 *
 * <p>线格式（oob 符号载荷，handshake.ts:3-11）：
 * <pre>
 *   HELLO     = magic16 "FCP_HELLO_V1\0\0\0\0" | sender_nonce16 | caps4 [+ TLV block]
 *   HELLO_ACK = magic16 "FCP_HELLO_ACK_V1" | client_nonce16 | server_nonce16 | caps4 [+ TLV block]
 *   caps      = ver(1) | data(1) | parity(1) | flags(1)
 *   TLV block = block_len(2 LE) | [type(1) | len(1) | value]...
 * </pre>
 * 16 字节 magic 兼作版本门：字节不匹配即"根本不是握手"（handshake.ts:9-11）。</p>
 *
 * <p>caps flags（constants.ts:52-59）：bit0 CAP_FRAMING、bit1 CAP_FECSTAT
 * <b>必需</b>；bit2 CAP_PER_SET_K、bit3 CAP_DEADLINE、bit4 CAP_PMTUD、
 * bit5 CAP_TLV；bit6..7 保留（capsValid 拒绝）。协商规则（handshake.ts:341-360）：
 * {@code flags = local & peer}（必需位缺失即失败）、{@code D' = min}、
 * {@code P' = min}；CAP_TLV 只有双方都提供才保留。</p>
 *
 * <p><b>重试约定</b>（handshake.ts:281-294）：9 次发送、间隔 250ms 倍增、封顶
 * 8s，累计时刻表 0/250/750/1750/3750/7750/15750/23750/31750ms。
 * <b>HELLO 每次重试必须换新 counter</b>（信封层 nonce_ctr 不得复用）——服务端
 * 180s 内对相同 salt‖nonce 去重（AGENTS.md 坑位 4）。</p>
 *
 * <p>线程模型：全部为无状态静态方法，可并发调用。</p>
 */
public final class Handshake {

    // ---- caps / 握手常量（constants.ts:50-108） ----
    /** caps 字段长度 = 4（constants.ts:50）。 */
    public static final int CAPS_LEN = 4;
    /** caps 版本（constants.ts:51）。 */
    public static final int CAPS_VERSION = 1;
    /** bit0：帧化收发（必需）（constants.ts:52）。 */
    public static final int CAP_FRAMING = 1 << 0;
    /** bit1：FECSTAT 报告（必需）（constants.ts:53）。 */
    public static final int CAP_FECSTAT = 1 << 1;
    /** bit2：每集合独立 k（constants.ts:54）。 */
    public static final int CAP_PER_SET_K = 1 << 2;
    /** bit3（constants.ts:55）。 */
    public static final int CAP_DEADLINE = 1 << 3;
    /** bit4：PMTUD（constants.ts:56）。 */
    public static final int CAP_PMTUD = 1 << 4;
    /** bit5：TLV 能力（constants.ts:57）。 */
    public static final int CAP_TLV = 1 << 5;
    /** 已知位掩码 0x3f，bit6..7 保留（constants.ts:58）。 */
    public static final int CAP_KNOWN_MASK = 0x3f;
    /** 客户端本地 flags 缺省：FRAMING|FECSTAT|PER_SET_K（constants.ts:59）。 */
    public static final int LOCAL_FLAGS_M1 = CAP_FRAMING | CAP_FECSTAT | CAP_PER_SET_K;

    /** HELLO magic16："FCP_HELLO_V1\0\0\0\0"（constants.ts:61）。 */
    public static final byte[] HELLO_MAGIC = {
            0x46, 0x43, 0x50, 0x5f, 0x48, 0x45, 0x4c, 0x4c, 0x4f, 0x5f, 0x56, 0x31,
            0x00, 0x00, 0x00, 0x00,
    };
    /** HELLO_ACK magic16："FCP_HELLO_ACK_V1"（constants.ts:62）。 */
    public static final byte[] HELLO_ACK_MAGIC = {
            0x46, 0x43, 0x50, 0x5f, 0x48, 0x45, 0x4c, 0x4c, 0x4f, 0x5f, 0x41, 0x43,
            0x4b, 0x5f, 0x56, 0x31,
    };
    public static final int HELLO_MAGIC_LEN = 16;      // constants.ts:63
    public static final int HELLO_ACK_MAGIC_LEN = 16;  // constants.ts:64
    public static final int HANDSHAKE_NONCE_LEN = 16;  // constants.ts:65
    /** HELLO 定长 = 36 = 16 + 16 + 4（constants.ts:66）。 */
    public static final int HELLO_LEN = HELLO_MAGIC_LEN + HANDSHAKE_NONCE_LEN + CAPS_LEN;
    /** HELLO_ACK 定长 = 52 = 16 + 16 + 16 + 4（constants.ts:67）。 */
    public static final int HELLO_ACK_LEN = HELLO_ACK_MAGIC_LEN + 2 * HANDSHAKE_NONCE_LEN + CAPS_LEN;

    public static final int TLV_BLOCK_LEN_BYTES = 2;   // constants.ts:68
    public static final int TLV_OVERHEAD = 2;          // constants.ts:69
    public static final int TLV_MAX_VALUE_LEN = 255;   // constants.ts:70
    public static final int TLV_BLOCK_MAX_LEN = 1024;  // constants.ts:71
    /** TLV type 1 = ERROR：1 字节 HandshakeError，出现在 HELLO_ACK 即快速失败（handshake.ts:419-426）。 */
    public static final int TLV_TYPE_ERROR = 1;        // constants.ts:72
    public static final int TLV_TYPE_ACK_V2 = 2;       // constants.ts:73
    public static final int TLV_TYPE_PREWARM = 3;      // constants.ts:74
    /** #84 epoch 密钥轮换，空 value（constants.ts:75-78）。 */
    public static final int TLV_TYPE_KEY_UPDATE = 4;   // constants.ts:78
    /** M1 会话多路复用（constants.ts:79-83）。 */
    public static final int TLV_TYPE_MULTIPLEX = 5;    // constants.ts:83
    /** 空闲路径探测（constants.ts:84-87）。 */
    public static final int TLV_TYPE_PATH_PROBE = 6;   // constants.ts:87

    /** 重试次数上限 = 9（constants.ts:95）。 */
    public static final int HANDSHAKE_MAX_RETRIES = 9;
    /** 首跳重试间隔 = 250ms（constants.ts:96）。 */
    public static final int HANDSHAKE_RETRY_MS = 250;
    /** 重试间隔封顶 = 8000ms（constants.ts:97）。 */
    public static final int HANDSHAKE_RETRY_CAP_MS = 8000;
    /**
     * 累计重试时刻表（handshake.ts:281-294，firstGap=250ms 倍增、封顶 8s）：
     * 0/250/750/1750/3750/7750/15750/23750/31750ms。会话层据此驱动重发，
     * 且每次重发必须换新信封 counter。
     */
    public static final int[] DEFAULT_RETRY_SCHEDULE_MS = {
            0, 250, 750, 1750, 3750, 7750, 15750, 23750, 31750,
    };

    // ---- SessionMode（constants.ts:103） ----
    /** 带修复（parity）的帧化模式。 */
    public static final int MODE_FRAMED_REPAIR = 0;
    /** 纯统计（parity = 0）模式。 */
    public static final int MODE_FRAMED_STATS = 1;

    // ---- HandshakeError（constants.ts:105-107） ----
    public static final int ERROR_NONE = 0;
    public static final int ERROR_NO_ACK = 1;
    public static final int ERROR_BAD_CAPS = 2;
    public static final int ERROR_MISSING_CAPABILITY = 3;
    public static final int ERROR_CACHE_OVERFLOW = 4;
    public static final int ERROR_BAD_NONCE = 5;

    private Handshake() {}

    /** caps 四元组（handshake.ts:27 HandshakeCaps）。 */
    public static final class Caps {
        public int ver;
        public int data;
        public int parity;
        public int flags;

        public Caps() {}

        public Caps(int ver, int data, int parity, int flags) {
            this.ver = ver;
            this.data = data;
            this.parity = parity;
            this.flags = flags;
        }
    }

    /** 单个 TLV（handshake.ts:28 HandshakeTlv）。value 长度 0..255。 */
    public static final class Tlv {
        public final int type;
        public final byte[] value;

        public Tlv(int type, byte[] value) {
            this.type = type;
            this.value = value;
        }
    }

    /** 协商结果（handshake.ts:29 NegotiatedParams）。 */
    public static final class Negotiated {
        public int d;
        public int p;
        public int flags;
        /** {@link #MODE_FRAMED_REPAIR} 或 {@link #MODE_FRAMED_STATS}。 */
        public int mode;
    }

    /** parseHello 的返回（HELLO 载荷拆解）。caps/tlvs 语义校验由调用方做。 */
    public static final class Hello {
        public byte[] senderNonce;
        public Caps caps;
        public List<Tlv> tlvs;
    }

    /** parseHelloAck 的返回（HELLO_ACK 载荷拆解）。 */
    public static final class HelloAck {
        public byte[] clientNonce;
        public byte[] serverNonce;
        public Caps caps;
        public List<Tlv> tlvs;
    }

    /** prewarm 车票（handshake.ts:146-157 encodePrewarmTlv 的入参）。 */
    public static final class PrewarmTicket {
        public int initialK;
        public int srttMs;
        public int windowKb;
        public int bwKbps;
        public int minRttMs;
    }

    // ---- caps 编解码（handshake.ts:36-56） ----

    /** 写 4 字节 caps：ver | data | parity | flags（handshake.ts:36-38）。 */
    public static void writeCaps(Caps c, byte[] out, int off) {
        out[off] = (byte) c.ver;
        out[off + 1] = (byte) c.data;
        out[off + 2] = (byte) c.parity;
        out[off + 3] = (byte) c.flags;
    }

    /** 读 4 字节 caps（handshake.ts:39-41，各字节无符号 0..255）。 */
    public static Caps parseCaps(byte[] b, int off) {
        return new Caps(b[off] & 0xff, b[off + 1] & 0xff, b[off + 2] & 0xff, b[off + 3] & 0xff);
    }

    /**
     * caps 校验（handshake.ts:42-46）：ver == 1；data &gt;= 1；parity &lt;= 7；
     * {@code d + p <= 256}（AGENTS.md 坑位 5）；flags 的保留位（bit6..7）必须为 0。
     */
    public static boolean capsValid(Caps c) {
        if (c.ver != CAPS_VERSION || c.data < 1 || c.parity > 7) return false;
        if (c.data + c.parity > 256) return false;
        return (c.flags & ~CAP_KNOWN_MASK) == 0;
    }

    /**
     * nonce 校验（handshake.ts:47-56）：长度至少 16 字节且 OR 不为全零。
     * 短 buffer 必须在此拒绝——TS 的历史缺陷是短 nonce 通过校验后
     * 在 deriveSessionKeyV7 里炸出未捕获异常（protocol.test.ts:1070-1089）。
     */
    public static boolean nonceValid(byte[] n) {
        if (n.length < HANDSHAKE_NONCE_LEN) return false;
        int acc = 0;
        for (int i = 0; i < HANDSHAKE_NONCE_LEN; ++i) acc |= n[i] & 0xff;
        return acc != 0;
    }

    // ---- TLV 编解码（handshake.ts:58-103） ----

    /**
     * 编码 TLV block：block_len(2 LE) | [type | len | value]...
     * （handshake.ts:58-74）。
     *
     * @return 消耗的字节数；含 type 0、value &gt; 255 字节、block 总长 &gt; 1024
     *         或输出空间不足时返回 0（不可编码）
     */
    public static int tlvEncode(List<Tlv> tlvs, byte[] out, int off) {
        int total = 0;
        for (Tlv t : tlvs) {
            if (t.type == 0 || t.value.length > TLV_MAX_VALUE_LEN) return 0;
            total += TLV_OVERHEAD + t.value.length;
        }
        if (total > TLV_BLOCK_MAX_LEN || out.length - off < TLV_BLOCK_LEN_BYTES + total) return 0;
        Wire.putLe16(total, out, off);
        int p = off + TLV_BLOCK_LEN_BYTES;
        for (Tlv t : tlvs) {
            out[p++] = (byte) t.type;
            out[p++] = (byte) t.value.length;
            System.arraycopy(t.value, 0, out, p, t.value.length);
            p += t.value.length;
        }
        return p - off;
    }

    /**
     * 解析 TLV block（handshake.ts:76-93）。
     *
     * @param block TLV 条目区（不含 2 字节 block_len 头）
     * @param len   声明的 block 长度；超过 block 数组长视为畸形（TS 的
     *              undefined 读取缺陷防护，protocol.test.ts:1091-1099）
     * @return TLV 列表；畸形（type 0、value 越界、尾部长度不足）返回 null
     */
    public static List<Tlv> tlvParse(byte[] block, int len) {
        List<Tlv> out = new ArrayList<Tlv>();
        if (len > block.length) return null;
        int off = 0;
        while (off < len) {
            if (len - off < TLV_OVERHEAD) return null;
            int type = block[off] & 0xff;
            int vlen = block[off + 1] & 0xff;
            if (type == 0 || len - off - TLV_OVERHEAD < vlen) return null;
            out.add(new Tlv(type, Arrays.copyOfRange(block, off + TLV_OVERHEAD, off + TLV_OVERHEAD + vlen)));
            off += TLV_OVERHEAD + vlen;
        }
        return out;
    }

    /**
     * 提取握手消息的 TLV 列表（handshake.ts:95-103 helloTlvs）。
     *
     * @return 空列表 = 未携带 CAP_TLV 位（无 block）；null = 声明了 block
     *         但缺失或畸形（调用方按 BadCaps 处理，handshake.ts:375/429）
     */
    public static List<Tlv> helloTlvs(byte[] data, int len, boolean isAck) {
        int fixed = isAck ? HELLO_ACK_LEN : HELLO_LEN;
        if (len > data.length) return null; // 防御性：TS 对越界 len 是 UB
        if (len < fixed || (data[fixed - 1] & CAP_TLV) == 0) return new ArrayList<Tlv>();
        if (len == fixed) return null; // 声明了 block 但缺失
        int block = Wire.getLe16(data, fixed);
        if (block > TLV_BLOCK_MAX_LEN || len != fixed + TLV_BLOCK_LEN_BYTES + block) return null;
        return tlvParse(Arrays.copyOfRange(data, fixed + TLV_BLOCK_LEN_BYTES, data.length), block);
    }

    /** 形状校验：长度 + magic + TLV block 声明一致性（handshake.ts:105-111 msgOk）。 */
    private static boolean msgOk(byte[] data, int len, int fixedLen, byte[] magic) {
        if (len > data.length) return false; // 防御性
        if (len < fixedLen || !Bytes.bytesEqual(magic, data, HELLO_MAGIC_LEN)) return false;
        if ((data[fixedLen - 1] & CAP_TLV) == 0) return len == fixedLen;
        if (len == fixedLen) return true; // 声明了 block 但缺失 -> 稍后按 caps 错误处理
        if (len < fixedLen + TLV_BLOCK_LEN_BYTES) return false;
        return len == fixedLen + TLV_BLOCK_LEN_BYTES + Wire.getLe16(data, fixedLen);
    }

    /** 是否为形状合法的 HELLO（handshake.ts:112）。 */
    public static boolean isHello(byte[] d, int len) {
        return msgOk(d, len, HELLO_LEN, HELLO_MAGIC);
    }

    /** 是否为形状合法的 HELLO_ACK（handshake.ts:113）。 */
    public static boolean isHelloAck(byte[] d, int len) {
        return msgOk(d, len, HELLO_ACK_LEN, HELLO_ACK_MAGIC);
    }

    public static boolean isHello(byte[] d) {
        return isHello(d, d.length);
    }

    public static boolean isHelloAck(byte[] d) {
        return isHelloAck(d, d.length);
    }

    // ---- 消息构造（handshake.ts:115-144） ----

    /**
     * 构造 HELLO（handshake.ts:115-124）。36 字节（无 TLV）或 36 + 2 + block。
     *
     * <p><b>重试约定</b>：HELLO 每次重发必须换新信封 counter（服务端 180s 内对
     * 相同 salt‖nonce 去重）——信封层动作，编解码层只负责字节形状。</p>
     *
     * @param senderNonce 16 字节发送方 nonce（须通过 {@link #nonceValid}）
     * @param tlvs        null 或空 = 不带 TLV block（也不置 CAP_TLV 位；
     *                    flags 由调用方的 caps 决定）
     * @throws IllegalArgumentException TLV 不可编码（handshake.ts:122）
     */
    public static byte[] buildHello(Caps caps, byte[] senderNonce, List<Tlv> tlvs) {
        boolean hasTlvs = tlvs != null && !tlvs.isEmpty();
        byte[] out = new byte[HELLO_LEN + (hasTlvs ? TLV_BLOCK_LEN_BYTES + TLV_BLOCK_MAX_LEN : 0)];
        System.arraycopy(HELLO_MAGIC, 0, out, 0, HELLO_MAGIC_LEN);
        if (senderNonce.length < HANDSHAKE_NONCE_LEN) {
            throw new IllegalArgumentException("buildHello: nonce must be 16 bytes");
        }
        System.arraycopy(senderNonce, 0, out, HELLO_MAGIC_LEN, HANDSHAKE_NONCE_LEN);
        writeCaps(caps, out, HELLO_MAGIC_LEN + HANDSHAKE_NONCE_LEN);
        if (!hasTlvs) return Arrays.copyOf(out, HELLO_LEN);
        int n = tlvEncode(tlvs, out, HELLO_LEN);
        if (n == 0) throw new IllegalArgumentException("buildHello: TLV block unencodable");
        return Arrays.copyOf(out, HELLO_LEN + n);
    }

    /**
     * 构造 HELLO_ACK（handshake.ts:130-144）。{@code withEmptyBlock} 对应
     * C++ build_hello_ack_ext：当我们回显对端的 CAP_TLV 位但自己没有 TLV 时，
     * block 必须仍在场且 block_len = 0——裸 52 字节 ACK 带该位会被对端按
     * "声明了 block 但缺失"（BadCaps）拒绝（handshake.ts:127-129 注释）。
     */
    public static byte[] buildHelloAck(Caps caps, byte[] clientNonce, byte[] serverNonce,
                                       List<Tlv> tlvs, boolean withEmptyBlock) {
        boolean block = (tlvs != null && !tlvs.isEmpty()) || withEmptyBlock;
        byte[] out = new byte[HELLO_ACK_LEN + (block ? TLV_BLOCK_LEN_BYTES + TLV_BLOCK_MAX_LEN : 0)];
        System.arraycopy(HELLO_ACK_MAGIC, 0, out, 0, HELLO_ACK_MAGIC_LEN);
        if (clientNonce.length < HANDSHAKE_NONCE_LEN || serverNonce.length < HANDSHAKE_NONCE_LEN) {
            throw new IllegalArgumentException("buildHelloAck: nonce must be 16 bytes");
        }
        System.arraycopy(clientNonce, 0, out, HELLO_ACK_MAGIC_LEN, HANDSHAKE_NONCE_LEN);
        System.arraycopy(serverNonce, 0, out, HELLO_ACK_MAGIC_LEN + HANDSHAKE_NONCE_LEN, HANDSHAKE_NONCE_LEN);
        writeCaps(caps, out, HELLO_ACK_MAGIC_LEN + 2 * HANDSHAKE_NONCE_LEN);
        if (!block) return Arrays.copyOf(out, HELLO_ACK_LEN);
        int n = tlvEncode(tlvs == null ? Collections.<Tlv>emptyList() : tlvs, out, HELLO_ACK_LEN);
        if (n == 0) throw new IllegalArgumentException("buildHelloAck: TLV block unencodable");
        return Arrays.copyOf(out, HELLO_ACK_LEN + n);
    }

    // ---- 消息解析（对 onHello/onHelloAck 的形状前置条件，handshake.ts:369-445） ----

    /**
     * 解析并校验 HELLO 形状。语义校验（capsValid / nonceValid / ERROR TLV 检查）
     * 与状态机（重 ACK、helloRefused、nonceMismatch）是 session 层的事，
     * 对应 handshake.ts:369-404 的前置检查次序。
     *
     * @return 拆解结果；magic/长度/TLV block 畸形（含"声明了 block 但缺失"）
     *         返回 null
     */
    public static Hello parseHello(byte[] data, int len) {
        if (!isHello(data, len)) return null;
        List<Tlv> tlvs = helloTlvs(data, len, false);
        if (tlvs == null) return null; // handshake.ts:375：tlvs === null -> BadCaps
        Hello h = new Hello();
        h.senderNonce = Arrays.copyOfRange(data, HELLO_MAGIC_LEN, HELLO_MAGIC_LEN + HANDSHAKE_NONCE_LEN);
        h.caps = parseCaps(data, HELLO_MAGIC_LEN + HANDSHAKE_NONCE_LEN);
        h.tlvs = tlvs;
        return h;
    }

    /**
     * 解析并校验 HELLO_ACK 形状（对应 handshake.ts:406-445 的形状前置条件）。
     * ERROR TLV（type 1、1 字节 HandshakeError）出现即快速失败——该判定由
     * 调用方遍历 {@code tlvs} 执行（handshake.ts:417-427）。
     */
    public static HelloAck parseHelloAck(byte[] data, int len) {
        if (!isHelloAck(data, len)) return null;
        List<Tlv> tlvs = helloTlvs(data, len, true);
        if (tlvs == null) return null; // handshake.ts:429：tlvs === null -> BadCaps
        HelloAck a = new HelloAck();
        a.clientNonce = Arrays.copyOfRange(data, HELLO_ACK_MAGIC_LEN, HELLO_ACK_MAGIC_LEN + HANDSHAKE_NONCE_LEN);
        a.serverNonce = Arrays.copyOfRange(data, HELLO_ACK_MAGIC_LEN + HANDSHAKE_NONCE_LEN,
                HELLO_ACK_MAGIC_LEN + 2 * HANDSHAKE_NONCE_LEN);
        a.caps = parseCaps(data, HELLO_ACK_MAGIC_LEN + 2 * HANDSHAKE_NONCE_LEN);
        a.tlvs = tlvs;
        return a;
    }

    // ---- 协商（handshake.ts:341-360 + 256-260） ----

    /**
     * 协商（handshake.ts:341-360 negotiate）：{@code flags = localFlags & peer.flags}；
     * 必需位 CAP_FRAMING|CAP_FECSTAT 缺失即失败；{@code D'=min(localD, peer.data)}、
     * {@code P'=min(localP, peer.parity)}；CAP_TLV 仅当双方都提供（本端有 TLV
     * 要发 && 对端 caps 带 CAP_TLV 位）才保留；P' == 0 时进入纯统计模式。
     *
     * @param localOffersTlv 本端是否主动提供 TLV（handshake.ts:204 tlvOffered
     *                       = localTlvs 非空；从"发过 HELLO 没有"改为从 TLV
     *                       列表推导，见 handshake.ts:200-204 注释）
     * @param peer           对端 caps（HELLO 或 HELLO_ACK 的 caps 字段，两者
     *                       都描述发送方自身，handshake.ts:206-218）
     * @return 协商结果；必需能力缺失返回 null（调用方按
     *         ERROR_MISSING_CAPABILITY 处理，handshake.ts:344）
     */
    public static Negotiated negotiate(int localD, int localP, int localFlags,
                                       boolean localOffersTlv, Caps peer) {
        int flags = (localFlags & peer.flags) & 0xff;
        int required = CAP_FRAMING | CAP_FECSTAT;
        if ((flags & required) != required) return null;
        boolean bothTlv = localOffersTlv && (peer.flags & CAP_TLV) != 0;
        Negotiated n = new Negotiated();
        n.d = Math.min(localD, peer.data);
        n.p = Math.min(localP, peer.parity);
        n.flags = (flags | (bothTlv ? CAP_TLV : 0)) & 0xff;
        n.mode = Math.min(localP, peer.parity) == 0 ? MODE_FRAMED_STATS : MODE_FRAMED_REPAIR;
        return n;
    }

    /** 协商结果是否带 TLV 帧化（handshake.ts:256 tlvNegotiated）。 */
    public static boolean tlvNegotiated(int negotiatedFlags) {
        return (negotiatedFlags & CAP_TLV) != 0;
    }

    /**
     * TLV 协商（handshake.ts:257-260 tlvAgreed）：某 type 生效当且仅当
     * TLV 帧化已协商 且 双方都提供该 type。
     */
    public static boolean tlvAgreed(int negotiatedFlags, List<Tlv> localTlvs, List<Tlv> peerTlvs, int type) {
        if (!tlvNegotiated(negotiatedFlags)) return false;
        return hasType(localTlvs, type) && hasType(peerTlvs, type);
    }

    private static boolean hasType(List<Tlv> tlvs, int type) {
        if (tlvs == null) return false;
        for (Tlv t : tlvs) {
            if (t.type == type) return true;
        }
        return false;
    }

    // ---- prewarm 车票（handshake.ts:146-175） ----

    /**
     * 编码 12 字节 prewarm TLV value（handshake.ts:146-157）：
     * {@code ver(1)=1 | initialK(1) | srttMs(2 LE) | windowKb(3 LE) | bwKbps(3 LE) | minRttMs(2 LE)}。
     */
    public static byte[] encodePrewarmTlv(PrewarmTicket ticket) {
        byte[] v = new byte[12];
        v[0] = 1;
        v[1] = (byte) ticket.initialK;
        Wire.putLe16(ticket.srttMs & 0xffff, v, 2);
        v[4] = (byte) (ticket.windowKb & 0xff);
        v[5] = (byte) ((ticket.windowKb >>> 8) & 0xff);
        v[6] = (byte) ((ticket.windowKb >>> 16) & 0xff);
        v[7] = (byte) (ticket.bwKbps & 0xff);
        v[8] = (byte) ((ticket.bwKbps >>> 8) & 0xff);
        v[9] = (byte) ((ticket.bwKbps >>> 16) & 0xff);
        Wire.putLe16(ticket.minRttMs & 0xffff, v, 10);
        return v;
    }

    /**
     * 解码 prewarm TLV value（handshake.ts:158-175）。k 是线上 3-bit 字段：
     * 高于"未知"标记（15）直接畸形；高于 parity 上限（7）且不是标记的
     * （8..14）同样是畸形——"不可能是测量值的 ticket 是畸形，不是值得采纳
     * 的种子"（handshake.ts:161-167，对应 C++ prewarm.cc）。
     *
     * @return 车票；长度/版本/k 非法返回 null。initialK == 0x0f 解码为 0。
     */
    public static PrewarmTicket decodePrewarmTlv(byte[] v) {
        if (v.length != 12 || (v[0] & 0xff) != 1) return null;
        int initialK = v[1] & 0xff;
        if (initialK > 0x0f) return null;
        if (initialK >= 8 && initialK <= 14) return null;
        PrewarmTicket t = new PrewarmTicket();
        t.initialK = initialK == 0x0f ? 0 : initialK;
        t.srttMs = Wire.getLe16(v, 2);
        t.windowKb = (v[4] & 0xff) | ((v[5] & 0xff) << 8) | ((v[6] & 0xff) << 16);
        t.bwKbps = (v[7] & 0xff) | ((v[8] & 0xff) << 8) | ((v[9] & 0xff) << 16);
        t.minRttMs = Wire.getLe16(v, 10);
        return t;
    }

    // ---- 重试时间表（handshake.ts:281-294） ----

    /**
     * 第 {@code retryNumber} 次（1 起始）重发前的等待间隔：
     * {@code min(firstGapMs × 2^(retryNumber-1), 8000)}（handshake.ts:293）。
     * firstGapMs 由会话层按 {@code clamp(2 × rttSeedMs, 250, 8000)} 预夹紧
     * （handshake.ts:243-245）；本方法再做一次同样的夹紧以兜底。
     */
    public static int retryGapMs(int firstGapMs, int retryNumber) {
        int first = Math.min(Math.max(firstGapMs, HANDSHAKE_RETRY_MS), HANDSHAKE_RETRY_CAP_MS);
        if (retryNumber <= 1) return first;
        long gap = (long) first << Math.min(retryNumber - 1, 30);
        return (int) Math.min(gap, HANDSHAKE_RETRY_CAP_MS);
    }
}
