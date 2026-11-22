package com.dchen.fcpvpn.core.session;

import com.dchen.fcpvpn.core.crypto.Handshake;
import com.dchen.fcpvpn.core.wire.Bytes;

import java.security.SecureRandom;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * 握手状态机（client/服务器双角色）。fcp-node 把它放在 crypto/handshake.ts 的
 * Handshake 类里；Java 侧编解码在 {@link Handshake}（crypto agent），状态机在此。
 *
 * 流程：start() 发 HELLO（bootstrap 信封）→ 按 DEFAULT_RETRY_SCHEDULE_MS 重发
 * （每次重发走 Envelope.seal 自动递增 counter，满足服务端 180s 去重要求）→
 * 收到 HELLO_ACK 校验 magic/client_nonce 回显/caps → negotiate → established。
 * 双方都发 HELLO 的同时打开也支持（角色由 Direction 固定，与谁先说话无关）。
 */
public final class FcpHandshake {

    public static final int ROLE_CLIENT = 0;
    public static final int ROLE_SERVER = 1;

    // HandshakeState（constants.ts:104）
    public static final int STATE_IDLE = 0;
    public static final int STATE_HELLO_SENT = 1;
    public static final int STATE_ESTABLISHED = 2;
    public static final int STATE_FAILED = 3;

    // HandshakeError（constants.ts:105-107）
    public static final int ERROR_NONE = 0;
    public static final int ERROR_NO_ACK = 1;
    public static final int ERROR_BAD_CAPS = 2;
    public static final int ERROR_MISSING_CAPABILITY = 3;
    public static final int ERROR_CACHE_OVERFLOW = 4;
    public static final int ERROR_BAD_NONCE = 5;

    /** onOob 的返回。 */
    public static final int IGNORED = 0;
    public static final int HANDLED = 1;
    /** 协议级失败（调用方必须关闭会话）。 */
    public static final int PROTOCOL_FAILURE = 2;

    /** 建立前缓存的待发送流段上限（constants.ts:98-99）。 */
    private static final int MAX_CACHED_SEGMENTS = 512;
    private static final int MAX_CACHED_BYTES = 512 * 1024;

    /** oob 发送回调（session 层封装成 bootstrap 信封）。 */
    public interface SendFn {
        void send(byte[] msg);
    }

    private final int role;
    private final int localD;
    private final int localP;
    private final int localFlags;
    private final byte[] clientNonce = new byte[16];
    private final byte[] serverNonce = new byte[16];
    private final SendFn send;
    private final SecureRandom random = new SecureRandom();

    private List<Handshake.Tlv> localTlvs = new ArrayList<>();
    private final Set<Integer> localTlvTypes = new HashSet<>();
    private final Set<Integer> peerTlvTypes = new HashSet<>();
    private final java.util.Map<Integer, byte[]> peerTlvValues = new java.util.HashMap<>();

    public int state = STATE_IDLE;
    public int error = ERROR_NONE;
    public final Handshake.Negotiated params = new Handshake.Negotiated();
    private boolean established = false;
    private boolean failed = false;
    private long startMs = 0;
    private int retryIdx = 0; // 已发送次数；start() 的首发使其变为 1

    private final Deque<byte[]> cachedData = new ArrayDeque<>();
    private int cachedBytes = 0;

    public FcpHandshake(int role, int localD, int localP, int localFlags, SendFn send) {
        this.role = role;
        this.localD = localD;
        this.localP = localP;
        this.localFlags = localFlags;
        this.send = send;
        random.nextBytes(clientNonce);
        // nonce 校验要求 OR 非全零；SecureRandom 全零概率可忽略，但保险起见。
        int acc = 0;
        for (byte b : clientNonce) acc |= b & 0xff;
        if (acc == 0) clientNonce[0] = 1;
    }

    public boolean isEstablished() { return established; }
    public boolean isFailed() { return failed; }
    public int getState() { return state; }
    public int getError() { return error; }
    public byte[] getClientNonce() { return clientNonce; }
    public byte[] getServerNonce() { return serverNonce; }

    public void setLocalTlvs(List<Handshake.Tlv> tlvs) {
        localTlvs = tlvs;
        localTlvTypes.clear();
        for (Handshake.Tlv t : tlvs) localTlvTypes.add(t.type);
    }

    /** 双端都提供过该 TLV 才算协商成功。 */
    public boolean tlvAgreed(int type) {
        return localTlvTypes.contains(type) && peerTlvTypes.contains(type);
    }

    /** 协商后的 caps flags（= local & peer）。 */
    public int tlvNegotiated() {
        return params.flags;
    }

    /** 对端 TLV 原始值（未提供返回 null）。 */
    public byte[] peerTlv(int type) {
        return peerTlvValues.get(type);
    }

    public void start(long nowMs) {
        startMs = nowMs;
        state = STATE_HELLO_SENT;
        sendHello();
    }

    private void sendHello() {
        // handshake.ts sendHello：提供 TLV 时自动并入 CAP_TLV 位，否则清除。
        boolean offer = !localTlvs.isEmpty();
        int flags = offer ? (localFlags | Handshake.CAP_TLV) & 0xff
                : (localFlags & ~Handshake.CAP_TLV) & 0xff;
        Handshake.Caps caps = new Handshake.Caps(Handshake.CAPS_VERSION, localD, localP, flags);
        send.send(Handshake.buildHello(caps, clientNonce, offer ? localTlvs : new ArrayList<Handshake.Tlv>()));
        ++retryIdx;
    }

    /**
     * 重试驱动。{@code retryIdx} 是「已发送次数」：start() 内的首发使其变为 1，
     * 因此本次该发的时刻正是 {@code DEFAULT_RETRY_SCHEDULE_MS[retryIdx]}
     * （0/250/750/1750/3750/7750/15750/23750/31750ms）。表用尽仍未免手即
     * ERROR_NO_ACK。
     *
     * 早期实现检查的是 {@code [retryIdx + 1]}，首发之后直接跳到 750ms——
     * 丢掉了 250ms 那一档，且总共只发 8 次（fcp-node 是 9 次）。
     */
    public void onTick(long nowMs) {
        if (established || failed || state != STATE_HELLO_SENT) return;
        if (retryIdx < Handshake.DEFAULT_RETRY_SCHEDULE_MS.length) {
            if (nowMs - startMs >= Handshake.DEFAULT_RETRY_SCHEDULE_MS[retryIdx]) {
                sendHello();
            }
            return;
        }
        failed = true;
        state = STATE_FAILED;
        error = ERROR_NO_ACK;
    }

    /** oob 分派：HELLO / HELLO_ACK。返回 HANDLED / IGNORED / PROTOCOL_FAILURE。 */
    public int onOob(byte[] payload, long nowMs) {
        if (payload.length < Handshake.HELLO_LEN) return IGNORED;
        boolean isAck = Handshake.isHelloAck(payload);
        if (!isAck && !Handshake.isHello(payload)) return IGNORED;
        if (isAck) {
            return onHelloAck(payload, nowMs);
        }
        // 同时打开：对端也发来了 HELLO（服务器主动发起或对端同时 start）。
        // 回 HELLO_ACK 并与对方的 caps 协商。
        return onPeerHello(payload, nowMs);
    }

    private int onHelloAck(byte[] payload, long nowMs) {
        // 已建立后到达的 ACK 是重传/延迟包：再解析一次会把 serverNonce 覆盖掉，
        // 而数据面密钥早已按旧 nonce 派生。无视即可。
        if (established) return HANDLED;
        Handshake.HelloAck ack = Handshake.parseHelloAck(payload, payload.length);
        if (ack == null) return IGNORED;
        // TLV type 1 = ERROR：1 字节 HandshakeError，快速失败。
        if (ack.tlvs != null) {
            for (Handshake.Tlv t : ack.tlvs) {
                if (t.type == Handshake.TLV_TYPE_ERROR && t.value.length >= 1) {
                    failed = true;
                    state = STATE_FAILED;
                    error = t.value[0] & 0xff;
                    return PROTOCOL_FAILURE;
                }
            }
        }
        if (!Handshake.capsValid(ack.caps)) {
            failed = true;
            state = STATE_FAILED;
            error = ERROR_BAD_CAPS;
            return PROTOCOL_FAILURE;
        }
        if (!Handshake.nonceValid(ack.serverNonce)
                || !Bytes.bytesEqual(ack.clientNonce, clientNonce)) {
            failed = true;
            state = STATE_FAILED;
            error = ERROR_BAD_NONCE;
            return PROTOCOL_FAILURE;
        }
        System.arraycopy(ack.serverNonce, 0, serverNonce, 0, 16);
        negotiate(ack.caps, ack.tlvs);
        return HANDLED;
    }

    private int onPeerHello(byte[] payload, long nowMs) {
        // 已建立后重复收到 HELLO（对端重传）：再回一次 ACK 并重新协商会把
        // serverNonce 换掉，与已 rekey 的数据面不一致。
        if (established) return HANDLED;
        Handshake.Hello hello = Handshake.parseHello(payload, payload.length);
        if (hello == null) return IGNORED;
        if (!Handshake.capsValid(hello.caps) || !Handshake.nonceValid(hello.senderNonce)) {
            failed = true;
            state = STATE_FAILED;
            error = ERROR_BAD_CAPS;
            return PROTOCOL_FAILURE;
        }
        random.nextBytes(serverNonce);
        int acc = 0;
        for (byte b : serverNonce) acc |= b & 0xff;
        if (acc == 0) serverNonce[0] = 1;
        // sendHelloAck：镜像对端的 TLV 支持位（peerSupportsTlv）。
        boolean offer = (hello.caps.flags & Handshake.CAP_TLV) != 0;
        int flags = offer ? (localFlags | Handshake.CAP_TLV) & 0xff
                : (localFlags & ~Handshake.CAP_TLV) & 0xff;
        Handshake.Caps caps = new Handshake.Caps(Handshake.CAPS_VERSION, localD, localP, flags);
        send.send(Handshake.buildHelloAck(caps, hello.senderNonce, serverNonce,
                offer ? localTlvs : new ArrayList<Handshake.Tlv>(), offer));
        negotiate(hello.caps, hello.tlvs);
        return HANDLED;
    }

    /** flags = local & peer，D' = min，P' = min；必需能力缺失即失败（MissingCapability）。 */
    private void negotiate(Handshake.Caps peerCaps, List<Handshake.Tlv> peerTlvs) {
        params.flags = localFlags & peerCaps.flags;
        int required = Handshake.CAP_FRAMING | Handshake.CAP_FECSTAT;
        if ((params.flags & required) != required) {
            failed = true;
            state = STATE_FAILED;
            error = ERROR_MISSING_CAPABILITY;
            return;
        }
        params.d = Math.min(localD, peerCaps.data);
        params.p = Math.min(localP, peerCaps.parity);
        params.mode = params.p == 0 ? Handshake.MODE_FRAMED_STATS : Handshake.MODE_FRAMED_REPAIR;
        peerTlvTypes.clear();
        peerTlvValues.clear();
        // 采纳对端 TLV 列表以对端自己的 CAP_TLV 位为准（wire caps），与协商后的
        // flags 无关——tlvAgreed 只看双端列表交集（handshake.ts:256-260）。
        if (peerTlvs != null && (peerCaps.flags & Handshake.CAP_TLV) != 0) {
            for (Handshake.Tlv t : peerTlvs) {
                peerTlvTypes.add(t.type);
                peerTlvValues.put(t.type, t.value);
            }
        }
        established = true;
        state = STATE_ESTABLISHED;
    }

    /** 建立前缓存待发送流段（configure 后经 takeCachedData 回放）。 */
    public void cacheData(byte[] seg) {
        if (cachedData.size() >= MAX_CACHED_SEGMENTS
                || cachedBytes + seg.length > MAX_CACHED_BYTES) {
            failed = true;
            state = STATE_FAILED;
            error = ERROR_CACHE_OVERFLOW;
            return;
        }
        cachedData.add(seg);
        cachedBytes += seg.length;
    }

    /** 取走全部缓存（调用后清空）。 */
    public List<byte[]> takeCachedData() {
        List<byte[]> out = new ArrayList<>(cachedData);
        cachedData.clear();
        cachedBytes = 0;
        return out;
    }
}
