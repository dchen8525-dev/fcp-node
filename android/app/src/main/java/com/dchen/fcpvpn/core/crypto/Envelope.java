package com.dchen.fcpvpn.core.crypto;

import java.util.Arrays;

import com.dchen.fcpvpn.core.wire.Bytes;
import com.dchen.fcpvpn.core.wire.Wire;

/**
 * AEAD 信封。移植自 fcp-node src/crypto/envelope.ts:1-306（其本身移植自
 * src/fcp/envelope.h / envelope.cc）。
 *
 * <p>线格式（envelope.ts:3）：
 * {@code salt(8) | nonce_ctr(8 LE) | AES-128-GCM 密文 | tag(12)}，开销 28 字节。
 * IV（12 字节，本地展开，不上线）：{@code LE64(counter) | direction(1) | 0x00×3}
 * （envelope.ts:21-26）。AAD 为空。两个方向密钥来自 SP 800-108 计数器 KDF，
 * 1024 槽抗重放窗口，可选 #84 epoch 密钥轮换，#86 无状态复位。</p>
 *
 * <p><b>重放窗口次序</b>：先查窗口（envelope.ts:171-176），再解密；
 * tag 验证通过后才提交窗口状态（envelope.ts:237-239）——失败的解密永不推进窗口。</p>
 *
 * <p>线程模型：<b>单写者</b>（single-writer）：seal()/open()/rekey()/setKeyUpdate()
 * 读写内部计数器与窗口状态，不加锁；发送与接收通常分属不同线程，各自只能有一个
 * 调用者并发访问（与 fcp-node Session 的单线程 tick 模型一致）。</p>
 */
public class Envelope {

    // ---- 线格式常量（constants.ts:29-41） ----
    /** salt 长度 = 8（constants.ts:30）。 */
    public static final int SALT_LEN = 8;
    /** nonce/counter 字段长度 = 8（constants.ts:31）。 */
    public static final int NONCE_LEN = 8;
    /** GCM tag 长度 = 12，非 16（constants.ts:32）。 */
    public static final int TAG_LEN = 12;
    /** 信封开销 = 28 = 8 + 8 + 12（constants.ts:33）。 */
    public static final int ENVELOPE_OVERHEAD = 28;
    /** 无状态复位明文长度 = 8（constants.ts:34）。 */
    public static final int RESET_MAGIC_LEN = 8;
    /** 常规信封 nonce 上限 = 2^32（constants.ts:35，u64 按位保真）。 */
    public static final long NONCE_LIMIT = 1L << 32;
    /** 抗重放窗口 = 1024 槽（constants.ts:36；规格 §4.1 写 256，以代码为准）。 */
    public static final int REPLAY_WINDOW = 1024;
    /** #84 epoch 跨度 = 2^24（constants.ts:37）。 */
    public static final long EPOCH_SPAN = 1L << 24;
    /** #84 开启后的 nonce 空间上界 = 65536 × EPOCH_SPAN = 2^40（constants.ts:38）。 */
    public static final long EPOCH_SPACE_END = 65536L * EPOCH_SPAN;
    /** #84 首次轮换阈值（constants.ts:39）。 */
    public static final long FIRST_ROLL_AT = 100;
    /** GCM IV 长度 = 12（constants.ts:40）。 */
    public static final int GCM_IV_LEN = 12;
    /** 无状态复位明文 "FCPRST1\0"（constants.ts:41）。 */
    public static final byte[] RESET_MAGIC = {
            0x46, 0x43, 0x50, 0x52, 0x53, 0x54, 0x31, 0x00,
    };

    /** u64 全 1（envelope.ts:19 U64_MAX），按位保真存 long。 */
    private static final long U64_MAX = 0xffffffffffffffffL;

    /** 本端 8 字节 salt（构造时拷贝；勿从外部改写）。 */
    public final byte[] salt;

    private final int sendDirection;
    private final int recvDirection;
    private byte[] sendKey;
    private byte[] recvKey;
    private byte[] prevRecvKey;
    private byte[] sessionKey;

    private long counterCeiling = NONCE_LIMIT;
    private long sendLimit = NONCE_LIMIT;
    private long sendNonceValue = 0;
    private boolean recvHasNonce = false;
    private long recvHighest = 0;
    private final byte[] recvSeen = new byte[REPLAY_WINDOW];

    private boolean keyUpdateEnabled = false;
    private long sendEpoch = 0;
    private boolean rolledOnce = false;
    private long recvEpochSeen = 0;
    private RecvEpoch recvCur = newRecvEpoch();
    private RecvEpoch recvPrev = newRecvEpoch();

    /**
     * Java 侧附加状态：信封是否处于引导（bootstrap）模式——即
     * {@link #initBootstrapNonce(int)} 已把发送计数器起点设为 CSPRNG u64、
     * 密钥仍是 v6 引导密钥。TS 版没有此标志（session.ts 用两个独立 Envelope
     * 对象区分数据面/引导面）；rekey() 后自动清除。
     */
    private boolean bootstrap = false;

    /**
     * 构造并安装 v6 引导密钥（envelope.ts:71-77）。
     *
     * @param psk         16 字节预共享密钥
     * @param salt        8 字节 salt
     * @param sendDirection 本端发送方向（FcpKeys.DIRECTION_C2S / DIRECTION_S2C）
     * @param recvDirection 本端接收方向
     * @throws IllegalArgumentException psk/salt 长度非法
     */
    public Envelope(byte[] psk, byte[] salt, int sendDirection, int recvDirection) {
        if (psk.length != 16 || salt.length != SALT_LEN) {
            throw new IllegalArgumentException("Envelope: bad key/salt length");
        }
        this.salt = salt.clone();
        this.sendDirection = sendDirection;
        this.recvDirection = recvDirection;
        installKeys(FcpKeys.deriveSessionKey(psk, salt));
    }

    /** 安装密钥并复位全部收发状态（envelope.ts:79-96 installKeys）。 */
    private void installKeys(byte[] sessionKey) {
        FcpKeys.DirectionKeys dk = FcpKeys.deriveDirectionKeys(sessionKey);
        this.sendKey = (sendDirection == FcpKeys.DIRECTION_C2S ? dk.c2s : dk.s2c).clone();
        this.recvKey = (recvDirection == FcpKeys.DIRECTION_C2S ? dk.c2s : dk.s2c).clone();
        this.sessionKey = sessionKey.clone();
        this.prevRecvKey = new byte[16];
        this.sendNonceValue = 0;
        this.counterCeiling = NONCE_LIMIT;
        this.sendLimit = NONCE_LIMIT;
        this.recvHasNonce = false;
        this.recvHighest = 0;
        Arrays.fill(this.recvSeen, (byte) 0);
        this.sendEpoch = 0;
        this.rolledOnce = false;
        this.recvEpochSeen = 0;
        this.recvCur = newRecvEpoch();
        this.recvPrev = newRecvEpoch();
        this.bootstrap = false; // Java 侧附加：rekey 即退出引导模式
    }

    /**
     * R3-1：握手产生双方 nonce 后替换数据面密钥（envelope.ts:98-101）。
     * 传入 {@link FcpKeys#deriveSessionKeyV7} 的结果。复位计数器与重放窗口。
     */
    public void rekey(byte[] sessionKey) {
        installKeys(sessionKey);
    }

    /**
     * 开关 #84 epoch 密钥轮换（envelope.ts:103-108）。开启后 nonce 空间扩展到
     * {@link #EPOCH_SPACE_END}（2^40）。注意 installKeys 不复位此开关
     * （与 TS 一致），因此调用次序应为 rekey() → setKeyUpdate()。
     */
    public void setKeyUpdate(boolean enabled) {
        this.keyUpdateEnabled = enabled;
        long limit = enabled ? EPOCH_SPACE_END : NONCE_LIMIT;
        this.counterCeiling = limit;
        this.sendLimit = limit;
    }

    /** #84 是否开启（envelope.ts:109）。 */
    public boolean isKeyUpdate() {
        return keyUpdateEnabled;
    }

    /** 当前发送 epoch 号 = nonce / EPOCH_SPAN（envelope.ts:110，无符号除法）。 */
    public long sendEpochValue() {
        return Long.divideUnsigned(sendNonceValue, EPOCH_SPAN);
    }

    /** 当前发送计数器（envelope.ts:111）。 */
    public long nonce() {
        return sendNonceValue;
    }

    /** 发送空间是否耗尽（envelope.ts:112，无符号比较）。 */
    public boolean isExhausted() {
        return Long.compareUnsigned(sendNonceValue, sendLimit) >= 0;
    }

    /** 是否处于引导模式（initBootstrapNonce 之后、rekey 之前）。 */
    public boolean isBootstrap() {
        return bootstrap;
    }

    /**
     * 重设发送计数器（envelope.ts:114-118）。测试/恢复用原语。
     *
     * @return 越过 counterCeiling 或 sendLimit 时返回 false
     */
    public boolean setSendNonce(long value) {
        if (Long.compareUnsigned(value, counterCeiling) >= 0
                || Long.compareUnsigned(value, sendLimit) >= 0) {
            return false;
        }
        this.sendNonceValue = value;
        return true;
    }

    /**
     * 引导信封：随机 64-bit 计数器起点，全量接收范围（envelope.ts:120-128）。
     * 发送预算 = budget + 1（会话层传 HANDSHAKE_SEND_BUDGET = 2^16，
     * constants.ts:363）。
     */
    public boolean initBootstrapNonce(int budget) {
        long draw = AesGcm.cspRandomU64();
        long span = (budget & 0xffffffffL) + 1L;
        this.sendNonceValue = Long.remainderUnsigned(draw, U64_MAX - span);
        this.sendLimit = this.sendNonceValue + span;
        this.counterCeiling = U64_MAX;
        this.bootstrap = true;
        return true;
    }

    /** #84：发送侧轮换到下一个 epoch 密钥（envelope.ts:130-138）。 */
    private boolean rollSendEpoch() {
        long epochNum = Long.divideUnsigned(sendEpoch, EPOCH_SPAN) + 1;
        if (Long.compareUnsigned(epochNum, 65535L) > 0) return false;
        this.sendKey = FcpKeys.deriveEpochDirectionKey(sessionKey, sendDirection, (int) epochNum);
        this.sendEpoch = epochNum * EPOCH_SPAN;
        this.sendNonceValue = this.sendEpoch;
        this.rolledOnce = true;
        return true;
    }

    /**
     * 封装一个数据报并推进发送计数器（envelope.ts:140-152）。
     * 空间耗尽（含 #84 轮换失败）返回 null。
     */
    public byte[] seal(byte[] plain) {
        if (keyUpdateEnabled) {
            long inEpoch = sendNonceValue - sendEpoch;
            long threshold = rolledOnce ? EPOCH_SPAN : FIRST_ROLL_AT;
            if (Long.compareUnsigned(inEpoch, threshold) >= 0 && !rollSendEpoch()) return null;
        }
        if (Long.compareUnsigned(sendNonceValue, sendLimit) >= 0) return null;
        byte[] wire = sealUnchecked(sendNonceValue, plain);
        if (wire == null) return null;
        this.sendNonceValue += 1;
        return wire;
    }

    /** 测试/重放原语：显式 counter，不推进发送状态（envelope.ts:154-158）。 */
    public byte[] sealAt(long counter, byte[] plain) {
        if (Long.compareUnsigned(counter, counterCeiling) >= 0) return null;
        return sealUnchecked(counter, plain);
    }

    /** 组线格式：salt | LE64(counter) | 密文 | tag（envelope.ts:160-169）。 */
    private byte[] sealUnchecked(long counter, byte[] plain) {
        AesGcm.Sealed sealed = AesGcm.gcmSeal(sendKey, makeIv(counter, sendDirection), plain, null);
        if (sealed == null) return null;
        byte[] wire = new byte[ENVELOPE_OVERHEAD + plain.length];
        System.arraycopy(salt, 0, wire, 0, SALT_LEN);
        Wire.putLe64(counter, wire, SALT_LEN);
        System.arraycopy(sealed.cipher, 0, wire, SALT_LEN + NONCE_LEN, sealed.cipher.length);
        System.arraycopy(sealed.tag, 0, wire, SALT_LEN + NONCE_LEN + plain.length, sealed.tag.length);
        return wire;
    }

    /** 12 字节 IV：LE64(counter) | direction | 0x00×3（envelope.ts:21-26）。 */
    private static byte[] makeIv(long counter, int direction) {
        byte[] iv = new byte[GCM_IV_LEN];
        Wire.putLe64(counter, iv, 0);
        iv[8] = (byte) direction;
        return iv; // 字节 9..11 已是 0
    }

    /** 窗口是否可能接受该 counter（envelope.ts:171-176）。 */
    private boolean nonceWindowMayAccept(long counter) {
        if (!recvHasNonce) return true;
        if (Long.compareUnsigned(counter, recvHighest) > 0) return true;
        long delta = recvHighest - counter;
        return Long.compareUnsigned(delta, REPLAY_WINDOW) < 0 && recvSeen[(int) delta] == 0;
    }

    /** 提交窗口状态（envelope.ts:178-196；仅 tag 验证通过后调用）。 */
    private boolean acceptNonce(long counter) {
        if (!recvHasNonce) {
            recvHasNonce = true;
            recvHighest = counter;
            Arrays.fill(recvSeen, (byte) 0);
            recvSeen[0] = 1;
            return true;
        }
        if (Long.compareUnsigned(counter, recvHighest) > 0) {
            shiftSeen(recvSeen, counter - recvHighest);
            recvSeen[0] = 1;
            recvHighest = counter;
            return true;
        }
        long delta = recvHighest - counter;
        if (Long.compareUnsigned(delta, REPLAY_WINDOW) >= 0 || recvSeen[(int) delta] != 0) return false;
        recvSeen[(int) delta] = 1;
        return true;
    }

    /** std::bitset &lt;&lt;= delta 的对应物：位 i 移到 i+delta，高位丢弃（envelope.ts:37-46）。 */
    private static void shiftSeen(byte[] seen, long delta) {
        if (Long.compareUnsigned(delta, seen.length) >= 0) {
            Arrays.fill(seen, (byte) 0);
            return;
        }
        int d = (int) delta;
        for (int i = seen.length - 1; i >= d; --i) seen[i] = seen[i - d];
        Arrays.fill(seen, 0, d, (byte) 0);
    }

    /** #84 接收侧的每-epoch 窗口状态（envelope.ts:28-35）。 */
    private static final class RecvEpoch {
        boolean hasNonce;
        long highest;
        final byte[] seen = new byte[REPLAY_WINDOW];
    }

    private static RecvEpoch newRecvEpoch() {
        return new RecvEpoch();
    }

    private boolean epochWindowMayAccept(RecvEpoch win, long counter) {
        if (!win.hasNonce) return true;
        if (Long.compareUnsigned(counter, win.highest) > 0) return true;
        long delta = win.highest - counter;
        return Long.compareUnsigned(delta, REPLAY_WINDOW) < 0 && win.seen[(int) delta] == 0;
    }

    private boolean epochAccept(RecvEpoch win, long counter) {
        if (!win.hasNonce) {
            win.hasNonce = true;
            win.highest = counter;
            Arrays.fill(win.seen, (byte) 0);
            win.seen[0] = 1;
            return true;
        }
        if (Long.compareUnsigned(counter, win.highest) > 0) {
            shiftSeen(win.seen, counter - win.highest);
            win.seen[0] = 1;
            win.highest = counter;
            return true;
        }
        long delta = win.highest - counter;
        if (Long.compareUnsigned(delta, REPLAY_WINDOW) >= 0 || win.seen[(int) delta] != 0) return false;
        win.seen[(int) delta] = 1;
        return true;
    }

    /**
     * 认证 + 解密（envelope.ts:225-241）。次序：长度 → salt → counter 上限 →
     * 重放窗口 → 解密 → 提交窗口。失败（认证失败/重放/错误 salt/错误 counter）
     * 返回 null 且不推进任何状态。
     */
    public byte[] open(byte[] wire) {
        if (wire.length < ENVELOPE_OVERHEAD) return null;
        if (!Bytes.bytesEqual(salt, wire, SALT_LEN)) return null;
        long counter = Wire.getLe64(wire, SALT_LEN);
        if (Long.compareUnsigned(counter, counterCeiling) >= 0) return null;
        if (keyUpdateEnabled) return openEpoch(counter, wire);
        if (!nonceWindowMayAccept(counter)) return null;
        byte[] iv = makeIv(counter, recvDirection);
        int cipherLen = wire.length - ENVELOPE_OVERHEAD;
        byte[] cipher = Arrays.copyOfRange(wire, SALT_LEN + NONCE_LEN, SALT_LEN + NONCE_LEN + cipherLen);
        byte[] tag = Arrays.copyOfRange(wire, SALT_LEN + NONCE_LEN + cipherLen, wire.length);
        byte[] plain = AesGcm.gcmOpen(recvKey, iv, cipher, tag, null);
        if (plain == null) return null;
        if (!acceptNonce(counter)) return null;
        return plain;
    }

    /** #84 接收路径：epoch 匹配当前/前一/下一 epoch，否则拒绝（envelope.ts:243-280）。 */
    private byte[] openEpoch(long nonce, byte[] wire) {
        long epoch = Long.divideUnsigned(nonce, EPOCH_SPAN);
        long counter = Long.remainderUnsigned(nonce, EPOCH_SPAN);
        byte[] key;
        RecvEpoch win;
        boolean commitNext = false;
        if (epoch == recvEpochSeen) {
            key = recvKey;
            win = recvCur;
        } else if (epoch + 1 == recvEpochSeen) {
            key = prevRecvKey;
            win = recvPrev;
        } else if (epoch == recvEpochSeen + 1) {
            key = FcpKeys.deriveEpochDirectionKey(sessionKey, recvDirection, (int) epoch);
            commitNext = true;
            win = newRecvEpoch(); // tag 验证通过后才替换 recvCur
        } else {
            return null;
        }
        if (Long.compareUnsigned(counter, counterCeiling) >= 0) return null;
        if (!commitNext && !epochWindowMayAccept(win, counter)) return null;
        byte[] iv = makeIv(nonce, recvDirection);
        int cipherLen = wire.length - ENVELOPE_OVERHEAD;
        byte[] cipher = Arrays.copyOfRange(wire, SALT_LEN + NONCE_LEN, SALT_LEN + NONCE_LEN + cipherLen);
        byte[] tag = Arrays.copyOfRange(wire, SALT_LEN + NONCE_LEN + cipherLen, wire.length);
        byte[] plain = AesGcm.gcmOpen(key, iv, cipher, tag, null);
        if (plain == null) return null;
        if (commitNext) {
            this.recvPrev = this.recvCur;
            this.prevRecvKey = this.recvKey;
            this.recvEpochSeen = epoch;
            this.recvKey = key;
            this.recvCur = newRecvEpoch();
            win = this.recvCur;
        }
        if (!epochAccept(win, counter)) return null;
        return plain;
    }

    /**
     * #86 无状态复位：绕过重放窗口（任意 nonce 均可，envelope.ts:282-292）。
     * 36 字节数据报 = 28 开销 + 8 字节明文 "FCPRST1\0"，用引导密钥。
     * 设计上可重放（对端可能反复收到同一份 reset）。
     */
    public byte[] openReset(byte[] wire) {
        if (wire.length != ENVELOPE_OVERHEAD + RESET_MAGIC_LEN) return null;
        if (!Bytes.bytesEqual(salt, wire, SALT_LEN)) return null;
        byte[] iv = makeIv(Wire.getLe64(wire, SALT_LEN), recvDirection);
        byte[] cipher = Arrays.copyOfRange(wire, SALT_LEN + NONCE_LEN, SALT_LEN + NONCE_LEN + RESET_MAGIC_LEN);
        byte[] tag = Arrays.copyOfRange(wire, SALT_LEN + NONCE_LEN + RESET_MAGIC_LEN, wire.length);
        byte[] plain = AesGcm.gcmOpen(recvKey, iv, cipher, tag, null);
        if (plain == null || !Bytes.bytesEqual(RESET_MAGIC, plain, RESET_MAGIC_LEN)) return null;
        return RESET_MAGIC.clone();
    }

    /** 清零密钥材料（envelope.ts:294-297；JVM 无法保证物理擦除，尽力而为）。 */
    public void destroy() {
        Bytes.secureZero(sendKey);
        Bytes.secureZero(recvKey);
        Bytes.secureZero(prevRecvKey);
        Bytes.secureZero(sessionKey);
    }

    /**
     * #86：为丢失会话的对端构造一份已封装的无状态复位数据报
     * （envelope.ts:300-306 sealReset）。counter 必须留在 NONCE_LIMIT（2^32）
     * 之内，否则 sealAt 返回 null（session.ts:865-875 的教训：随机 64-bit
     * 计数器永远封不出去）。
     */
    public static byte[] sealReset(byte[] psk, byte[] salt, int sendDir, int recvDir, long counter) {
        Envelope env = new Envelope(psk, salt, sendDir, recvDir);
        byte[] wire = env.sealAt(counter, RESET_MAGIC);
        env.destroy();
        return wire;
    }
}
