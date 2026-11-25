package com.dchen.fcpvpn.core.session;

/**
 * 换路径后的"对端回音"验证窗口。
 *
 * <p>底层网络切换（Wi-Fi → 蜂窝）时客户端的 UDP socket 不重连：不 connect、不绑网络，
 * 换网后从新网卡发出，源地址变了、端口不变；两端都会跟随对端地址漂移（客户端
 * {@code FcpTunnelEngine.handleDatagram}，服务端 tunnel.ts "peer address moved"），
 * 所以正常切换是透明续传，不需要重新握手。</p>
 *
 * <p>但"旧路径还在收包却不转发"（走出 Wi-Fi 覆盖、旧 NAT 映射未老化、运营商侧黑洞）
 * 不会产生任何 socket 错误：发送照常成功，只是永远收不到回音。原来唯一的判据是
 * 静默 3×45s = 135 秒，这期间浏览器下载会毫无提示地冻住两分多钟。</p>
 *
 * <p>本类把这段等待换成一个有界窗口：路径一变就上膛，只有<b>对换网后我们亲自发出的
 * 探测的应答</b>才算回音（见 {@code FcpSession.sendPathProbe}，凭换网时轮换的 PMTU
 * token 识别），窗口内一直等不到就交给会话关闭 → 引擎重连。</p>
 *
 * <p>为什么不能用"收到任何认证报文"当回音：换网那一刻仍在空中的旧路径报文与普通
 * 数据报文在帧层完全一样，先到的那一枚就会把窗口误判成"通"，于是又退回 135 秒的
 * 静默判死——正是这个窗口要消除的现象。探测的 token 是换网后才生成的，只有对端
 * 收到我们换网后发出的探测才会带着它回来。</p>
 *
 * <p>纯状态机：无时钟、无 socket、无分配，时间由调用方传入（与 FcpSession 的单写者
 * 契约一致，只在引擎线程上调用）。</p>
 */
final class PathVerifyWindow {

    private final long verifyMs;
    private boolean armed;
    private long deadlineMs;

    PathVerifyWindow(long verifyMs) {
        this.verifyMs = verifyMs;
    }

    /** 上膛。重复调用 = 重新计时（网络连续抖动时窗口跟着续期，不会提前放弃）。 */
    void arm(long nowMs) {
        armed = true;
        deadlineMs = nowMs + verifyMs;
    }

    /** 换网后发出的探测被对端应答：当前路径确实可达。 */
    void noteInbound() {
        armed = false;
    }

    boolean armed() {
        return armed;
    }

    /** 回音后仍冻结地址到窗口结束，避免紧随其后的旧路径包改写对端。 */
    boolean addressFrozen(long nowMs) {
        return nowMs < deadlineMs;
    }

    /** 窗口到期仍未收到任何回音。 */
    boolean expired(long nowMs) {
        return armed && nowMs >= deadlineMs;
    }

    long deadlineMs() {
        return deadlineMs;
    }
}
