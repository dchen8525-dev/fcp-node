package com.dchen.fcpvpn.core.session;

/** open() 的结果回调：恰好一次。 */
public interface OpenCallback {

    /** 对端返回 OPEN_OK，流可用。 */
    void onOpened(StreamHandle stream);

    /** 对端返回 OPEN_ERR（code 1=refused 2=DNS 3=timeout 4=not supported 5=too many sessions）或本地失败（code<=0）。 */
    void onFailed(int code, String message);
}
