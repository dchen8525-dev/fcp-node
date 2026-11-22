# KCP VPN R8 规则（release 目前 minifyEnabled false；启用混淆时此文件生效）
#
# 代码全部为直接引用的 Java（无反射、无 JNI 按名回调、无序列化反射），
# 默认规则即可。保留以下防线防止未来引入的依赖被过度裁剪：

# android.net.VpnService 子类由系统按清单中的类名实例化，必须保留类名
-keep class com.dchen.kcpvpn.vpn.KcpVpnService { *; }

# androidx.localbroadcastmanager / lifecycle 通过反射回调，keep 默认规则已覆盖，
# 这里显式列出以防 -optimization 调整后失效
-keepclassmembers class * extends android.os.Binder {
    public *;
}
