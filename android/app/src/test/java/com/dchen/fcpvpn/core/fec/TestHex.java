package com.dchen.fcpvpn.core.fec;

/** 测试小工具：hex/bin 助手，对齐 fcp-node tests 的同名函数。 */
final class TestHex {

    private TestHex() {}

    static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte v : b) {
            sb.append(Character.forDigit((v >> 4) & 0xf, 16));
            sb.append(Character.forDigit(v & 0xf, 16));
        }
        return sb.toString();
    }

    static byte[] bin(String s) {
        String t = s.replaceAll("\\s+", "");
        byte[] out = new byte[t.length() / 2];
        for (int i = 0; i < out.length; ++i) {
            out[i] = (byte) Integer.parseInt(t.substring(i * 2, i * 2 + 2), 16);
        }
        return out;
    }

    static byte[] fill(int len, int v) {
        byte[] b = new byte[len];
        java.util.Arrays.fill(b, (byte) v);
        return b;
    }
}
