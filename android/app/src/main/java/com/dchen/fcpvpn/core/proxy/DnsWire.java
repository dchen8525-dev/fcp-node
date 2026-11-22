package com.dchen.fcpvpn.core.proxy;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * 最小 DNS wire-format 编解码器：只做 DoH 回退所需的两件事——
 * 解析查询里的 (qname, qtype)，以及按 A/AAAA 记录构造应答。
 *
 * 设计取舍：完整 DNS 解析器（压缩指针、EDNS、DNSSEC）在这里是过度工程——
 * 我们的用途只是给本地 DNS 中继加一条 DoH 回退路径，只要 A/AAAA 正确即可，
 * 其余查询原样返回 NXDOMAIN/失败让应用自己重试。
 */
public final class DnsWire {

    private DnsWire() {}

    public static final int TYPE_A = 1;
    public static final int TYPE_CNAME = 5;
    public static final int TYPE_AAAA = 28;

    /** 解析出的查询。 */
    public static final class Query {
        public final byte[] id;          // 2 字节事务 ID（原样回填）
        public final String name;        // 点分域名
        public final int qtype;
        public final byte[] questionSection; // 原样回填的 question 区（含 qname/qtype/qclass）

        Query(byte[] id, String name, int qtype, byte[] questionSection) {
            this.id = id;
            this.name = name;
            this.qtype = qtype;
            this.questionSection = questionSection;
        }
    }

    /**
     * 解析查询包的 question 区。失败返回 null（畸形包 / 无 question / 非查询）。
     * 只支持单 question（DNS 的实际约定）。
     */
    public static Query parseQuery(byte[] packet) {
        return parseQuery(packet, packet.length);
    }

    public static Query parseQuery(byte[] packet, int len) {
        if (len < 12) return null;
        int flags = ((packet[2] & 0xff) << 8) | (packet[3] & 0xff);
        if ((flags & 0x8000) != 0) return null;      // QR=1：这是应答，不是查询
        int qdcount = ((packet[4] & 0xff) << 8) | (packet[5] & 0xff);
        if (qdcount < 1) return null;

        byte[] id = new byte[]{packet[0], packet[1]};
        int off = 12;
        StringBuilder name = new StringBuilder();
        while (off < len) {
            int labelLen = packet[off] & 0xff;
            if (labelLen == 0) {
                off++;
                break;
            }
            // 压缩指针（0xC0）：查询里不该出现，出现即畸形
            if ((labelLen & 0xc0) != 0) return null;
            off++;
            if (off + labelLen > len) return null;
            if (name.length() > 0) name.append('.');
            name.append(new String(packet, off, labelLen, StandardCharsets.US_ASCII));
            off += labelLen;
        }
        if (off + 4 > len) return null;
        int qtype = ((packet[off] & 0xff) << 8) | (packet[off + 1] & 0xff);
        int qclass = ((packet[off + 2] & 0xff) << 8) | (packet[off + 3] & 0xff);
        off += 4;
        if (qclass != 1) return null;                 // 只处理 IN 类
        byte[] question = java.util.Arrays.copyOfRange(packet, 12, off);
        return new Query(id, name.toString(), qtype, question);
    }

    /**
     * 构造应答包。answers 为 A 记录的 4 字节地址列表（qtype=A）或 AAAA 的 16 字节。
     * rcode: 0=NOERROR, 3=NXDOMAIN。
     */
    public static byte[] buildResponse(Query q, List<byte[]> answers, int rcode) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(512);
        out.write(q.id[0]);
        out.write(q.id[1]);
        // flags: QR=1, RD=1, RA=1, rcode
        out.write(0x81);
        out.write(0x80 | (rcode & 0x0f));
        writeU16(out, 1);                       // qdcount
        writeU16(out, answers == null ? 0 : answers.size()); // ancount
        writeU16(out, 0);                       // nscount
        writeU16(out, 0);                       // arcount
        out.write(q.questionSection, 0, q.questionSection.length);
        if (answers != null) {
            for (byte[] addr : answers) {
                // 名字用压缩指针指向 offset 12 的 qname
                out.write(0xc0);
                out.write(0x0c);
                writeU16(out, q.qtype);          // type
                writeU16(out, 1);                // class IN
                writeU32(out, 60);               // TTL 60s
                writeU16(out, addr.length);
                out.write(addr, 0, addr.length);
            }
        }
        return out.toByteArray();
    }

    /** 构造空应答（NXDOMAIN / SERVFAIL），用于上游失败时让客户端立刻重试。 */
    public static byte[] buildError(Query q, int rcode) {
        return buildResponse(q, new ArrayList<byte[]>(), rcode);
    }

    // ---- 缓存辅助 ----------------------------------------------------------

    /**
     * 读应答报文里答案记录的最小 TTL（秒）。返回 -1 表示报文畸形、不可缓存；
     * 返回 0 表示没有答案记录（负应答，调用方应使用自己的负缓存时长）。
     *
     * 只需遍历 answer 区：每个 RR 的形状是 name(type/class/ttl/rdlength/rdata)，
     * name 可能是压缩指针（2 字节）或标签序列。
     */
    public static int minTtl(byte[] packet, int len) {
        if (len < 12) return -1;
        int qdcount = ((packet[4] & 0xff) << 8) | (packet[5] & 0xff);
        int ancount = ((packet[6] & 0xff) << 8) | (packet[7] & 0xff);
        int off = 12;
        for (int i = 0; i < qdcount; ++i) {
            off = skipName(packet, off, len);
            if (off < 0 || off + 4 > len) return -1;
            off += 4; // qtype + qclass
        }
        if (ancount == 0) return 0;
        int min = Integer.MAX_VALUE;
        for (int i = 0; i < ancount; ++i) {
            off = skipName(packet, off, len);
            if (off < 0 || off + 10 > len) return -1;
            int ttl = ((packet[off + 4] & 0xff) << 24)
                    | ((packet[off + 5] & 0xff) << 16)
                    | ((packet[off + 6] & 0xff) << 8)
                    | (packet[off + 7] & 0xff);
            int rdlen = ((packet[off + 8] & 0xff) << 8) | (packet[off + 9] & 0xff);
            if (ttl < 0) ttl = 0;
            if (ttl < min) min = ttl;
            off += 10 + rdlen;
            if (off > len) return -1;
        }
        return min == Integer.MAX_VALUE ? 0 : min;
    }

    /**
     * 把缓存的应答适配成本次查询可用的报文：替换事务 ID，并按已过时间递减
     * 答案记录的 TTL（不低于 0）。缓存内容本身不被修改。
     */
    public static byte[] adaptCached(byte[] cached, byte[] newId, long elapsedSec) {
        byte[] out = cached.clone();
        if (out.length < 12) return out;
        out[0] = newId[0];
        out[1] = newId[1];
        int len = out.length;
        int qdcount = ((out[4] & 0xff) << 8) | (out[5] & 0xff);
        int ancount = ((out[6] & 0xff) << 8) | (out[7] & 0xff);
        int off = 12;
        for (int i = 0; i < qdcount; ++i) {
            off = skipName(out, off, len);
            if (off < 0 || off + 4 > len) return out;
            off += 4;
        }
        for (int i = 0; i < ancount; ++i) {
            off = skipName(out, off, len);
            if (off < 0 || off + 10 > len) return out;
            long ttl = ((out[off + 4] & 0xffL) << 24)
                    | ((out[off + 5] & 0xffL) << 16)
                    | ((out[off + 6] & 0xffL) << 8)
                    | (out[off + 7] & 0xffL);
            long left = ttl - elapsedSec;
            if (left < 0) left = 0;
            out[off + 4] = (byte) ((left >>> 24) & 0xff);
            out[off + 5] = (byte) ((left >>> 16) & 0xff);
            out[off + 6] = (byte) ((left >>> 8) & 0xff);
            out[off + 7] = (byte) (left & 0xff);
            int rdlen = ((out[off + 8] & 0xff) << 8) | (out[off + 9] & 0xff);
            off += 10 + rdlen;
            if (off > len) return out;
        }
        return out;
    }

    /** 跳过 DNS name，返回下一个字段的偏移；畸形返回 -1。 */
    private static int skipName(byte[] b, int off, int len) {
        while (off < len) {
            int c = b[off] & 0xff;
            if (c == 0) return off + 1;
            if ((c & 0xc0) == 0xc0) {
                // 压缩指针占 2 字节，指向别处——这里只需要跨过它。
                return off + 2 <= len ? off + 2 : -1;
            }
            if ((c & 0xc0) != 0) return -1;
            off += 1 + c;
        }
        return -1;
    }

    private static void writeU16(ByteArrayOutputStream out, int v) {
        out.write((v >>> 8) & 0xff);
        out.write(v & 0xff);
    }

    private static void writeU32(ByteArrayOutputStream out, long v) {
        out.write((int) ((v >>> 24) & 0xff));
        out.write((int) ((v >>> 16) & 0xff));
        out.write((int) ((v >>> 8) & 0xff));
        out.write((int) (v & 0xff));
    }
}
