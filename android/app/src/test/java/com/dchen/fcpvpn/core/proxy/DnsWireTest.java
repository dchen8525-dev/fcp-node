package com.dchen.fcpvpn.core.proxy;

import org.junit.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

/** DnsWire：查询解析 + 应答 TTL 解析 + 缓存适配（换 ID、递减 TTL）。 */
public class DnsWireTest {

    /** 手搓一个 A 查询包。 */
    private static byte[] buildQuery(int id, String name, int qtype) {
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        out.write((id >>> 8) & 0xff);
        out.write(id & 0xff);
        out.write(0x01); // RD
        out.write(0x00);
        out.write(0); out.write(1); // qdcount=1
        out.write(0); out.write(0);
        out.write(0); out.write(0);
        out.write(0); out.write(0);
        for (String label : name.split("\\.")) {
            byte[] b = label.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            out.write(b.length);
            out.write(b, 0, b.length);
        }
        out.write(0);
        out.write((qtype >>> 8) & 0xff); out.write(qtype & 0xff);
        out.write(0); out.write(1); // IN
        return out.toByteArray();
    }

    @Test
    public void parsesQueryNameAndType() {
        byte[] q = buildQuery(0x1234, "www.example.com", DnsWire.TYPE_A);
        DnsWire.Query parsed = DnsWire.parseQuery(q);
        assertNotNull(parsed);
        assertEquals("www.example.com", parsed.name);
        assertEquals(DnsWire.TYPE_A, parsed.qtype);
        assertEquals(0x12, parsed.id[0] & 0xff);
        assertEquals(0x34, parsed.id[1] & 0xff);
    }

    @Test
    public void rejectsMalformedAndResponses() {
        assertNull(DnsWire.parseQuery(new byte[5]));
        byte[] resp = buildQuery(1, "a.com", DnsWire.TYPE_A);
        resp[2] = (byte) 0x81; // QR=1 → 这是应答，不是查询
        assertNull(DnsWire.parseQuery(resp));
    }

    @Test
    public void buildsResponseAndReadsTtlBack() {
        byte[] q = buildQuery(7, "example.com", DnsWire.TYPE_A);
        DnsWire.Query query = DnsWire.parseQuery(q);
        List<byte[]> answers = new ArrayList<>();
        answers.add(new byte[]{93, (byte) 184, (byte) 216, 34});
        byte[] resp = DnsWire.buildResponse(query, answers, 0);

        // 解析回来的 TTL 应为构造时的 60 秒
        assertEquals(60, DnsWire.minTtl(resp, resp.length));
        // ancount
        assertEquals(1, ((resp[6] & 0xff) << 8) | (resp[7] & 0xff));
    }

    @Test
    public void negativeResponseHasZeroTtl() {
        byte[] q = buildQuery(8, "nope.example", DnsWire.TYPE_A);
        DnsWire.Query query = DnsWire.parseQuery(q);
        byte[] resp = DnsWire.buildResponse(query, new ArrayList<byte[]>(), 3);
        assertEquals(0, DnsWire.minTtl(resp, resp.length));
    }

    @Test
    public void adaptCachedSwapsIdAndDecrementsTtl() {
        byte[] q = buildQuery(0x1111, "example.com", DnsWire.TYPE_A);
        DnsWire.Query query = DnsWire.parseQuery(q);
        List<byte[]> answers = new ArrayList<>();
        answers.add(new byte[]{1, 2, 3, 4});
        byte[] cached = DnsWire.buildResponse(query, answers, 0);
        assertEquals(60, DnsWire.minTtl(cached, cached.length));

        byte[] adapted = DnsWire.adaptCached(cached, new byte[]{0x22, 0x22}, 25);
        // ID 已替换
        assertEquals(0x22, adapted[0] & 0xff);
        assertEquals(0x22, adapted[1] & 0xff);
        // TTL 递减 25 → 35
        assertEquals(35, DnsWire.minTtl(adapted, adapted.length));
        // 原缓存未被修改
        assertEquals(60, DnsWire.minTtl(cached, cached.length));
        assertEquals(0x11, cached[0] & 0xff);
    }

    @Test
    public void adaptCachedClampsTtlAtZero() {
        byte[] q = buildQuery(1, "example.com", DnsWire.TYPE_A);
        DnsWire.Query query = DnsWire.parseQuery(q);
        List<byte[]> answers = new ArrayList<>();
        answers.add(new byte[]{1, 2, 3, 4});
        byte[] cached = DnsWire.buildResponse(query, answers, 0);
        byte[] adapted = DnsWire.adaptCached(cached, new byte[]{0, 1}, 9999);
        assertEquals(0, DnsWire.minTtl(adapted, adapted.length));
    }

    @Test
    public void minTtlPicksSmallestAcrossRecords() {
        byte[] q = buildQuery(1, "example.com", DnsWire.TYPE_A);
        DnsWire.Query query = DnsWire.parseQuery(q);
        // 两条答案（构造器统一用 60s，这里手工改第二条的 TTL 验证取最小）
        List<byte[]> answers = new ArrayList<>();
        answers.add(new byte[]{1, 2, 3, 4});
        answers.add(new byte[]{5, 6, 7, 8});
        byte[] resp = DnsWire.buildResponse(query, answers, 0);
        // 每条 RR = name(2, 压缩指针) + type(2) + class(2) + ttl(4) + rdlen(2) + rdata(4) = 16
        int qlen = 12 + query.questionSection.length;
        int secondTtl = qlen + 16 + 6; // 跳过第一条 RR，再跨过 name/type/class
        assertEquals(60, DnsWire.minTtl(resp, resp.length));
        resp[secondTtl] = 0; resp[secondTtl + 1] = 0;
        resp[secondTtl + 2] = 0; resp[secondTtl + 3] = 12;
        assertEquals(12, DnsWire.minTtl(resp, resp.length));
    }
}
