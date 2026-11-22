package com.dchen.fcpvpn.core.fec;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Random;

import org.junit.Test;

/**
 * RS 编解码测试。金标期望值抄自 fcp-node tests/golden.test.ts:80-92
 * （tests/rs_test.cc:24-50 的 parity 字节）与 tests/bytes.test.ts
 * 'RS systematic codec recovers up to k erasures'；round-trip 为任务书要求的
 * 自洽测试（多组 d/k 参数，覆盖 d + p ≤ 256 边界）。
 */
public class RsTest {

    @Test
    public void goldenParityBytes() {
        // golden.test.ts:80-92（n=4, k=2, len=6）
        byte[][] data = {
                TestHex.bin("000102030405"), TestHex.bin("101112131415"),
                TestHex.bin("202122232425"), TestHex.bin("303132333435"),
        };
        byte[][] parity = Rs.rsEncode(data, 4, 2, 6);
        assertNotNull(parity);
        assertEquals("089221bb5ac0", TestHex.hex(parity[0]));
        assertEquals("5dc774ee0f95", TestHex.hex(parity[1]));
        // 同一组向量在擦除两个 data 段后必须能解码回来
        byte[][] symbols = {null, data[1], null, data[3], parity[0], parity[1]};
        byte[][] rec = Rs.rsDecode(symbols, 4, 2, 6);
        assertNotNull(rec);
        assertEquals(TestHex.hex(data[0]), TestHex.hex(rec[0]));
        assertEquals(TestHex.hex(data[2]), TestHex.hex(rec[2]));
    }

    @Test
    public void recoversUpToKErasures() {
        // bytes.test.ts 'RS systematic codec recovers up to k erasures'
        byte[][] data = new byte[10][];
        for (int i = 0; i < 10; ++i) {
            data[i] = new byte[64];
            Arrays.fill(data[i], (byte) (i + 1));
        }
        byte[][] par = Rs.rsEncode(data, 10, 3, 64);
        assertNotNull(par);
        assertEquals(3, par.length);
        byte[][] shards = new byte[13][];
        System.arraycopy(data, 0, shards, 0, 10);
        System.arraycopy(par, 0, shards, 10, 3);
        shards[2] = null;
        shards[7] = null;
        shards[10] = null;
        byte[][] rec = Rs.rsDecode(shards, 10, 3, 64);
        assertNotNull(rec);
        assertEquals(TestHex.hex(data[2]), TestHex.hex(rec[2]));
        assertEquals(TestHex.hex(data[7]), TestHex.hex(rec[7]));
    }

    /**
     * 任务书 round-trip：编码 → 随机擦除（data 擦 m 个、parity 擦 t 个，m + t ≤ k，
     * 即最多消耗 k 个冗余度）→ RS 重构逐字节一致。多组 (n, k) 参数，
     * 含 n + k = 256（MAX_S）边界与 k=1 / n=1 极端。
     */
    @Test
    public void roundTripRandomDrops() {
        int[][] cases = {{4, 2}, {10, 3}, {10, 6}, {10, 7}, {100, 7}, {1, 1}, {255, 1}, {249, 7}};
        Random rnd = new Random(0xFCC7);
        for (int[] cs : cases) {
            int n = cs[0];
            int k = cs[1];
            assertTrue(n + k <= Rs.RS_MAX_SHARDS);
            int symLen = 6 + rnd.nextInt(40);
            byte[][] data = new byte[n][];
            for (int i = 0; i < n; ++i) {
                data[i] = new byte[symLen];
                rnd.nextBytes(data[i]);
                data[i][0] = (byte) i; // 首字节可辨识
            }
            byte[][] parity = Rs.rsEncode(data, n, k, symLen);
            assertNotNull("encode " + n + "/" + k, parity);
            assertEquals(k, parity.length);

            // 擦 m 个 data + t 个 parity（m + t ≤ k 保证可解），m/t 随机
            int m = rnd.nextInt(k + 1);          // 0..k 个 data 擦除
            int t = rnd.nextInt(k - m + 1);      // 0..k-m 个 parity 擦除
            ArrayList<Integer> pool = new ArrayList<>();
            for (int i = 0; i < n; ++i) pool.add(i);
            java.util.Collections.shuffle(pool, rnd);
            boolean[] dataErased = new boolean[n];
            for (int i = 0; i < m; ++i) dataErased[pool.get(i)] = true;
            int firstParityErased = t == 0 ? k : rnd.nextInt(k - t + 1); // 连续擦 t 个 parity 行
            byte[][] shards = new byte[n + k][];
            for (int i = 0; i < n; ++i) if (!dataErased[i]) shards[i] = data[i];
            for (int r = 0; r < k; ++r) {
                if (r >= firstParityErased && r < firstParityErased + t) continue;
                shards[n + r] = parity[r];
            }

            byte[][] rec = Rs.rsDecode(shards, n, k, symLen);
            assertNotNull("decode " + n + "/" + k + " m=" + m + " t=" + t, rec);
            for (int i = 0; i < n; ++i) {
                if (!dataErased[i]) {
                    assertNull("在场 data 段不重复给出，i=" + i, rec[i]);
                } else {
                    assertArrayEquals("recovered " + n + "/" + k + " idx " + i, data[i], rec[i]);
                }
            }
        }
    }

    @Test
    public void geometryBounds() {
        // rs.ts:16/33 的入参守卫
        assertNull(Rs.rsEncode(new byte[1][], 1, 0, 4)); // k == 0
        assertNull(Rs.rsEncode(new byte[0][], 0, 1, 4)); // n == 0
        assertNull(Rs.rsEncode(new byte[250][], 250, 7, 4)); // n + k = 257 > 256
        assertNull(Rs.rsDecode(new byte[6][], 4, 0, 6)); // k == 0
        assertNull(Rs.rsDecode(new byte[0][], 0, 1, 6)); // n == 0
        assertNull(Rs.rsDecode(new byte[257][], 250, 7, 6)); // n + k = 257 > 256
        // 缺失数超过 k
        assertNull(Rs.rsDecode(new byte[6][], 4, 1, 6));
        // 缺失数 ≤ k 但幸存 parity 不足
        byte[][] s = new byte[6][];
        s[0] = new byte[6];
        s[1] = new byte[6];
        assertNull(Rs.rsDecode(s, 4, 2, 6));
        // 无缺失时返回全 null 数组（rs.ts:37）
        byte[][] data = {TestHex.bin("0102"), TestHex.bin("0304")};
        byte[][] par = Rs.rsEncode(data, 2, 1, 2);
        assertNotNull(par);
        byte[][] full = {data[0], data[1], par[0]};
        byte[][] rec = Rs.rsDecode(full, 2, 1, 2);
        assertNotNull(rec);
        assertNull(rec[0]);
        assertNull(rec[1]);
    }
}
