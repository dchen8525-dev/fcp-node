package com.dchen.fcpvpn.core.fec;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

/**
 * GF(2^8) 域公理与 Cauchy 系数。期望值抄自 fcp-node tests/bytes.test.ts:36-44
 * （'GF(256) field axioms and Cauchy coefficients'），矩阵求逆验证为
 * 代数性质测试（A·A⁻¹ = I，期望值由域公理唯一确定，非编造线格式）。
 */
public class Gf256CauchyTest {

    @Test
    public void fieldAxioms() {
        // bytes.test.ts:37-40
        assertEquals(1, Gf256.gfMul(0x53, Gf256.gfInv(0x53)));
        assertEquals(Gf256.gfMul(0x57, 0x83), Gf256.gfMul(0x83, 0x57)); // 交换律
        // 分配律：0x57 · (0x12 ^ 0x34) = 0x57·0x12 ^ 0x57·0x34
        assertEquals(Gf256.gfMul(0x57, 0x12 ^ 0x34),
                Gf256.gfMul(0x57, 0x12) ^ Gf256.gfMul(0x57, 0x34));
        // bytes.test.ts:40：乘法表单位行
        assertEquals(0x42, Gf256.gfMulRow(1, 0x42));
    }

    @Test
    public void inversionIsTotalOnNonzero() {
        assertEquals(0, Gf256.gfInv(0));
        for (int a = 1; a < 256; ++a) {
            assertEquals("a * inv(a) == 1 for a=" + a, 1, Gf256.gfMul(a, Gf256.gfInv(a)));
        }
    }

    @Test
    public void generatorCyclesWholeField() {
        // 生成元 2 的幂遍历全部 255 个非零元（多项式 0x11D 是本原多项式）
        boolean[] seen = new boolean[256];
        for (int i = 0; i < 255; ++i) {
            int v = Gf256.gfExp(i);
            assertEquals(Gf256.gfPow(2, i), v);
            assertFalse("duplicate power at " + i, seen[v]);
            seen[v] = true;
        }
        for (int a = 1; a < 256; ++a) assertTrue(seen[a]);
    }

    @Test
    public void cauchyCoeffMatchesDefinition() {
        // bytes.test.ts:41-44：coeff(r,c,7) == gfInv((r ^ (7 + c)) & 0xff)
        for (int r = 0; r < 7; ++r) {
            for (int c = 0; c < 10; ++c) {
                int v = Cauchy.cauchyCoeff(r, c, 7);
                assertTrue(v >= 0 && v <= 255);
                assertEquals(Gf256.gfInv((r ^ (7 + c)) & 0xff), v);
            }
        }
    }

    @Test
    public void cauchyMatrixShapeAndInversion() {
        int n = 16;
        int k = 4;
        byte[] m = Cauchy.cauchyMatrix(n, k);
        assertEquals(n * k, m.length);
        for (int r = 0; r < k; ++r) {
            for (int c = 0; c < n; ++c) {
                assertEquals(Cauchy.cauchyCoeff(r, c, k), m[r * n + c] & 0xff);
            }
        }
        // 任取 k 列（2,5,9,13）构成的 4x4 子阵必须可逆，且 A·A⁻¹ = I。
        int[] cols = {2, 5, 9, 13};
        byte[][] orig = new byte[k][k];
        for (int r = 0; r < k; ++r) {
            for (int i = 0; i < k; ++i) orig[r][i] = m[r * n + cols[i]];
        }
        byte[] t = new byte[k * k];
        for (int r = 0; r < k; ++r) {
            for (int c = 0; c < k; ++c) t[r * k + c] = orig[r][c];
        }
        assertTrue(Cauchy.cauchyInvertMatrix(t, k));
        for (int r = 0; r < k; ++r) {
            for (int c = 0; c < k; ++c) {
                int sum = 0;
                for (int i = 0; i < k; ++i) {
                    sum ^= Gf256.gfMul(orig[r][i] & 0xff, t[i * k + c] & 0xff);
                }
                assertEquals(r == c ? 1 : 0, sum);
            }
        }
        // 全零矩阵奇异
        assertFalse(Cauchy.cauchyInvertMatrix(new byte[4], 2));
    }
}
