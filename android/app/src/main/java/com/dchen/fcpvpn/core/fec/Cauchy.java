package com.dchen.fcpvpn.core.fec;

/**
 * GF(2^8) 上的 Cauchy 矩阵。移植自 fcp-node src/fec/cauchy.ts:1-54
 * （其移植自 C++ src/fcp/cauchy.cc）。
 *
 * 编码矩阵 coeff(r,c,k) = inv(uint8(r ^ (k + c)))，行主序 k x n；
 * 该矩阵任意方子阵非奇异（x_r = r、y_c = k+c 互异且 x_r ^ y_c 恒非 0），
 * 这是 RS 从任意 ≥k 个幸存符号重构的代数基础。
 */
public final class Cauchy {

    private Cauchy() {}

    /**
     * cauchy.ts:6-8：C++ 对 (r ^ (k + c)) 做了 uint8 截断，故先整体 & 0xff 再求逆。
     * 协议约束 n + k ≤ 256 保证 k + c ≤ 255，实际不会触到 256 回绕，但公式保持原样。
     */
    public static int cauchyCoeff(int r, int c, int k) {
        return Gf256.gfInv((r ^ (k + c)) & 0xff);
    }

    /** 行主序 k x n 矩阵，m[r * n + c]（cauchy.ts:11-17 cauchyMatrix）。 */
    public static byte[] cauchyMatrix(int n, int k) {
        byte[] m = new byte[n * k];
        for (int r = 0; r < k; ++r) {
            for (int c = 0; c < n; ++c) m[r * n + c] = (byte) cauchyCoeff(r, c, k);
        }
        return m;
    }

    /**
     * GF(2^8) Gauss-Jordan 求逆；成功时就把 matrix 就地变为逆矩阵
     * （cauchy.ts:19-54 cauchyInvertMatrix）。奇异（出现零主元列）返回 false。
     */
    public static boolean cauchyInvertMatrix(byte[] matrix, int dim) {
        byte[] inverse = new byte[dim * dim];
        for (int i = 0; i < dim; ++i) inverse[i * dim + i] = 1;
        for (int col = 0; col < dim; ++col) {
            int pivot = col;
            while (pivot < dim && matrix[pivot * dim + col] == 0) ++pivot;
            if (pivot == dim) return false;
            if (pivot != col) {
                for (int j = 0; j < dim; ++j) {
                    byte a = matrix[pivot * dim + j];
                    matrix[pivot * dim + j] = matrix[col * dim + j];
                    matrix[col * dim + j] = a;
                    byte b = inverse[pivot * dim + j];
                    inverse[pivot * dim + j] = inverse[col * dim + j];
                    inverse[col * dim + j] = b;
                }
            }
            int pivotInv = Gf256.gfInv(matrix[col * dim + col] & 0xff);
            for (int j = 0; j < dim; ++j) {
                matrix[col * dim + j] = (byte) Gf256.gfMul(matrix[col * dim + j] & 0xff, pivotInv);
                inverse[col * dim + j] = (byte) Gf256.gfMul(inverse[col * dim + j] & 0xff, pivotInv);
            }
            for (int row = 0; row < dim; ++row) {
                if (row == col) continue;
                int factor = matrix[row * dim + col] & 0xff;
                if (factor == 0) continue;
                for (int j = 0; j < dim; ++j) {
                    matrix[row * dim + j] ^= (byte) Gf256.gfMul(factor, matrix[col * dim + j] & 0xff);
                    inverse[row * dim + j] ^= (byte) Gf256.gfMul(factor, inverse[col * dim + j] & 0xff);
                }
            }
        }
        System.arraycopy(inverse, 0, matrix, 0, inverse.length);
        return true;
    }
}
