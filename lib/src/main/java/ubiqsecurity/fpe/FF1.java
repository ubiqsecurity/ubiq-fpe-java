package ubiqsecurity.fpe;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * FF1 algorithm for format-preserving encryption
 */
public class FF1
{
    private FFX ctx;

    /**
     * Constructs a new context object for the FF1 algorithm.
     *
     * @param key     a byte array containing the key
     * @param twk     a byte array containing the "tweak" or iv. this value
     *                may not be null, and the number of bytes must be between
     *                the minimum and maximum allowed sizes
     * @param twkmin  the minimum number of bytes allowable for a tweak
     * @param twkmax  the maximum number of bytes allowable for a tweak or
     *                0 to indicate that there is no maximum
     * @param radix   the radix of the alphabet used for the plain and cipher
     *                text inputs/outputs
     */
    public FF1(final byte[] key, final byte[] twk,
               final long twkmin, final long twkmax,
               final int radix) {
        ctx = new FFX(key, twk, (long)1 << 32, twkmin, twkmax, radix);
    }

    private String cipher(final String X, byte[] twk, final boolean encrypt) {
        final int n = X.length();
        final int u = n / 2, v = n - u;

        final int b = ((int)Math.ceil(
                           (Math.log(ctx.radix) / Math.log(2)) * v) + 7) / 8;
        final int d = 4 * ((b + 3) / 4) + 4;

        final int p = 16;
        final int r = ((d + 15) / 16) * 16;

        String A, B, Y;
        byte[] PQ, R;
        int q;

        if (twk == null) {
            twk = ctx.twk;
        }

        if (n < ctx.txtmin || n > ctx.txtmax) {
            throw new IllegalArgumentException("invalid input length");
        } else if (twk.length < ctx.twkmin ||
                   (ctx.twkmax > 0 && twk.length > ctx.twkmax)) {
            throw new IllegalArgumentException("invalid tweak length");
        }

        q = ((twk.length + b + 1 + 15) / 16) * 16;

        PQ = new byte[p + q];
        R  = new byte[r];

        if (encrypt) {
            A = X.substring(0, u);
            B = X.substring(u);
        } else {
            B = X.substring(0, u);
            A = X.substring(u);
        }

        PQ[0]  = 1;
        PQ[1]  = 2;
        PQ[2]  = 1;
        PQ[3]  = (byte)(ctx.radix >> 16);
        PQ[4]  = (byte)(ctx.radix >>  8);
        PQ[5]  = (byte)(ctx.radix >>  0);
        PQ[6]  = 10;
        PQ[7]  = (byte)u;
        PQ[8]  = (byte)(n >> 24);
        PQ[9]  = (byte)(n >> 16);
        PQ[10] = (byte)(n >>  8);
        PQ[11] = (byte)(n >>  0);
        PQ[12] = (byte)(twk.length >> 24);
        PQ[13] = (byte)(twk.length >> 16);
        PQ[14] = (byte)(twk.length >>  8);
        PQ[15] = (byte)(twk.length >>  0);

        System.arraycopy(twk, 0, PQ, p, twk.length);
        /* remainder of Q already initialized to 0 */

        for (int i = 0; i < 10; i++) {
            final int m = (((i + (encrypt ? 1 : 0)) % 2) == 1) ? u : v;

            BigInteger c, y;
            byte[] numb;

            PQ[PQ.length - b - 1] = (byte)(encrypt ? i : (9 - i));

            c = new BigInteger(B, ctx.radix);
            numb = c.toByteArray();
            if (b <= numb.length) {
                System.arraycopy(numb, 0, PQ, PQ.length - b, b);
            } else {
                Arrays.fill(PQ, PQ.length - b,
                            PQ.length - numb.length,
                            (byte)0);
                System.arraycopy(numb, 0,
                                 PQ, PQ.length - numb.length,
                                 numb.length);
            }

            ctx.prf(R, 0, PQ, 0);

            for (int j = 1; j < r / 16; j++) {
                final int l = j * 16;

                Arrays.fill(R, l, l + 12, (byte)0);
                R[l + 12] = (byte)(j >> 24);
                R[l + 13] = (byte)(j >> 16);
                R[l + 14] = (byte)(j >>  8);
                R[l + 15] = (byte)(j >>  0);

                FFX.xor(R, l, R, 0, R, l, 16);

                ctx.ciph(R, l, R, l);
            }

            y = new BigInteger(Arrays.copyOf(R, d));
            y = y.mod(BigInteger.ONE.shiftLeft(8 * d));

            c = new BigInteger(A, ctx.radix);
            if (encrypt) {
                c = c.add(y);
            } else {
                c = c.subtract(y);
            }

            c = c.mod(BigInteger.valueOf(ctx.radix).pow(m));

            A = B;
            B = FFX.str(m, ctx.radix, c);
        }

        if (encrypt) {
            Y = A + B;
        } else {
            Y = B + A;
        }

        return Y;
    }

    /**
     * Encrypt a string, returning a cipher text using the same alphabet.
     *
     * The key, tweak parameters, and radix were all already set
     * by the initialization of the FF1 object.
     *
     * @param X   the plain text to be encrypted
     * @param twk the tweak used to perturb the encryption
     *
     * @return    the encryption of the plain text, the cipher text
     */
    public String encrypt(String X, byte[] twk) {
        return this.cipher(X, twk, true);
    }

    /**
     * Encrypt a string, returning a cipher text using the same alphabet.
     *
     * The key, tweak parameters, and radix were all already set
     * by the initialization of the FF1 object.
     *
     * @param X   The plain text to be encrypted
     *
     * @return    the encryption of the plain text, the cipher text
     */
    public String encrypt(String X) {
        return this.encrypt(X, null);
    }

    /**
     * Decrypt a string, returning the plain text.
     *
     * The key, tweak parameters, and radix were all already set
     * by the initialization of the FF1 object.
     *
     * @param X   the cipher text to be decrypted
     * @param twk the tweak used to perturb the encryption
     *
     * @return    the decryption of the cipher text, the plain text
     */
    public String decrypt(String X, byte[] twk) {
        return this.cipher(X, twk, false);
    }

    /**
     * Decrypt a string, returning the plain text.
     *
     * The key, tweak parameters, and radix were all already set
     * by the initialization of the FF1 object.
     *
     * @param X   the cipher text to be decrypted
     *
     * @return    the decryption of the cipher text, the plain text
     */
    public String decrypt(String X) {
        return this.decrypt(X, null);
    }
}
