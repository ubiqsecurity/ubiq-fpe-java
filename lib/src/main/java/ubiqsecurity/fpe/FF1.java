package ubiqsecurity.fpe;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * FF1 algorithm for format-preserving encryption
 */
public class FF1 extends FFX
{
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
        super(key, twk, (long)1 << 32, twkmin, twkmax, radix, FFX.DEFAULT_ALPHABET);
    }

    public FF1(final byte[] key, final byte[] twk,
      final long twkmin, final long twkmax,
      final int radix, final String alpha) {
      super(key, twk, (long)1 << 32, twkmin, twkmax, radix, alpha);
    }

    /*
     * The comments below reference the steps of the algorithm described here:
     *
     * https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38Gr1-draft.pdf
     */
    protected String cipher(final String X, byte[] twk, final boolean encrypt) {
        /* Step 1 */
        final int n = X.length();
        final int u = n / 2, v = n - u;

        /* Step 3, 4 */
        final int b = ((int)Math.ceil(
                           (Math.log(this.radix) / Math.log(2)) * v) + 7) / 8;
        final int d = 4 * ((b + 3) / 4) + 4;

        final int p = 16;
        final int r = ((d + 15) / 16) * 16;

        String A, B;
        byte[] PQ, R;
        int q;

        /* use default tweak if none is supplied */
        if (twk == null) {
            twk = this.twk;
        }

        /* check text and tweak lengths */
        if (n < this.txtmin || n > this.txtmax) {
            throw new IllegalArgumentException("invalid input length");
        } else if (twk.length < this.twkmin ||
                   (this.twkmax > 0 && twk.length > this.twkmax)) {
            throw new IllegalArgumentException("invalid tweak length");
        }

        /* the number of bytes in Q */
        q = ((twk.length + b + 1 + 15) / 16) * 16;

        /*
         * P and Q need to be adjacent in memory for the
         * purposes of encryption
         */
        PQ = new byte[p + q];
        R  = new byte[r];

        /* Step 2 */
        if (encrypt) {
            A = X.substring(0, u);
            B = X.substring(u);
        } else {
            B = X.substring(0, u);
            A = X.substring(u);
        }
        /* Step 5 */
        PQ[0]  = 1;
        PQ[1]  = 2;
        PQ[2]  = 1;
        PQ[3]  = (byte)(this.radix >> 16);
        PQ[4]  = (byte)(this.radix >>  8);
        PQ[5]  = (byte)(this.radix >>  0);
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

        /* Step 6i, the static parts */
        System.arraycopy(twk, 0, PQ, p, twk.length);
        /* remainder of Q already initialized to 0 */

        for (int i = 0; i < 10; i++) {
          /* Step 6v */
            final int m = (((i + (encrypt ? 1 : 0)) % 2) == 1) ? u : v;

            BigInteger c, y;
            byte[] numb;

            /* Step 6i, the non-static parts */
            PQ[PQ.length - b - 1] = (byte)(encrypt ? i : (9 - i));

            /*
             * convert the numeral string B to an integer and
             * export that integer as a byte array into Q
             */
            c = FFX.number(B, this.radix, this.alpha); //new BigInteger(B, this.radix);
            numb = c.toByteArray();
            if (numb[0] == 0 && numb.length > 1) {
                /*
                 * Per the Java documentation, BigInteger.toByteArray always
                 * returns enough bytes to contain a sign bit. For the purposes
                 * of this function all numbers are unsigned; however, when the
                 * most-significant bit is set in a number, the Java library
                 * returns an extra most-significant byte that is set to 0.
                 * That byte must be removed for the cipher to work correctly.
                 */
                numb = Arrays.copyOfRange(numb, 1, numb.length);
            }
            if (b <= numb.length) {
                System.arraycopy(numb, 0, PQ, PQ.length - b, b);
            } else {
                /* pad on the left with zeros */
                Arrays.fill(PQ, PQ.length - b,
                            PQ.length - numb.length,
                            (byte)0);
                System.arraycopy(numb, 0,
                                 PQ, PQ.length - numb.length,
                                 numb.length);
            }

            /* Step 6ii */
            this.prf(R, 0, PQ, 0, PQ.length);

            /*
             * Step 6iii
             * if r is greater than 16, fill the subsequent blocks
             * with the result of ciph(R ^ 1), ciph(R ^ 2), ...
             */
            for (int j = 1; j < r / 16; j++) {
                final int l = j * 16;

                Arrays.fill(R, l, l + 12, (byte)0);
                R[l + 12] = (byte)(j >> 24);
                R[l + 13] = (byte)(j >> 16);
                R[l + 14] = (byte)(j >>  8);
                R[l + 15] = (byte)(j >>  0);

                FFX.xor(R, l, R, 0, R, l, 16);

                this.ciph(R, l, R, l);
            }

            /*
             * Step 6vi
             * calculate A +/- y mod radix**m
             * where y is the number formed by the first d bytes of R
             */
            y = new BigInteger(Arrays.copyOf(R, d));
            y = y.mod(BigInteger.ONE.shiftLeft(8 * d));

            c = FFX.number(A, this.radix, this.alpha); //new BigInteger(A, this.radix);
            if (encrypt) {
                c = c.add(y);
            } else {
                c = c.subtract(y);
            }

            c = c.mod(BigInteger.valueOf(this.radix).pow(m));

            /* Step 6viii */
            A = B;
            /* Step 6vii, 6ix */
            B = FFX.str(m, this.radix, this.alpha, c);
        }

        /* Step 7 */
        return encrypt ? (A + B) : (B + A);
    }
}
