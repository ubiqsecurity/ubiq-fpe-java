package ubiqsecurity.fpe;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * FF3-1 algorithm for format-preserving encryption
 */
public class FF3_1 extends FFX
{
    /**
     * Constructs a new context object for the FF3-1 algorithm.
     *
     * @param key     a byte array containing the key
     * @param twk     a byte array containing the "tweak" or iv. this value
     *                may not be null, and the number of bytes must be 7
     * @param radix   the radix of the alphabet used for the plain and cipher
     *                text inputs/outputs
     */
    public FF3_1(final byte[] key, final byte[] twk, final int radix) {
        /*
         * maxlen for ff3-1:
         * = 2 * log_radix(2**96)
         * = 2 * log_radix(2**48 * 2**48)
         * = 2 * (log_radix(2**48) + log_radix(2**48))
         * = 2 * (2 * log_radix(2**48))
         * = 4 * log_radix(2**48)
         * = 4 * log2(2**48) / log2(radix)
         * = 4 * 48 / log2(radix)
         * = 192 / log2(radix)
         *
         * note also that the key is reversed for FF3-1
         */
        super(FFX.rev(key), twk,
              (long)(192.0 / (Math.log(radix) / Math.log(2))),
              7, 7,
              radix);
    }

    protected String cipher(final String X, byte[] twk, final boolean encrypt) {
        /* Step 1 */
        final int n = X.length();
        final int v = n / 2, u = n - v;

        String A, B;
        byte[][] Tw;
        byte[] P;

        /* use the default tweak if none is given */
        if (twk == null) {
            twk = this.twk;
        }

        /* check text and tweak lengths */
        if (n < this.txtmin || n > this.txtmax) {
            throw new IllegalArgumentException("illegal input length");
        } else if (twk.length < this.twkmin ||
                   (this.twkmax > 0 && twk.length > this.twkmax)) {
            throw new IllegalArgumentException("illegal tweak length");
        }

        /* Step 2 */
        if (encrypt) {
            A = X.substring(0, u);
            B = X.substring(u);
        } else {
            B = X.substring(0, u);
            A = X.substring(u);
        }

        /* Step 3 */
        Tw = new byte[2][4];
        System.arraycopy(twk, 0, Tw[0], 0, 3);
        Tw[0][3] = (byte)(twk[3] & 0xf0);

        System.arraycopy(twk, 4, Tw[1], 0, 3);
        Tw[1][3] = (byte)((twk[3] & 0x0f) << 4);

        P = new byte[16];

        for (int i = 0; i < 8; i++) {
            /* Step 4i */
            final int m = (((i + (encrypt ? 1 : 0)) % 2) == 1) ? u : v;
            BigInteger c, y;
            byte[] numb;

            /* Step 4i, 4ii */
            System.arraycopy(Tw[(i + (encrypt ? 1 : 0)) % 2], 0, P, 0, 4);
            /* W ^ i */
            P[3] ^= encrypt ? i : (7 - i);

            /*
             * reverse B and convert the numeral string to an
             * integer. then, export that integer as an array.
             * store the array into the latter part of P
             */
            c = new BigInteger(FFX.rev(B), this.radix);
            numb = c.toByteArray();
            if (12 <= numb.length) {
                System.arraycopy(numb, 0, P, 4, 12);
            } else {
                /* zero pad on the left */
                Arrays.fill(P, 4, P.length - numb.length, (byte)0);
                System.arraycopy(
                    numb, 0, P, P.length - numb.length, numb.length);
            }

            /* Step 4iv */
            P = FFX.rev(this.ciph(FFX.rev(P)));

            /*
             * Step 4v
             * calculate reverse(A) +/- y mode radix**m
             * where y is the number formed by the byte array P
             */
            y = new BigInteger(P);
            y = y.mod(BigInteger.ONE.shiftLeft(16 * 8));

            c = new BigInteger(FFX.rev(A), this.radix);
            if (encrypt) {
                c = c.add(y);
            } else {
                c = c.subtract(y);
            }

            c = c.mod(BigInteger.valueOf(this.radix).pow(m));

            /* Step 4vii */
            A = B;
            /* Step 4vi */
            B = FFX.rev(FFX.str(m, this.radix, c));
        }

        /* Step 5 */
        return encrypt ? (A + B) : (B + A);
    }
}
