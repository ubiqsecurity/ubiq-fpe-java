package ubiqfpe;

import java.math.BigInteger;

public class FF3_1
{
    private FFX ctx;

    public FF3_1(final byte[] key, final byte[] twk, final int radix) {
        ctx = new FFX(FFX.rev(key), twk,
                      (long)(192.0 / (Math.log(radix) / Math.log(2))),
                      7, 7,
                      radix);
    }

    private String cipher(final String X, byte[] twk, final boolean encrypt) {
        final int n = X.length();
        final int v = n / 2, u = n - v;

        String A, B, Y;
        byte[][] Tw;
        byte[] P;

        if (twk == null) {
            twk = ctx.twk;
        }

        if (n < ctx.txtmin || n > ctx.txtmax) {
            throw new IllegalArgumentException("illegal input length");
        } else if (twk.length < ctx.twkmin ||
                   (ctx.twkmax > 0 && twk.length > ctx.twkmax)) {
            throw new IllegalArgumentException("illegal tweak length");
        }

        if (encrypt) {
            A = X.substring(0, u);
            B = X.substring(u);
        } else {
            B = X.substring(0, u);
            A = X.substring(u);
        }

        Tw = new byte[2][4];
        System.arraycopy(twk, 0, Tw[0], 0, 3);
        Tw[0][3] = (byte)(twk[3] & 0xf0);

        System.arraycopy(twk, 4, Tw[1], 0, 3);
        Tw[1][3] = (byte)((twk[3] & 0x0f) << 4);

        P = new byte[16];

        for (int i = 0; i < 8; i++) {
            final int m = (((i + (encrypt ? 1 : 0)) % 2) == 1) ? u : v;
            BigInteger c, y;
            byte[] numb;

            System.arraycopy(Tw[(i + (encrypt ? 1 : 0)) % 2], 0, P, 0, 4);
            P[3] ^= encrypt ? i : (7 - i);

            c = new BigInteger(FFX.rev(B), ctx.radix);
            numb = c.toByteArray();
            if (12 <= numb.length) {
                System.arraycopy(numb, 0, P, 4, 12);
            } else {
                for (int j = 0; j < 12 - numb.length; j++) {
                    P[4 + j] = 0;
                }
                System.arraycopy(
                    numb, 0, P, P.length - numb.length, numb.length);
            }

            P = FFX.rev(ctx.ciph(FFX.rev(P)));

            y = new BigInteger(P);
            y = y.mod(BigInteger.ONE.shiftLeft(16 * 8));

            c = new BigInteger(FFX.rev(A), ctx.radix);
            if (encrypt) {
                c = c.add(y);
            } else {
                c = c.subtract(y);
            }

            c = c.mod(BigInteger.valueOf(ctx.radix).pow(m));

            A = B;
            B = FFX.rev(FFX.str(m, ctx.radix, c));
        }

        if (encrypt) {
            Y = A + B;
        } else {
            Y = B + A;
        }

        return Y;
    }

    public String encrypt(String X, byte[] twk) {
        return this.cipher(X, twk, true);
    }

    public String encrypt(String X) {
        return this.encrypt(X, null);
    }

    public String decrypt(String X, byte[] twk) {
        return this.cipher(X, twk, false);
    }

    public String decrypt(String X) {
        return this.decrypt(X, null);
    }
}
