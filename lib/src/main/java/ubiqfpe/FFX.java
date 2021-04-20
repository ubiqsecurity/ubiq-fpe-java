package ubiqfpe;

import java.math.BigInteger;

import java.util.Arrays;

import javax.crypto.Cipher;

import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.params.KeyParameter;

class FFX
{
    private CBCBlockCipher cipher;
    private int radix;
    private int txtmin, txtmax;
    private int twkmin, twkmax;
    private byte[] twk;

    public FFX(final byte[] key, final byte[] twk,
               final int txtmax,
               final int twkmin, final int twkmax,
               final int radix) {
        int txtmin;

        switch (key.length) {
        case 16:
        case 24:
        case 32:
            break;
        default:
            throw new IllegalArgumentException("key size error");
        }

        if (radix < 2 || radix > 36) {
            throw new IllegalArgumentException("invalid radix");
        }

        txtmin = (int)Math.ceil(6.0 / Math.log10(radix));
        if (txtmin < 2 || txtmin > txtmax) {
            throw new RuntimeException("minimum text length out of range");
        }

        if (twkmin > twkmax ||
            twk.length < twkmin ||
            (twkmax > 0 && twk.length > twkmax)) {
            throw new IllegalArgumentException("invalid tweak length");
        }

        this.cipher = new CBCBlockCipher(new AESEngine());
        this.cipher.init(true, new KeyParameter(key));

        this.radix = radix;

        this.txtmin = txtmin;
        this.txtmax = txtmax;

        this.twkmin = twkmin;
        this.twkmax = twkmax;

        this.twk = Arrays.copyOf(twk, twk.length);
    }

    public byte[] prf(final byte[] src) {
        byte[] dst = new byte[this.cipher.getBlockSize()];

        if (src.length % dst.length != 0) {
            throw new IllegalArgumentException("invalid source length");
        }

        for (int i = 0; i < src.length; i += dst.length) {
            this.cipher.processBlock(src, i, dst, 0);
        }
        this.cipher.reset();

        return dst;
    }

    public byte[] ciph(final byte[] src) {
        if (src.length != this.cipher.getBlockSize()) {
            throw new IllegalArgumentException("invalid source length");
        }

        return this.prf(src);
    }

    public static byte[] rev(final byte[] src) {
        byte[] dst = new byte[src.length];

        for (int i = 0; i < src.length; i++) {
            dst[i] = src[src.length - i - 1];
        }

        return dst;
    }

    public static String rev(final String str) {
        StringBuilder sb =  new StringBuilder(str);
        return sb.reverse().toString();
    }

    public static byte[] xor(final byte[] s1, final byte[] s2) {
        byte[] dst = new byte[Math.min(s1.length, s2.length)];

        for (int i = 0; i < dst.length; i++) {
            dst[i] = (byte)(s1[i] ^ s2[i]);
        }

        return dst;
    }

    public static String str(final int m, final int r, final BigInteger i) {
        String s = i.toString(r);

        if (s.length() > m) {
            throw new RuntimeException("string exceeds desired length");
        } else if (s.length() < m) {
            StringBuilder sb = new StringBuilder();

            while (sb.length() < m - s.length()) {
                sb.append('0');
            }

            sb.append(s);
            s = sb.toString();
        }

        return s;
    }
}
