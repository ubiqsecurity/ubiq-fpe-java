package ubiqfpe;

import java.math.BigInteger;

import java.util.Arrays;

import javax.crypto.Cipher;

import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.params.KeyParameter;

class FFX
{
    public CBCBlockCipher cipher;
    public int radix;
    public long txtmin, txtmax;
    public long twkmin, twkmax;
    public byte[] twk;

    public FFX(final byte[] key, final byte[] twk,
               final long txtmax,
               final long twkmin, final long twkmax,
               final int radix) {
        long txtmin;

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

    public void prf(byte[] dst, final int doff,
                    final byte[] src, final int soff) {
        if ((src.length - soff) % this.cipher.getBlockSize() != 0) {
            throw new IllegalArgumentException("invalid source length");
        }

        for (int i = 0; i < src.length; i += dst.length) {
            this.cipher.processBlock(src, soff + i, dst, doff);
        }
        this.cipher.reset();
    }

    public void ciph(byte[] dst, final int doff,
                     final byte[] src, final int soff) {
        if (src.length - soff != this.cipher.getBlockSize()) {
            throw new IllegalArgumentException("invalid source length");
        }

        this.prf(dst, doff, src, soff);
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

    public static void xor(byte[] d, final int doff,
                           final byte[] s1, final int s1off,
                           final byte[] s2, final int s2off,
                           final int len) {
        for (int i = 0; i < len; i++) {
            d[doff + i] = (byte)(s1[s1off + i] ^ s2[s2off + i]);
        }
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
