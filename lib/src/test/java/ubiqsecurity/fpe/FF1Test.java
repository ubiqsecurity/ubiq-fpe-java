package ubiqsecurity.fpe;

import java.util.Arrays;

import org.junit.Test;
import static org.junit.Assert.*;

public class FF1Test
{
    private void test(final byte[] key, final byte[] twk,
                      final String PT, final String CT,
                      final int radix) {
        String out;
        FF1 ctx;

        assertEquals(PT.length(), CT.length());

        ctx = new FF1(key, twk, 0, 0, radix);

        out = ctx.encrypt(PT);
        assertEquals(CT, out);

        out = ctx.decrypt(CT);
        assertEquals(PT, out);
    }

    private final byte[] key = {
        (byte)0x2b, (byte)0x7e, (byte)0x15, (byte)0x16,
        (byte)0x28, (byte)0xae, (byte)0xd2, (byte)0xa6,
        (byte)0xab, (byte)0xf7, (byte)0x15, (byte)0x88,
        (byte)0x09, (byte)0xcf, (byte)0x4f, (byte)0x3c,
        (byte)0xef, (byte)0x43, (byte)0x59, (byte)0xd8,
        (byte)0xd5, (byte)0x80, (byte)0xaa, (byte)0x4f,
        (byte)0x7f, (byte)0x03, (byte)0x6d, (byte)0x6f,
        (byte)0x04, (byte)0xfc, (byte)0x6a, (byte)0x94,
    };

    private final byte[] twk1 = {};
    private final byte[] twk2 = {
        (byte)0x39, (byte)0x38, (byte)0x37, (byte)0x36,
        (byte)0x35, (byte)0x34, (byte)0x33, (byte)0x32,
        (byte)0x31, (byte)0x30,
    };
    private final byte[] twk3 = {
        (byte)0x37, (byte)0x37, (byte)0x37, (byte)0x37,
        (byte)0x70, (byte)0x71, (byte)0x72, (byte)0x73,
        (byte)0x37, (byte)0x37, (byte)0x37,
    };

    private final String[] PT = {
        "0123456789", "0123456789abcdefghi"
    };

    @Test
    public void nist1() {
        this.test(Arrays.copyOf(this.key, 16),
                  this.twk1,
                  PT[0], "2433477484", 10);
    }

    @Test
    public void nist2() {
        this.test(Arrays.copyOf(this.key, 16),
                  this.twk2,
                  PT[0], "6124200773", 10);
    }

    @Test
    public void nist3() {
        test(Arrays.copyOf(this.key, 16),
             this.twk3,
             PT[1], "a9tv40mll9kdu509eum", 36);
    }

    @Test
    public void nist4() {
        test(Arrays.copyOf(this.key, 24),
             this.twk1,
             PT[0], "2830668132", 10);
    }

    @Test
    public void nist5() {
        test(Arrays.copyOf(this.key, 24),
             this.twk2,
             PT[0], "2496655549", 10);
    }

    @Test
    public void nist6() {
        test(Arrays.copyOf(this.key, 24),
             this.twk3,
             PT[1], "xbj3kv35jrawxv32ysr", 36);
    }

    @Test
    public void nist7() {
        test(Arrays.copyOf(this.key, 32),
             this.twk1,
             PT[0], "6657667009", 10);
    }

    @Test
    public void nist8() {
        test(Arrays.copyOf(this.key, 32),
             this.twk2,
             PT[0], "1001623463", 10);
    }

    @Test
    public void nist9() {
        test(Arrays.copyOf(this.key, 32),
             this.twk3,
             PT[1], "xs8a0azh2avyalyzuwd", 36);
    }

    @Test
    public void base2() {
        byte[] l_key = {
            (byte)0xF4, (byte)0xA1, (byte)0x16, (byte)0xD6,
            (byte)0xEE, (byte)0x40, (byte)0x6A, (byte)0x53,
            (byte)0xA5, (byte)0x6C, (byte)0xBE, (byte)0x0F,
            (byte)0x4A, (byte)0xA7, (byte)0xB1, (byte)0x00,
            (byte)0x1C, (byte)0xDC, (byte)0x0A, (byte)0x55,
            (byte)0xCA, (byte)0xC9, (byte)0x63, (byte)0xCF,
            (byte)0x5A, (byte)0xCE, (byte)0x39, (byte)0x04,
            (byte)0x88, (byte)0xB3, (byte)0x47, (byte)0x7A
        };
        byte[] l_tweak = {
            (byte)0xFD, (byte)0x7F, (byte)0x4B, (byte)0x99,
            (byte)0x45, (byte)0xA3, (byte)0xC5, (byte)0x35,
            (byte)0xAD, (byte)0xB4, (byte)0x72, (byte)0x00,
            (byte)0x27, (byte)0x11, (byte)0x6C, (byte)0xA0,
            (byte)0xF4, (byte)0x98, (byte)0x7D, (byte)0x7F,
            (byte)0x3F, (byte)0xDB, (byte)0xA9, (byte)0xBB,
            (byte)0xC4, (byte)0x0E, (byte)0x75, (byte)0x37,
            (byte)0x5F, (byte)0xEA, (byte)0xA6, (byte)0x3C
        };
        test(l_key,
             l_tweak,
             "00000101011011011101001001010011100111100011001",
             "10110101001110101101110000011000000011111100111",
             2);
    }

    @Test
    public void base2_a() {
        byte[] l_key = {
            (byte)0xF4, (byte)0xA1, (byte)0x16, (byte)0xD6,
            (byte)0xEE, (byte)0x40, (byte)0x6A, (byte)0x53,
            (byte)0xA5, (byte)0x6C, (byte)0xBE, (byte)0x0F,
            (byte)0x4A, (byte)0xA7, (byte)0xB1, (byte)0x00,
            (byte)0x1C, (byte)0xDC, (byte)0x0A, (byte)0x55,
            (byte)0xCA, (byte)0xC9, (byte)0x63, (byte)0xCF,
            (byte)0x5A, (byte)0xCE, (byte)0x39, (byte)0x04,
            (byte)0x88, (byte)0xB3, (byte)0x47, (byte)0x7A
        };
        byte[] l_tweak = {
            (byte)0xFD, (byte)0x7F, (byte)0x4B, (byte)0x99,
            (byte)0x45, (byte)0xA3, (byte)0xC5, (byte)0x35,
            (byte)0xAD, (byte)0xB4, (byte)0x72, (byte)0x00,
            (byte)0x27, (byte)0x11, (byte)0x6C, (byte)0xA0,
            (byte)0xF4, (byte)0x98, (byte)0x7D, (byte)0x7F,
            (byte)0x3F, (byte)0xDB, (byte)0xA9, (byte)0xBB,
            (byte)0xC4, (byte)0x0E, (byte)0x75, (byte)0x37,
            (byte)0x5F, (byte)0xEA, (byte)0xA6, (byte)0x3C
        };
        test(l_key,
             l_tweak,
             "000010101100011111010000111001100001011010011110100100110010010000000101000011000000001111110101111100111001001001100100100110101111110000011101010111001111010000010010111110101100001001100011",
             "111110001101110010010110001010100001101011001010011010111001001101101000011110000110110000001101011110101100001101000011101110110101001111100001011010010000010111001110010011001100001111100101",
             2);
    }

    @Test
    public void base2_b() {
        byte[] l_key = {
            (byte)0xF4, (byte)0xA1, (byte)0x16, (byte)0xD6,
            (byte)0xEE, (byte)0x40, (byte)0x6A, (byte)0x53,
            (byte)0xA5, (byte)0x6C, (byte)0xBE, (byte)0x0F,
            (byte)0x4A, (byte)0xA7, (byte)0xB1, (byte)0x00,
            (byte)0x1C, (byte)0xDC, (byte)0x0A, (byte)0x55,
            (byte)0xCA, (byte)0xC9, (byte)0x63, (byte)0xCF,
            (byte)0x5A, (byte)0xCE, (byte)0x39, (byte)0x04,
            (byte)0x88, (byte)0xB3, (byte)0x47, (byte)0x7A
        };
        byte[] l_tweak = {
            (byte)0xFD, (byte)0x7F, (byte)0x4B, (byte)0x99,
            (byte)0x45, (byte)0xA3, (byte)0xC5, (byte)0x35,
            (byte)0xAD, (byte)0xB4, (byte)0x72, (byte)0x00,
            (byte)0x27, (byte)0x11, (byte)0x6C, (byte)0xA0,
            (byte)0xF4, (byte)0x98, (byte)0x7D, (byte)0x7F,
            (byte)0x3F, (byte)0xDB, (byte)0xA9, (byte)0xBB,
            (byte)0xC4, (byte)0x0E, (byte)0x75, (byte)0x37,
            (byte)0x5F, (byte)0xEA, (byte)0xA6, (byte)0x3C
        };
        test(l_key,
             l_tweak,
             "00000111011010010101111110011110001011111000110100000101001010001100001101111000010000101011100100010111011101001010010100101010100011010101010000101111111001111100110100001100011001011010010000110",
             "00110011001000111100010111110001000110110110010010101101001011101001101010010001111001010100100001110101010101101110110010100110101110111011111010110010101110000001101000101010100011010100111011000",
             2);
    }
}
